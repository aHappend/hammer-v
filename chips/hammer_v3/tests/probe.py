"""Bounded advisory probes; not a substitute for the five admitted suites."""

import argparse
import difflib
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import BareMachine, StartupMachine, bare_program, startup_program
from scenarios import walker_cases
from peripherals import plic_vectors, uart_vectors, compare_waveform


ROOT = Path(__file__).resolve().parent.parent


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Probe:
    def __init__(self, name):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self.folder = ROOT / "evidence" / "preparation" / f"{name}-{stamp}"
        self.folder.mkdir(parents=True, exist_ok=False)
        sources = sorted([*ROOT.glob("rtl/*.sv"), *ROOT.glob("design/*.md"),
                          *ROOT.glob("tests/*"), *ROOT.glob("hammer_v2_reference/rtl/*.sv")])
        sources = [p for p in sources if p.is_file()]
        self.receipt = {
            "kind": "advisory-verifier-preparation",
            "acceptance_evidence": False,
            "argv": [sys.executable, *sys.argv],
            "cwd": ".",
            "python_version": sys.version,
            "started_at": now(),
            "source_sha256": {str(p.relative_to(ROOT)): digest(p) for p in sources},
            "commands": [],
            "assertions": [],
        }
        for source in sources:
            copy = self.folder / "source" / source.relative_to(ROOT)
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copy)
        self.persist()

    def relative(self, path):
        return str(path.relative_to(ROOT))

    def persist(self):
        (self.folder / "receipt.json").write_text(json.dumps(self.receipt, indent=2) + "\n")

    def run(self, label, argv, timeout=3600, accepted_exits=(0,)):
        record = {"argv": argv, "cwd": ".", "started_at": now(), "timeout_s": timeout}
        stdout = self.folder / f"{label}.stdout.txt"
        stderr = self.folder / f"{label}.stderr.txt"
        record.update(stdout=self.relative(stdout), stderr=self.relative(stderr))
        start = time.monotonic()
        with stdout.open("w") as out, stderr.open("w") as err:
            try:
                child = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, timeout=timeout)
                record.update(exit_status=child.returncode, timed_out=False)
            except subprocess.TimeoutExpired:
                record.update(exit_status=None, timed_out=True)
            except OSError as error:
                record.update(exit_status=None, timed_out=False, tool_error=str(error))
        record.update(ended_at=now(), elapsed_s=time.monotonic() - start)
        self.receipt["commands"].append(record)
        self.persist()
        if record["timed_out"] or record["exit_status"] not in accepted_exits:
            raise RuntimeError(f"{label} failed; see {record['stderr']} and {record['stdout']}")
        return stdout.read_text()

    def finish(self, error=None):
        self.receipt.update(ended_at=now(), exit_status=int(error is not None),
                            failure=error)
        self.persist()
        print(self.relative(self.folder / "receipt.json"))


def generate_top_wiring(top, source, folder, dmem_words):
    header = source.read_text().split(");", 1)[0].split(") (", 1)[1]
    ports = []
    for declaration in header.split(","):
        match = re.match(r"\s*(input|output)\s+(?:wire|reg)\s*(\[[^]]+\])?\s*(\w+)\s*$",
                         declaration)
        if match:
            direction, width, name = match.groups()
        else:
            match = re.match(r"\s*(\w+)\s*$", declaration)
            if not match or not ports:
                raise ValueError(f"unparsed public port declaration: {declaration!r}")
            name = match[1]
        ports.append((direction, width or "", name))
    driven = {"clk", "rst_n", "start", "host_valid", "host_write", "host_imem",
              "host_addr", "host_wdata", "host_wstrb", "dbg_raddr"}
    declarations = []
    for direction, width, name in ports:
        if direction == "output":
            declarations.append(f"wire {width} {name};")
        elif name in driven:
            declarations.append(f"reg {width} {name};")
        else:
            value = "1'b1" if name == "uart_rx" else "'0"
            declarations.append(f"wire {width} {name} = {value};")
    (folder / "top_declarations.svh").write_text("\n".join(declarations) + "\n")
    instance = f"""{top} #(.IMEM_WORDS(128), .DMEM_WORDS({dmem_words}), .BTB_ENTRIES(1),
        .PRED_MODE(0), .ICACHE_LINES(1), .DCACHE_LINES(1)) dut (
"""
    instance += ",\n".join(f".{name}({name})" for _, _, name in ports) + ");\n"
    (folder / "top_instance.svh").write_text(instance)


def compare_trace(probe, trace, model):
    comparisons = 0
    terminal = False
    for line in trace.read_text().splitlines():
        fields = line.split()
        values = [int(field, 16) for field in fields[1:]]
        expected = model.step()
        if fields[0] != expected[0]:
            raise AssertionError(f"event {comparisons}: expected {expected}, observed {line}")
        if fields[0] == "T":
            if tuple(values) != expected[1:]:
                raise AssertionError(f"trap expected {expected}, observed {line}")
            terminal = True
        else:
            if tuple(values[:6]) != expected[1:7] or values[12] != expected[8]:
                raise AssertionError(f"retirement {comparisons}: expected {expected}, observed {line}")
            memory = expected[7]
            if values[6] != int(memory is not None):
                raise AssertionError(f"memory validity expected {expected}, observed {line}")
            if memory:
                write, address, mask, data, read = memory
                if (values[7], values[8]) != (write, address):
                    raise AssertionError(f"memory operation expected {expected}, observed {line}")
                if write and (values[9], values[10]) != (mask, data):
                    raise AssertionError(f"store expected {expected}, observed {line}")
                if not write and values[11] != read:
                    raise AssertionError(f"load expected {expected}, observed {line}")
        comparisons += 1
    if not terminal:
        raise AssertionError(f"incomplete probe: comparisons={comparisons}, terminal={terminal}")
    probe.receipt["assertions"].append(
        {"id": "startup-public-retirement" if isinstance(model, StartupMachine) else
               "bare-public-retirement",
         "passed": True, "comparisons": comparisons,
         "scope": "bounded startup/integer/M/load-store/fence probe, not full coverage closure"})


def top_probe(probe, parent, sv39_startup=False):
    for tool, option in (("iverilog", "-V"), ("vvp", "-V"), ("python3", "--version")):
        probe.run(f"version-{tool}", [tool, option])
    top = "hammer_v2_top" if parent else "hammer_v3_top"
    source = ROOT / "rtl" / f"{top}.sv"
    generate_top_wiring(top, source, probe.folder, 4096 if sv39_startup else 32)
    words, data = startup_program() if sv39_startup else (bare_program(), {})
    program = probe.folder / "program.hex"
    program.write_text("".join(f"{word:08x}\n" for word in words + [0x13] * (128 - len(words))))
    binary = probe.folder / "simulation.vvp"
    trace = probe.folder / "trace.txt"
    probe.run("compile", ["iverilog", "-g2012", "-Wall", "-s", "top_probe",
                         "-I", probe.relative(probe.folder), "-o", probe.relative(binary),
                         "tests/top_probe.sv",
                         *[str(p.relative_to(ROOT)) for p in sorted(ROOT.glob("rtl/*.sv"))]])
    argv = ["vvp", probe.relative(binary),
            f"+program={probe.relative(program)}", f"+trace={probe.relative(trace)}"]
    if data:
        image = probe.folder / "data.hex"
        image.write_text("".join(f"{address:08x} {word:016x}\n"
                                 for address, word in sorted(data.items())))
        argv.append(f"+data={probe.relative(image)}")
    probe.run("simulation", argv)
    model = StartupMachine(words, data) if sv39_startup else BareMachine(words)
    compare_trace(probe, trace, model)


def synthesis_probe(probe):
    probe.run("version-yosys", ["yosys", "-V"])
    netlist = probe.folder / "netlist.json"
    script = probe.folder / "synthesis.ys"
    script.write_text(
        "read_verilog -sv " +
        " ".join(str(p.relative_to(ROOT)) for p in sorted(ROOT.glob("rtl/*.sv"))) + "\n"
        "chparam -set IMEM_WORDS 1 -set DMEM_WORDS 1 -set ICACHE_LINES 1 "
        "-set DCACHE_LINES 1 -set BTB_ENTRIES 1 -set ITLB_ENTRIES 1 "
        "-set DTLB_ENTRIES 1 hammer_v3_top\n"
        "hierarchy -check -top hammer_v3_top\n"
        "proc\nopt_expr\nopt_clean\ncheck -assert\n"
        "memory -nomap\nopt_clean\ncheck -assert\n"
        "select -assert-none t:$dlatch t:$adlatch t:$div t:$mod t:$divfloor t:$modfloor\n"
        "stat\nwrite_json " + probe.relative(netlist) + "\n"
    )
    probe.run("synthesis", ["yosys", "-Q", "-T", "-s", probe.relative(script)])
    modules = json.loads(netlist.read_text())["modules"]
    cells = sum(len(module.get("cells", {})) for module in modules.values())
    memories = sum(1 for module in modules.values() for cell in module.get("cells", {}).values()
                   if cell["type"].startswith("$mem"))
    if cells < 100 or memories == 0:
        raise AssertionError(f"non-substantive synthesis: cells={cells}, memories={memories}")
    probe.receipt["assertions"].append(
        {"id": "minimum-structural-preparation", "passed": True, "cells": cells,
         "memory_cells": memories, "scope": "minimum only; no timing claim"})


WALKER_MUTANTS = {
    "vpn-index": ("hammer_v3_ptw.sv", [
        ("va_q[38:30]", "va_q[37:29]")], "PTW_ADDRESS"),
    "superpage-alignment": ("hammer_v3_page_leaf.sv", [
        ("if (|ppn[8:0]) fault = 1'b1;", "if (1'b0) fault = 1'b1;")], "PTW_RESULT"),
    "user-permission": ("hammer_v3_page_leaf.sv", [
        ("if (priv == 0 && !flags[4])", "if (1'b0)")], "PTW_RESULT"),
    "accessed-dirty": ("hammer_v3_page_leaf.sv", [
        ("(!flags[1] && !flags[3]) || !flags[6] ||", "(!flags[1] && !flags[3]) ||"),
        ("2'd2: if (!flags[2] || !flags[7])", "2'd2: if (!flags[2])"),
        ("2'd3: if (!flags[1] || !flags[2] || !flags[7])",
         "2'd3: if (!flags[1] || !flags[2])")], "PTW_RESULT"),
}


def walker_probe(probe, mutant=None):
    probe.run("version-verilator", ["verilator", "--version"])
    probe.run("version-g++", ["g++", "--version"])
    probe.run("version-make", ["make", "--version"])
    cases = list(walker_cases())
    vector_file = probe.folder / "vectors.txt"
    with vector_file.open("w") as stream:
        for case in cases:
            stream.write(" ".join(f"{case[key]:x}" for key in
                         ("va", "root", "asid", "access", "priv", "sum", "mxr",
                          "expected_pa", "fault", "level", "global")) +
                         f" {len(case['reads'])}\n")
            for address, pte, error in case["reads"]:
                stream.write(f"{address:x} {pte:x} {error:x}\n")
    (probe.folder / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    objects = probe.folder / "compile-obj"
    rtl = ["rtl/hammer_v3_ptw.sv", "rtl/hammer_v3_page_leaf.sv"]
    if mutant:
        filename, changes, intended_assertion = WALKER_MUTANTS[mutant]
        copied = probe.folder / "mutant-rtl"
        copied.mkdir()
        for path in rtl:
            shutil.copyfile(ROOT / path, copied / Path(path).name)
        target = copied / filename
        before = target.read_text()
        after = before
        for old, new in changes:
            if after.count(old) != 1:
                raise AssertionError(f"mutation {mutant} does not have one exact target: {old}")
            after = after.replace(old, new, 1)
        target.write_text(after)
        delta = probe.folder / "mutation.diff"
        delta.write_text("".join(difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True),
            fromfile=f"rtl/{filename}", tofile=f"mutant-rtl/{filename}")))
        probe.receipt["mutation"] = {
            "class": mutant, "delta": probe.relative(delta),
            "original_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "mutant_sha256": digest(target),
            "intended_assertion": intended_assertion,
        }
        rtl = [probe.relative(copied / Path(path).name) for path in rtl]
        probe.persist()
    try:
        probe.run("compile", ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                             "--top-module", "ptw_probe", "--Mdir", probe.relative(objects),
                             "-o", "../simulation", "tests/ptw_probe.sv", *rtl])
        output = probe.run("simulation", [probe.relative(probe.folder / "simulation"),
                                          f"+vectors={probe.relative(vector_file)}"],
                           accepted_exits=(1, -6, 134) if mutant else (0,))
        if mutant:
            failure = re.search(rf"{intended_assertion} case=\d+[^\n]*", output)
            if not failure:
                raise AssertionError(f"{mutant}: rejection was not its intended semantic comparison")
            probe.receipt["assertions"].append(
                {"id": "disposable-defect-sensitivity", "passed": True, "mutant": mutant,
                 "first_failing_assertion": failure[0],
                 "scope": "four PTW classes only, not the complete nine-class defect suite"})
            return
        match = re.search(r"PTW_COMPARE_COMPLETE cases=(\d+) success=(\d+) page=(\d+) access=(\d+)",
                          output)
        if not match or int(match[1]) != len(cases) or any(int(match[n]) == 0 for n in (2, 3, 4)):
            raise AssertionError("walker result lacks required actual comparison summary")
        probe.receipt["assertions"].append(
            {"id": "ptw-independent-translation", "passed": True, "seed": 17,
             "comparisons": int(match[1]), "success": int(match[2]),
             "page_faults": int(match[3]), "access_faults": int(match[4]),
             "scope": "supplemental real PTW, not the top-level seeded system matrix"})
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def parameter_probe(probe):
    probe.run("version-iverilog", ["iverilog", "-V"])
    probe.run("version-vvp", ["vvp", "-V"])
    legal = {
        "IMEM_WORDS": [1, 3, 16384], "DMEM_WORDS": [1, 3, 8192],
        "PRED_MODE": [0, 1], "BTB_ENTRIES": [1, 4, 16, 64],
        "ICACHE_LINES": [1, 4, 16, 64], "DCACHE_LINES": [1, 4, 16, 64],
        "LEGACY_TRAPS": [0, 1], "ITLB_ENTRIES": [1, 4, 8, 16],
        "DTLB_ENTRIES": [1, 4, 8, 16],
    }
    illegal = {
        "IMEM_WORDS": [-1, 0, 16385], "DMEM_WORDS": [-1, 0, 8193],
        "PRED_MODE": [-1, 2], "BTB_ENTRIES": [0, 2, 65],
        "ICACHE_LINES": [0, 2, 65], "DCACHE_LINES": [0, 2, 65],
        "LEGACY_TRAPS": [-1, 2], "ITLB_ENTRIES": [0, 2, 17],
        "DTLB_ENTRIES": [0, 2, 17],
    }
    sources = [str(p.relative_to(ROOT)) for p in sorted(ROOT.glob("rtl/*.sv"))]
    for rejected, matrix in ((False, legal), (True, illegal)):
        for parameter, values in matrix.items():
            for value in values:
                identity = f"{'illegal' if rejected else 'legal'}-{parameter}-{value}"
                binary = probe.folder / f"{identity}.vvp"
                argv = ["iverilog", "-g2012", "-Wall", "-s", "parameter_probe",
                        f"-Pparameter_probe.{parameter}={value}"]
                argv += ["-o", probe.relative(binary)] if rejected else ["-t", "null"]
                probe.run(identity + "-compile", argv + ["tests/parameter_probe.sv", *sources])
                if rejected:
                    output = probe.run(identity + "-simulation", ["vvp", probe.relative(binary)],
                                       accepted_exits=(1,))
                    if "PARAMETER ERROR" not in output:
                        raise AssertionError(f"{identity}: no required explicit diagnostic")
                probe.receipt["assertions"].append(
                    {"id": identity, "passed": True, "parameter": parameter, "value": value,
                     "scope": "illegal-runtime-rejection" if rejected else "legal-elaboration-only"})
                probe.persist()


def peripheral_probe(probe, unit):
    probe.run("version-verilator", ["verilator", "--version"])
    vectors = plic_vectors() if unit == "plic" else uart_vectors()
    vector_file = probe.folder / "vectors.txt"
    vector_file.write_text("\n".join(vectors.lines) + "\n")
    waveform = probe.folder / "waveform.txt"
    objects = probe.folder / "compile-obj"
    try:
        probe.run("compile", ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                             "--top-module", "peripheral_probe", "--Mdir",
                             probe.relative(objects), "-o", "../simulation",
                             "tests/peripheral_probe.sv", "rtl/hammer_v3_plic.sv",
                             "rtl/hammer_v3_uart.sv"])
        output = probe.run("simulation", [probe.relative(probe.folder / "simulation"),
                                          f"+vectors={probe.relative(vector_file)}",
                                          f"+waveform={probe.relative(waveform)}"])
        match = re.search(r"PERIPHERAL_COMPARE_COMPLETE commands=(\d+) comparisons=(\d+) cycles=(\d+)",
                          output)
        if not match or int(match[2]) == 0:
            raise AssertionError("peripheral probe lacks completed real comparisons")
        serial_frames = compare_waveform(waveform, vectors.frames)
        probe.receipt["assertions"].append({
            "id": f"{unit}-public-interface", "passed": True,
            "comparisons": int(match[2]), "serial_frames": serial_frames,
            "completed_bins": vectors.coverage,
            "scope": "leaf peripheral experiment; top-level integration remains mandatory",
        })
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=["top-bare", "top-sv39", "synthesis-min", "walker",
                                          "parameters", "plic", "uart"],
                        default="top-bare")
    parser.add_argument("--parent", action="store_true")
    parser.add_argument("--mutant", choices=sorted(WALKER_MUTANTS))
    parser.add_argument("--repair-of", help="Project-relative retained diagnostic being repaired")
    args = parser.parse_args()
    if args.mutant and args.probe != "walker":
        parser.error("--mutant requires --probe walker")
    if args.parent and args.probe != "top-bare":
        parser.error("--parent requires --probe top-bare")
    probe = Probe(f"verifier-mutant-{args.mutant}" if args.mutant else
                  "verifier-parameters" if args.probe == "parameters" else
                  f"verifier-{args.probe}" if args.probe in ("plic", "uart") else
                  "verifier-walker" if args.probe == "walker" else
                  "verifier-synthesis-min" if args.probe == "synthesis-min" else
                  "verifier-top-sv39" if args.probe == "top-sv39" else
                  "verifier-parent-bare" if args.parent else "verifier-top-bare")
    if args.repair_of:
        prior = ROOT / args.repair_of
        if not prior.is_file() or ROOT not in prior.resolve().parents:
            raise ValueError("--repair-of must identify an existing project-local receipt")
        probe.receipt["repair_of"] = args.repair_of
        probe.persist()
    try:
        if args.probe in ("plic", "uart"):
            peripheral_probe(probe, args.probe)
        elif args.probe == "synthesis-min":
            synthesis_probe(probe)
        elif args.probe == "walker":
            walker_probe(probe, args.mutant)
        elif args.probe == "parameters":
            parameter_probe(probe)
        else:
            top_probe(probe, args.parent, args.probe == "top-sv39")
    except Exception as error:
        probe.finish(f"{type(error).__name__}: {error}")
        print(str(error), file=sys.stderr)
        return 1
    probe.finish()
    return 0


if __name__ == "__main__":
    sys.exit(main())
