"""Bounded advisory probes; not a substitute for the five admitted suites."""

import argparse
import difflib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import (BareMachine, StartupMachine, FaultMachine, bare_program, startup_program,
                    SystemMachine, ConsoleMachine, i_type, s_type, load_constant, sv39)
from scenarios import (walker_cases, fault_programs, context_program, isa_program,
                       shootdown_program)
from peripherals import plic_vectors, uart_vectors, compare_waveform


ROOT = Path(__file__).resolve().parent.parent


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Probe:
    def __init__(self, name, preparation=True):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = ROOT / "evidence" / "preparation" if preparation else ROOT / "evidence"
        self.folder = base / f"{name}-{stamp}"
        self.folder.mkdir(parents=True, exist_ok=False)
        self.rtl_folder = ROOT / "rtl"
        sources = sorted([*ROOT.glob("rtl/*.sv"), *ROOT.glob("design/*.md"),
                          *ROOT.glob("tests/*"), *ROOT.glob("hammer_v2_reference/rtl/*.sv")])
        sources = [p for p in sources if p.is_file()]
        self.receipt = {
            "kind": "advisory-verifier-preparation" if preparation else "portable-l1-execution",
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

    def storage_snapshot(self, label):
        files = [path.stat() for path in self.folder.rglob("*")
                 if path.is_file() and not path.is_symlink()]
        record = {
            "label": label, "at": now(), "files": len(files),
            "apparent_bytes": sum(stat.st_size for stat in files),
            "allocated_bytes": sum(stat.st_blocks * 512 for stat in files),
            "filesystem_available_bytes": shutil.disk_usage(self.folder).free,
        }
        self.receipt.setdefault("storage_samples", []).append(record)
        self.persist()
        return record

    def release_compiler_intermediates(self):
        binary = self.folder / "simulation"
        objects = self.folder / "compile-obj"
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"LINKED_EXECUTABLE_MISSING: {self.relative(binary)}")
        if objects.is_symlink() or not objects.is_dir():
            raise RuntimeError(f"COMPILER_INTERMEDIATES_INVALID: {self.relative(objects)}")
        self.storage_snapshot("linked-before-intermediate-cleanup")
        files = [path.stat() for path in objects.rglob("*") if path.is_file()]
        record = {
            "path": self.relative(objects), "executable": self.relative(binary),
            "executable_sha256": digest(binary), "files": len(files),
            "apparent_bytes": sum(stat.st_size for stat in files),
            "allocated_bytes": sum(stat.st_blocks * 512 for stat in files),
        }
        shutil.rmtree(objects)
        self.receipt.setdefault("compiler_intermediates_removed", []).append(record)
        self.storage_snapshot("linked-after-intermediate-cleanup")

    def persist(self):
        destination = self.folder / "receipt.json"
        temporary = None
        active_error = sys.exc_info()[1]
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.folder,
                                             prefix=".receipt-", suffix=".tmp",
                                             delete=False) as output:
                temporary = Path(output.name)
                json.dump(self.receipt, output, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        except OSError as error:
            detail = f"{type(error).__name__}: {error}"
            self.receipt.setdefault("persistence_errors", []).append(detail)
            trace_failure = next((record["failure"] for record in
                                  reversed(self.receipt.get("trace_streams", []))
                                  if "failure" in record), None)
            primary = (f"TRACE_CAPTURE_FAILED: {trace_failure}" if trace_failure else
                       self.receipt.get("failure") or
                       (f"{type(active_error).__name__}: {active_error}"
                        if active_error is not None else None))
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError as cleanup_error:
                    detail += f"; temporary cleanup failed: {cleanup_error}"
            message = f"RECEIPT_PERSIST_FAILED: {self.relative(destination)}: {detail}"
            if primary:
                message = f"{primary}; {message}"
            raise RuntimeError(message) from error

    def run(self, label, argv, timeout=3600, accepted_exits=(0,)):
        if argv[0] == "verilator" and "--binary" in argv:
            argv = [*argv, "-MAKEFLAGS", "VM_PARALLEL_BUILDS=0"]
            for tool in ("g++", "make"):
                if not any(record["argv"] == [tool, "--version"]
                           for record in self.receipt["commands"]):
                    self.run("version-" + tool, [tool, "--version"])
        if argv[0] == "vvp" and argv != ["vvp", "-V"] and not any(
                record["argv"] == ["vvp", "-V"] for record in self.receipt["commands"]):
            self.run("version-vvp", ["vvp", "-V"])
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


def generate_top_wiring(top, source, folder, dmem_words, parameters=None, extra_driven=(),
                        responding_memory=False):
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
    driven.update(extra_driven)
    if responding_memory:
        driven.update(name for direction, _, name in ports
                      if direction == "input" and
                      name.startswith(("m_mem_axi_", "m_axi_")))
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
    configuration = {"IMEM_WORDS": 128, "DMEM_WORDS": dmem_words, "BTB_ENTRIES": 1,
                     "PRED_MODE": 0, "ICACHE_LINES": 1, "DCACHE_LINES": 1}
    configuration.update(parameters or {})
    if responding_memory:
        (folder / "system_configuration.svh").write_text(
            f"localparam integer SYSTEM_DMEM_WORDS = {configuration['DMEM_WORDS']};\n")
    instance = top + " #(" + ", ".join(
        f".{key}({value})" for key, value in configuration.items()) + ") dut (\n"
    instance += ",\n".join(f".{name}({name})" for _, _, name in ports) + ");\n"
    (folder / "top_instance.svh").write_text(instance)
    (folder / "top_initial.svh").write_text(
        "\n".join(f"{name} = '0;" for direction, _, name in ports
                  if direction == "input" and name in driven) + "\n")
    (folder / "top_observers.svh").write_text(
        "wire monitor_uart_tx = " +
        ("uart_tx" if any(name == "uart_tx" for _, _, name in ports) else "1'b1") + ";\n")


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
                if values[1] & 127 == 0x2F and values[11] != read:
                    raise AssertionError(f"atomic old data expected {expected}, observed {line}")
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
    source = probe.rtl_folder / f"{top}.sv"
    generate_top_wiring(top, source, probe.folder, 4096 if sv39_startup else 32)
    words, data = startup_program() if sv39_startup else (bare_program(), {})
    program = probe.folder / "program.hex"
    program.write_text("".join(f"{word:08x}\n" for word in words + [0x13] * (128 - len(words))))
    binary = probe.folder / "simulation.vvp"
    trace = probe.folder / "trace.txt"
    probe.run("compile", ["iverilog", "-g2012", "-Wall", "-s", "top_probe",
                         "-I", probe.relative(probe.folder), "-o", probe.relative(binary),
                         "tests/top_probe.sv",
                         *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
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


def synthesis_probe(probe, configuration="min"):
    probe.run("version-yosys", ["yosys", "-V"])
    netlist = probe.folder / "netlist.json"
    script = probe.folder / "synthesis.ys"
    configurations = {
        "min": {"IMEM_WORDS": 1, "DMEM_WORDS": 1, "ICACHE_LINES": 1,
                "DCACHE_LINES": 1, "BTB_ENTRIES": 1, "ITLB_ENTRIES": 1, "DTLB_ENTRIES": 1},
        "default": {},
        "odd": {"IMEM_WORDS": 4093, "DMEM_WORDS": 4093, "ICACHE_LINES": 4,
                "DCACHE_LINES": 16, "ITLB_ENTRIES": 4, "DTLB_ENTRIES": 8},
    }
    parameters = configurations[configuration]
    parameter_command = ("chparam " + " ".join(
        f"-set {key} {value}" for key, value in parameters.items()) +
        " hammer_v3_top\n") if parameters else ""
    script.write_text(
        "read_verilog -sv " +
        " ".join(str(p.relative_to(ROOT)) for p in sorted(ROOT.glob("rtl/*.sv"))) + "\n"
        + parameter_command +
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
    names = {name: module.get("attributes", {}).get("hdlname", name).split()[0].lstrip("\\")
             for name, module in modules.items()}

    def hierarchy(module_name, path):
        module = modules[module_name]
        for cell_name, cell in module.get("cells", {}).items():
            if cell["type"] in modules:
                child = f"{path}.{cell_name}" if path else cell_name
                yield child, names[cell["type"]], cell
                yield from hierarchy(cell["type"], child)

    instances = list(hierarchy("hammer_v3_top", ""))
    required = {
        "u_core": "hammer_v3_core", "u_mmu": "hammer_v3_mmu",
        "u_icache": "hammer_v3_icache", "u_dcache": "hammer_v3_dcache",
        "u_fabric": "hammer_v3_fabric", "u_plic": "hammer_v3_plic",
        "u_uart": "hammer_v3_uart", "u_clint": "hammer_v2_clint",
        "u_accel": "hammer_v3_accel_bridge", "u_mem_axi": "hammer_v3_axi_master",
        "u_mmu.u_itlb": "hammer_v3_tlb", "u_mmu.u_dtlb": "hammer_v3_tlb",
        "u_mmu.u_ptw": "hammer_v3_ptw",
    }
    for suffix, expected in required.items():
        matching = [(path, cell) for path, module, cell in instances
                    if path.endswith("." + suffix) and module == expected]
        if len(matching) != 1 or not matching[0][1].get("connections"):
            raise AssertionError(f"SYNTHESIS_HIERARCHY {suffix}:{expected} missing or disconnected")
    core_children = {"u_decode", "u_regfile", "u_hazard", "u_alu", "u_predictor",
                     "u_muldiv", "u_atomic", "u_csr", "u_trap"}
    for child in core_children:
        if not any(path.endswith(".u_core." + child) for path, _, _ in instances):
            raise AssertionError(f"SYNTHESIS_CORE_HIERARCHY missing {child}")
    memory_bits = 0
    state_cells = 0
    for module in modules.values():
        for cell in module.get("cells", {}).values():
            if cell["type"].startswith("$mem"):
                memory_bits += int(cell["parameters"]["WIDTH"], 2) * int(
                    cell["parameters"]["SIZE"], 2)
            if "dff" in cell["type"]:
                state_cells += 1
    if memory_bits == 0 or state_cells < 50:
        raise AssertionError(f"SYNTHESIS_STATE memory_bits={memory_bits} state_cells={state_cells}")
    probe.receipt["assertions"].append(
        {"id": f"{configuration}-structural-preparation", "passed": True, "cells": cells,
         "memory_cells": memories, "memory_bits": memory_bits, "state_cells": state_cells,
         "required_hierarchy": required, "parameters": parameters,
         "scope": "generic structural synthesis; no physical timing claim"})


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
        probe.release_compiler_intermediates()
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
                             "tests/peripheral_probe.sv",
                             probe.relative(probe.rtl_folder / "hammer_v3_plic.sv"),
                             probe.relative(probe.rtl_folder / "hammer_v3_uart.sv")])
        probe.release_compiler_intermediates()
        output = probe.run("simulation", [probe.relative(probe.folder / "simulation"),
                                          f"+vectors={probe.relative(vector_file)}",
                                          f"+waveform={probe.relative(waveform)}"])
        match = re.search(r"PERIPHERAL_COMPARE_COMPLETE commands=(\d+) comparisons=(\d+) cycles=(\d+)",
                          output)
        if not match or int(match[2]) == 0:
            raise AssertionError("peripheral probe lacks completed real comparisons")
        serial_frames = compare_waveform(waveform, vectors.frames, vectors.streams)
        probe.receipt["assertions"].append({
            "id": f"{unit}-public-interface", "passed": True,
            "comparisons": int(match[2]), "serial_frames": serial_frames,
            "completed_bins": vectors.coverage,
            "scope": "leaf peripheral experiment; top-level integration remains mandatory",
        })
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def fault_probe(probe):
    probe.run("version-verilator", ["verilator", "--version"])
    generate_top_wiring("hammer_v3_top", probe.rtl_folder / "hammer_v3_top.sv", probe.folder, 4096)
    objects = probe.folder / "compile-obj"
    records = []
    try:
        probe.run("compile", ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                             "--top-module", "top_probe", "--Mdir", probe.relative(objects),
                             "-o", "../simulation", "-I" + probe.relative(probe.folder),
                             "tests/top_probe.sv",
                             *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
        probe.release_compiler_intermediates()
        for index, (spec, words, data) in enumerate(fault_programs()):
            case = probe.folder / f"case-{index:03d}"
            case.mkdir()
            program, image, trace = case / "program.hex", case / "data.hex", case / "trace.txt"
            program.write_text("".join(f"{word:08x}\n" for word in
                                      words + [0x13] * (128 - len(words))))
            image.write_text("".join(f"{address:08x} {word:016x}\n"
                                     for address, word in sorted(data.items())))
            (case / "specification.json").write_text(json.dumps(spec, indent=2) + "\n")
            probe.run(f"case-{index:03d}", [probe.relative(probe.folder / "simulation"),
                                          f"+program={probe.relative(program)}",
                                          f"+trace={probe.relative(trace)}",
                                          f"+data={probe.relative(image)}"])
            compare_trace(probe, trace, FaultMachine(words, data))
            records.append({"case": index, "specification": spec, "passed": True,
                            "trace": probe.relative(trace)})
            probe.receipt["fault_cases"] = records
            probe.persist()
        probe.receipt["assertions"].append({
            "id": "top-precise-translation-faults", "passed": True, "cases": len(records),
            "scope": "short terminal-fault programs; no handler/context-switch closure"})
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def coherence_probe(probe, simulator="verilator", exchanges=100, reset_abort=False):
    probe.run(f"version-{simulator}", [simulator, "--version" if simulator == "verilator" else "-V"])
    top = probe.rtl_folder / "hammer_v3_top.sv"
    header = top.read_text().split(");", 1)[0]
    extra_driven = re.findall(r"\bs_acc_axi_\w+", header)
    generate_top_wiring("hammer_v3_top", top, probe.folder, 1024,
                        extra_driven=extra_driven)
    words = [0x100000B7, i_type(0x13, 2, 0, 0, 0),
             i_type(0x03, 3, 3, 1, 0), i_type(0x13, 2, 0, 2, 1),
             s_type(3, 1, 2, 8), 0xFF5FF06F]
    program = probe.folder / "program.hex"
    program.write_text("".join(f"{word:08x}\n" for word in words + [0x13] * (128 - len(words))))
    trace = probe.folder / "trace.txt"
    objects = probe.folder / "compile-obj"
    try:
        sources = [str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]
        if simulator == "verilator":
            binary = probe.folder / "simulation"
            compile_argv = ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                            "--top-module", "coherence_probe", "--Mdir", probe.relative(objects),
                            "-o", "../simulation", "-I" + probe.relative(probe.folder),
                            f"-GEXCHANGES={exchanges}", f"-GRESET_ABORT={int(reset_abort)}",
                            "tests/coherence_probe.sv", *sources]
            execute = [probe.relative(binary)]
        else:
            binary = probe.folder / "simulation.vvp"
            compile_argv = ["iverilog", "-g2012", "-Wall", "-s", "coherence_probe",
                            f"-Pcoherence_probe.EXCHANGES={exchanges}",
                            f"-Pcoherence_probe.RESET_ABORT={int(reset_abort)}",
                            "-I", probe.relative(probe.folder), "-o", probe.relative(binary),
                            "tests/coherence_probe.sv", *sources]
            execute = ["vvp", probe.relative(binary)]
        probe.run("compile", compile_argv)
        if simulator == "verilator":
            probe.release_compiler_intermediates()
        output = probe.run("simulation", [*execute,
                                          f"+program={probe.relative(program)}",
                                          f"+trace={probe.relative(trace)}"])
        if reset_abort:
            if not re.search(r"RESET_ABORT_COMPLETE cases=2 cycles=\d+", output):
                raise AssertionError("RESET_ABORT_COVERAGE missing actual abort comparisons")
            probe.receipt["assertions"].append({
                "id": "public-top-outstanding-reset-abort", "passed": True, "cases": 2,
                "scope": "stalled accelerator read response and address-before-write-data epochs"})
            return
        model = BareMachine(words)
        model.memory = {0x10000000 + offset: 0 for offset in range(32)}
        model.memory.update({0x10000100 + offset: 0 for offset in range(32)})
        cpu = reads = writes = progress = observations = 0
        last_admission = -1
        last_value = None
        for line in trace.read_text().splitlines():
            fields = line.split()
            if fields[0] == "N":
                retired = int(fields[3])
                if retired <= last_admission:
                    raise AssertionError(f"COHERENCE_CPU_STARVATION: {line}")
                last_admission = retired
                progress += 1
            elif fields[0] == "A":
                address, value, identity = (int(field, 16) for field in fields[2:])
                if fields[1] == "W":
                    for byte in range(8):
                        model.memory[address + byte] = (value >> (8 * byte)) & 255
                    last_value = value
                    writes += 1
                else:
                    expected = sum(model.memory[address + byte] << (8 * byte) for byte in range(8))
                    if value != expected:
                        raise AssertionError(f"COHERENCE_ACCEL_READ address={address:x} "
                                             f"expected={expected:x} got={value:x}")
                    reads += 1
            else:
                values = [int(field, 16) for field in fields[1:]]
                expected = model.step()
                if fields[0] != "R" or tuple(values[:6]) != expected[1:7] or values[12] != expected[8]:
                    raise AssertionError(f"COHERENCE_CPU_RETIRE expected={expected} got={line}")
                memory = expected[7]
                if values[6] != int(memory is not None):
                    raise AssertionError(f"COHERENCE_CPU_MEMORY_VALID expected={expected} got={line}")
                if memory:
                    write, address, mask, data, read = memory
                    if (values[7], values[8]) != (write, address):
                        raise AssertionError(f"COHERENCE_CPU_MEMORY expected={expected} got={line}")
                    if write and (values[9], values[10]) != (mask, data):
                        raise AssertionError(f"COHERENCE_CPU_STORE expected={expected} got={line}")
                    if not write and values[11] != read:
                        raise AssertionError(f"COHERENCE_CPU_LOAD expected={expected} got={line}")
                    if not write and last_value is not None and read == last_value:
                        observations += 1
                cpu += 1
        if (writes != exchanges or reads != exchanges or observations < exchanges or
                progress != 2 * exchanges or cpu == 0):
            raise AssertionError(f"COHERENCE_INCOMPLETE writes={writes} reads={reads} "
                                 f"cpu_observations={observations} admissions={progress}")
        probe.receipt["assertions"].append({
            "id": "public-top-running-coherence", "passed": True,
            "cpu_retirements": cpu, "accelerator_reads": reads, "accelerator_writes": writes,
            "cpu_observations": observations, "forward_progress_admissions": progress,
            "scope": "single-beat legacy data RAM; full AXI/external executable RAM still required"})
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def console_probe(probe):
    probe.run("version-iverilog", ["iverilog", "-V"])
    probe.run("version-vvp", ["vvp", "-V"])
    words, data = startup_program()
    words = words[:64] + load_constant(5, 0x40010000)
    words += [i_type(0x13, 3, 0, 0, 3), s_type(0, 5, 3, 3),
              i_type(0x13, 3, 0, 0, ord("V")), s_type(0, 5, 3, 0)]
    words += [0x13] * 250
    words += [i_type(0x03, 6, 4, 5, 5), 0x73]
    generate_top_wiring("hammer_v3_top", probe.rtl_folder / "hammer_v3_top.sv", probe.folder,
                        4096, parameters={"IMEM_WORDS": 512})
    program, image, trace, waveform = (probe.folder / name for name in
                                      ("program.hex", "data.hex", "trace.txt", "waveform.txt"))
    program.write_text("".join(f"{word:08x}\n" for word in words))
    image.write_text("".join(f"{address:08x} {word:016x}\n"
                             for address, word in sorted(data.items())))
    binary = probe.folder / "simulation.vvp"
    probe.run("compile", ["iverilog", "-g2012", "-Wall", "-s", "top_probe",
                         f"-Ptop_probe.PROGRAM_WORDS={len(words)}",
                         "-Ptop_probe.MAX_CYCLES=500000", "-I", probe.relative(probe.folder),
                         "-o", probe.relative(binary), "tests/top_probe.sv",
                         *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
    probe.run("simulation", ["vvp", probe.relative(binary),
                             f"+program={probe.relative(program)}",
                             f"+data={probe.relative(image)}", f"+trace={probe.relative(trace)}",
                             f"+waveform={probe.relative(waveform)}"])
    model = ConsoleMachine(words, data)
    compare_trace(probe, trace, model)
    frames = [{"marker": 0, "value": ord("V"), "lcr": 3, "divisor": 1}]
    compared = compare_waveform(waveform, frames)
    if model.console != [ord("V")] or compared != 1 or model.regs[6] != 0x60:
        raise AssertionError("CONSOLE_COVERAGE missing actual software/serial comparison")
    probe.receipt["assertions"].append({
        "id": "public-top-sv39-console", "passed": True, "serial_bytes": model.console,
        "serial_frames": compared, "scope": "compact real S-mode console; not Linux boot"})


def boundary_probe(probe):
    probe.run("version-iverilog", ["iverilog", "-V"])
    for iwords, dwords in ((1, 1), (1, 3), (3, 1), (3, 3)):
        folder = probe.folder / f"tuple-{iwords}-{dwords}"
        folder.mkdir()
        generate_top_wiring("hammer_v3_top", probe.rtl_folder / "hammer_v3_top.sv", folder,
                            dwords, parameters={"IMEM_WORDS": iwords})
        binary = folder / "simulation.vvp"
        identity = f"tuple-{iwords}-{dwords}"
        probe.run(identity + "-compile",
                  ["iverilog", "-g2012", "-Wall", "-s", "boundary_probe",
                   f"-Pboundary_probe.IWORDS={iwords}", f"-Pboundary_probe.DWORDS={dwords}",
                   "-I", probe.relative(folder), "-o", probe.relative(binary),
                   "tests/boundary_probe.sv",
                   *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
        output = probe.run(identity + "-simulation", ["vvp", probe.relative(binary)])
        match = re.search(
            r"BOUNDARY_COMPARE_COMPLETE imem=(\d+) dmem=(\d+) comparisons=(\d+) cycles=(\d+)",
            output)
        if not match or (int(match[1]), int(match[2])) != (iwords, dwords) or int(match[3]) == 0:
            raise AssertionError(f"BOUNDARY_COVERAGE missing completed tuple {identity}")
        probe.receipt["assertions"].append({
            "id": "singleton-odd-top-behavior", "passed": True, "imem_words": iwords,
            "dmem_words": dwords, "comparisons": int(match[3]), "cycles": int(match[4]),
            "scope": "host byte writes/bounds, reachable singleton fetch and odd partial-line load"})
        probe.persist()


def context_probe(probe):
    probe.run("version-verilator", ["verilator", "--version"])
    words, data = context_program()
    generate_top_wiring("hammer_v3_top", probe.rtl_folder / "hammer_v3_top.sv", probe.folder, 8192,
                        parameters={"IMEM_WORDS": 4096})
    program, image, trace = (probe.folder / name for name in
                             ("program.hex", "data.hex", "trace.txt"))
    program.write_text("".join(f"{word:08x}\n" for word in words))
    image.write_text("".join(f"{address:08x} {word:016x}\n"
                             for address, word in sorted(data.items())))
    objects = probe.folder / "compile-obj"
    try:
        probe.run("compile", ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                             "--top-module", "top_probe",
                             f"-GPROGRAM_WORDS={len(words)}", "-GMAX_CYCLES=500000",
                             "-GCONTINUE_TRAPS=1", "--Mdir", probe.relative(objects),
                             "-o", "../simulation", "-I" + probe.relative(probe.folder),
                             "tests/top_probe.sv",
                             *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
        probe.release_compiler_intermediates()
        probe.run("simulation", [probe.relative(probe.folder / "simulation"),
                                 f"+program={probe.relative(program)}",
                                 f"+trace={probe.relative(trace)}",
                                 f"+data={probe.relative(image)}"])
        model = SystemMachine(words, data)
        compare_trace(probe, trace, model)
        if not model.stopped or model.trap_counts != {13: 1, 8: 20, 9: 1} or model.user_returns != 21:
            raise AssertionError(f"CONTEXT_COVERAGE traps={model.trap_counts} "
                                 f"returns={model.user_returns} stopped={model.stopped}")
        probe.receipt["assertions"].append({
            "id": "public-top-context-switch-software", "passed": True,
            "traps": model.trap_counts, "user_returns": model.user_returns,
            "scope": "20 user-ECALL scheduler round trips and delegated A-bit repair; "
                     "timer preemption and full seeded matrix still mandatory"})
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def isa_probe(probe, parent=False, seed=17):
    probe.run("version-verilator", ["verilator", "--version"])
    top = "hammer_v2_top" if parent else "hammer_v3_top"
    source_folder = ROOT / "hammer_v2_reference/rtl" if parent else probe.rtl_folder
    generate_top_wiring(top, source_folder / f"{top}.sv", probe.folder, 1024,
                        parameters={"IMEM_WORDS": 1024})
    words, labels = isa_program(seed)
    program, trace = probe.folder / "program.hex", probe.folder / "trace.txt"
    program.write_text("".join(f"{word:08x}\n" for word in words))
    objects = probe.folder / "compile-obj"
    try:
        probe.run("compile", ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                             "--top-module", "top_probe",
                             f"-GPROGRAM_WORDS={len(words)}", "-GMAX_CYCLES=500000",
                             "--Mdir", probe.relative(objects),
                             "-o", "../simulation", "-I" + probe.relative(probe.folder),
                             "tests/top_probe.sv",
                             *[str(p.relative_to(ROOT)) for p in sorted(source_folder.glob("*.sv"))]])
        probe.release_compiler_intermediates()
        probe.run("simulation", [probe.relative(probe.folder / "simulation"),
                                 f"+program={probe.relative(program)}",
                                 f"+trace={probe.relative(trace)}"])
        model = SystemMachine(words, {})
        compare_trace(probe, trace, model)
        if model.trap_counts != {11: 1}:
            raise AssertionError(f"ISA_TERMINATION unexpected traps={model.trap_counts}")
        completed_bins = {}
        for line in trace.read_text().splitlines():
            fields = line.split()
            label = labels.get(int(fields[1], 16))
            if label and fields[0] == "R":
                completed_bins[label] = completed_bins.get(label, 0) + 1
        if completed_bins.get("jump-skipped", 0):
            raise AssertionError("ISA_WRONG_PATH_SIDE_EFFECT: skipped instruction retired")
        for label in set(labels.values()) - {"jump-skipped", "terminal-ecall"}:
            if completed_bins.get(label, 0) == 0:
                raise AssertionError(f"ISA_MISSING_COMPARISON: {label}")
        probe.receipt["assertions"].append({
            "id": "parent-isa-oracle" if parent else "v3-isa-oracle", "passed": True,
            "seed": seed, "program_words": len(words), "completed_program_bins": completed_bins,
            "scope": "Bare RV64IMA instructions and machine scratch CSR operations; "
                     "CLINT/interrupt/host/MMIO regressions remain separate"})
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


def shootdown_probe(probe):
    probe.run("version-verilator", ["verilator", "--version"])
    words, data = shootdown_program()
    generate_top_wiring("hammer_v3_top", probe.rtl_folder / "hammer_v3_top.sv", probe.folder, 8192)
    program, image, trace = (probe.folder / name for name in
                             ("program.hex", "data.hex", "trace.txt"))
    program.write_text("".join(f"{word:08x}\n" for word in words + [0x13] * (128 - len(words))))
    image.write_text("".join(f"{address:08x} {word:016x}\n"
                             for address, word in sorted(data.items())))
    objects = probe.folder / "compile-obj"
    try:
        probe.run("compile", ["verilator", "--binary", "--timing", "-Wall", "-Wno-fatal",
                             "--top-module", "top_probe", "--Mdir", probe.relative(objects),
                             "-o", "../simulation", "-I" + probe.relative(probe.folder),
                             "tests/top_probe.sv",
                             *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
        probe.release_compiler_intermediates()
        probe.run("simulation", [probe.relative(probe.folder / "simulation"),
                                 f"+program={probe.relative(program)}",
                                 f"+trace={probe.relative(trace)}",
                                 f"+data={probe.relative(image)}"])
        model = SystemMachine(words, data)
        compare_trace(probe, trace, model)
        if model.regs[6] != 0x1234567887654321 or model.regs[9] != 0x55AA55AA55667788:
            raise AssertionError("SHOOTDOWN_COVERAGE: remapped values not independently observed")
        probe.receipt["assertions"].append({
            "id": "public-top-dirty-pte-shootdown", "passed": True, "old_pa": 0x10003000,
            "new_pa": 0x10006000, "old_value": model.regs[6], "new_value": model.regs[9],
            "scope": "all/all fence on a dirty cached PTE; selective forms still mandatory"})
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)


SYSTEM_MUTANTS = {
    "final-store": ("hammer_v3_cache.sv", [
        ("wire [63:0] write_data = fill_write ? fill_q : wdata_q;",
         "wire [63:0] write_data = fill_write ? fill_q : "
         "(write_hit && addr_q == 64'h8006f000 ? wdata_q ^ 64'd1 : wdata_q);")],
        "final-state", r"FINAL_MEMORY_MISMATCH address=000000008006f000"),
    "sfence": ("hammer_v3_mmu.sv", [
        ("wire invalidate = rst_n && fence_state == INVALIDATE;",
         "wire invalidate = 1'b0;")], "shootdown", r"retirement \d+: expected"),
    "fault-record": ("hammer_v3_core.sv", [
        ("d_rsp_page_fault ? (m.load ? 4'd13 : 4'd15)",
         "d_rsp_page_fault ? (m.load ? 4'd5 : 4'd15)")],
        "faults", r"trap expected"),
    "plic-claim": ("hammer_v3_plic.sv", [
        ("rank[c][2*t] >= rank[c][2*t+1]",
         "rank[c][2*t][8:6] > rank[c][2*t+1][8:6]")],
        "plic", r"PERIPHERAL_RESULT command=\d+ unit=1"),
    "uart-byte": ("hammer_v3_uart.sv", [
        ("tx_fifo[tx_tail] <= write_byte;", "tx_fifo[tx_tail] <= write_byte ^ 8'h01;")],
        "uart", r"PERIPHERAL_RESULT command=\d+ unit=0"),
    "coherence": ("hammer_v3_top.sv", [
        (".req_ready(da_ready), .req_cmd({2'b11,2'b0,route_cmd}),",
         ".req_ready(da_ready), .req_cmd({2'b10,2'b0,route_cmd}),")],
        "coherence", r"COHERENCE_CPU_RETIRE expected="),
}


def mmu_probe(probe, itlb=1, dtlb=1):
    probe.run("version-iverilog", ["iverilog", "-V"])
    ptes = {
        0x80000000: (0x80001 << 10) | 1,
        0x80001000: (0x80002 << 10) | 1,
        0x80002008: (0x80010 << 10) | 0xCB,
        0x80002010: (0x80011 << 10) | 0xC7,
    }
    expected = []
    for bank in (0, 1):
        if bank:
            ptes[0x80002008] = (0x80030 << 10) | 0xCB
            ptes[0x80002010] = (0x80031 << 10) | 0xC7
        for address, access in ((0x1000, 0), (0x2000, 1)):
            result = sv39(address, access, 1, (8 << 60) | 0x80000, 0, ptes.__getitem__)
            if result.fault:
                raise AssertionError(f"MMU_ORACLE: unexpected reference fault {result}")
            expected.append(result.pa)
    binary, trace = probe.folder / "simulation", probe.folder / "pte-trace.txt"
    probe.run("compile", [
        "iverilog", "-g2012", "-Wall", "-s", "mmu_probe",
        f"-Pmmu_probe.ITLB_ENTRIES={itlb}", f"-Pmmu_probe.DTLB_ENTRIES={dtlb}",
        "-o", probe.relative(binary), "tests/mmu_probe.sv",
        *[str(p.relative_to(ROOT)) for p in sorted(probe.rtl_folder.glob("*.sv"))]])
    output = probe.run("simulation", [
        "vvp", probe.relative(binary), f"+trace={probe.relative(trace)}",
        *[f"+{name}={pa:x}" for name, pa in zip(
            ("old_i", "old_d", "new_i", "new_d"), expected)]])
    summary = re.search(r"MMU_SUMMARY pairs=(\d+) comparisons=(\d+) fences=(\d+) resets=(\d+) reads=(\d+)", output)
    if not summary or tuple(map(int, summary.groups()[:4])) != (6, 12, 2, 1):
        raise AssertionError("MMU_COVERAGE: concurrent, fence, hit and reset comparisons missing")
    leaves = [int(line.split()[1], 16) for line in trace.read_text().splitlines()
              if int(line.split()[1], 16) in (0x80002008, 0x80002010)]
    if leaves != [0x80002008, 0x80002010] * 2:
        raise AssertionError(f"MMU_ARBITRATION: expected alternating instruction/data walks: {leaves}")
    probe.receipt["assertions"].append({
        "id": "public-mmu-cycle-fence-reset", "passed": True, "itlb": itlb, "dtlb": dtlb,
        "response_comparisons": int(summary[2]), "completed_pairs": int(summary[1]),
        "fences": int(summary[3]), "reset_aborts": int(summary[4]),
        "pte_reads": int(summary[5]), "leaf_order": leaves, "oracle_pas": expected,
        "scope": "registered minimum latency, independent held responses, concurrent misses, "
                 "captured privilege, hit permission reevaluation, fence during walk, "
                 "drain held responses, stale-refill exclusion, reset during walk"})


def system_mutant_probe(probe, mutant):
    filename, changes, experiment, intended = SYSTEM_MUTANTS[mutant]
    copied = probe.folder / "mutant-rtl"
    copied.mkdir()
    for source in sorted((ROOT / "rtl").glob("*.sv")):
        shutil.copyfile(source, copied / source.name)
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
        "mutant_sha256": digest(target), "intended_assertion": intended,
    }
    probe.rtl_folder = copied
    probe.persist()
    try:
        if experiment == "shootdown":
            shootdown_probe(probe)
        elif experiment == "faults":
            fault_probe(probe)
        elif experiment == "coherence":
            coherence_probe(probe)
        elif experiment == "final-state":
            import system
            system.run_configuration(probe, system.CONFIGURATIONS[0], (17,),
                                     scenario="final-state")
        else:
            peripheral_probe(probe, experiment)
    except AssertionError as error:
        first_failure = str(error)
        if not re.search(intended, first_failure):
            raise AssertionError(f"{mutant}: wrong rejection, not intended mismatch: {error}") from error
    except RuntimeError as error:
        record = probe.receipt["commands"][-1]
        if record["timed_out"] or record["exit_status"] not in (1, -6, 134):
            raise
        output = (ROOT / record["stdout"]).read_text()
        match = re.search(intended + r"[^\n]*", output)
        if not match or "simulation" not in record["stdout"]:
            raise RuntimeError(f"{mutant}: tool/harness failure is not detection: {error}") from error
        first_failure = match[0]
    else:
        raise AssertionError(f"{mutant}: semantic mutant survived actual functional comparison")
    compiled = [record for record in probe.receipt["commands"]
                if record["argv"][0] == "verilator" and "--binary" in record["argv"]]
    if not compiled or any(record["exit_status"] != 0 for record in compiled):
        raise AssertionError(f"{mutant}: compile failure is not semantic detection")
    if mutant == "final-store":
        divergence = probe.receipt.get("first_divergence", {})
        simulations = [record for record in probe.receipt["commands"]
                       if record["argv"][0].endswith("/simulation")]
        if (divergence.get("comparison") != "final-state" or
                divergence.get("compared_retirement_events", 0) <= 0 or
                not simulations or any(record["exit_status"] != 0 for record in simulations)):
            raise AssertionError("final-store: detection requires a completed simulation, "
                                 "matched retirements and final-memory mismatch")
    probe.receipt["assertions"].append({
        "id": "disposable-defect-sensitivity", "passed": True, "mutant": mutant,
        "first_failing_assertion": first_failure, "experiment": experiment,
        "scope": "independent semantic comparison on a disposable complete RTL copy"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=["top-bare", "top-sv39", "synthesis-min", "walker",
                                          "synthesis-default", "synthesis-odd",
                                          "parameters", "plic", "uart", "faults", "coherence",
                                          "context", "isa", "shootdown", "mutants", "console",
                                          "coherence-compact", "boundaries", "reset-abort", "mmu"],
                        default="top-bare")
    parser.add_argument("--parent", action="store_true")
    parser.add_argument("--itlb", type=int, choices=(1, 4, 8, 16), default=1)
    parser.add_argument("--dtlb", type=int, choices=(1, 4, 8, 16), default=1)
    parser.add_argument("--mutant", choices=sorted({**WALKER_MUTANTS, **SYSTEM_MUTANTS}))
    parser.add_argument("--repair-of", help="Project-relative retained diagnostic being repaired")
    args = parser.parse_args()
    if args.mutant and args.probe not in ("walker", "mutants"):
        parser.error("--mutant requires --probe walker or mutants")
    if args.probe == "mutants" and not args.mutant:
        parser.error("--probe mutants requires --mutant")
    if args.parent and args.probe not in ("top-bare", "isa"):
        parser.error("--parent requires --probe top-bare or isa")
    probe = Probe(f"verifier-mutant-{args.mutant}" if args.mutant else
                  "verifier-parameters" if args.probe == "parameters" else
                  f"verifier-{args.probe}" if args.probe in ("plic", "uart") else
                  "verifier-top-faults" if args.probe == "faults" else
                  "verifier-top-coherence" if args.probe == "coherence" else
                  "verifier-top-context" if args.probe == "context" else
                  "verifier-top-shootdown" if args.probe == "shootdown" else
                  f"verifier-top-{args.probe}" if args.probe in ("console", "coherence-compact") else
                  "verifier-top-boundaries" if args.probe == "boundaries" else
                  "verifier-top-reset-abort" if args.probe == "reset-abort" else
                  "verifier-mmu" if args.probe == "mmu" else
                  ("verifier-parent-isa" if args.parent else "verifier-top-isa")
                  if args.probe == "isa" else
                  f"verifier-{args.probe}" if args.probe.startswith("synthesis-") else
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
        if args.probe == "mmu":
            mmu_probe(probe, args.itlb, args.dtlb)
        elif args.probe == "reset-abort":
            coherence_probe(probe, "iverilog", 2, True)
        elif args.probe == "boundaries":
            boundary_probe(probe)
        elif args.probe == "console":
            console_probe(probe)
        elif args.probe == "coherence-compact":
            coherence_probe(probe, "iverilog", 2)
        elif args.mutant in SYSTEM_MUTANTS:
            system_mutant_probe(probe, args.mutant)
        elif args.probe == "shootdown":
            shootdown_probe(probe)
        elif args.probe == "isa":
            isa_probe(probe, args.parent)
        elif args.probe == "context":
            context_probe(probe)
        elif args.probe == "coherence":
            coherence_probe(probe)
        elif args.probe == "faults":
            fault_probe(probe)
        elif args.probe in ("plic", "uart"):
            peripheral_probe(probe, args.probe)
        elif args.probe.startswith("synthesis-"):
            synthesis_probe(probe, args.probe.removeprefix("synthesis-"))
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
