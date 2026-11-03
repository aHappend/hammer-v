#!/usr/bin/env python3
"""Source-bound RTL compilation experiments with unchanged public-pin comparisons."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from boot import BUILD_FLAGS, HARNESS, checked_images, custom_fault_expectations
from boot_efficiency import instrument
from boot_support import CPP as SUPPORT
from evidence import Evidence, ROOT, digest
from integration import ports
from rv64 import CPP, decode_image
from verify import SOURCE_SELECTORS, bind_outputs


def lower_rtl(ev, parameters):
    """Lower the default core's processes without changing other modules or RAM."""
    ev.version("yosys", ("-V",))
    script = ev.directory / "lower.ys"
    output = ev.directory / "lowered.v"
    script.write_text(
        "read_verilog -lib -sv " +
        " ".join(ev.relative(path) for path in sorted((ROOT / "rtl").glob("*.sv"))
                 if path.name != "hammer_v5_core.sv") +
        "\nread_verilog -sv rtl/hammer_v5_core.sv\n"
        "proc\nopt\nopt_clean\ncheck -assert\n"
        "write_verilog -noattr " + ev.relative(output) + "\n")
    ev.record.setdefault("generated_sha256", {})[ev.relative(script)] = digest(script)
    ev.run(["yosys", "-Q", "-T", "-s", ev.relative(script)], "lower-rtl")
    interface = ports(ROOT / "rtl/hammer_v5_core.sv")
    wrapper = ROOT / "rtl/hammer_v5_core.sv"
    parameters_text = wrapper.read_text().split("#(", 1)[1].split(") (", 1)[0]
    defaults = {"IMEM_WORDS": 16384, "DMEM_WORDS": 8192, "PRED_MODE": 1,
                "BTB_ENTRIES": 16, "LEGACY_TRAPS": 0}
    text = output.read_text()
    if text.count("module hammer_v5_core(") != 1:
        raise AssertionError("lowered core module declaration changed")
    text = text.replace("module hammer_v5_core(", "module hammer_v5_core_lowered(")
    text += (
        "\nmodule hammer_v5_core #(" + parameters_text + ") (\n" +
        ",\n".join(f"{direction} wire {width} {name}"
                    for direction, width, name in interface) + "\n);\n"
        "initial if (" + " || ".join(f"{name} != {value}" for name, value in defaults.items()) +
        ') $fatal(1,"LOWERED MODEL REQUIRES DEFAULT CORE PARAMETERS");\n'
        "hammer_v5_core_lowered implementation (\n" +
        ",\n".join(f".{name}({name})" for _, _, name in interface) +
        "\n);\nendmodule\n")
    output.write_text(text)
    ev.record["generated_sha256"][ev.relative(output)] = digest(output)
    ev.save()
    return output


def measure(ev, images, cycles, prefetch, lowered=False, prefix_cycles=None):
    directory, _ = checked_images(ev, images)
    custom_fault_expectations(ev, directory)
    initialize = "\n".join(f" d.{name}=0;" for direction, _, name in
                           ports(ROOT / "rtl/hammer_v5_top.sv") if direction == "input")
    source = ev.directory / "boot.cpp"
    text = HARNESS.replace('if(goal=="userland") custom_fault.load();',
                           "custom_fault.load();")
    source.write_text(instrument(text, prefix_cycles)
                      .replace("__INITIALIZE_INPUTS__", initialize)
                      .replace("__ISA_ORACLE__", CPP).replace("__BOOT_SUPPORT__", SUPPORT))
    decode_image(ev.directory / "decode.bin")
    for path in (source, ev.directory / "decode.bin"):
        ev.record.setdefault("generated_sha256", {})[ev.relative(path)] = digest(path)
    for tool in ("verilator", "make", "g++"):
        ev.version(tool)
    parameters = {"PREFETCH_ENABLE": prefetch}
    sources = sorted((ROOT / "rtl").glob("*.sv"))
    if lowered:
        sources = [lower_rtl(ev, parameters),
                   *[path for path in sources if path.name != "hammer_v5_core.sv"]]
    objects = ev.directory / "compile-obj"
    objects.mkdir()
    flags = [f"-G{name}={value}" for name, value in parameters.items()]
    try:
        ev.run(["verilator", "--cc", "--exe", "--build", "-j", "2", "-Wno-fatal",
                "-O3", *BUILD_FLAGS, "--top-module", "hammer_v5_top", *flags,
                "--Mdir", ".", "-o", "boot-sim", "../boot.cpp",
                *[os.path.relpath(path, objects) for path in sources]], "compile", cwd=objects)
        ev.run(["./compile-obj/boot-sim",
                *[os.path.relpath(directory / name, ev.directory) for name in
                  ("opensbi.bin", "Image", "hammer_v5.dtb")], str(cycles), "efficiency"],
               "measure", cwd=ev.directory, expected_exit=1)
        if "bounded RTL boot goal not reached" not in (
                ROOT / ev.record["commands"][-1]["stderr"]).read_text():
            raise AssertionError("compilation experiment failed for an unexpected reason")
        observed = json.loads((ev.directory / "boot-observed.json").read_text())
        if observed["cycles"] != cycles or observed["goal_reached"] or not observed["integer_checks"]:
            raise AssertionError("compilation experiment did not complete its diagnostic edge window")
        result = {
            "architectural": observed,
            "pins": json.loads((ev.directory / "efficiency-observed.json").read_text()),
            "profile": json.loads((ev.directory / "boot-profile.json").read_text()),
            "raw_sha256": {name: digest(ev.directory / name) for name in (
                "uart.txt", "uart-events.txt", "milestones.txt", "retirement-tail.txt",
                "pc-samples.txt", "boot-phase-samples.txt", "counter-reads.txt",
                "bf16-observed.txt", "user-ecalls.txt", "user-pids.txt", "custom-faults.txt")},
        }
        ev.record["observed"] = result
        return result
    finally:
        shutil.rmtree(objects)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", required=True)
    parser.add_argument("--repair-of", required=True)
    parser.add_argument("--cycles", type=int, default=2000000)
    parser.add_argument("--prefetch", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    if not 1 <= args.cycles <= 20000000:
        raise ValueError("compact compiler comparison requires 1..20000000 edges")
    ev = Evidence("v5-model-lowering", SOURCE_SELECTORS, args.repair_of)
    ev.record["argv"] = ["python3", "tests/model_efficiency.py", *sys.argv[1:]]
    ev.record["scope"] = {"compiler_only": True, "full_linux_acceptance": False,
                          "cycles": args.cycles, "prefetch": args.prefetch}
    try:
        ev.version("python3")
        results = []
        for lowered in (False, True):
            name = "lowered" if lowered else "direct"
            child = Evidence("v5-model-" + name, SOURCE_SELECTORS, args.repair_of)
            child.record["invoked_by"] = ev.relative(ev.directory / "receipt.json")
            try:
                result = measure(child, args.images, args.cycles, args.prefetch, lowered)
                bind_outputs(child)
            except (OSError, RuntimeError, AssertionError, ValueError) as error:
                child.finish(1, error)
                raise
            receipt = child.finish(0)
            ev.record.setdefault("variants", []).append({
                "name": name, "receipt": receipt, "sha256": digest(ROOT / receipt),
                "profile": result["profile"]})
            ev.save()
            results.append(result)
        if (results[0]["architectural"] != results[1]["architectural"] or
                results[0]["raw_sha256"] != results[1]["raw_sha256"] or
                results[0]["pins"]["pin_hash"] != results[1]["pins"]["pin_hash"]):
            raise AssertionError("RTL process lowering changed public observations")
        ev.record["matched_fixed_edge_variants"] = 2
        bind_outputs(ev)
        print(json.dumps({"exit": 0, "receipt": ev.finish(0)}))
        return 0
    except (OSError, RuntimeError, AssertionError, ValueError) as error:
        print(json.dumps({"exit": 1, "receipt": ev.finish(1, error), "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
