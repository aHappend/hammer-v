#!/usr/bin/env python3
"""Bounded before/after harness diagnostic, never a Linux acceptance substitute."""
import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from boot import (BUILD_FLAGS, HARNESS, MODEL_FLAGS, checked_images, compile_model,
                  custom_fault_expectations, scheduler_configuration, boot_specialization)
from boot_support import CPP as SUPPORT
from evidence import Evidence, ROOT, digest, stamp
from integration import ports
from rv64 import CPP, decode_image
from verify import SOURCE_SELECTORS, bind_outputs


def baseline_harness(path):
    tree = ast.parse(path.read_text())
    values = [ast.literal_eval(node.value) for node in tree.body
              if isinstance(node, ast.Assign) and
              any(isinstance(target, ast.Name) and target.id == "HARNESS"
                  for target in node.targets)]
    if len(values) != 1 or not isinstance(values[0], str):
        raise AssertionError("baseline must contain exactly one literal boot HARNESS")
    return values[0]


def fault_probe(ev, images, prefetch):
    from userland import compare_custom_faults, fields, number
    directory, _ = checked_images(ev, images)
    custom_fault_expectations(ev, directory)
    ev.record["scope"] = {"genuine_RTL_boot_to_fault_records_only": True,
                          "no_full_linux_acceptance": True, "prefetch": prefetch,
                          "cycle_bound": 650000000}
    old = 'line.find("HV5 DONE")'
    if HARNESS.count(old) != 1:
        raise AssertionError("bounded custom-fault probe completion anchor changed")
    text = HARNESS.replace(old, 'line.find("HV5 FAULTS")')
    objects = compile_model(ev, text, {"PREFETCH_ENABLE": prefetch})
    try:
        ev.run(["./compile-obj/boot-sim",
                os.path.relpath(directory / "opensbi.bin", ev.directory),
                os.path.relpath(directory / "Image", ev.directory),
                os.path.relpath(directory / "hammer_v5.dtb", ev.directory),
                "650000000", "userland"], "genuine-custom-fault-probe", cwd=ev.directory,
               timeout_s=None)
        records = [fields(line.split(" ", 1)[1]) for line in
                   (ev.directory / "uart-events.txt").read_text().splitlines()]
        faults = [record for record in records if record and record[0] == "FAULTS"]
        if len(faults) != 1:
            raise AssertionError("missing/duplicate genuine user fault record")
        record = faults[0][1]
        if any(number(record, key) != value for key, value in
               (("successful_vload", 1), ("rejected", 5), ("state_preserved", 1))):
            raise AssertionError("genuine custom fault cases incomplete")
        ev.record["custom_fault_comparisons"] = compare_custom_faults(ev.directory, record)
        ev.record["observed"] = json.loads((ev.directory / "boot-observed.json").read_text())
    finally:
        shutil.rmtree(objects)


def instrument(text):
    declaration = r"""
 uint64_t pin_hash=14695981039346656037ULL;
 auto mix=[&](uint64_t value) {pin_hash=(pin_hash^value)*1099511628211ULL;};
 uint64_t sampled_eval_ns=0,sampled_host_ns=0,samples=0;
 std::chrono::steady_clock::time_point sample_start,sample_low,sample_high;
"""
    output_hash = "\n".join(f"   mix(uint64_t(d.{name}));"
                            for direction, _, name in ports(ROOT / "rtl/hammer_v5_top.sv")
                            if direction == "output")
    pairs = (
        (" Memory memory;", " Memory memory;\n" + declaration),
        ("   d.clk=0; d.eval();", r"""
   bool sample=(cycles&1023)==0;
   if(sample) sample_start=std::chrono::steady_clock::now();
   d.clk=0; d.eval();
   if(sample) sample_low=std::chrono::steady_clock::now();
""" + output_hash),
        ("   d.clk=1; d.eval(); context.timeInc(10);", r"""
   if(sample) sample_high=std::chrono::steady_clock::now();
   d.clk=1; d.eval(); context.timeInc(10);
   if(sample) {
    auto end=std::chrono::steady_clock::now();
    sampled_eval_ns+=std::chrono::duration_cast<std::chrono::nanoseconds>(
        sample_low-sample_start+end-sample_high).count();
    sampled_host_ns+=std::chrono::duration_cast<std::chrono::nanoseconds>(
        sample_high-sample_low).count();
    samples++;
   }
   mix((uint64_t(d.m_mem_axi_awvalid)<<9)|(uint64_t(d.m_mem_axi_awready)<<8)|
       (uint64_t(d.m_mem_axi_wvalid)<<7)|(uint64_t(d.m_mem_axi_wready)<<6)|
       (uint64_t(d.m_mem_axi_arvalid)<<5)|(uint64_t(d.m_mem_axi_arready)<<4)|
       (uint64_t(d.m_mem_axi_rvalid)<<3)|(uint64_t(d.m_mem_axi_rready)<<2)|
       (uint64_t(d.m_mem_axi_bvalid)<<1)|uint64_t(d.m_mem_axi_bready));
   if(accept_aw) {mix(cycles);mix(captured_aw);}
   if(accept_w) {mix(cycles);mix(captured_w);mix(captured_mask);}
   if(accept_ar) {mix(cycles);mix(captured_ar);}
   if(accept_r) {mix(cycles);mix(rdata);}
   if(accept_b) mix(cycles);
   mix(uint64_t(d.uart_tx));
""" + output_hash),
        ("  if(!done) throw", r"""
  std::ofstream signature("efficiency-observed.json");
  signature<<"{\"pin_hash\":"<<pin_hash<<",\"sampled_eval_ns\":"<<sampled_eval_ns
   <<",\"sampled_host_ns\":"<<sampled_host_ns<<",\"samples\":"<<samples<<"}\n";
  signature.close();
  if(!done) throw"""),
    )
    for old, new in pairs:
        if text.count(old) != 1:
            raise AssertionError("efficiency instrumentation anchor missing/ambiguous: " + old)
        text = text.replace(old, new)
    return text


def run_variant(ev, images, text, optimized, cycles, prefetch, profile=False,
                scheduler=False, extra_flags=()):
    directory, _ = checked_images(ev, images)
    custom_fault_expectations(ev, directory)
    initialize = "\n".join(f" d.{name}=0;" for direction, _, name in
                           ports(ROOT / "rtl/hammer_v5_top.sv") if direction == "input")
    if "--threads" in extra_flags:
        threads = int(extra_flags[extra_flags.index("--threads") + 1])
        if not 1 <= threads <= 4 or text.count("context.threads(1)") != 1:
            raise ValueError("bounded model-thread experiment requires 1..4 context threads")
        text = text.replace("context.threads(1)", f"context.threads({threads})")
    source = ev.directory / "boot.cpp"
    source.write_text(instrument(text).replace("__INITIALIZE_INPUTS__", initialize)
                      .replace("__ISA_ORACLE__", CPP).replace("__BOOT_SUPPORT__", SUPPORT))
    decode_image(ev.directory / "decode.bin")
    ev.record["generated_sha256"].update({
        ev.relative(path): digest(path) for path in (source, ev.directory / "decode.bin")})
    for tool in ("verilator", "make", "g++"):
        ev.version(tool)
    objects = ev.directory / "compile-obj"
    objects.mkdir()
    options = list(BUILD_FLAGS) if optimized else ["-CFLAGS", "-O3"]
    if optimized:
        options += MODEL_FLAGS
    if profile:
        ev.version("gprof")
        options += ["-CFLAGS", "-pg", "-LDFLAGS", "-pg"]
    if scheduler:
        options += [os.path.relpath(scheduler_configuration(ev), objects)]
    extra_flags = list(extra_flags)
    top = "hammer_v5_top"
    host_pgo = "--host-pgo" in extra_flags
    if host_pgo:
        extra_flags.remove("--host-pgo")
        options += ["-CFLAGS", "-fprofile-generate", "-LDFLAGS", "-fprofile-generate"]
    if "--boot-specialize" in extra_flags:
        extra_flags.remove("--boot-specialize")
        options += ["--prefix", "Vhammer_v5_top",
                    os.path.relpath(boot_specialization(ev), objects)]
        top = "hammer_v5_boot_model"
    options += extra_flags
    try:
        ev.run(["verilator", "--cc", "--exe", "--build", "-j", "2", "-Wno-fatal",
                *options, "--top-module", top,
                f"-GPREFETCH_ENABLE={prefetch}", "--Mdir", ".", "-o", "boot-sim",
                "../boot.cpp", *[os.path.relpath(path, objects) for path in
                                 sorted((ROOT / "rtl").glob("*.sv"))]],
               "compile", cwd=objects)
        if host_pgo:
            training = ev.directory / ("compiler-training-" + stamp())
            training.mkdir()
            shutil.copyfile(ev.directory / "decode.bin", training / "decode.bin")
            ev.run(["../compile-obj/boot-sim",
                    *[os.path.relpath(directory / name, training) for name in
                      ("opensbi.bin", "Image", "hammer_v5.dtb")],
                    str(cycles), "efficiency"], "compiler-training", cwd=training,
                   expected_exit=1)
            if "bounded RTL boot goal not reached" not in (
                    ROOT / ev.record["commands"][-1]["stderr"]).read_text():
                raise AssertionError("compiler training failed for an unexpected reason")
            ev.run(["make", "-f", "Vhammer_v5_top.mk", "-B", "-j", "2",
                    "VM_USER_CFLAGS=", "VM_USER_LDLIBS=",
                    "OPT_FAST=-O3 -fprofile-use -Werror=missing-profile -Werror=coverage-mismatch",
                    "OPT_SLOW=-O3 -fprofile-use -Werror=missing-profile -Werror=coverage-mismatch",
                    "OPT_GLOBAL=-O3 -fprofile-use -Werror=missing-profile -Werror=coverage-mismatch",
                    "LDFLAGS=-fprofile-use"], "profile-guided-compile", cwd=objects)
        ev.run(["./compile-obj/boot-sim",
                os.path.relpath(directory / "opensbi.bin", ev.directory),
                os.path.relpath(directory / "Image", ev.directory),
                os.path.relpath(directory / "hammer_v5.dtb", ev.directory),
                str(cycles), "efficiency"], "fixed-edge-profile", cwd=ev.directory,
               expected_exit=1)
        command = ev.record["commands"][-1]
        if "bounded RTL boot goal not reached" not in (ROOT / command["stderr"]).read_text():
            raise AssertionError("efficiency experiment failed for an unexpected reason")
        observed = json.loads((ev.directory / "boot-observed.json").read_text())
        if observed["cycles"] != cycles or observed["goal_reached"] or not observed["integer_checks"]:
            raise AssertionError("fixed-edge probe did not execute its complete diagnostic window")
        if profile:
            ev.run(["gprof", "-b", "-p", "./compile-obj/boot-sim", "gmon.out"],
                   "model-profile", cwd=ev.directory)
        if profile or scheduler or extra_flags:
            generated = ev.directory / ("generated-model-" + digest(source)[:16])
            generated.mkdir()
            for path in objects.iterdir():
                if path.suffix in (".cpp", ".h", ".mk"):
                    shutil.copyfile(path, generated / path.name)
        result = {
            "architectural": observed,
            "pins": json.loads((ev.directory / "efficiency-observed.json").read_text()),
            "profile": json.loads((ev.directory / "boot-profile.json").read_text()),
            "raw_sha256": {name: digest(ev.directory / name) for name in (
                "uart.txt", "uart-events.txt", "milestones.txt", "retirement-tail.txt",
                "pc-samples.txt", "boot-phase-samples.txt", "counter-reads.txt",
                "bf16-observed.txt", "user-ecalls.txt", "user-pids.txt")},
        }
        ev.record["observed"] = result
        return result
    finally:
        shutil.rmtree(objects)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="retained pre-repair tests/boot.py snapshot")
    parser.add_argument("--images", required=True)
    parser.add_argument("--repair-of", required=True)
    parser.add_argument("--baseline-receipt", help="source binding when repairing a prior diagnostic")
    parser.add_argument("--cycles", type=int, default=10000000)
    parser.add_argument("--prefetch", type=int, choices=(0, 1), default=0)
    parser.add_argument("--profile-only", action="store_true",
                        help="sample the current compiled model with existing GNU gprof")
    parser.add_argument("--options-only", action="store_true", help="retain installed compiler options")
    parser.add_argument("--faults-only", action="store_true",
                        help="genuine boot through faults only; never full Linux acceptance")
    parser.add_argument("--scheduler-compare", action="store_true",
                        help="compare unchanged RTL with array-split scheduling configuration")
    parser.add_argument("--compiler-compare", action="store_true",
                        help="compare bounded code-generation/installed-compiler optimizations")
    parser.add_argument("--candidate", nargs=2, action="append", metavar=("NAME", "FLAGS_JSON"),
                        help="additional installed-tool compiler flags, compared with scheduler baseline")
    args = parser.parse_args()
    if not 1 <= args.cycles <= 20000000:
        raise ValueError("efficiency diagnostic requires 1..20000000 edges")
    ev = Evidence("v5-boot-efficiency", SOURCE_SELECTORS, args.repair_of)
    ev.record["argv"] = ["python3", "tests/boot_efficiency.py", *sys.argv[1:]]
    ev.record["scope"] = {"fixed_edge_diagnostic_only": True, "cycles": args.cycles,
                          "prefetch": args.prefetch, "no_linux_acceptance": True}
    try:
        ev.version("python3")
        if args.options_only:
            ev.version("verilator")
            ev.run(["verilator", "--help"], "verilator-help")
            print(json.dumps({"exit": 0, "receipt": ev.finish(0)}))
            return 0
        if args.faults_only:
            fault_probe(ev, args.images, args.prefetch)
            bind_outputs(ev)
            print(json.dumps({"exit": 0, "receipt": ev.finish(0)}))
            return 0
        baseline = (ROOT / args.baseline).resolve()
        baseline.relative_to(ROOT)
        baseline_receipt = args.baseline_receipt or args.repair_of
        prior = json.loads((ROOT / baseline_receipt).read_text())
        if digest(baseline) != prior["sources_sha256"]["tests/boot.py"]:
            raise AssertionError("baseline harness is not bound to retained failed receipt")
        saved = ev.directory / "baseline-boot.py"
        shutil.copyfile(baseline, saved)
        ev.record["baseline_sha256"] = digest(saved)
        ev.record["baseline_receipt"] = {
            "path": baseline_receipt, "sha256": digest(ROOT / baseline_receipt)}
        results = []
        variants = (
                ("baseline", baseline_harness(saved), False, False, ()),
                ("host-repair", HARNESS, False, False, ()),
                ("optimized", HARNESS, True, False, ()))
        if args.profile_only:
            variants = (("profile-scheduler", HARNESS, True, True, ("--prof-cfuncs",)),)
        if args.scheduler_compare:
            variants = (("current", HARNESS, True, False, ()),
                        ("scheduler", HARNESS, True, True, ()))
        if args.compiler_compare:
            variants = (
                ("scheduler", HARNESS, True, True, ()),
                ("small-functions", HARNESS, True, True,
                 ("--output-split", "5000", "--output-split-cfuncs", "500")),
                ("lto", HARNESS, True, True,
                 ("-CFLAGS", "-flto", "-LDFLAGS", "-flto")),
                ("gate", HARNESS, True, True, ("--gate-stmts", "5000")),
            )
        if args.candidate:
            variants = [("scheduler", HARNESS, True, True, ())]
            for name, encoded in args.candidate:
                flags = json.loads(encoded)
                if (not name.replace("-", "").isalnum() or not isinstance(flags, list)
                        or not all(isinstance(flag, str) for flag in flags)):
                    raise ValueError("candidate needs a simple name and JSON string-list flags")
                variants.append((name, HARNESS, True, True, tuple(flags)))
        for name, text, optimized, scheduler, extra_flags in variants:
            child = Evidence("v5-boot-efficiency-" + name, SOURCE_SELECTORS, args.repair_of)
            child.record["invoked_by"] = ev.relative(ev.directory / "receipt.json")
            entry = {"name": name, "receipt": ev.relative(child.directory / "receipt.json")}
            ev.record.setdefault("variants", []).append(entry)
            ev.save()
            try:
                result = run_variant(child, args.images, text, optimized, args.cycles,
                                     args.prefetch, args.profile_only, scheduler, extra_flags)
                bind_outputs(child)
            except (OSError, RuntimeError, AssertionError, ValueError) as error:
                child.finish(1, error)
                entry.update(exit=1, error=str(error), sha256=digest(ROOT / entry["receipt"]))
                ev.save()
                raise
            receipt = child.finish(0)
            results.append(result)
            entry.update(exit=0, sha256=digest(ROOT / receipt),
                         profile=result["profile"], timing_samples=result["pins"])
            ev.save()
        for result in results[1:]:
            if (result["architectural"] != results[0]["architectural"] or
                    result["raw_sha256"] != results[0]["raw_sha256"] or
                    result["pins"]["pin_hash"] != results[0]["pins"]["pin_hash"]):
                raise AssertionError("harness optimization changed fixed-edge public observations")
        if not args.profile_only:
            ev.record["matched_fixed_edge_variants"] = len(results)
        else:
            ev.record["compiled_model_profile_only"] = True
        bind_outputs(ev)
        print(json.dumps({"exit": 0, "receipt": ev.finish(0)}))
        return 0
    except (OSError, RuntimeError, AssertionError, ValueError) as error:
        print(json.dumps({"exit": 1, "receipt": ev.finish(1, error), "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
