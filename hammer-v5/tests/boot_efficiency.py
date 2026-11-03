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
                  custom_fault_expectations, scheduler_configuration, boot_specialization,
                  profile_compile)
from boot_support import CPP as SUPPORT
from evidence import Evidence, ROOT, digest, stamp
from integration import ports
from rv64 import CPP, decode_image
from verify import SOURCE_SELECTORS, bind_outputs, build_software


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


def instrument(text, prefix_cycles=None):
    declaration = r"""
 uint64_t pin_hash=14695981039346656037ULL;
 auto mix=[&](uint64_t value) {pin_hash=(pin_hash^value)*1099511628211ULL;};
 uint64_t sampled_eval_ns=0,sampled_host_ns=0,samples=0;
 std::chrono::steady_clock::time_point sample_start,sample_low,sample_high;
 std::chrono::steady_clock::time_point prefix_end;
"""
    if prefix_cycles is not None:
        anchor = '   if(context.gotFinish()) throw std::runtime_error("RTL terminated before boot goal");'
        if text.count(anchor) != 1:
            raise AssertionError("late-prefix observation anchor changed")
        text = text.replace(anchor, r"""
   if(cycles+1==__PREFIX_CYCLES__) {
    prefix_end=std::chrono::steady_clock::now();
    std::ofstream prefix("prefix-observed.json");
    prefix<<"{\"cycles\":"<<cycles+1<<",\"retired\":"<<retired<<",\"dram_reads\":"<<reads
     <<",\"dram_writes\":"<<writes<<",\"s_retired\":"<<sretired<<",\"u_retired\":"<<uretired
     <<",\"high_va_retired\":"<<translated<<",\"u_custom\":"<<custom
     <<",\"traps\":"<<traps<<",\"integer_checks\":"<<isa.checked
     <<",\"m_mode_load_checks\":"<<isa.loads<<",\"m_mode_store_checks\":"<<isa.stores
     <<",\"user_pid_count\":"<<observed_pids.size()
     <<",\"retirement_hash\":"<<retirement_hash<<",\"goal_reached\":false}\n";
    uart.flush();uart_events.flush();ecalls.flush();pids.flush();
    std::ofstream prefix_time("prefix-timing.json");
    prefix_time<<"{\"seconds\":"<<std::chrono::duration<double>(prefix_end-wall_start).count()
     <<",\"cycles\":"<<cycles+1<<"}\n";
    for(const char *name: {"uart.txt","uart-events.txt","user-ecalls.txt","user-pids.txt"}) {
     std::ifstream input(name,std::ios::binary);
     std::ofstream output(std::string("prefix-")+name,std::ios::binary);
     output<<input.rdbuf();
    }
   }
""" .replace("__PREFIX_CYCLES__", str(prefix_cycles)) + anchor)
    output_hash = "\n".join(f"   mix(uint64_t(d.{name}));"
                            for direction, _, name in ports(ROOT / "rtl/hammer_v5_top.sv")
                            if direction == "output")
    if prefix_cycles is not None:
        # Late diagnostics still execute every edge; hash all pins in the compact
        # equivalence prefix and every AXI handshake/stall throughout the run.
        output_hash = "   if(cycles<20000000) {\n" + output_hash + "\n   }\n"
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
  profile();
  signature<<"{\"pin_hash\":"<<pin_hash<<",\"sampled_eval_ns\":"<<sampled_eval_ns
   <<",\"sampled_host_ns\":"<<sampled_host_ns<<",\"samples\":"<<samples;
  if(prefix_end.time_since_epoch().count()) {
   double seconds=std::chrono::duration<double>(
       std::chrono::steady_clock::now()-prefix_end).count();
   signature<<",\"late_seconds\":"<<seconds;
  }
  signature<<"}\n";
  signature.close();
  if(!done) throw"""),
    )
    for old, new in pairs:
        if text.count(old) != 1:
            raise AssertionError("efficiency instrumentation anchor missing/ambiguous: " + old)
        text = text.replace(old, new)
    return text


def run_variant(ev, images, text, optimized, cycles, prefetch, profile=False,
                scheduler=False, extra_flags=(), prefix_cycles=None, completion=False):
    directory, _ = checked_images(ev, images)
    custom_fault_expectations(ev, directory)
    initialize = "\n".join(f" d.{name}=0;" for direction, _, name in
                           ports(ROOT / "rtl/hammer_v5_top.sv") if direction == "input")
    if "--threads" in extra_flags:
        threads = int(extra_flags[extra_flags.index("--threads") + 1])
        if not 1 <= threads <= 4 or text.count("context.threads(1)") != 1:
            raise ValueError("bounded model-thread experiment requires 1..4 context threads")
        text = text.replace("context.threads(1)", f"context.threads({threads})")
    if prefix_cycles is not None:
        anchor = 'if(goal=="userland") custom_fault.load();'
        if text.count(anchor) != 1:
            raise AssertionError("late custom-fault observation anchor changed")
        text = text.replace(anchor, 'custom_fault.load();')
    source = ev.directory / "boot.cpp"
    source.write_text(instrument(text, prefix_cycles).replace("__INITIALIZE_INPUTS__", initialize)
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
    sources = sorted((ROOT / "rtl").glob("*.sv"))
    parameters = [f"-GPREFETCH_ENABLE={prefetch}"]
    if "--lower-core" in extra_flags:
        extra_flags.remove("--lower-core")
        from model_efficiency import lower_rtl
        sources = [lower_rtl(ev, {"PREFETCH_ENABLE": prefetch}),
                   *[path for path in sources if path.name != "hammer_v5_core.sv"]]
    if "--lower-soc" in extra_flags:
        extra_flags.remove("--lower-soc")
        from model_efficiency import lower_top
        sources = [lower_top(ev, prefetch)]
        parameters = []
    if "--split-core" in extra_flags:
        extra_flags.remove("--split-core")
        configuration = ev.directory / "core-scheduler.vlt"
        configuration.write_text("`verilator_config\n" + "".join(
            f'split_var -module "hammer_v5_core" -var "{name}"\n'
            for name in ("x", "m", "w", "queue_head")))
        ev.record.setdefault("generated_sha256", {})[ev.relative(configuration)] = digest(configuration)
        options += [os.path.relpath(configuration, objects)]
    options += extra_flags
    try:
        ev.run(["verilator", "--cc", "--exe", "--build", "-j", "2", "-Wno-fatal",
                *options, "--top-module", top,
                *parameters, "--Mdir", ".", "-o", "boot-sim",
                "../boot.cpp", *[os.path.relpath(path, objects) for path in
                                 sources]],
               "compile", cwd=objects)
        if host_pgo:
            profile_compile(ev, objects, directory, min(cycles, 2000000))
        ev.run(["./compile-obj/boot-sim",
                os.path.relpath(directory / "opensbi.bin", ev.directory),
                os.path.relpath(directory / "Image", ev.directory),
                os.path.relpath(directory / "hammer_v5.dtb", ev.directory),
                str(cycles), "userland" if completion else "efficiency"],
               "completion-measurement" if completion else "fixed-edge-profile",
               cwd=ev.directory, expected_exit=0 if completion else 1)
        command = ev.record["commands"][-1]
        if not completion and "bounded RTL boot goal not reached" not in (
                ROOT / command["stderr"]).read_text():
            raise AssertionError("efficiency experiment failed for an unexpected reason")
        observed = json.loads((ev.directory / "boot-observed.json").read_text())
        if ((not completion and observed["cycles"] != cycles) or
                observed["goal_reached"] != completion or not observed["integer_checks"]):
            raise AssertionError("fixed-edge probe did not execute its complete diagnostic window")
        if completion:
            from userland import compare_userland
            ev.record["userland_comparisons"] = compare_userland(ev.directory)
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
    parser.add_argument("--late-candidate", action="store_true",
                        help="one bounded fresh-reset candidate with failed-run prefix equivalence")
    parser.add_argument("--completion-measure", action="store_true",
                        help="measure one late candidate through all unchanged userland comparisons")
    parser.add_argument("--fresh-build", action="store_true",
                        help="measure fresh offline software preparation and verify image identity")
    args = parser.parse_args()
    if not 1 <= args.cycles <= (1000000000 if args.late_candidate else 20000000):
        raise ValueError("efficiency diagnostic exceeds its declared edge bound")
    if args.late_candidate and (not args.candidate or len(args.candidate) != 1):
        raise ValueError("late diagnostic requires exactly one explicit candidate")
    if (args.completion_measure or args.fresh_build) and not args.late_candidate:
        raise ValueError("completion/build measurement requires a source-bound late candidate")
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
        prefix_cycles = None
        if args.late_candidate:
            prefix_cycles = prior["observed"]["cycles"]
            if not prefix_cycles < args.cycles:
                raise ValueError("late diagnostic must extend the retained failed prefix")
            for name, expected in prior["sources_sha256"].items():
                if name.startswith(("rtl/", "software/")) or name in (
                        "tests/rv64.py", "tests/compressed.py", "tests/boot_support.py"):
                    if ev.record["sources_sha256"][name] != expected:
                        raise AssertionError("late comparison source changed: " + name)
            if baseline_harness(saved) != HARNESS:
                raise AssertionError("late comparison must preserve the baseline boot harness")
            ev.record["scope"].update(
                retained_prefix_cycles=prefix_cycles, fresh_software_build=False,
                full_remaining_workload_not_yet_measured=True)
        images = args.images
        if args.fresh_build:
            images = build_software(ev)
            identity = {}
            for name in ("opensbi.bin", "Image", "hammer_v5.dtb", "init.elf"):
                identity[name] = {
                    "prior_sha256": digest(ROOT / args.images / name),
                    "fresh_sha256": digest(ROOT / images / name),
                }
            ev.record["fresh_image_identity"] = identity
            ev.record["scope"]["fresh_software_build"] = True
        if args.late_candidate:
            identity = {
                item["file"]: {"prior_sha256": item["sha256"],
                               "actual_sha256": digest(ROOT / images / item["file"])}
                for item in prior["software_build"]["images"]}
            ev.record["historical_image_identity"] = identity
            if any(item["prior_sha256"] != item["actual_sha256"] for item in identity.values()):
                if not args.completion_measure:
                    raise AssertionError("controlled prefix comparison requires identical boot images")
                prefix_cycles = None
                ev.record["scope"]["historical_prefix_comparison"] = (
                    "not comparable: different boot image bytes; execute all current independent oracles")
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
            if args.late_candidate:
                variants = variants[1:]
        for name, text, optimized, scheduler, extra_flags in variants:
            child = Evidence("v5-boot-efficiency-" + name, SOURCE_SELECTORS, args.repair_of)
            child.record["invoked_by"] = ev.relative(ev.directory / "receipt.json")
            entry = {"name": name, "receipt": ev.relative(child.directory / "receipt.json")}
            ev.record.setdefault("variants", []).append(entry)
            ev.save()
            try:
                result = run_variant(child, images, text, optimized, args.cycles,
                                     args.prefetch, args.profile_only, scheduler, extra_flags,
                                     prefix_cycles, args.completion_measure)
                if args.late_candidate:
                    if prefix_cycles is not None:
                        prefix = json.loads((child.directory / "prefix-observed.json").read_text())
                        if prefix != prior["observed"]:
                            raise AssertionError("late candidate changed retained architectural prefix")
                        for name in ("uart.txt", "uart-events.txt", "user-ecalls.txt", "user-pids.txt"):
                            if digest(child.directory / ("prefix-" + name)) != digest(
                                    (ROOT / baseline_receipt).parent / name):
                                raise AssertionError("late candidate changed retained raw prefix: " + name)
                        child.record["retained_prefix_equivalent"] = prefix
                    from userland import compare_custom_faults, fields
                    faults = [record[1] for line in (child.directory / "uart-events.txt").read_text().splitlines()
                              if (record := fields(line.split(" ", 1)[1])) and record[0] == "FAULTS"]
                    if len(faults) != 1:
                        raise AssertionError("late diagnostic did not complete genuine fault cases")
                    child.record["custom_fault_comparisons"] = compare_custom_faults(
                        child.directory, faults[0])
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
        if not args.profile_only and not args.late_candidate:
            ev.record["matched_fixed_edge_variants"] = len(results)
        elif args.profile_only:
            ev.record["compiled_model_profile_only"] = True
        if args.completion_measure:
            ev.record["scope"]["full_remaining_workload_not_yet_measured"] = False
            ev.record["complete_workload_measured"] = True
        bind_outputs(ev)
        print(json.dumps({"exit": 0, "receipt": ev.finish(0)}))
        return 0
    except (OSError, RuntimeError, AssertionError, ValueError) as error:
        print(json.dumps({"exit": 1, "receipt": ev.finish(1, error), "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
