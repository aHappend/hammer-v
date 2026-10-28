#!/usr/bin/env python3
"""Portable HAMMER-V1 checks. Each invocation retains a fresh source-bound receipt."""

import argparse
from collections import Counter
import itertools
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

from cycle import ComparisonFailure, CycleModel, POST_KEYS, PRE_KEYS, equal
from encoding import ECALL, EBREAK, NOP, auipc, branch, i, jal, jalr, load, lui, r, store
from iss import BRANCH_NAMES, DATA, ISS, MASK, M_NAMES, NORMAL_NAMES, Fault
from retention import Evidence, ROOT, ToolFailure, fresh, require
import scenarios


RTL = sorted(str(p.relative_to(ROOT)) for p in ROOT.glob("rtl/*.sv"))


class Campaign:
    def __init__(self, evidence):
        self.evidence = evidence
        self.builds = {}
        self.retirements = Counter()
        self.directions = Counter()
        self.traps = Counter()
        self.cycles = Counter()
        self.m_operands = Counter()
        self.records = []

    def build(self, config, simulator="verilator", rtl=None):
        key = (config, simulator, tuple(rtl or RTL))
        if key in self.builds:
            return self.builds[key]
        require("iverilog", "vvp") if simulator == "icarus" else require("verilator", "make", "g++")
        folder = fresh(self.evidence.directory, "build")
        relative = folder.relative_to(ROOT)
        params = dict(zip(("IMEM_WORDS", "DMEM_WORDS", "PRED_MODE", "BTB_ENTRIES"), config))
        if simulator == "icarus":
            binary = str(relative / "sim.vvp")
            argv = ["iverilog", "-g2012", "-Wall", "-s", "bridge", "-o", binary]
            argv += [f"-Pbridge.{name}={value}" for name, value in params.items()]
            argv += [*(rtl or RTL), "tests/bridge.sv"]
            self.evidence.command(argv)
            command = ["vvp", binary]
        else:
            self.evidence.version("make")
            self.evidence.version("g++")
            argv = ["verilator", "--binary", "--timing", "-Wno-fatal", "--top-module", "bridge",
                    "--Mdir", str(relative / "obj"), "-o", "sim", "-j", "2"]
            argv += [f"-G{name}={value}" for name, value in params.items()]
            argv += [*(rtl or RTL), "tests/bridge.sv", "tests/write_observer.sv"]
            self.evidence.command(argv)
            command = [str(relative / "obj" / "sim")]
        self.builds[key] = command
        return command

    def run(self, name, program, config=(769, 257, 1, 16), data=None,
            simulator="verilator", delays=(0, 0, 0, 0, 0), response=0,
            limit=500000, rtl=None, expected_trap=None, expected_buffer=None, reset_outstanding=False):
        if data is None:
            data = [0x80ff01fe7f0081aa] * config[1]
        if len(program) > config[0]:
            raise ValueError(f"{name}: program {len(program)} exceeds IMEM_WORDS={config[0]}")
        if simulator == "icarus" and limit > 500000:
            raise ValueError("Icarus is limited to 500000 functional cycles")
        # Initialize speculative fetch locations too, never discard an X/Z comparison.
        program = program + [0] * (config[0] - len(program))
        command = self.build(config, simulator, rtl)
        folder = fresh(self.evidence.directory, name)
        input_path, trace_path = folder / "input.txt", folder / "trace.txt"
        scratchpad_trace = folder / "scratchpad-writes.txt" if simulator == "verilator" else None
        input_path.write_text(
            " ".join(map(str, (len(program), len(data), limit, *delays, response))) + "\n" +
            "".join(f"{word:08x}\n" for word in program) +
            "".join(f"{word:016x}\n" for word in data))
        argv = command + [f"+input={input_path.relative_to(ROOT)}", f"+trace={trace_path.relative_to(ROOT)}"]
        if reset_outstanding:
            argv += ["+reset_outstanding=1"]
        if scratchpad_trace is not None:
            argv += [f"+scratchpad_trace={scratchpad_trace.relative_to(ROOT)}"]
        self.evidence.command(argv)
        result = self.compare(trace_path, program, data, config, response, expected_trap,
                              expected_buffer, reset_outstanding, scratchpad_trace)
        record = {"name": name, "config": config, "simulator": simulator, "delays": delays,
                  "response": response, "trace": str(trace_path.relative_to(ROOT)),
                  "scratchpad_trace": str(scratchpad_trace.relative_to(ROOT)) if scratchpad_trace else None,
                  **result}
        self.records.append(record)
        return result

    def compare(self, path, program, data, config, response, expected_trap, expected_buffer,
                reset_outstanding, scratchpad_trace):
        memory = bytearray(b"".join(v.to_bytes(8, "little") for v in data))
        iss = ISS(program, bytearray(memory), config[0], config[1], response)
        iss.mmio[:] = bytes.fromhex("aa81007ffe01ff80") * 8192
        model = CycleModel(program, memory, config, response)
        observed_trap = None
        finished = False
        count = 0
        final_reads = set()
        reset_observed = False
        reset_checked = False
        trap_guard_cycles = 0
        edge_times = {}
        for line in path.open():
            fields = line.split()
            if fields[0] == "RESET":
                equal(tuple(int(v, 16) for v in fields[1:]), (1, 0), "postponed time-zero reset")
                reset_checked = True
                continue
            if fields[0] == "ABORT":
                equal(reset_outstanding, True, "only an explicit reset case may abort")
                if model.bus is None or not any(model.bus[k] for k in ("aw", "w", "ar")):
                    raise ComparisonFailure("reset did not coincide with a publicly accepted outstanding request")
                reset_observed = True
                continue
            if fields[0] == "G":
                if observed_trap is None:
                    raise ComparisonFailure("held-trap record before a checked terminal episode")
                equal(tuple(int(v, 16) for v in fields[1:3]), observed_trap, "held terminal cause/PC")
                equal([int(v, 16) for v in fields[3:]], iss.registers, "no younger writes after terminal trap")
                trap_guard_cycles += 1
                continue
            if fields[0] == "H":
                im, offset, value = (int(v, 16) for v in fields[1:])
                if im:
                    equal(value, program[offset // 4], "host instruction boundary read")
                else:
                    equal(value, iss.read(DATA + offset, 8), f"actual scratchpad readback {offset:#x}")
                    final_reads.add(offset)
                continue
            if fields[0] == "END":
                finished = True
                continue
            if fields[0] != "T":
                raise ComparisonFailure(f"unknown trace record: {line[:80]}")
            cycle = int(fields[1])
            values = [int(value, 16) for value in fields[2:]]
            pre = dict(zip(PRE_KEYS, values[:len(PRE_KEYS)]))
            edge_times[cycle] = pre["edge_time"]
            post = dict(zip(POST_KEYS, values[len(PRE_KEYS):len(PRE_KEYS) + len(POST_KEYS)]))
            post["registers"] = values[len(PRE_KEYS) + len(POST_KEYS):]
            equal(cycle, count, "trace cycle continuity")
            model.edge(pre, post, cycle)
            if post["retire"]:
                registers_before = iss.registers.copy()
                try:
                    expected = iss.step()
                except Fault as fault:
                    raise ComparisonFailure(f"faulting instruction retired: {fault}") from fault
                equal(tuple(post[k] for k in POST_KEYS[1:13]), expected.trace(),
                      f"cycle {cycle} independent ISS retirement")
                equal(post["registers"], iss.registers, f"cycle {cycle} ISS x0..x31")
                self.retirements[expected.insn.name] += 1
                if expected.insn.muldiv:
                    self.m_operands[(expected.insn.name, registers_before[expected.insn.rs1],
                                     registers_before[expected.insn.rs2])] += 1
                if expected.insn.branch:
                    self.directions[(expected.insn.name, expected.taken)] += 1
            if post["trap"]:
                if observed_trap is not None:
                    raise ComparisonFailure("duplicate terminal observation without reset")
                expected = iss.effect()
                equal(post["retire"], 0, "faulting instruction must not retire")
                equal((post["trap_pc"], post["cause"]), (iss.pc, expected.cause), "ISS terminal cause/PC")
                equal(post["registers"], iss.registers, "no younger architectural writes at trap")
                if expected_trap is not None:
                    equal((post["trap_pc"], post["cause"]), expected_trap, "directed trap expectation")
                observed_trap = (iss.pc, expected.cause)
            count += 1
        if not reset_checked or not finished or (observed_trap is None and not reset_observed):
            raise ComparisonFailure("missing terminal completion record")
        equal(reset_observed, reset_outstanding, "required outstanding-request reset occurred")
        equal(trap_guard_cycles, 0 if reset_outstanding else 6, "required held-trap guard cycles")
        equal(final_reads, set(range(0, len(memory), 8)), "all initialized scratchpad words read back")
        equal(model.memory, iss.memory, "cycle/architectural scratchpad effects")
        equal(model.mmio, iss.mmio, "cycle/architectural MMIO effects")
        if scratchpad_trace is not None:
            observed_writes = [tuple(int(value, 16) for value in line.split())
                               for line in scratchpad_trace.read_text().splitlines()]
            expected_writes = [(edge_times[c], address, value, mask)
                               for c, address, value, mask in model.writes]
            equal(observed_writes, expected_writes, "actual scratchpad write pin transfers/count/timing")
        if expected_buffer is not None:
            address, expected_values = expected_buffer
            actual_values = [iss.read(address + 8 * n, 8) for n in range(len(expected_values))]
            equal(actual_values, expected_values, "compiled C exact independently computed result buffer")
        if observed_trap is not None:
            self.traps[iss.effect().insn.name] += 1
        self.cycles.update(model.coverage)
        return {"retired": len(iss.history), "cycles": count, "trap": observed_trap,
                "trap_guard_cycles": trap_guard_cycles,
                "reset_outstanding": reset_observed, "cycle_coverage": dict(model.coverage)}

    def hazard_probe(self, simulator="icarus"):
        program = [
            lui(1, DATA >> 12), i("ADDI", 2, 0, -1), store("SW", 2, 1),
            load("LW", 3, 1), r("ADD", 4, 3, 2),
            i("ADDI", 5, 0, 7), i("ADDI", 5, 5, 9), r("ADD", 6, 5, 4),
            r("DIVU", 7, 6, 0), r("MULH", 8, 3, 4),
            branch("BEQ", 8, 8, 12), i("ADDI", 9, 0, 123), store("SD", 9, 1, 8),
            ECALL, i("ADDI", 10, 0, 91), store("SD", 10, 1, 16),
        ]
        return self.run("compact-hazard-m", program, (64, 3, 1, 4), simulator=simulator,
                 expected_trap=(52, 11), limit=2000)

    def smoke(self):
        self.hazard_probe()
        for iw, dw in ((1, 1), (3, 3), (769, 257), (16384, 8192)):
            self.run("memory-boundary", [NOP] if iw == 1 else [NOP, EBREAK],
                     (iw, dw, 0, 1), simulator="icarus", limit=100,
                     expected_trap=(4, 1 if iw == 1 else 3))
        for config in itertools.product((1, 3, 16384), (1, 3, 8192), (0, 1), (1, 4, 16, 64)):
            output = fresh(self.evidence.directory, "elaborate")
            argv = ["iverilog", "-g2012", "-Wall", "-t", "null", "-s", "hammer_v1_top"]
            argv += [f"-Phammer_v1_top.{name}={value}" for name, value in zip(
                ("IMEM_WORDS", "DMEM_WORDS", "PRED_MODE", "BTB_ENTRIES"), config)]
            self.evidence.command(argv + RTL)
        for param, value in (("IMEM_WORDS", 0), ("IMEM_WORDS", 16385), ("DMEM_WORDS", 0),
                             ("DMEM_WORDS", 8193), ("PRED_MODE", -1), ("PRED_MODE", 2),
                             ("BTB_ENTRIES", 0), ("BTB_ENTRIES", 2)):
            output = fresh(self.evidence.directory, "illegal")
            binary = str((output / "illegal.vvp").relative_to(ROOT))
            self.evidence.command(["iverilog", "-g2012", "-Wall", "-s", "hammer_v1_top", "-o", binary,
                                   f"-Phammer_v1_top.{param}={value}", *RTL])
            folder, result = self.evidence.command(["vvp", binary], expect_failure=True)
            equal(result["exit_code"] != 0, True, f"explicit rejection {param}={value}")
            log = (folder / "stdout.log").read_text() + (folder / "stderr.log").read_text()
            if f"PARAMETER ERROR: {param}" not in log:
                raise ComparisonFailure(f"missing explicit diagnostic {param}={value}")

    def summary(self):
        return {"cases": self.records, "retirements": dict(self.retirements),
                "branch_directions": {f"{name}:{int(taken)}": count for (name, taken), count in self.directions.items()},
                "traps": dict(self.traps), "cycle_coverage": dict(self.cycles)}

    def terminal_precision(self, compact=False):
        before = self.traps.copy()
        for terminal in (ECALL, EBREAK):
            for episode in range(32):
                config = ((32, 3) if compact else (769, 257)) + (
                    episode % 2, (1, 4, 16, 64)[episode // 2 % 4])
                result = self.run("terminal-precision", scenarios.precision_program(terminal),
                                  config, expected_trap=(20, 11 if terminal == ECALL else 3),
                                  limit=100 if compact else 500000)
                equal(result["retired"], 5, "all and only five older instructions retired before terminal")
        for name in ("ECALL", "EBREAK"):
            equal(self.traps[name] - before[name], 32, f"distinct fully checked {name} episodes")

    def m_cartesian(self):
        before = self.m_operands.copy()
        code, operands = scenarios.m_cartesian()
        result = self.run("complete-m-cartesian", code, (16384, 8192, 1, 16),
                          data=operands + [0] * (8192 - len(operands)), limit=200000)
        equal(result["retired"], len(code) - 1, "all directed M Cartesian instructions executed")
        for name, a, b in itertools.product(M_NAMES, scenarios.PATTERNS, scenarios.PATTERNS):
            if self.m_operands[name, a, b] - before[name, a, b] == 0:
                raise ComparisonFailure(f"unobserved M Cartesian operand pair {name}:{a:#x},{b:#x}")

    def directed(self):
        self.evidence.command(["python3", "tests/selftest.py"])
        for mode, entries in itertools.product((0, 1), (1, 4, 16, 64)):
            config = (769, 257, mode, entries)
            before = self.cycles.copy()
            self.run("functional-matrix", scenarios.functional_program(), config)
            self.run("prediction-target-correction", scenarios.target_correction(), config)
            self.run("wrong-path-effects", scenarios.flush_program(), config)
            delta = self.cycles - before
            for key in ("correct_prediction", "redirect", "branch_forward", "jalr_forward"):
                if delta[key] == 0:
                    raise ComparisonFailure(f"prediction configuration {config} missing {key}")
            if mode == 0:
                for key in ("static_backward", "static_forward"):
                    if delta[key] == 0:
                        raise ComparisonFailure(f"static configuration {config} missing {key}")
            elif delta["target_correction"] == 0 or delta["btb_collision"] == 0:
                raise ComparisonFailure(f"dynamic configuration {config} missing target/collision evidence")
        self.m_cartesian()
        # Complete bit-boundary matrix, including shifts whose upper operand bits must be ignored.
        code = [lui(20, DATA >> 12), i("ADDI", 1, 0, -1)]
        for amount in (0, 1, 31, 32, 63, 64, 127):
            code += [i("ADDI", 2, 0, amount)]
            for name in ("SLL", "SRL", "SRA", "SLLW", "SRLW", "SRAW"):
                code += [r(name, 3, 1, 2)]
            if amount < 64:
                for name in ("SLLI", "SRLI", "SRAI"):
                    code += [i(name, 3, 1, amount)]
            if amount < 32:
                for name in ("SLLIW", "SRLIW", "SRAIW"):
                    code += [i(name, 3, 1, amount)]
        code += [EBREAK]
        self.run("shift-boundaries", code)
        self.terminal_precision()
        for name, code, trap in scenarios.trap_cases():
            self.run(name, code, expected_trap=trap)
        schedules = ((0, 0, 0, 0, 0), (1, 2, 17, 1, 2), (17, 1, 2, 2, 17),
                     (2, 17, 1, 17, 1))
        rng = random.Random(2027)
        schedules += tuple(tuple(rng.choice((1, 2, 17)) for _ in range(5)) for _ in range(8))
        for delays in schedules:
            self.run("axi-lanes-and-stalls", scenarios.axi_program(), delays=delays)
        for response, write in itertools.product((1, 2, 3), (False, True)):
            access = store("SD", 2, 1) if write else load("LD", 2, 1)
            self.run("axi-error-precision", [lui(1, 0x40000), NOP, access,
                                           store("SD", 0, 1), ECALL],
                     delays=(17, 1, 2, 2, 17), response=response, expected_trap=(8, 7 if write else 5))
        self.run("m-completion-under-memory-stall", [
            lui(20, 0x40000), i("ADDI", 1, 0, 17), i("ADDI", 2, 0, 19),
            store("SD", 1, 20), r("MUL", 3, 1, 2), r("ADD", 4, 3, 3), EBREAK],
            delays=(1, 2, 97, 0, 0))
        self.run("redirect-after-memory-hold", [
            lui(20, 0x40000), store("SD", 0, 20), branch("BEQ", 0, 0, 8),
            store("SD", 0, 20, 8), ECALL], delays=(17, 1, 17, 0, 0))
        for access in (store("SD", 0, 20), load("LD", 1, 20)):
            self.run("reset-accepted-outstanding-request", [lui(20, 0x40000), access, ECALL],
                     delays=(0, 17, 17, 0, 17), reset_outstanding=True)
        self.run("last-legal-data-word", [
            lui(20, DATA >> 12), i("ADDI", 20, 20, 1024), i("ADDI", 20, 20, 1024),
            i("ADDI", 1, 0, -17), store("SD", 1, 20), load("LD", 2, 20), ECALL])
        for name in NORMAL_NAMES:
            if self.retirements[name] < 32:
                raise ComparisonFailure(f"retirement coverage {name}={self.retirements[name]} < 32")
        for name in BRANCH_NAMES:
            for taken in (False, True):
                if self.directions[name, taken] < 16:
                    raise ComparisonFailure(f"branch direction coverage {name}:{taken} < 16")
        for name in ("ECALL", "EBREAK"):
            if self.traps[name] < 32:
                raise ComparisonFailure(f"distinct terminal episodes {name} < 32")
        for key in ("youngest_priority", "rs1_2", "rs1_1", "rs2_2", "rs2_1",
                    "store_1", "store_2", "wb_id", "isolated_load_use", "unused_no_interlock",
                    "x0_no_interlock", "branch_forward", "jalr_forward",
                    "flush_ADDI", "flush_scratchpad", "flush_mmio", "flush_ILLEGAL",
                    "redirect_after_hold", "m_complete_mem_hold"):
            if self.cycles[key] == 0:
                raise ComparisonFailure(f"required observed cycle coverage missing: {key}")

    def random(self, seed, minimum):
        if seed not in (17, 89, 2027):
            raise ValueError("the admitted random seeds are 17, 89 and 2027")
        retired = 0
        rng = random.Random(seed)
        # Splitting programs, not checks, keeps instruction SRAM below its legal maximum.
        for part in range((minimum + 1999) // 2000):
            code, data = scenarios.random_program(rng, 2500)
            result = self.run(f"random-{seed}-part-{part}", code, (16384, 8192, 1, 16),
                              data=data + [0] * (8192 - len(data)), limit=1000000)
            retired += result["retired"]
        if retired < minimum:
            raise ComparisonFailure(f"random seed {seed}: {retired} < {minimum} compared retirements")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=(
        "smoke", "directed", "random", "benchmarks", "mutations", "synthesis", "portable"))
    parser.add_argument("--seed", type=int)
    parser.add_argument("--min-retirements", type=int, default=10000)
    parser.add_argument("--prepare", action="store_true", help="retain bounded advisory preparation, not acceptance")
    parser.add_argument("--compact-only", action="store_true", help="advisory first smoke only; never full acceptance")
    parser.add_argument("--repair-of", help="project-relative retained failed preparation receipt")
    parser.add_argument("--probe", choices=("hazard", "axi", "functional", "synthesis", "compiler", "reset",
                                           "terminal", "m-cartesian", "lw-sign"),
                        help="bounded advisory experiment")
    args = parser.parse_args()
    if (args.compact_only or args.probe) and not args.prepare:
        parser.error("bounded subsets require --prepare")
    if args.prepare and not (args.compact_only or args.probe):
        parser.error("--prepare requires a bounded --probe or --compact-only")
    if args.probe and (args.suite != "smoke" or args.compact_only):
        parser.error("--probe is exclusive with --compact-only and requires --suite smoke")
    evidence = Evidence(args.suite, args.prepare)
    campaign = Campaign(evidence)
    try:
        if args.suite == "smoke":
            if args.probe == "hazard":
                campaign.hazard_probe()
            elif args.probe == "functional":
                evidence.command(["python3", "tests/selftest.py"])
                campaign.run("functional-first-configuration", scenarios.functional_program())
            elif args.probe == "synthesis":
                from synthesis import run_synthesis
                campaign.records.extend(run_synthesis(evidence, ((3, 3, 1, 4),)))
            elif args.probe == "compiler":
                from compiler import compile_benchmark
                _, _, symbols, elf = compile_benchmark(evidence, 5)
                campaign.records.append({
                    "name": "compiler-sha256-link-and-elf",
                    "elf": str(elf.relative_to(ROOT)),
                    "symbols": symbols,
                    "scope": "fresh RV64IM compilation, linking and ELF loading only; no RTL execution",
                })
            elif args.probe == "terminal":
                campaign.terminal_precision(compact=True)
            elif args.probe == "m-cartesian":
                campaign.m_cartesian()
            elif args.probe == "lw-sign":
                from mutations import run_mutations
                campaign.records.extend(run_mutations(campaign, names=("lw-sign",)))
            elif args.probe == "reset":
                campaign.run("reset-read-outstanding",
                             [lui(20, 0x40000), load("LD", 1, 20), ECALL],
                             (32, 3, 1, 4), delays=(0, 17, 17, 0, 17),
                             reset_outstanding=True)
            elif args.probe == "axi":
                campaign.run("axi-independent-channels",
                             [lui(1, 0x40000), i("ADDI", 2, 0, -1), store("SW", 2, 1, 4),
                              load("LW", 3, 1, 4), r("ADD", 4, 3, 2), EBREAK],
                             (32, 3, 1, 4), delays=(17, 1, 2, 2, 17), limit=1000,
                             expected_trap=(20, 3))
            elif args.compact_only:
                campaign.run("first-alu", [i("ADDI", 1, 0, 7), i("ADDI", 2, 1, -3),
                                          r("ADD", 3, 1, 2), ECALL, store("SD", 3, 0)],
                             (16, 3, 1, 4), simulator="icarus", expected_trap=(12, 11), limit=100)
            else:
                campaign.smoke()
        elif args.suite == "directed":
            campaign.directed()
        elif args.suite == "random":
            campaign.random(args.seed, args.min_retirements)
        elif args.suite == "synthesis":
            from synthesis import run_synthesis
            campaign.records.extend(run_synthesis(evidence))
        elif args.suite == "benchmarks":
            from benchmarks import run_benchmarks
            run_benchmarks(campaign)
        elif args.suite == "mutations":
            from mutations import run_mutations
            campaign.records.extend(run_mutations(campaign))
        elif args.suite == "portable":
            from portable import run_portable
            campaign.records.append(run_portable(campaign))
        else:
            raise ToolFailure(f"SUITE_NOT_IMPLEMENTED: {args.suite}; verification is not ready")
        receipt = evidence.finish("passed", advisory=args.prepare, repair_of=args.repair_of, **campaign.summary())
        print(json.dumps({"status": "passed", "advisory": args.prepare, "receipt": receipt}))
        return 0
    except (ComparisonFailure, ToolFailure, ValueError, OSError) as exc:
        receipt = evidence.finish("failed", error=str(exc), advisory=args.prepare, repair_of=args.repair_of, **campaign.summary())
        print(json.dumps({"status": "failed", "error": str(exc), "receipt": receipt}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
