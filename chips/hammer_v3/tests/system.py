"""Compiled, public-pin system experiments and independently measured coverage."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import random
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe
from axi_vectors import AxiScoreboard, READ_ERROR, WRITE_ERROR, vectors, write_vectors
from oracle import (ArchitecturalTrap, MASK64, SystemMachine, i_type, load_constant,
                    s_type, sv39)
from scenarios import branch


CONFIGURATIONS = (
    (1, 1, 1, 1, 1024, 1024), (4, 8, 4, 16, 4093, 4093),
    (8, 8, 64, 64, 16384, 8192), (16, 16, 16, 4, 4096, 4096),
)
SEEDS = (17, 29, 43)
TIMER_DEADLINE = 1000000
PARAMETERS = ("ITLB_ENTRIES", "DTLB_ENTRIES", "ICACHE_LINES", "DCACHE_LINES",
              "IMEM_WORDS", "DMEM_WORDS")

# Every bin is per configuration/seed, not the union of supplemental leaf results.
DIRECTED_REQUIREMENTS = {
    "selective-sfence-survivors-and-overlapping-walks": (
        "fence-all-all", "fence-va-all", "fence-all-asid", "fence-va-asid",
        "fence-zero-register-operand", "fence-global-survivor", "fence-inherited-global",
        "fence-selective-survivor", "overlapping-walk-context", "dirty-pte-remap",
        "fence-no-stale-refill", "tlb-hit-miss-replacement", "tlb-first-invalid-round-robin",
        "same-vpn-asids", "satp-drain-invalidation", "permission-hit-reevaluation"),
    "timer-preemption-and-interrupt-delegation": (
        "timer-preemption", "delegated-interrupt", "mret", "sret", "wfi"),
    "clint-host-and-legacy-mmio-preservation": (
        "clint", "host-byte-write", "host-halted-validation", "legacy-mmio"),
    "full-fault-matrix-and-faulting-side-effect-exclusion": (
        "invalid-v", "write-only", "reserved-upper", "nonleaf-u", "nonleaf-a", "nonleaf-d",
        "root-read-error", "middle-read-error", "bottom-read-error",
        "superpage-misalignment", "accessed-clear-repair", "dirty-clear-repair",
        "noncanonical", "page-edges", "root-high-rejection", "sum-mxr-mprv",
        "permissions-fetch-load-store-amo", "failed-sc-permission", "precise-fault-no-side-effect",
        "wrong-path-fault-suppression"),
    "complete-isa-csr-hazard-and-reservation-regression": (
        "rv64i-classes", "all-m-and-word", "all-amo-word-double", "lr-sc-success-failure",
        "coherent-reservation-interference", "forwarding-load-use", "csr-permissions",
        "branches-fences", "misalignment"),
    "top-level-plic-uart-and-peripheral-corner-integration": (
        "plic-all-ids-priorities-contexts", "plic-claims-completion-ownership",
        "plic-held-level", "uart-all-registers-dlab-triggers", "uart-all-serial-formats",
        "uart-divisors", "uart-timeout-errors-overrun", "uart-full-backpressure",
        "uart-loopback-modem", "uart-plic-integration", "exact-software-console"),
}


def coverage_closure(rows):
    identities = {(tuple(row["configuration"]), row["seed"]) for row in rows}
    expected = {(configuration, seed) for configuration in CONFIGURATIONS for seed in SEEDS}
    executed = (len(rows) == len(expected) and identities == expected and
                all(row.get("actual") is not None for row in rows))
    closure = {
        "twelve-seeded-integrated-system-runs": executed and all(
            row["actual"].get("translation_comparisons", 0) >= 1000 and
            row["actual"].get("context_round_trips", 0) >= 20 and
            row["actual"].get("coherent_exchanges", 0) >= 100 for row in rows),
        "external-executable-ram-and-instruction-coherence": executed and all(
            row.get("coherence", {}).get("code_observations", 0) >= 100 and
            row.get("coherence", {}).get("data_observations", 0) >= 100 for row in rows),
        "axi-burst-invalid-geometry-and-external-errors": executed and all(
            row.get("axi", {}).get("compared_transactions", 0) == row.get("required_axi_transactions", -1)
            and row.get("memory", {}).get("read_errors", 0) > 0
            and row.get("memory", {}).get("write_errors", 0) > 0 for row in rows),
    }
    closure.update({name: executed and all(
        all(row.get("directed_bins", {}).get(item, 0) > 0 for item in requirements)
        for row in rows) for name, requirements in DIRECTED_REQUIREMENTS.items()})
    return closure


def csr(address, source, rd=0, operation=1):
    return (address << 20) | (source << 15) | (operation << 12) | (rd << 7) | 0x73


def workload(seed, rounds=20, iterations=64):
    """Two genuine address spaces, an Svade handler, and external S/U code."""
    rng = random.Random(seed)
    image = {}
    metadata = {}

    def put(address, value, size=8):
        for byte in range(size):
            image[address + byte] = (value >> (byte * 8)) & 255

    def pte(address, target, flags):
        put(address, ((target >> 12) << 10) | flags)

    def emit(virtual, code):
        for index, word in enumerate(code):
            put(0x80000000 + virtual + index * 4, word, 4)

    satps = []
    for root, middle, leaf, physical, asid in (
            (0x80000000, 0x80004000, 0x80006000, 0x80060000, 1),
            (0x80001000, 0x80005000, 0x80007000, 0x80061000, 2)):
        satps.append((8 << 60) | (asid << 44) | (root >> 12))
        pte(root, 0x80002000, 1)
        pte(root + 8, middle, 1)
        pte(root + 16, 0x80000000, 0xD7)
        pte(root + 257 * 8, middle, 1)
        pte(middle, leaf, 1)
        pte(middle + 8, 0x80000000, 0xD7)
        pte(leaf + 24, physical, 0x97 if asid == 1 else 0xD7)
        put(physical, rng.getrandbits(48))
    pte(0x80002000, 0x80003000, 1)
    pte(0x80002008, 0x80000000, 0xC7)
    pte(0x80003000 + 16 * 8, 0x80010000, 0x4B)
    pte(0x80003000 + 17 * 8, 0x80011000, 0x5B)
    pte(0x80003000 + 18 * 8, 0x80012000, 0x5B)
    put(0x80062000, rng.getrandbits(64))

    boot = load_constant(5, 0x40000000) + load_constant(6, rng.getrandbits(64))
    boot += [s_type(3, 5, 6, 0), i_type(0x03, 7, 3, 5, 0),
             s_type(0, 5, 6, 3), i_type(0x03, 7, 4, 5, 3)]
    boot += load_constant(25, 0x200) + [csr(0x305, 25)]
    boot += load_constant(25, (1 << 7) | (1 << 5)) + [csr(0x304, 25)]
    boot += load_constant(25, 1 << 5) + [csr(0x303, 25)]
    boot += load_constant(25, 0x02004000) + load_constant(26, TIMER_DEADLINE)
    boot += [s_type(3, 25, 26, 0), i_type(0x03, 26, 3, 25, 0)]
    boot += load_constant(1, satps[0]) + [csr(0x180, 1)]
    boot += load_constant(2, (1 << 8) | (1 << 13)) + [csr(0x302, 2)]
    boot += load_constant(3, 1 << 11) + [csr(0x300, 3)]
    boot += load_constant(4, 0x10000) + [csr(0x341, 4), 0x30200073]
    if len(boot) > 128:
        raise AssertionError("system bootstrap exceeds compact host image")
    boot += [0x13] * (256 - len(boot))
    machine_handler = load_constant(25, 0x02004000) + load_constant(26, MASK64)
    machine_handler += [s_type(3, 25, 26, 0), i_type(0x13, 31, 0, 31, 1)]
    machine_handler += load_constant(26, 1 << 5) + [
        csr(0x344, 26, operation=2), 0x10500073, 0x30200073]
    boot[128:128 + len(machine_handler)] = machine_handler

    supervisor = load_constant(10, 0) + load_constant(11, rounds)
    supervisor += load_constant(12, satps[0]) + load_constant(13, satps[1])
    supervisor += load_constant(14, 0x11000) + load_constant(15, 0x10200)
    supervisor += [csr(0x105, 15), csr(0x141, 14), csr(0x100, 0), 0x10200073]
    if len(supervisor) > 128:
        raise AssertionError("system supervisor overlaps trap handler")
    emit(0x10000, supervisor)
    handler = [csr(0x142, 0, 20, 2), csr(0x141, 0, 21, 2),
               csr(0x143, 0, 22, 2), i_type(0x13, 23, 0, 0, 13)]
    handler += [branch(20, 23, 0, 0x10300 - (0x10200 + len(handler) * 4))]
    handler += load_constant(23, (1 << 63) | 5)
    handler += [branch(20, 23, 0, 0x10380 - (0x10200 + len(handler) * 4))]
    handler += [i_type(0x13, 10, 0, 10, 1), csr(0x180, 0, 15, 2)]
    handler += [branch(15, 12, 1, 12), csr(0x180, 13), 0x0080006F, csr(0x180, 12),
                0x12000073, csr(0x141, 14)]
    handler += [branch(10, 11, 5, 8), 0x10200073, 0x73]
    emit(0x10200, handler)
    repair = load_constant(23, 0x206018)
    repair += [i_type(0x03, 24, 3, 23, 0), i_type(0x13, 24, 6, 24, 0x40),
               s_type(3, 23, 24, 0), 0x12000073, 0x10200073]
    emit(0x10300, repair)
    emit(0x10380, [csr(0x104, 0), i_type(0x13, 31, 0, 31, 1), 0x10200073])
    user = load_constant(5, 0x40003000) + load_constant(7, iterations)
    user += load_constant(9, 1) + load_constant(16, 0xFFFFFFC040003000)
    user += load_constant(17, 0x80062000) + load_constant(28, 0x40262000)
    user += load_constant(27, 0x12000)
    loop = 0x11000 + len(user) * 4
    user += [i_type(0x03, 6, 3, 5, 0), i_type(0x13, 6, 0, 6, 1),
             s_type(3, 5, 6, 0),
             (9 << 20) | (5 << 15) | (3 << 12) | (8 << 7) | 0x2F,
             i_type(0x03, 19, 3, 16, 0), i_type(0x03, 18, 3, 17, 0),
             i_type(0x03, 19, 3, 28, 0), i_type(0x67, 30, 0, 27, 0),
             i_type(0x13, 7, 0, 7, -1)]
    user += [branch(7, 0, 1, loop - (0x11000 + len(user) * 4)), 0x73]
    emit(0x11000, user)
    emit(0x12000, [i_type(0x13, 29, 0, 29, 1), i_type(0x67, 0, 0, 30, 0)])
    metadata.update(rounds=rounds, iterations=iterations, user_loop=loop, satps=satps)
    return boot, image, metadata


class IntegratedMachine(SystemMachine):
    def __init__(self, words, image, dmem_words):
        super().__init__(words, {})
        self.memory = defaultdict(int, image)
        self.dmem_words = dmem_words
        self.checked_accesses = Counter()
        self.event_accesses = {}
        self.contexts = Counter()
        self.completed_round_trips = 0
        self.in_user = False
        self.csrs.update({0x303: 0, 0x304: 0, 0x344: 0})
        self.timer_compare = MASK64
        self.timer_interrupts = 0
        self.delegated_interrupts = 0
        self.clint_compares = 0

    def csr_read(self, address):
        if address == 0x104:
            return self.csrs[0x304] & self.csrs[0x303] & 0x222
        if address == 0x144:
            return self.csrs[0x344] & self.csrs[0x303]
        return super().csr_read(address)

    def csr_write(self, address, value):
        if address == 0x104:
            mask = self.csrs[0x303] & 0x222
            self.csrs[0x304] = (self.csrs[0x304] & ~mask) | (value & mask)
        elif address == 0x144:
            mask = self.csrs[0x303] & 2
            self.csrs[0x344] = (self.csrs[0x344] & ~mask) | (value & mask)
        else:
            super().csr_write(address, value)

    def read_memory(self, address, size):
        if 0x02004000 <= address and address + size <= 0x02004008:
            self.clint_compares += 1
            return (self.timer_compare >> (8 * (address - 0x02004000))) & ((1 << (8 * size)) - 1)
        return sum(self.memory[address + byte] << (8 * byte) for byte in range(size))

    def write_memory(self, address, size, value):
        if 0x02004000 <= address and address + size <= 0x02004008:
            shift = 8 * (address - 0x02004000)
            mask = ((1 << (size * 8)) - 1) << shift
            self.timer_compare = (self.timer_compare & ~mask) | ((value << shift) & mask)
        else:
            super().write_memory(address, size, value)

    def take_interrupt(self, cause, cycle):
        number = cause & 63
        delegated = bool(self.csrs[0x303] & (1 << number))
        target = 1 if delegated else 3
        enabled = (self.priv < target or self.priv == target and
                   self.csrs[0x300] & (1 << (1 if target == 1 else 3)))
        if not (cause >> 63 and enabled and self.csrs[0x304] & (1 << number)):
            raise AssertionError(f"SYSTEM_INTERRUPT_NOT_ENABLED cause={cause:x} cycle={cycle}")
        if number == 7:
            if self.priv != 0 or cycle < self.timer_compare + 3 or self.timer_interrupts:
                raise AssertionError(f"SYSTEM_TIMER_PREEMPTION cycle={cycle} cmp={self.timer_compare}")
            self.timer_interrupts += 1
        elif number == 5:
            if self.priv != 0 or not delegated or not self.csrs[0x344] & (1 << 5):
                raise AssertionError("SYSTEM_DELEGATED_INTERRUPT_NOT_PENDING")
            self.delegated_interrupts += 1
        else:
            raise AssertionError(f"SYSTEM_UNEXPECTED_INTERRUPT {cause:x}")
        self.event_accesses = {}
        return self.trap(cause, 0)

    def read_pte(self, address):
        if not (0x80000000 <= address <= 0x800FFFF8 or
                0x10000000 <= address <= 0x10000000 + 8 * self.dmem_words - 8):
            raise OSError("physical page-table read outside responding memory")
        return self.read_memory(address, 8)

    def physical(self, address, access):
        status, satp = self.csrs[0x300], self.csrs[0x180]
        result = sv39(address, access, self.priv, satp, status, self.read_pte)
        effective = ((status >> 11) & 3
                     if access != 0 and self.priv == 3 and status & (1 << 17) else self.priv)
        key = (address, access, self.priv, effective, satp, status)
        self.event_accesses[key] = result
        if result.fault:
            raise ArchitecturalTrap((12, 13, 15, 15)[access] if result.fault == "page"
                                    else (1, 5, 7, 7)[access], address)
        legal = (0x80000000 <= result.pa < 0x80100000 or
                 0 <= result.pa < len(self.words) * 4 if access == 0 else
                 0x80000000 <= result.pa < 0x80100000 or
                 0x10000000 <= result.pa < 0x10000000 + 8 * self.dmem_words or
                 0x02004000 <= result.pa < 0x02004008 or
                 0x40000000 <= result.pa < 0x40010000)
        if not legal:
            raise ArchitecturalTrap((1, 5, 7, 7)[access], address)
        return result.pa

    def fetch(self):
        physical = self.physical(self.pc, 0)
        if physical < len(self.words) * 4:
            return self.words[physical // 4]
        return self.read_memory(physical, 4)

    def step(self):
        self.event_accesses = {}
        return super().step()

    def accept_event(self, event):
        for key, result in self.event_accesses.items():
            address, access, _, effective, satp, _ = key
            mode = "Bare" if effective == 3 or satp >> 60 == 0 else "Sv39"
            self.checked_accesses["total"] += 1
            self.checked_accesses[f"access-{access}"] += 1
            self.checked_accesses[f"privilege-{effective}"] += 1
            self.checked_accesses[mode] += 1
            if mode == "Sv39":
                self.checked_accesses["upper" if address >> 63 else "lower"] += 1
                self.checked_accesses[f"leaf-{result.level}"] += int(not result.fault)
            if result.fault:
                self.checked_accesses[result.fault + "-fault"] += 1
        if event[0] == "R" and event[2] == 0x10200073 and self.priv == 0:
            self.in_user = True
        if event[0] == "T" and event[2] == 8:
            if not self.in_user:
                raise AssertionError("SYSTEM_CONTEXT user ECALL without checked SRET")
            self.contexts[(self.csrs[0x180] >> 44) & 65535] += 1
            self.completed_round_trips += 1
            self.in_user = False


def compare_retirement(line, expected, number):
    fields = line.split()
    values = tuple(int(field, 16) for field in fields[1:])
    if fields[0] != expected[0]:
        raise AssertionError(f"SYSTEM_EVENT event={number} expected={expected} observed={line}")
    if fields[0] == "T":
        if values != expected[1:]:
            raise AssertionError(f"SYSTEM_TRAP event={number} expected={expected} observed={line}")
        return
    if values[:6] != expected[1:7] or values[12] != expected[8]:
        raise AssertionError(f"SYSTEM_RETIRE event={number} expected={expected} observed={line}")
    memory = expected[7]
    if values[6] != int(memory is not None):
        raise AssertionError(f"SYSTEM_MEMORY_VALID event={number} expected={expected} observed={line}")
    if memory:
        write, address, mask, data, read = memory
        if values[7:9] != (write, address):
            raise AssertionError(f"SYSTEM_MEMORY event={number} expected={expected} observed={line}")
        if write and values[9:11] != (mask, data):
            raise AssertionError(f"SYSTEM_STORE event={number} expected={expected} observed={line}")
        if (not write or values[1] & 127 == 0x2F) and values[11] != read:
            raise AssertionError(f"SYSTEM_LOAD event={number} expected={expected} observed={line}")


def run_configuration(experiment, configuration, seeds=SEEDS, accelerator=False):
    configuration = tuple(configuration)
    experiment.run("version-verilator", ["verilator", "--version"])
    parameters = dict(zip(PARAMETERS, configuration))
    top = experiment.rtl_folder / "hammer_v3_top.sv"
    extra_driven = re.findall(r"\bs_acc_axi_\w+", top.read_text().split(");", 1)[0])
    probe.generate_top_wiring("hammer_v3_top", top, experiment.folder, configuration[5],
                              parameters=parameters, extra_driven=extra_driven if accelerator else (),
                              responding_memory=True)
    objects = experiment.folder / "compile-obj"
    records = []
    try:
        experiment.run("compile", [
            "verilator", "--binary", "--timing", "-j", "4", "-Wall", "-Wno-fatal",
            "--top-module", "top_probe", "--Mdir", experiment.relative(objects),
            "-o", "../simulation", "-I" + experiment.relative(experiment.folder), "-Itests",
            "-DSYSTEM_MEMORY", *(["-DSYSTEM_ACCEL"] if accelerator else []),
            "-GPROGRAM_WORDS=256", "-GCONTINUE_TRAPS=1", "-GMAX_CYCLES=5000000", "tests/top_probe.sv",
            *[str(p.relative_to(probe.ROOT)) for p in sorted(experiment.rtl_folder.glob("*.sv"))]])
        for seed in seeds:
            folder = experiment.folder / f"seed-{seed}"
            folder.mkdir()
            words, image, metadata = workload(seed)
            commands = vectors(seed, configuration[5]) if accelerator else []
            axi_path = folder / "axi.txt"
            write_vectors(axi_path, commands)
            (folder / "axi-cases.json").write_text(json.dumps(commands, indent=2) + "\n")
            (folder / "workload.json").write_text(json.dumps(metadata, indent=2) + "\n")
            program, external, trace = (folder / name for name in
                                        ("program.hex", "external.hex", "trace.txt"))
            program.write_text("".join(f"{word:08x}\n" for word in words))
            external.write_text("".join(f"{address:016x} " + f"{sum(image.get(address+b, 0) << (8*b) for b in range(8)):016x}\n"
                                       for address in sorted({p & ~7 for p in image})))
            output = experiment.run(f"seed-{seed}", [
                experiment.relative(experiment.folder / "simulation"),
                f"+program={experiment.relative(program)}", f"+external={experiment.relative(external)}",
                f"+trace={experiment.relative(trace)}", f"+seed={seed}",
                f"+axi={experiment.relative(axi_path)}",
                f"+read_error={READ_ERROR:x}", f"+write_error={WRITE_ERROR:x}"])
            model = IntegratedMachine(words, image, configuration[5])
            axi = AxiScoreboard(commands)
            events = 0
            accelerator_reads = accelerator_data_writes = accelerator_code_writes = 0
            observed_data = observed_code = progress = 0
            pending_data = pending_code = None
            last_admission = -1
            cycle = 0
            mret_comparisons = 0
            wfi_comparisons = 0
            for line in trace.read_text().splitlines():
                fields = line.split()
                if fields[0] == "K":
                    cycle = int(fields[1])
                    continue
                if fields[0] == "V":
                    axi.accept(fields)
                    continue
                if fields[0] == "N":
                    retired = int(fields[3])
                    if retired <= last_admission:
                        raise AssertionError(f"SYSTEM_CPU_STARVATION: {line}")
                    last_admission = retired
                    model.reservation = None
                    progress += 1
                    continue
                if fields[0] == "A":
                    address, value, _ = (int(field, 16) for field in fields[2:])
                    if fields[1] == "W":
                        model.write_memory(address, 8, value)
                        if address == 0x80062000:
                            if pending_data is not None:
                                raise AssertionError("SYSTEM_COHERENCE missing CPU data observation")
                            accelerator_data_writes += 1
                            pending_data = value
                        elif address == 0x80012000:
                            if pending_code is not None:
                                raise AssertionError("SYSTEM_COHERENCE missing CPU code observation")
                            accelerator_code_writes += 1
                            pending_code = value & 0xFFFFFFFF
                        else:
                            raise AssertionError(f"SYSTEM_ACCEL unexpected write: {line}")
                    else:
                        expected = model.read_memory(address, 8)
                        if value != expected:
                            raise AssertionError(f"SYSTEM_ACCEL_DIRTY_READ expected={expected:x} observed={line}")
                        accelerator_reads += 1
                    continue
                if fields[0] == "T" and int(fields[5], 16):
                    expected = model.take_interrupt(int(fields[2], 16), cycle)
                else:
                    expected = model.step()
                compare_retirement(line, expected, events)
                model.accept_event(expected)
                if expected[0] == "R":
                    mret_comparisons += int(expected[2] == 0x30200073)
                    wfi_comparisons += int(expected[2] == 0x10500073)
                    memory = expected[7]
                    if (pending_data is not None and memory and not memory[0] and
                            memory[1] in (0x80062000, 0x40262000) and memory[4] == pending_data):
                        observed_data += 1
                        pending_data = None
                    if expected[1] == 0x12000 and expected[2] == pending_code:
                        observed_code += 1
                        pending_code = None
                events += 1
            if (not model.stopped or model.completed_round_trips != metadata["rounds"] or
                    model.timer_interrupts != 1 or model.delegated_interrupts != 1):
                raise AssertionError("SYSTEM_CONTEXT_INCOMPLETE: terminal software/round trips missing")
            summary = re.search(r"MEMORY_SUMMARY reads=(\d+) writes=(\d+) lite_reads=(\d+) lite_writes=(\d+) stalls=(\d+) independent_aw_w=(\d+) read_errors=(\d+) write_errors=(\d+)", output)
            if not summary or min(int(summary[n]) for n in (1, 2, 5, 6)) == 0:
                raise AssertionError("SYSTEM_MEMORY_INCOMPLETE: external reads/writes/stalls/AW-W absent")
            counts = dict(model.checked_accesses)
            for item in ("total", "access-0", "access-1", "access-2", "access-3", "privilege-0",
                         "privilege-1", "privilege-3", "Bare", "Sv39", "lower", "upper",
                         "leaf-0", "leaf-1", "leaf-2", "page-fault"):
                if counts.get(item, 0) == 0:
                    raise AssertionError(f"SYSTEM_TRANSLATION_COVERAGE missing {item}")
            if counts["total"] < 1000 or set(model.contexts) != {1, 2}:
                raise AssertionError("SYSTEM_TRANSLATION_CONTEXT_THRESHOLDS")
            if accelerator and (
                    (accelerator_reads, accelerator_data_writes, accelerator_code_writes,
                     observed_data, observed_code, progress) != (100, 100, 100, 100, 100, 300) or
                    pending_data is not None or pending_code is not None):
                raise AssertionError(f"SYSTEM_COHERENCE_INCOMPLETE reads={accelerator_reads} "
                                     f"data={accelerator_data_writes}/{observed_data} "
                                     f"code={accelerator_code_writes}/{observed_code} progress={progress}")
            axi_result = axi.finish()
            host_summary = re.search(r"HOST_SUMMARY comparisons=(\d+) active_blocked=(\d+)", output)
            if not host_summary or tuple(map(int, host_summary.groups())) != (7, 4):
                raise AssertionError("SYSTEM_HOST_INCOMPLETE")
            record = {
                "configuration": list(configuration), "seed": seed, "status": "executed-partial",
                "actual": {"translation_comparisons": counts["total"],
                           "context_round_trips": model.completed_round_trips,
                           "coherent_exchanges": accelerator_reads},
                "coherence": {"data_observations": observed_data, "code_observations": observed_code,
                              "forward_progress_admissions": progress},
                "axi": axi_result,
                "required_axi_transactions": len(commands),
                "directed_bins": {
                    "accessed-clear-repair": model.trap_counts.get(13, 0),
                    "mret": mret_comparisons,
                    "wfi": wfi_comparisons,
                    "sret": model.user_returns,
                    "timer-preemption": model.timer_interrupts,
                    "delegated-interrupt": model.delegated_interrupts,
                    "legacy-mmio": min(int(summary[3]), int(summary[4])),
                    "clint": model.clint_compares,
                    "host-byte-write": int(host_summary[1]),
                    "host-halted-validation": int(host_summary[2]),
                },
                "translation_bins": counts, "context_asids": dict(model.contexts),
                "compared_events": events, "trap_counts": model.trap_counts,
                "memory": dict(zip(("reads", "writes", "lite_reads", "lite_writes", "stalls",
                                    "independent_aw_w", "read_errors", "write_errors"),
                                   map(int, summary.groups()))),
                "trace": experiment.relative(trace),
                "remaining": ([] if accelerator else ["coherence"]) +
                             ["selective-fences", "interrupts", "full-directed-matrix"],
            }
            records.append(record)
            experiment.receipt["system_runs"] = records
            experiment.receipt["assertions"].append({
                "id": "integrated-software-oracle", "passed": True, **record})
            experiment.persist()
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", type=int, choices=range(4), default=0)
    parser.add_argument("--seed", type=int, choices=SEEDS)
    parser.add_argument("--accelerator", action="store_true")
    parser.add_argument("--repair-of", help="Project-relative retained diagnostic being repaired")
    args = parser.parse_args()
    experiment = probe.Probe("verifier-integrated-system")
    if args.repair_of:
        prior = probe.ROOT / args.repair_of
        if not prior.is_file() or probe.ROOT not in prior.resolve().parents:
            raise ValueError("--repair-of must name an existing project-local receipt")
        experiment.receipt["repair_of"] = args.repair_of
        experiment.persist()
    try:
        run_configuration(experiment, CONFIGURATIONS[args.configuration],
                          (args.seed,) if args.seed else SEEDS, args.accelerator)
    except Exception as error:
        experiment.finish(f"{type(error).__name__}: {error}")
        print(str(error), file=sys.stderr)
        return 1
    experiment.finish()
    return 0


if __name__ == "__main__":
    sys.exit(main())
