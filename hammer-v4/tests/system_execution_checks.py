#!/usr/bin/env python3
"""Check ISA continuations through the clocked cache/PTW/fabric RAM path.

The initiation/commit slots below are diagnostic stimulus, NOT a prediction of
the V4 core pipeline. No DUT, Linux boot or complete UART oracle is claimed.
"""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import struct
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from architecture import signed
from rv64_reference import Machine, ReferencePlatform
from system_execution import Access, Fault, Instruction, architectural_state
from system_memory import AtomicRequest, MemoryExecution, TranslationRequest, Word
from system_oracle import Clock, Counter, MASK, Phase, SEEDS, canonical_json


def rejected(function, exception, marker):
    try:
        function()
    except exception as error:
        if marker not in str(error):
            raise AssertionError(f"Wrong rejection: {error}") from error
        return
    raise AssertionError(f"Missing rejection: {marker}")


def image():
    memory = bytearray(0x4000)
    root, middle, code, data = (0x80010000, 0x80011000, 0x80012000, 0x80013000)
    for address, pte in (
        (root, (middle >> 12) << 10 | 1),
        (middle + 2 * 8, (code >> 12) << 10 | 1),
        (middle + 4 * 8, (data >> 12) << 10 | 1),
        (code, (0x80200000 >> 12) << 10 | 0xDB),
        (data, (0x80300000 >> 12) << 10 | 0xD7),
    ):
        struct.pack_into("<Q", memory, address - root, pte)
    # lui x1,0x800; addi x2,x0,42; sb x2,1(x1); lbu x3,1(x1);
    # csrr x4,time; ecall. Expected values are hand-derived, not DUT output.
    code = struct.pack("<8I", 0x008000B7, 0x02A00113, 0x002080A3,
                       0x0010C183, 0xC0102273, 0x00000073, 0x13, 0x13)
    return (("tables", root, bytes(memory)), ("code", 0x80200000, code))


def integrated(seed):
    clock = Clock()
    memory = MemoryExecution(clock, seed, image(), cache_lines=4)
    platform = ReferencePlatform()
    machine = Machine(platform)
    machine.pc, machine.privilege = 0x400000, 0
    machine.csrs.update({
        0x180: (8 << 60) | (0x80010000 >> 12),
        0x306: 7, 0x106: 7, 0x302: 1 << 8, 0x105: 0x400100,
    })
    counter = Counter()
    commits, accesses, faults = [], [], []

    def begin(edge):
        instruction = Instruction(machine)
        handle(instruction, instruction.advance(), edge)

    def handle(instruction, operation, edge):
        if isinstance(operation, Access):
            if operation.kind in ("fetch", "load", "store"):
                translated = instruction.translation_request()
                before = architectural_state(machine)

                def received(reply):
                    if architectural_state(machine) != before:
                        raise AssertionError("An in-flight access published architectural state")
                    accesses.append((operation.kind, edge + 1, reply.edge, reply.data))
                    value = Fault(
                        {"fetch": 12, "load": 13, "store": 15}[operation.kind]
                        if reply.page_fault else
                        {"fetch": 1, "load": 5, "store": 7}[operation.kind],
                        operation.address,
                    ) if reply.error or reply.page_fault else reply.data
                    handle(instruction, instruction.reply(value), reply.edge)
                memory.ports[int(operation.kind != "fetch")].submit(
                    0, edge + 1, (translated, operation.width, operation.value), received)
            elif operation.kind == "csr":
                if operation.address != 0xC01:
                    raise AssertionError("Unexpected CSR in the fixed continuation workload")
                sample_edge = edge + 3

                def sample():
                    value = counter.sample(sample_edge)
                    accesses.append(("csr", sample_edge, sample_edge, value))
                    handle(instruction, instruction.reply(value), sample_edge)
                clock.schedule(sample_edge, Phase.SAMPLE, sample)
            else:
                raise AssertionError("Unexpected fence/operation in continuation workload")
            return

        def publish():
            machine.csrs[0xB00] = counter.sample(edge + 1)
            # A pending timer update during stalls must survive publication of
            # an ordinary instruction; replay cannot restore stale mip.
            machine.csrs[0x344] = 32
            result = instruction.publish()
            rejected(instruction.publish, AssertionError, "Cannot publish")
            if isinstance(result, Fault):
                faults.append((edge + 1, asdict(result)))
            else:
                commits.append((edge + 1, result.pc, result.instruction,
                                result.rd, result.value))
                clock.schedule(edge + 2, Phase.SAMPLE, lambda: begin(edge + 2))
        clock.schedule(edge + 1, Phase.UPDATE, publish)

    clock.schedule(0, Phase.SAMPLE, lambda: begin(0))
    clock.run(100000)
    if len(commits) != 5 or faults != [(faults[0][0], {"cause": 8, "tval": 0})] or \
            machine.registers[1:4] != [0x800000, 42, 42] or \
            machine.privilege != 1 or machine.pc != 0x400100 or \
            machine.csrs[0x141] != 0x400014 or machine.csrs[0x344] != 32:
        raise AssertionError("Scheduled ISA/load/store/trap comparison failed")
    csr = [item for item in accesses if item[0] == "csr"]
    if len(csr) != 1 or machine.registers[4] != csr[0][1] or \
            machine.registers[4] <= machine.commits or \
            machine.csrs[0xB00] != faults[0][0]:
        raise AssertionError("CSR sample used instruction count or publication overwrote clock")
    if memory.backing.ram.memory[0x300001] != 0:
        raise AssertionError("A write-back cache store incorrectly wrote external RAM")
    line = next(line for line in memory.dcache.lines
                if line.valid and line.base == 0x80300000)
    if not line.dirty or line.data[1] != 42:
        raise AssertionError("Architectural store did not update its dirty cache line")
    if memory.translation.walks != 2 or memory.translation.pte_reads != 6 or \
            memory.translation.hits != 6:
        raise AssertionError("Instructions/data did not traverse real scheduled Sv39 walks/hits")
    for port in (memory.backing.port, memory.backing.master, memory.icache.port,
                 memory.dcache.port, memory.instruction.port, memory.data.port,
                 memory.translation.walker, *memory.translation.ports, *memory.ports):
        if port.live or port.waiting or port.busy or port.accepted != port.completed:
            raise AssertionError("Scheduled memory work did not settle/conserve")
    return {
        "seed": seed, "commits": commits, "faults": faults,
        "accesses": accesses, "clock_callbacks": clock.callbacks,
        "pte_reads": memory.translation.pte_reads,
        "tlb_hits": memory.translation.hits,
        "axi_reads": memory.backing.ram.reads, "axi_writes": memory.backing.ram.writes,
        "data_cache_hits": memory.dcache.hits, "data_cache_misses": memory.dcache.misses,
    }


def competing_paths(seed):
    clock = Clock()
    memory = MemoryExecution(clock, seed, image(), cache_lines=1)
    satp = (8 << 60) | (0x80010000 >> 12)
    seen = []
    for port, address, access, width in (
        (0, 0x400000, "fetch", 4), (1, 0x800000, "load", 8),
    ):
        request = TranslationRequest(address, access, satp, 0, 0)
        memory.ports[port].submit(
            0, 0, (request, width, 0),
            lambda reply, p=port: seen.append((p, reply.edge, reply.data,
                                               reply.error, reply.page_fault)))
    clock.run(100000)
    if sorted((p, value, error, page) for p, _, value, error, page in seen) != [
        (0, 0x008000B7, False, False), (1, 0, False, False),
    ] or memory.translation.walks != 2 or memory.translation.pte_reads != 6:
        raise AssertionError("Concurrent instruction/data walk/fabric contention failed")
    return {"seed": seed, "responses": seen, "callbacks": clock.callbacks,
            "axi_reads": memory.backing.ram.reads}


def continuation_rejections():
    machine = Machine(ReferencePlatform())
    instruction = Instruction(machine)
    fetch = instruction.advance()
    if fetch != Access("fetch", 0, 4):
        raise AssertionError("Initial architectural operation is not the instruction fetch")
    rejected(instruction.advance, AssertionError, "pending reply")
    rejected(lambda: instruction.reply(1 << 32), ValueError, "access width")
    # A rejected reply must leave the pending operation available for a repair.
    commit = instruction.reply(0x00100093)
    if machine.registers[1] != 0 or commit.value != 1:
        raise AssertionError("Continuation committed before publication")
    machine.csrs[0xB00] = 1000
    machine.csrs[0x344] = 32
    instruction.publish()
    if machine.registers[1] != 1 or machine.csrs[0xB00] != 1000 or machine.csrs[0x344] != 32:
        raise AssertionError("Architectural publication restored stale asynchronous state")
    rejected(lambda: instruction.reply(0), AssertionError, "without an outstanding")
    second = Instruction(machine)
    second.advance()
    second.reply(0x00100093)
    machine.registers[2] = 1
    rejected(second.publish, AssertionError, "state changed")
    atomic = Instruction(Machine(ReferencePlatform()))
    atomic.advance()
    if atomic.reply(0x100030AF) != Access("atomic", 0, 8, operation=2):
        raise AssertionError("LR did not suspend at its scheduled atomic operation")
    for address in (0xB00, 0x344):
        state = Machine(ReferencePlatform())
        pending = Instruction(state)
        pending.advance()
        operation = pending.reply(address << 20 | 0x1073)
        if operation != Access("csr", address):
            raise AssertionError("Counter/pending write did not await its CSR sample")
        state.csrs[address] = 1000 if address == 0xB00 else 32
        pending.reply(state.csrs[address])
        pending.publish()
        if state.csrs[address] != 0:
            raise AssertionError("A same-value CSR write lost its override/clear")
    return {"early_or_repeated_operations_rejected": 5,
            "atomic_dispatch_compared": True,
            "counter_and_pending_state_preserved": True,
            "same_value_csr_overrides_compared": 2}


def atomic_cases(seed):
    clock = Clock()
    cases, data = [], bytearray(512)
    operations = (0, 1, 4, 8, 12, 16, 20, 24, 28)
    for width in (4, 8):
        bits, mask = width * 8, (1 << (width * 8)) - 1
        old, operand = (1 << (bits - 1)) + 1, mask - 1
        expected = (
            (1 << (bits - 1)) - 1, operand, (1 << (bits - 1)) - 1,
            mask, 1 << (bits - 1), old, operand, old, operand,
        )
        for operation, updated in zip(operations, expected):
            offset = len(cases) * 8 + (4 if width == 4 else 0)
            data[offset:offset + width] = old.to_bytes(width, "little")
            cases.append((operation, width, offset, operand, signed(old, bits) & MASK,
                          updated, False))
    # SC cannot succeed without LR; width is part of the physical reservation.
    offset = 256
    data[offset:offset + 8] = (0x8877665580000001).to_bytes(8, "little")
    cases.extend([
        (3, 8, offset, 9, 1, 0x8877665580000001, False),
        (2, 4, offset, 0, 0xFFFFFFFF80000001, 0x80000001, False),
        (3, 8, offset, 9, 1, 0x8877665580000001, False),
        (2, 4, offset, 0, 0xFFFFFFFF80000001, 0x80000001, False),
        (3, 4, offset, 9, 0, 9, False),
        (3, 4, offset, 10, 1, 9, False),
        (2, 8, offset, 0, 0x8877665500000009, 0x8877665500000009, False),
        (3, 8, offset, 10, 1, 0x8877665500000009, True),
    ])
    code = []
    for operation, width, _, _, _, _, _ in cases:
        rs2 = 0 if operation == 2 else 2
        code.append(operation << 27 | rs2 << 20 | 1 << 15 |
                    (2 if width == 4 else 3) << 12 | 3 << 7 | 0x2F)
    images = image()[:1] + (
        ("atomics", 0x80200000, struct.pack("<" + "I" * len(code), *code)),
        ("data", 0x80300000, bytes(data)),
    )
    memory = MemoryExecution(clock, seed, images, cache_lines=4)
    machine = Machine(ReferencePlatform())
    machine.pc, machine.privilege = 0x400000, 0
    machine.csrs[0x180] = (8 << 60) | (0x80010000 >> 12)
    commits, requests = [], []

    def begin(index, edge):
        operation, width, offset, operand, _, _, invalidate = cases[index]
        machine.registers[1:3] = [0x800000 + offset, operand]
        if invalidate:
            memory.invalidate_reservation(edge + 1)
        instruction = Instruction(machine)
        handle(index, instruction, instruction.advance(), edge)

    def handle(index, instruction, access, edge):
        if isinstance(access, Access):
            before = architectural_state(machine)

            def received(reply):
                if architectural_state(machine) != before:
                    raise AssertionError("Atomic/fetch reply published state before retirement")
                if reply.error or reply.page_fault:
                    raise AssertionError("Legal atomic/fetch unexpectedly faulted")
                handle(index, instruction, instruction.reply(reply.data), reply.edge)
            if access.kind == "fetch":
                memory.ports[0].submit(
                    0, edge + 1, (instruction.translation_request(), 4, 0), received)
            elif access.kind == "atomic":
                requests.append((index, access.operation, access.width, edge + 1))
                memory.atomic.submit(
                    0, edge + 1, AtomicRequest(instruction.translation_request(), access.width,
                                              access.value, access.operation), received)
            else:
                raise AssertionError(f"Unscheduled atomic side effect: {access}")
            return
        if isinstance(access, Fault):
            raise AssertionError(f"Legal atomic instruction trapped: {access}")

        def publish():
            result = instruction.publish()
            operation, width, offset, operand, expected, updated, _ = cases[index]
            if result.value != expected or machine.registers[3] != expected:
                raise AssertionError(f"Atomic old/result mismatch case={index}: {result}")
            line = next((line for line in memory.dcache.lines
                         if line.valid and line.base == (0x80300000 + offset) & ~31), None)
            actual_bytes = line.data[offset % 32:offset % 32 + width] if line else \
                memory.backing.ram.memory[0x300000 + offset:0x300000 + offset + width]
            actual = int.from_bytes(actual_bytes, "little")
            if actual != updated:
                raise AssertionError(f"Atomic memory mismatch case={index}: {actual:#x} != {updated:#x}")
            expected_memory = ("load", 0x800000 + offset, width, expected) if operation == 2 else \
                (("store", 0x800000 + offset, width, operand & ((1 << (width * 8)) - 1))
                 if expected == 0 else None) if operation == 3 else \
                ("atomic", 0x800000 + offset, width, updated)
            if result.memory != expected_memory:
                raise AssertionError(f"Atomic architectural event mismatch case={index}: {result}")
            commits.append((index, edge + 1, result.value, actual))
            if index + 1 < len(cases):
                clock.schedule(edge + 2, Phase.SAMPLE, lambda: begin(index + 1, edge + 2))
        clock.schedule(edge + 1, Phase.UPDATE, publish)

    clock.schedule(0, Phase.SAMPLE, lambda: begin(0, 0))
    clock.run(100000)
    if len(commits) != len(cases) or len(requests) != len(cases) or \
            machine.commits != len(cases) or memory.reservation is not None:
        raise AssertionError("Missing or repeated atomic comparison/reservation invalidation")
    return {"seed": seed, "atomic_instructions_compared": len(commits), "commits": commits,
            "requests": requests, "callbacks": clock.callbacks,
            "scope": "scheduled ISA/RAM atomic integration, not core timing or Linux"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    began = time.monotonic()
    results = [integrated(seed) for seed in SEEDS]
    concurrent = [competing_paths(seed) for seed in SEEDS]
    atomics = [atomic_cases(seed) for seed in SEEDS]
    rejections = continuation_rejections()
    if len({tuple(record["accesses"]) for record in results}) == 1:
        raise AssertionError("All seeded memory access schedules were identical")
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "ISA continuation/cache/PTW/fabric integration; not core pipeline or Linux acceptance",
        "dut_execution": False, "full_system_timed_oracle": False,
        "sequential": results, "concurrent": concurrent, "rejections": rejections,
        "atomics": atomics,
        "seconds": time.monotonic() - began,
    }))
    print("COMPARED scheduled architectural continuations/atomics/cache/PTW/fabric "
          "for seeds 11/29/47; "
          "full_system_timed_oracle=false dut_execution=false", flush=True)


if __name__ == "__main__":
    main()
