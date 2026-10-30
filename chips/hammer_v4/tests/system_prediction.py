#!/usr/bin/env python3
"""Execute immutable images on the independent released-edge machine.

The normal CLI produces complete expectations or fails. The explicitly bounded
diagnostic mode produces a prefix with a different scope and no launch seal;
it cannot satisfy freeze_expectations or qualify a Linux boot.
"""

import argparse
from collections import deque
import hashlib
from pathlib import Path
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_core import Core
from system_oracle import (
    BOUND, Clock, Phase, Scenario, canonical_json, digest,
    load_images, project_file,
)
from system_protocol import (
    MAX_EVENT_BYTES, MAX_EVENTS, MAX_UART_BYTES, MIN_COVERAGE, PANIC_END,
    coverage_counts, event_line, selected_retirement,
)


ROOT = Path(__file__).resolve().parent.parent


class Coverage:
    """Observe actual architectural effects, including syscall return values."""

    def __init__(self, ranges):
        self.counts = dict.fromkeys(MIN_COVERAGE, 0)
        self.ranges = ranges
        self.syscall = None
        self.exited = False
        self.mapping = None
        self.written, self.read = set(), set()
        self.claimed = set()

    def trap(self, record, registers):
        _, cause, tval, target, interrupt = record
        if interrupt and cause == 5 and target == 1:
            self.counts["supervisor_timers"] += 1
        if not interrupt and cause in (13, 15) and self.mapping is not None and \
                self.mapping <= tval < self.mapping + 12288:
            self.counts["demand_faults"] += 1
        if not interrupt and cause == 8:
            if self.syscall is not None:
                raise AssertionError("Another U-mode ecall preceded the syscall return")
            self.syscall = (registers[17], registers[10], registers[12])
            if registers[17] == 93:
                if registers[10] != 0:
                    raise AssertionError("Independent /init exited with nonzero status")
                self.exited = True
                self.counts["syscall_exit"] += 1

    def retire(self, commit, registers, memory, before):
        counts = self.counts
        word = commit.instruction
        if word == 0x30200073 and commit.next_pc == 0x80200000:
            if commit.privilege != 3 or registers[10:12] != (0, 0x87E00000):
                raise AssertionError("Independent M-to-S handoff ABI")
            counts["mret_handoff"] += 1
        if word & 127 == 0x73 and word >> 20 == 0x180 and word >> 12 & 7 and (
            word >> 12 & 3 == 1 or word >> 15 & 31
        ):
            operation = word >> 12 & 7
            rs1 = word >> 15 & 31
            source = rs1 if operation & 4 else before[rs1]
            old = commit.value
            value = source if operation & 3 == 1 else \
                old | source if operation & 3 == 2 else old & ~source
            if value >> 60 == 8:
                counts["satp_sv39"] += 1
        if word & 0xFE007FFF == 0x12000073:
            counts["sfence"] += 1
        if commit.privilege == 0:
            counts["user_retired"] += 1
        if word == 0x10200073 and commit.next_pc < 1 << 38:
            counts["sret_user"] += 1
            if self.syscall is not None:
                number, argument, length = self.syscall
                result = registers[10]
                if number == 64:
                    if argument != 1 or not 0 < result <= length:
                        raise AssertionError("Independent Linux write ABI/result")
                    counts["syscall_write"] += 1
                elif number == 160:
                    if result:
                        raise AssertionError("Independent Linux uname result")
                    counts["syscall_uname"] += 1
                elif number == 172:
                    if result != 1:
                        raise AssertionError("Independent Linux PID-1 getpid result")
                    counts["syscall_getpid"] += 1
                elif number == 222:
                    if result >= (1 << 64) - 4095 or result & 4095:
                        raise AssertionError("Independent anonymous mmap result")
                    self.mapping = result
                elif number == 93:
                    raise AssertionError("Linux exit returned to user mode")
                self.syscall = None
        if not memory.valid:
            return
        if commit.privilege == 3 and memory.write and memory.address == 0x02004000:
            counts["timer_rearms"] += 1
        for item in self.ranges:
            if not item["start"] <= memory.address < item["end"]:
                continue
            if item["name"] == "fdt" and not memory.write:
                counts["fdt_reads"] += 1
            if item["name"] not in ("plic_m", "plic_s"):
                continue
            context = item["name"]
            if not memory.write and memory.rdata == 1:
                if context in self.claimed:
                    raise AssertionError("UART PLIC claim while already in service")
                self.claimed.add(context)
                counts["uart_plic_claims"] += 1
            elif memory.write and memory.wdata >> (8 * (memory.address & 7)) & \
                    0xFFFFFFFF == 1:
                if context not in self.claimed:
                    raise AssertionError("UART PLIC completion without a claim")
                self.claimed.remove(context)
                counts["uart_plic_completions"] += 1
        if commit.privilege != 0 or self.mapping is None or \
                not self.mapping <= memory.address < self.mapping + 12288:
            return
        offset = memory.address - self.mapping
        if offset & 7:
            raise AssertionError("Unaligned /init demand-page access")
        index = offset // 8
        expected = 0x48414D4D45525634 ^ (index * 0x102030405)
        if memory.write:
            if memory.mask != 255 or memory.wdata != expected:
                raise AssertionError("Independent /init demand-page stored data")
            self.written.add(index)
            counts["demand_stores"] += 1
        else:
            if index not in self.written or memory.rdata != expected:
                raise AssertionError("Independent /init demand-page retried read")
            self.read.add(index)
            counts["demand_loads"] += 1

    def complete(self):
        coverage_counts(self.counts)
        if self.written != set(range(1536)) or self.read != self.written:
            raise AssertionError("Incomplete independent demand-page word comparisons")
        if not self.exited or self.syscall is None or self.syscall[0] != 93:
            raise AssertionError("Missing independently executed PID-1 exit")
        if self.claimed:
            raise AssertionError("UART PLIC claim not completed")


class Prediction:
    def __init__(self, scenario, images, out, *, diagnostic_retirements=None):
        self.scenario, self.out = scenario, out
        self.diagnostic_retirements = diagnostic_retirements
        self.clock = Clock()
        self.ranges = [
            {"name": "fdt", "start": 0x87E00000, "end": 0x87E00000 + len(images[2][2])},
            {"name": "uart", "start": 0x10010000, "end": 0x10010008},
            {"name": "plic_m", "start": 0x0C200004, "end": 0x0C200008},
            {"name": "plic_s", "start": 0x0C201004, "end": 0x0C201008},
        ]
        self.coverage = Coverage(self.ranges)
        self.before = (0,) * 32
        self.events = self.event_bytes = self.uart_bytes = 0
        self.tail = deque(maxlen=len(PANIC_END))
        self.active = False
        self.line = 1
        self.final_edge = None
        self.core = Core(self.clock, scenario.seed, images, retirement=self.retire,
                         trap=self.trap, wire=self.wire, start_edge=scenario.start_edge)
        for edge, level in scenario.rx_transitions():
            self.core.platform.receiver.transition(edge, level)
        for drive in scenario.document()["external_irqs"]:
            self.core.platform.set_external(drive["edge"], drive["plic_sources"])

    def write_event(self, line):
        self.events += 1
        self.event_bytes += len(line)
        if self.events > MAX_EVENTS or self.event_bytes > MAX_EVENT_BYTES:
            raise AssertionError("Independent event prediction exceeds admitted storage bound")
        self.event_file.write(line)

    def retire(self, edge, ordinal, commit, registers, memory):
        self.coverage.retire(commit, registers, memory, self.before)
        self.before = registers
        if selected_retirement(ordinal, commit.instruction, commit.privilege,
                               memory.address, memory.valid, self.ranges):
            self.write_event(event_line(
                "R", edge, ordinal, commit.pc, commit.instruction, commit.next_pc,
                commit.privilege, int(bool(commit.rd)), commit.rd,
                commit.value if commit.rd else 0, memory.valid, memory.write,
                memory.address, memory.mask, memory.wdata, memory.rdata,
                registers[10], registers[11], registers[12], registers[17],
            ))
        if self.diagnostic_retirements is not None and \
                ordinal >= self.diagnostic_retirements and \
                self.core.platform.transmitter.temt and not self.active:
            self.final_edge = edge
            self.core.stopped = True

    def trap(self, edge, record, registers):
        pc, cause, tval, target, interrupt = record
        self.coverage.trap(record, registers)
        self.write_event(event_line("T", edge, pc, cause | (int(interrupt) << 63),
                                    tval, target, int(interrupt),
                                    registers[10], registers[11], registers[17]))

    def wire(self, edge, level):
        self.line = level
        if self.active or level:
            return
        self.active = True
        bits = []
        for bit in range(10):
            self.clock.schedule(edge + 8 + 16 * bit, Phase.OBSERVE,
                                lambda: bits.append(self.line))

        def finish():
            if len(bits) != 10 or bits[0] or not bits[9] or not self.line:
                raise AssertionError("Independent serialized console framing failure")
            byte = sum(value << bit for bit, value in enumerate(bits[1:9]))
            self.uart_bytes += 1
            if self.uart_bytes > MAX_UART_BYTES:
                raise AssertionError("Independent UART exceeds admitted storage bound")
            self.uart_file.write(bytes((byte,)))
            self.tail.append(byte)
            self.active = False
            if self.diagnostic_retirements is None and bytes(self.tail) == PANIC_END:
                last_rx = self.scenario.rx_first_edge + 2 * self.scenario.rx_spacing + 160
                if edge + 160 < last_rx:
                    raise AssertionError("PID-1 panic preceded admitted console input")
                self.coverage.complete()
                if not self.core.platform.transmitter.temt:
                    raise AssertionError("Expected complete panic has queued console bytes")
                self.final_edge = edge + 160
                self.core.stopped = True
        self.clock.schedule(edge + 160, Phase.OBSERVE, finish)

    def execute(self, limit):
        began, heartbeat = time.monotonic(), time.monotonic()
        with (self.out / "expected-events.txt").open("x", encoding="ascii") as events, (
            self.out / "expected-uart.bin"
        ).open("xb") as uart:
            self.event_file, self.uart_file = events, uart
            while self.final_edge is None and self.clock.edge < limit - 1:
                self.clock.run(min(limit - 1, self.clock.edge + 100000))
                if time.monotonic() - heartbeat >= 20:
                    print(f"ORACLE_PROGRESS seed={self.scenario.seed} edge={self.clock.edge} "
                          f"retired={self.core.machine.commits} uart_bytes={self.uart_bytes} "
                          f"pc={self.core.machine.pc:x} "
                          f"seconds={time.monotonic() - began:.3f}", flush=True)
                    heartbeat = time.monotonic()
            if self.final_edge is None:
                raise AssertionError(
                    f"Independent workload not complete at edge {limit - 1}; "
                    f"pc={self.core.machine.pc:#x} retired={self.core.machine.commits} "
                    f"uart_bytes={self.uart_bytes}; recent={list(self.core.recent)}"
                )
        return {
            "prediction_seconds": time.monotonic() - began,
            "callbacks": self.clock.callbacks, "retired": self.core.machine.commits,
            "final_edge": self.final_edge, "events": self.events,
            "uart_bytes": self.uart_bytes, "coverage": self.coverage.counts,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--diagnostic-retirements", type=int)
    parser.add_argument("--diagnostic-edge-limit", type=int, default=BOUND)
    args = parser.parse_args(argv)
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    if not (ROOT / relative).resolve().is_relative_to(ROOT.resolve()) or any(
        (ROOT / Path(*relative.parts[:index])).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    ):
        parser.error("--out may not escape the project or contain symlinks")
    if args.diagnostic_retirements is not None and args.diagnostic_retirements <= 0 or \
            not 0 < args.diagnostic_edge_limit <= BOUND:
        parser.error("Invalid diagnostic bound")
    if args.diagnostic_retirements is None and args.diagnostic_edge_limit != BOUND:
        parser.error("Complete predictions retain the continuous 4294967296-edge bound")
    manifest_path = project_file(ROOT, args.manifest)
    scenario_path = project_file(ROOT, args.scenario)
    _, images = load_images(ROOT, args.manifest)
    scenario = Scenario.read(scenario_path)
    if dict(scenario.image_hashes) != {
        name: hashlib.sha256(data).hexdigest() for name, _, data in images
    }:
        raise AssertionError("Scenario and loaded image identities differ")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    prediction = Prediction(scenario, images, out,
                            diagnostic_retirements=args.diagnostic_retirements)
    result = {"scope": "incomplete-independent-prediction", "seed": scenario.seed,
              "bound": BOUND, "completed": False}
    try:
        result.update(prediction.execute(args.diagnostic_edge_limit))
        complete = args.diagnostic_retirements is None
        metadata = {
            "schema": 1,
            "scope": "independent-clocked-complete-linux" if complete else
                     "independent-clocked-prefix",
            "scenario_sha256": digest(scenario_path), "manifest_sha256": digest(manifest_path),
            "images": dict(scenario.image_hashes), "seed": scenario.seed, "bound": BOUND,
            "final_edge": result["final_edge"], "coverage": result["coverage"],
            "watches": prediction.ranges, "event_count": prediction.events,
        }
        for key, name in (("uart", "expected-uart.bin"), ("events", "expected-events.txt")):
            metadata[key] = {"path": name, "bytes": (out / name).stat().st_size,
                             "sha256": digest(out / name)}
        (out / "expectations.json").write_bytes(canonical_json(metadata))
        if not complete:
            controls = [
                scenario.seed, scenario.start_edge, scenario.rx_first_edge,
                scenario.rx_spacing, result["final_edge"], prediction.events,
                prediction.uart_bytes, len(prediction.ranges),
            ]
            (out / "control.txt").write_text(
                " ".join(map(str, controls)) + "\n" + "".join(
                    f"{item['name']} {item['start']} {item['end']}\n"
                    for item in prediction.ranges), encoding="ascii")
            (out / "counts.txt").write_text(
                f"{prediction.events} {prediction.uart_bytes}\n", encoding="ascii")
        result.update(scope=metadata["scope"], completed=True)
        print(f"ORACLE_GENERATED scope={metadata['scope']} seed={scenario.seed} "
              f"final_edge={prediction.final_edge} events={prediction.events} "
              f"uart_bytes={prediction.uart_bytes}", flush=True)
    except Exception as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (out / "prediction.json").write_bytes(canonical_json(result))


if __name__ == "__main__":
    main()
