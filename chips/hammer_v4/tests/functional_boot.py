#!/usr/bin/env python3
"""Diagnostic Linux execution in the untimed independent ISA model.

Output is NOT an admitted UART expectation. Functional instruction ticks, MMIO
transactions and immediate UART completion do not implement RTL timing or pin
framing. No observed DUT input is consumed by this interpreter.
"""

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rv64_reference import Machine, ReferencePlatform, install_trampoline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rx-at", type=int, default=40000000,
                        help="frozen functional-tick RX input; not RTL released edges")
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    if not 0 < args.rx_at < 100000000:
        parser.error("--rx-at must lie within the diagnostic functional-tick bound")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((ROOT / args.manifest).read_text())
    platform = ReferencePlatform()
    install_trampoline(platform)
    for name, address in (("fw_jump.bin", 0x80000000), ("Image", 0x80200000),
                          ("hammer-v4.dtb", 0x87E00000)):
        image = manifest["images"][name]
        path = ROOT / image["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != image["sha256"]:
            raise AssertionError(f"Image hash mismatch: {name}")
        platform.load_image(path, address)
    machine = Machine(platform)
    milestones, syscalls = {}, Counter()
    last_commits = deque(maxlen=32)
    last_traps = deque(maxlen=32)
    exited = False
    observed_uart = 0
    began = time.monotonic()
    bound = 100000000
    complete = False
    panic_end = (
        b"---[ end Kernel panic - not syncing: Attempted to kill init! "
        b"exitcode=0x00000000 ]---"
    )
    with (out / "events.log").open("w") as events:
        try:
            for step in range(bound):
                if step + 1 == args.rx_at:
                    platform.rx.extend(b"v4\n")
                    events.write(f"FROZEN_FUNCTIONAL_RX tick={step + 1}\n")
                commit = machine.step()
                for trap in machine.traps:
                    last_traps.append(trap)
                    pc, cause, tval, target, interrupt = trap
                    if not interrupt and cause == 8:
                        number = machine.registers[17]
                        syscalls[number] += 1
                        events.write(f"U_ECALL tick={platform.ticks} nr={number} "
                                     f"a0={machine.registers[10]:x}\n")
                        if number == 93:
                            if machine.registers[10] != 0:
                                raise AssertionError("Functional /init exit status")
                            exited = True
                    if not interrupt and cause in (13, 15) and target == 1:
                        milestones.setdefault("page_fault", platform.ticks)
                    if interrupt and cause == 5:
                        milestones["supervisor_timer_count"] = \
                            milestones.get("supervisor_timer_count", 0) + 1
                machine.traps.clear()
                if commit:
                    last_commits.append((commit.pc, commit.instruction, commit.next_pc,
                                         commit.privilege, commit.rd, commit.value))
                    if commit.instruction == 0x30200073 and commit.next_pc == 0x80200000:
                        if machine.registers[10:12] != [0, 0x87E00000]:
                            raise AssertionError("Functional firmware ABI")
                        milestones["kernel_handoff"] = platform.ticks
                    if commit.instruction & 0xFE007FFF == 0x12000073:
                        milestones.setdefault("sfence", platform.ticks)
                    if machine.csrs[0x180] >> 60 == 8:
                        milestones.setdefault("sv39", platform.ticks)
                    if commit.privilege == 0:
                        milestones.setdefault("user", platform.ticks)
                if len(platform.uart) != observed_uart:
                    observed_uart = len(platform.uart)
                    if b"HAMMER firmware fatal" in platform.uart or \
                            b"HAMMER /init: FAIL" in platform.uart:
                        raise AssertionError("Functional software reported a failure")
                    if b"Kernel panic - not syncing:" in platform.uart and not exited:
                        raise AssertionError("Functional Linux panicked before successful PID-1 exit")
                    if panic_end in platform.uart:
                        complete = True
                        break
                if step % 1000000 == 0:
                    print(f"FUNCTIONAL_PROGRESS ticks={platform.ticks} "
                          f"commits={machine.commits} pc={machine.pc:x} "
                          f"priv={machine.privilege} uart_bytes={len(platform.uart)} "
                          f"seconds={time.monotonic() - began:.3f}", flush=True)
                    events.flush()
            if not complete:
                raise AssertionError("Untimed diagnostic functional-tick bound exhausted")
            for number in (64, 93, 160, 172):
                if not syscalls[number]:
                    raise AssertionError(f"Missing functional syscall {number}")
            if not all(name in milestones for name in (
                "kernel_handoff", "sv39", "sfence", "user", "page_fault"
            )):
                raise AssertionError("Missing functional boot milestones")
        finally:
            (out / "functional-uart.bin").write_bytes(platform.uart)
            (out / "result.json").write_text(json.dumps({
                "diagnostic_only": True, "timed_full_system_oracle": False,
                "complete_pid1_panic": complete, "milestones": milestones,
                "syscall_counts": dict(syscalls), "functional_ticks": platform.ticks,
                "commits": machine.commits, "seconds": time.monotonic() - began,
                "uart_bytes": len(platform.uart),
                "uart_sha256": hashlib.sha256(platform.uart).hexdigest(),
                "frozen_functional_rx_tick": args.rx_at,
                "plic_claims": platform.plic_claims,
                "plic_completions": platform.plic_completions,
                "last_commits": list(last_commits), "last_traps": list(last_traps),
            }, indent=2) + "\n")
    print("Completed untimed functional Linux diagnostic; not an admitted UART oracle")


if __name__ == "__main__":
    main()
