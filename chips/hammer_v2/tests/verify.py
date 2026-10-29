#!/usr/bin/env python3
"""Portable verification entry point. Every invocation retains its own evidence."""

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rv64_model import Fault, Machine
from cache_model import compare_cache

ROOT = Path(__file__).resolve().parent.parent
SUITES = ("compatibility", "privileged", "atomic", "cache", "sensitivity", "synthesis", "portable")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def source_files(root=ROOT):
    paths = []
    for pattern in ("rtl/*.sv", "design/SPEC.md", "design/ARCHITECTURE.md",
                    "tests/*", "hammer_v1_reference/rtl/*.sv"):
        matched = sorted(p for p in root.glob(pattern) if p.is_file())
        if not matched:
            raise RuntimeError(f"empty required source selector: {pattern}")
        paths.extend(matched)
    return paths


class Run:
    def __init__(self, suite, preparation=False):
        self.started = time.monotonic()
        self.build_cache = {}
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        parent = ROOT / "evidence" / "preparation" if preparation else ROOT / "evidence"
        self.directory = parent / f"{suite}-{stamp}-{uuid.uuid4().hex[:8]}"
        self.directory.mkdir(parents=True, exist_ok=False)
        hashes = {}
        for source in source_files():
            rel = source.relative_to(ROOT)
            hashes[str(rel)] = hashlib.sha256(source.read_bytes()).hexdigest()
            target = self.directory / "sources" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.receipt = {
            "schema": 1, "suite": suite, "acceptance_evidence": not preparation,
            "argv": [sys.executable, *sys.argv], "cwd": ".",
            "start": now(), "end": None, "timeout_s": 2700,
            "source_sha256": hashes, "commands": [], "tool_versions": {},
            "coverage": {}, "comparisons": {}, "exit_status": None,
        }
        self.save()

    def relative(self, path):
        return str(Path(path).relative_to(ROOT))

    def save(self):
        (self.directory / "receipt.json").write_text(
            json.dumps(self.receipt, indent=2) + "\n")

    def command(self, label, argv, cwd=ROOT, timeout=3600, expect_exit=0):
        if time.monotonic() - self.started >= 2650:
            raise RuntimeError("check safeguard: 2700-second execution budget nearly exhausted")
        stdout = self.directory / f"{label}.stdout.txt"
        stderr = self.directory / f"{label}.stderr.txt"
        record = {"argv": [str(x) for x in argv], "cwd": self.relative(cwd),
                  "start": now(), "timeout_s": timeout,
                  "stdout": self.relative(stdout), "stderr": self.relative(stderr),
                  "exit_status": None, "timed_out": False, "expected_exit": expect_exit}
        self.receipt["commands"].append(record)
        self.save()
        begin = time.monotonic()
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.Popen([str(x) for x in argv], cwd=cwd,
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                code = process.returncode
            record.update(exit_status=code, end=now(), duration_s=time.monotonic() - begin)
            self.save()
        if code != expect_exit or record["timed_out"]:
            raise RuntimeError(f"{label}: exit={code}, timeout={record['timed_out']}; "
                               f"see {record['stdout']} and {record['stderr']}")
        return stdout

    def tools(self, names):
        flags = {"python3": ["--version"], "iverilog": ["-V"], "vvp": ["-V"],
                 "verilator": ["--version"], "yosys": ["-V"], "make": ["--version"],
                 "g++": ["--version"]}
        for name in names:
            if not shutil.which(name):
                raise RuntimeError(f"missing required executable: {name}; installation is not permitted")
            output = self.command(f"version-{name.replace('+', 'p')}", [name, *flags[name]])
            error_output = self.directory / f"version-{name.replace('+', 'p')}.stderr.txt"
            self.receipt["tool_versions"][name] = (
                output.read_text(errors="replace") + error_output.read_text(errors="replace")).strip()
        self.save()

    def finish(self, error=None):
        self.receipt.update(end=now(), duration_s=time.monotonic() - self.started,
                            exit_status=int(error is not None), failure=str(error) if error else None)
        self.save()


def read_events(path):
    formats = {
        1: ("QQIIIIQIIQIQQ", ("pc", "next_pc", "insn", "priv", "rd_we", "rd",
                            "rd_data", "mem_valid", "mem_write", "mem_addr",
                            "mem_wmask", "mem_wdata", "mem_rdata")),
        2: ("QQQII", ("pc", "cause", "tval", "target", "interrupt")),
        3: ("IIQ", ("imem", "address", "data")),
        4: ("IQ", ("reg", "data")),
        5: ("IQ", ("flags", "pc")),
        6: ("I", ("retirements",)),
        7: ("II", ("meip", "seip")),
    }
    with path.open("rb") as stream:
        while header := stream.read(12):
            if len(header) != 12:
                raise AssertionError("truncated event header")
            kind, edge = struct.unpack("<IQ", header)
            if kind not in formats:
                raise AssertionError(f"unknown binary event kind {kind}")
            fmt, fields = formats[kind]
            size = struct.calcsize("<" + fmt)
            payload = stream.read(size)
            if len(payload) != size:
                raise AssertionError(f"truncated event {kind}")
            yield kind, edge, dict(zip(fields, struct.unpack("<" + fmt, payload)))


def compare_top(run, path, program, dwords, legacy=True, reference=False):
    model = Machine(program, dwords)
    counts = {"retirements": 0, "traps": 0, "registers": 0, "memory_beats": 0,
              "host_initial_reads": 0, "ex_mem_forward": 0, "mem_wb_forward": 0,
              "load_use": 0, "muldiv_stall": 0}
    counts["timer_interrupts"] = 0
    counts["returns"] = 0
    counts["trap_causes"] = {}
    counts["privileges"] = {}
    counts["interrupt_sequence"] = []
    counts["external_input_changes"] = 0
    counts["retire_pc_hits"] = {}
    complete = False
    stopped = False
    for kind, edge, event in read_events(path):
        if kind == 1:
            if stopped:
                raise AssertionError("retirement after terminal trap")
            try:
                expected = dataclasses.asdict(model.step(edge))
            except Fault as fault:
                raise AssertionError(f"edge {edge}: DUT retired faulting instruction at "
                                     f"{model.pc:#x}: {fault}") from fault
            for name, value in expected.items():
                if event[name] != value:
                    raise AssertionError(f"edge {edge}, pc={expected['pc']:#x}, "
                                         f"insn={expected['insn']:08x}: {name} "
                                         f"expected={value:#x}, observed={event[name]:#x}")
            counts["retirements"] += 1
            pc_key = str(event["pc"])
            counts["retire_pc_hits"][pc_key] = counts["retire_pc_hits"].get(pc_key, 0) + 1
            privilege = str(event["priv"])
            counts["privileges"][privilege] = counts["privileges"].get(privilege, 0) + 1
            counts["returns"] += int(event["insn"] in (0x30200073, 0x10200073))
        elif kind == 2:
            if stopped:
                raise AssertionError("duplicate terminal trap event")
            if event["interrupt"]:
                cause = model.eligible_interrupt(edge)
                if cause is None:
                    raise AssertionError(f"edge {edge}: interrupt while masked/not pending: {event}")
                expected = model.trap(Fault(cause, 0), interrupt=True)
                counts["timer_interrupts"] += int(cause == 7)
                counts["interrupt_sequence"].append([cause, expected[3]])
            else:
                try:
                    next_event = model.step(edge)
                except Fault as fault:
                    expected = model.trap(fault)
                else:
                    raise AssertionError(f"unexpected DUT trap {event}; next expected retirement {next_event}")
            actual = tuple(event[x] for x in ("pc", "cause", "tval", "target", "interrupt"))
            mismatch = actual[:2] != expected[:2] if reference else actual != expected
            if mismatch:
                raise AssertionError(f"trap expected={expected}, observed={actual}")
            stopped = legacy or event["cause"] == 3
            counts["traps"] += 1
            cause = str(event["cause"])
            counts["trap_causes"][cause] = counts["trap_causes"].get(cause, 0) + 1
        elif kind == 3:
            if event["imem"]:
                expected = program[event["address"] // 4]
            elif stopped:
                off = event["address"]
                expected = int.from_bytes(model.memory[off:off + 8], "little")
                counts["memory_beats"] += 1
            else:
                expected = 0
                counts["host_initial_reads"] += 1
            if event["data"] != expected:
                raise AssertionError(f"host read {event['address']:#x}: "
                                     f"expected={expected:#x}, observed={event['data']:#x}")
        elif kind == 4:
            expected = model.regs[event["reg"]]
            if event["data"] != expected:
                raise AssertionError(f"debug x{event['reg']}: expected={expected:#x}, observed={event['data']:#x}")
            counts["registers"] += 1
        elif kind == 5:
            flags = event["flags"]
            counts["load_use"] += int(bool(flags & 1))
            counts["muldiv_stall"] += int(bool(flags & 4))
            if flags & 8:
                sels = ((flags >> 4) & 3, (flags >> 6) & 3, (flags >> 8) & 3)
                counts["ex_mem_forward"] += int(2 in sels)
                counts["mem_wb_forward"] += int(1 in sels)
        elif kind == 6:
            if event["retirements"] != counts["retirements"]:
                raise AssertionError("bridge/model event conservation failure")
            complete = True
        elif kind == 7:
            if event["meip"] not in (0, 1) or event["seip"] not in (0, 1):
                raise AssertionError(f"invalid external interrupt input event: {event}")
            model.external_pending = (event["meip"] << 11) | (event["seip"] << 9)
            counts["external_input_changes"] += 1
    if not complete or counts["registers"] != 32 or counts["memory_beats"] != dwords:
        raise AssertionError(f"incomplete public comparison: {counts}, complete={complete}")
    if not counts["retirements"] or not counts["traps"]:
        raise AssertionError(f"missing architectural comparisons: {counts}")
    return counts


def ri(rd, rs1, imm, f3=0, op=0x13):
    return ((imm & 4095) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op


def rr(rd, rs1, rs2, f3=0, f7=0, op=0x33):
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op


def store(rs1, rs2, offset=0, f3=3):
    imm = offset & 4095
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 31) << 7) | 0x23


def branch(rs1, rs2, offset, f3=0):
    imm = offset & 8191
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 63) << 25) | (
        rs2 << 20) | (rs1 << 15) | (f3 << 12) | (((imm >> 1) & 15) << 8) | (
        ((imm >> 11) & 1) << 7) | 0x63


def smoke_program():
    return [
        ri(1, 0, 7), ri(1, 1, 9), rr(2, 1, 1), ri(3, 2, -1),
        0x10000237, store(4, 3), ri(5, 4, 0, 3, 3), rr(6, 5, 3),
        rr(7, 6, 3, 0, 1), rr(8, 7, 1, 4, 1),
        rr(9, 7, 1, 6, 1), ri(10, 0, -1), rr(11, 10, 1, 1),
        rr(12, 10, 1, 5, 0x20), ri(13, 10, 0, 0, 0x1B),
        0x34001773,  # CSRRW x14,mscratch,x0
        0x300027F3,  # CSRRS x15,mstatus,x0
        0x0000000F, 0x00100073,
    ]


def constant(rd, value):
    value &= (1 << 64) - 1
    digits = []
    while value:
        digits.append(value & 2047)
        value >>= 11
    if not digits:
        return [ri(rd, 0, 0)]
    code = [ri(rd, 0, digits.pop())]
    while digits:
        code.extend((ri(rd, rd, 11, 1), ri(rd, rd, digits.pop())))
    return code


def integer_program(seed=17, count=2000, looped=False):
    rng = random.Random(seed)
    code = []
    boundaries = (0, 1, (1 << 64) - 1, 1 << 63, (1 << 63) - 1,
                  1 << 31, (1 << 32) - 1, 63)
    for rd, value in enumerate(boundaries, 1):
        code.extend(constant(rd, value))
    if looped:
        body_count = min(80, count)
        if count % body_count:
            raise AssertionError("looped random count must be a multiple of body length")
        code.append(ri(30, 0, count // body_count))
        body_start = len(code)
    else:
        body_count = count
    for _ in range(body_count):
        word = rng.choice((False, True))
        rd, a, b = (rng.randrange(1, 30 if looped else 32) for _ in range(3))
        kind = rng.randrange(4)
        if kind == 0:
            f3 = rng.choice((0, 1, 5) if word else tuple(range(8)))
            f7 = rng.choice((0, 32)) if f3 in (0, 5) else 0
            code.append(rr(rd, a, b, f3, f7, 0x3B if word else 0x33))
        elif kind == 1:
            f3 = rng.choice((0, 4, 5, 6, 7) if word else tuple(range(8)))
            code.append(rr(rd, a, b, f3, 1, 0x3B if word else 0x33))
        elif kind == 2:
            f3 = rng.choice((0, 1, 5) if word else tuple(range(8)))
            imm = rng.randrange(-2048, 2048)
            if f3 in (1, 5):
                imm = rng.randrange(32 if word else 64)
                if f3 == 5 and rng.randrange(2):
                    imm |= 0x400
            code.append(ri(rd, a, imm, f3, 0x1B if word else 0x13))
        else:
            code.append(ri(rd, 0, rng.randrange(-2048, 2048)))
    if looped:
        code.append(ri(30, 30, -1))
        code.append(branch(30, 0, (body_start - len(code)) * 4, 1))
    code.append(0x00100073)
    return code


def atomic_program():
    code = [0x10000A37]  # x20 = RAM_BASE
    pairs = ((0, 0), (0, 1), (-1, 1), (1, -1), (1 << 63, -1),
             ((1 << 63) - 1, 1 << 63), (1 << 31, (1 << 31) - 1),
             ((1 << 32) - 1, 1 << 32))
    for width in (2, 3):
        for op in (0, 1, 4, 8, 12, 16, 20, 24, 28):
            for index, (old, rhs) in enumerate(pairs):
                code.extend(constant(1, old))
                code.extend(constant(2, rhs))
                code.append(store(20, 1))
                code.append((op << 27) | ((index & 3) << 25) | (2 << 20) |
                            (20 << 15) | (width << 12) | (3 << 7) | 0x2F)
                code.append(ri(4, 20, 0, 3, 3))
        for index in range(8):
            code.extend(constant(2, index - 4))
            code.extend((
                (2 << 27) | ((index & 3) << 25) | (20 << 15) |
                (width << 12) | (5 << 7) | 0x2F,
                (3 << 27) | ((index & 3) << 25) | (2 << 20) | (20 << 15) |
                (width << 12) | (6 << 7) | 0x2F,
                (3 << 27) | (2 << 20) | (20 << 15) |
                (width << 12) | (7 << 7) | 0x2F,
            ))
    code.extend((0x0000000F, 0x00100073))
    return code


def csr_insn(address, rd, rs1, f3=1):
    return (address << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x73


def privilege_program():
    code = [
        ri(1, 0, 1), ri(1, 1, 11, 1), csr_insn(0x300, 0, 1),
        ri(2, 0, 32), csr_insn(0x341, 0, 2), 0x30200073,
        0x00100073, 0x00100073,
        csr_insn(0x100, 3, 0, 2), ri(2, 0, 64), csr_insn(0x141, 0, 2),
        0x10200073, 0x00100073, 0x00100073, 0x00100073, 0x00100073,
        ri(4, 0, 99), 0x00000073,
    ]
    return code


def memory_control_program(seed=17):
    rng = random.Random(seed)
    code = [0x10000A37]
    for iteration in range(160):
        size = iteration % 4
        offset = (rng.randrange(16) * 32 + (iteration & 7)) & ~((1 << size) - 1)
        code.extend(constant(1, rng.getrandbits(64)))
        code.extend((store(20, 1, offset, size), ri(2, 20, offset, size, 3),
                     rr(3, 1, 2), ri(4, 20, offset, (size + 4) if size < 3 else 3, 3)))
        code.extend((ri(5, 0, iteration & 7), ri(6, 0, (iteration + 1) & 7)))
        f3 = (0, 1, 4, 5, 6, 7)[iteration % 6]
        code.extend((branch(5, 6, 12, f3), ri(7, 7, 1), store(20, 7, 504)))
        if iteration % 9 == 0:
            code.append(0x0000000F)
    code.extend((ri(8, 0, 40), ri(9, 9, 1), ri(8, 8, -1), branch(8, 0, -8, 1),
                 0x0000100F, 0x00100073))
    return code


def timer_program():
    code = [
        0x02004A37, ri(1, 0, 512), csr_insn(0x305, 0, 1),
        ri(1, 0, 128), csr_insn(0x304, 0, 1),
        ri(1, 0, 8), csr_insn(0x300, 0, 1),
        ri(21, 0, 0), ri(23, 0, 3),
        csr_insn(0xC01, 1, 0, 2), ri(1, 1, 400), store(20, 1),
        ri(22, 22, 1), branch(21, 23, -4, 4),
        csr_insn(0x304, 0, 0), 0x00100073,
    ]
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x342, 10, 0, 2),
                 csr_insn(0xC01, 1, 0, 2), ri(1, 1, 400),
                 store(20, 1), ri(21, 21, 1), 0x30200073))
    return code


def fault_program():
    """Recover through an architectural handler; compare every trap and return."""
    code = [*constant(1, 512), csr_insn(0x305, 0, 1),
            0x10000A37, ri(2, 0, 37),
            0xFFFFFFFF, csr_insn(0xFFF, 3, 0, 2),
            csr_insn(0xF11, 3, 2), 0x00000073,
            ri(3, 20, 1, 3, 3), store(20, 2, 1),
            ri(3, 0, 0, 3, 3), store(0, 2),
            # An SC without a reservation still must check its address.
            (3 << 27) | (2 << 20) | (0 << 15) | (3 << 12) | (3 << 7) | 0x2F,
            (2 << 27) | (20 << 15) | (3 << 12) | (3 << 7) | 0x2F,
            0xFFFFFFFF,
            (3 << 27) | (2 << 20) | (20 << 15) | (3 << 12) | (3 << 7) | 0x2F,
            # Move to S with TVM/TW/TSR set.
            *constant(1, (1 << 11) | (1 << 20) | (1 << 21) | (1 << 22)),
            csr_insn(0x300, 0, 1)]
    s_jump = len(code)
    code.extend((0, csr_insn(0x341, 0, 1), 0x30200073))
    s_pc = len(code) * 4
    code[s_jump] = ri(1, 0, s_pc)
    code.extend((csr_insn(0x300, 3, 0, 2), csr_insn(0x180, 3, 0, 2),
                 0x12000073, 0x10500073, 0x10200073,
                 csr_insn(0xC00, 3, 0, 2), 0x00000073,
                 # S may clear SPP and return to U.
                 csr_insn(0x100, 0, 0)))
    # TSR must be cleared in M: ECALL handler clears it for this transition.
    code.extend((ri(25, 0, 1), 0x00000073))
    u_jump = len(code)
    code.extend((0, csr_insn(0x141, 0, 1), 0x10200073))
    u_pc = len(code) * 4
    code[u_jump] = ri(1, 0, u_pc)
    code.extend((csr_insn(0x100, 3, 0, 2), 0x10200073, 0x12000073,
                 csr_insn(0xC01, 3, 0, 2), 0x00000073,
                 ri(4, 20, 0, 3, 3), 0x00100073))
    if len(code) > 128:
        raise AssertionError("fault program overlaps handler")
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x342, 28, 0, 2), csr_insn(0x343, 29, 0, 2),
                 csr_insn(0x341, 30, 0, 2), ri(30, 30, 4),
                 csr_insn(0x341, 0, 30),
                 branch(25, 0, 16), *constant(31, 1 << 22),
                 csr_insn(0x300, 0, 31, 3), 0x30200073))
    # Branch target is generated from the final handler layout, not assumed
    # from the number of instructions needed to construct the status mask.
    handler_branch = 128 + 5
    code[handler_branch] = branch(25, 0, (len(code) - 1 - handler_branch) * 4)
    return code


def interrupt_program():
    code = [0x02000A37, 0x02004AB7,
            ri(1, 0, 512), csr_insn(0x305, 0, 1),
            ri(1, 0, 1), store(20, 1, f3=2), store(21, 0),
            ri(1, 0, 34), csr_insn(0x344, 0, 1),
            *constant(1, 0xAAA), csr_insn(0x304, 0, 1),
            ri(22, 0, 0), ri(23, 0, 6), ri(1, 0, 8),
            csr_insn(0x300, 0, 1)]
    trigger_pc = (len(code) - 1) * 4
    code.extend((ri(24, 24, 1), branch(22, 23, -4, 4),
                 csr_insn(0x304, 0, 0), 0x00100073))
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x342, 25, 0, 2), ri(25, 25, 63, 7),
                 ri(26, 0, 1), rr(26, 26, 25, 1),
                 csr_insn(0x304, 0, 26, 3), ri(22, 22, 1), 0x30200073))
    return code, trigger_pc


def supervisor_timer_program():
    code = [ri(1, 0, 512), csr_insn(0x105, 0, 1),
            ri(1, 0, 32), csr_insn(0x303, 0, 1),
            csr_insn(0x304, 0, 1), csr_insn(0x344, 0, 1),
            *constant(1, (1 << 11) | 2), csr_insn(0x300, 0, 1),
            ri(1, 0, 96), csr_insn(0x341, 0, 1), 0x30200073]
    code.extend([0] * (24 - len(code)))
    code.extend((ri(4, 0, 7), 0x00100073))
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x142, 25, 0, 2), csr_insn(0x100, 26, 0, 2),
                 ri(1, 0, 32), csr_insn(0x104, 0, 1, 3),
                 ri(22, 22, 1), 0x10200073))
    return code


def top_case(run, name, program, simulator="iverilog", config=None, reference=False,
             source_root=ROOT, irq_trigger_pc=None):
    config = config or {"IMEM_WORDS": 256, "DMEM_WORDS": 128, "PRED_MODE": 0,
                        "BTB_ENTRIES": 16, "ICACHE_LINES": 4,
                        "DCACHE_LINES": 4, "LEGACY_TRAPS": 1}
    case = run.directory / name
    case.mkdir()
    if len(program) > config["IMEM_WORDS"]:
        raise AssertionError("program exceeds configured instruction storage")
    padded = [*program, *([0] * (config["IMEM_WORDS"] - len(program)))]
    (case / "program.hex").write_text("".join(f"{word:08x}\n" for word in padded))
    (case / "data.hex").write_text("0\n" * config["DMEM_WORDS"])
    source_dir = source_root / ("hammer_v1_reference/rtl" if reference else "rtl")
    rtl = [str(p.relative_to(ROOT)) for p in sorted(source_dir.glob("*.sv"))]
    key = (str(source_root), simulator, reference, tuple(sorted(config.items())))
    if key in run.build_cache:
        executable = run.build_cache[key]
    elif simulator == "iverilog":
        binary = case / "sim.vvp"
        argv = ["iverilog", "-g2012", "-Wall", "-s", "top_bridge", "-o", run.relative(binary)]
        argv += [f"-Ptop_bridge.{k}={v}" for k, v in config.items()]
        if reference:
            argv.append("-DPARENT_REFERENCE")
        argv += [*rtl, "tests/top_bridge.sv"]
        run.command(f"{name}-compile", argv)
        executable = ["vvp", run.relative(binary)]
    else:
        obj = case / "compile-obj"
        argv = ["verilator", "--binary", "--timing", "-Wno-fatal",
                "--top-module", "top_bridge", "--Mdir", run.relative(obj), "-j", "2"]
        argv += [f"-G{k}={v}" for k, v in config.items()]
        if reference:
            argv.append("-DPARENT_REFERENCE")
        run.command(f"{name}-compile", [*argv, *rtl, "tests/top_bridge.sv"])
        binary = case / "simulator"
        shutil.copyfile(obj / "Vtop_bridge", binary)
        binary.chmod(0o755)
        executable = [run.relative(binary)]
        shutil.rmtree(obj)
    run.build_cache[key] = executable
    event_path = case / "events.bin"
    extra_args = [] if irq_trigger_pc is None else [f"+irq_trigger_pc={irq_trigger_pc:x}"]
    run.command(f"{name}-simulate", [
        *executable, f"+program={run.relative(case / 'program.hex')}",
        f"+data={run.relative(case / 'data.hex')}",
        f"+events={run.relative(event_path)}", "+cycles=200000", *extra_args,
    ], timeout=60 if simulator == "iverilog" else 3600)
    counts = compare_top(run, event_path, padded, config["DMEM_WORDS"],
                         bool(config["LEGACY_TRAPS"]), reference=reference)
    run.receipt["comparisons"][name] = counts
    run.save()
    return counts


def parent_differential(run, name, program, config):
    if not config["LEGACY_TRAPS"]:
        raise AssertionError("parent differential requires the admitted legacy trap policy")
    counts = top_case(run, name + "-v2", program, "verilator", config)
    parent_counts = top_case(run, name + "-v1", program, "verilator", config, reference=True)

    def architectural(path):
        for kind, _, event in read_events(path):
            if kind in (1, 3, 4):
                if kind == 1:
                    event.pop("priv")
                yield kind, event
            elif kind == 2:
                yield kind, {key: event[key] for key in ("pc", "cause")}

    first = list(architectural(run.directory / (name + "-v2") / "events.bin"))
    second = list(architectural(run.directory / (name + "-v1") / "events.bin"))
    if first != second:
        mismatch = next((index for index, pair in enumerate(zip(first, second))
                         if pair[0] != pair[1]), min(len(first), len(second)))
        raise AssertionError(f"parent differential {name}: event {mismatch}, "
                             f"V2={first[mismatch:mismatch+1]}, V1={second[mismatch:mismatch+1]}")
    result = {"events_compared": len(first), "v2": counts, "v1": parent_counts,
              "oracle": "both independently compared before secondary event differential",
              "absent_v1_fields_excluded": ["retire_priv", "trap_tval",
                                           "trap_target_priv", "trap_interrupt"]}
    run.receipt["comparisons"][name + "-differential"] = result
    run.save()
    return result


def random_case(run, name, seed, config):
    looped = config["IMEM_WORDS"] < 2001
    program = integer_program(seed=seed, count=2000, looped=looped)
    body_length = 80 if looped else 2000
    body_start = len(program) - body_length - (3 if looped else 1)
    counts = top_case(run, name, program, "verilator", config)
    expected_visits = 25 if looped else 1
    compared = 0
    for pc in range(body_start * 4, (body_start + body_length) * 4, 4):
        actual = counts["retire_pc_hits"].get(str(pc), 0)
        if actual != expected_visits:
            raise AssertionError(f"{name}: randomized operation PC {pc:#x} "
                                 f"required {expected_visits} visits, observed {actual}")
        compared += actual
    if compared < 2000:
        raise AssertionError(f"{name}: randomized operation denominator not met: {compared}")
    counts.update(seed=seed, configuration=config, randomized_required=2000,
                  randomized_independently_compared=compared,
                  randomized_unique_instruction_sites=body_length)
    run.save()
    return counts


CONFIGS = {
    "A": (16384, 8192, 1, 16, 64, 64),
    "B": (256, 128, 0, 64, 16, 4),
    "C": (1, 1, 0, 1, 1, 1),
    "D": (33, 17, 1, 4, 4, 16),
}
PARAM_NAMES = ("IMEM_WORDS", "DMEM_WORDS", "PRED_MODE", "BTB_ENTRIES",
               "ICACHE_LINES", "DCACHE_LINES")


def configuration(name, legacy=0):
    return dict(zip((*PARAM_NAMES, "LEGACY_TRAPS"), (*CONFIGS[name], legacy)))


def synthesis_case(run, name, config):
    case = run.directory / name
    case.mkdir()
    rtl = [str(p.relative_to(ROOT)) for p in sorted((ROOT / "rtl").glob("*.sv"))]
    script = ["read_verilog -sv " + " ".join(rtl)]
    for parameter, value in config.items():
        script.append(f"chparam -set {parameter} {value} hammer_v2_top")
    hierarchy_path = case / "hierarchy.json"
    netlist_path = case / "netlist.json"
    script.extend((
        "hierarchy -check -top hammer_v2_top",
        "proc",
        "write_json " + run.relative(hierarchy_path),
        "opt_expr", "opt_clean", "check -assert",
        "memory -nomap", "opt_clean", "check -assert", "stat",
        "write_json " + run.relative(netlist_path),
    ))
    script_path = case / "synthesis.ys"
    script_path.write_text(";\n".join(script) + "\n")
    run.command(f"{name}-yosys", ["yosys", "-Q", "-T", "-s", run.relative(script_path)])
    pre = json.loads(hierarchy_path.read_text())["modules"]
    expected = {
        "hammer_v2_top": ("u_core", "u_icache", "u_dcache", "u_imem", "u_dmem", "u_clint", "u_axi"),
        "hammer_v2_core": ("u_decode", "u_regfile", "u_alu", "u_hazard", "u_predictor",
                           "u_muldiv", "u_csr", "u_trap", "u_atomic"),
    }

    def original_name(key, module):
        return str(module.get("attributes", {}).get("hdlname", key)).split()[0].lstrip("\\")

    for original, instances in expected.items():
        matches = [(key, module) for key, module in pre.items()
                   if original_name(key, module) == original]
        if len(matches) != 1:
            raise AssertionError(f"{name}: required module {original}: found {len(matches)}")
        for instance in instances:
            cells = matches[0][1]["cells"]
            if instance not in cells or not cells[instance]["connections"]:
                raise AssertionError(f"{name}: required connected instance {original}.{instance} absent")
            child = cells[instance]
            child_original = original_name(child["type"], pre[child["type"]])
            suffix = "axi_lite" if instance == "u_axi" else instance.removeprefix("u_")
            expected_child = "hammer_v2_" + suffix
            if child_original != expected_child:
                raise AssertionError(f"{name}: {instance} expected {expected_child}, got {child_original}")
    netlist = json.loads(netlist_path.read_text())["modules"]
    totals = {"latches": 0, "division": 0, "state_bits": 0, "memory_bits": 0,
              "modules": len(netlist), "cells": 0}
    module_state = {}
    for key, module in netlist.items():
        if int(module.get("attributes", {}).get("blackbox", "0"), 2):
            raise AssertionError(f"{name}: functional blackbox {key}")
        state = 0
        for cell in module["cells"].values():
            typ = cell["type"]
            totals["cells"] += 1
            totals["latches"] += int("latch" in typ.lower())
            totals["division"] += int(typ in ("$div", "$mod", "$divfloor", "$modfloor"))
            if "dff" in typ.lower():
                state += len(cell["connections"]["Q"])
            if typ.startswith("$mem"):
                parameters = cell["parameters"]
                width = int(parameters.get("WIDTH", "0"), 2)
                size = int(parameters.get("SIZE", "0"), 2)
                totals["memory_bits"] += width * size
                state += width * size
            if not typ.startswith("$") and typ not in netlist:
                raise AssertionError(f"{name}: unresolved nonprimitive {typ}")
        totals["state_bits"] += state
        module_state[original_name(key, module)] = (
            module_state.get(original_name(key, module), 0) + state)
    if totals["latches"] or totals["division"]:
        raise AssertionError(f"{name}: forbidden synthesis cells {totals}")
    if totals["state_bits"] < 1024:
        raise AssertionError(f"{name}: architectural state unexpectedly absent: {totals}")
    for original in ("hammer_v2_csr", "hammer_v2_regfile", "hammer_v2_cache", "hammer_v2_ram"):
        if module_state.get(original, 0) == 0:
            raise AssertionError(f"{name}: no substantive state retained in {original}")
    result = {"configuration": config, **totals, "state_by_original_module": module_state}
    (case / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    run.receipt["comparisons"][name] = result
    run.save()
    return result


def model_selfcheck():
    cases = (
        (rr(3, 1, 2), 0xFFFFFFFFFFFFFFFF, 1, 0),
        (rr(3, 1, 2, 0, 0, 0x3B), 0x7FFFFFFF, 1, 0xFFFFFFFF80000000),
        (rr(3, 1, 2, 4, 1), 0x8000000000000000, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000),
        (rr(3, 1, 2, 4, 1), 123, 0, 0xFFFFFFFFFFFFFFFF),
        (rr(3, 1, 2, 6, 1), 0xFFFFFFFFFFFFFFF9, 3, 0xFFFFFFFFFFFFFFFF),
        (rr(3, 1, 2, 5, 1, 0x3B), 0x80000000, 1, 0xFFFFFFFF80000000),
        (rr(3, 1, 2, 1, 1), 0xFFFFFFFFFFFFFFFF, 2, 0xFFFFFFFFFFFFFFFF),
        (rr(3, 1, 2, 2, 1), 0x8000000000000000, 2, 0xFFFFFFFFFFFFFFFF),
        (rr(3, 1, 2, 3, 1), 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE),
    )
    for insn, a, b, expected in cases:
        model = Machine([insn], 1)
        model.regs[1:3] = [a, b]
        event = model.step()
        if event.rd_data != expected:
            raise AssertionError(f"independent model analytical self-check: {insn:08x}, "
                                 f"expected={expected:#x}, observed={event.rd_data:#x}")
    return len(cases)


def portable_case(run):
    bundle = run.directory / "clean-copy"
    bundle.mkdir()
    copied = {}
    forbidden = (
        ("private absolute path", re.compile(r"(?:/(?:data|home|Users|root|tmp)/|[~]/)[^\s\"']+")),
        ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("GitHub credential", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
        ("AWS credential", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("local PCIe BDF", re.compile(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")),
    )
    for source in source_files():
        relative = source.relative_to(ROOT)
        if source.suffix not in (".sv", ".py", ".md"):
            raise AssertionError(f"unrecognized shipped verification dependency: {relative}")
        text = source.read_text()
        for label, pattern in forbidden:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                raise AssertionError(f"shipped-text audit: {label} in {relative}:{line}")
        target = bundle / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied[str(relative)] = hashlib.sha256(target.read_bytes()).hexdigest()
    if copied != run.receipt["source_sha256"]:
        raise AssertionError("clean-copy input binding differs from invocation snapshot")
    (run.directory / "clean-copy-inputs.json").write_text(json.dumps(copied, indent=2) + "\n")
    run.command("clean-copy-execute", [
        sys.executable, "-B", "tests/verify.py", "--suite", "portable",
        "--probe", "clean-copy-child",
    ], cwd=bundle)
    receipts = sorted((bundle / "evidence" / "preparation").glob("portable-clean-copy-child-*/receipt.json"))
    if len(receipts) != 1:
        raise AssertionError(f"expected exactly one clean-copy child receipt, got {len(receipts)}")
    result = json.loads(receipts[0].read_text())
    if result["exit_status"] != 0 or result["source_sha256"] != copied:
        raise AssertionError("clean-copy child failed or ran a different source set")
    required = ("compact-icarus", "compact-verilator", "C")
    if any(name not in result["comparisons"] for name in required):
        raise AssertionError("clean-copy child did not execute all required tools/comparisons")
    for name in required[:2]:
        if not result["comparisons"][name]["retirements"]:
            raise AssertionError(f"clean-copy child has no actual comparisons for {name}")
    run.receipt["comparisons"]["portable"] = {
        "files_audited_and_copied": len(copied),
        "child_receipt": run.relative(receipts[0]),
        "child_comparisons": result["comparisons"],
    }
    run.save()


def parameter_cases(run, compact=False):
    case = run.directory / "parameters"
    case.mkdir()
    rtl = [str(p.relative_to(ROOT)) for p in sorted((ROOT / "rtl").glob("*.sv"))]
    configurations = []
    for pred in (0, 1):
        for btb in (1, 4, 16, 64):
            for icache in (1, 4, 16, 64):
                for dcache in (1, 4, 16, 64):
                    configurations.append({
                        "IMEM_WORDS": 3, "DMEM_WORDS": 3, "PRED_MODE": pred,
                        "BTB_ENTRIES": btb, "ICACHE_LINES": icache,
                        "DCACHE_LINES": dcache, "LEGACY_TRAPS": 0,
                    })
    if compact:
        configurations = [configurations[0], configurations[-1]]
    configurations.extend((configuration("A"), configuration("C"), configuration("D")))
    invalid = {
        "IMEM_WORDS": (-1, 0, 16385),
        "DMEM_WORDS": (-1, 0, 8193),
        "PRED_MODE": (-1, 2),
        "BTB_ENTRIES": (-1, 0, 2, 3, 65, 128),
        "ICACHE_LINES": (-1, 0, 2, 3, 65, 128),
        "DCACHE_LINES": (-1, 0, 2, 3, 65, 128),
        "LEGACY_TRAPS": (-1, 2),
    }
    ledger = []

    def execute(config, label, illegal_parameter=None):
        binary = case / f"{label}.vvp"
        argv = ["iverilog", "-g2012", "-Wall", "-s", "parameter_bridge",
                "-o", run.relative(binary)]
        argv.extend(f"-Pparameter_bridge.{key}={value}" for key, value in config.items())
        run.command(f"{label}-compile", [*argv, *rtl, "tests/parameter_bridge.sv"])
        stdout = run.command(f"{label}-execute", ["vvp", run.relative(binary)],
                             timeout=60, expect_exit=1 if illegal_parameter else 0)
        output = stdout.read_text()
        if illegal_parameter:
            if not re.search(r"PARAMETER ERROR:.*\b" + illegal_parameter + r"\b", output):
                raise AssertionError(f"{label}: missing specific {illegal_parameter} diagnostic")
            if "LEGAL_PARAMETER_ELABORATION" in output:
                raise AssertionError(f"{label}: illegal parameters reached legal execution")
        elif "LEGAL_PARAMETER_ELABORATION" not in output:
            raise AssertionError(f"{label}: legal configuration did not complete")
        ledger.append({"configuration": config, "illegal_parameter": illegal_parameter,
                       "compile_exit": 0, "execution_exit": 1 if illegal_parameter else 0,
                       "diagnostic_checked": bool(illegal_parameter)})
        (case / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")

    for index, config in enumerate(configurations):
        execute(config, f"legal-{index:03d}")
    base = configurations[0]
    for parameter, values in invalid.items():
        for index, value in enumerate(values):
            execute({**base, parameter: value}, f"illegal-{parameter}-{index}", parameter)
    result = {"legal_required": len(configurations), "legal_compared": len(configurations),
              "invalid_required": sum(map(len, invalid.values())),
              "invalid_diagnostics_compared": sum(map(len, invalid.values())),
              "scope": "bounded subset" if compact else "128-cache-predictor-product-plus-boundaries",
              "ledger": run.relative(case / "ledger.json")}
    run.receipt["comparisons"]["parameters"] = result
    run.save()


def cache_vectors(lines, words, readonly):
    base = 0 if readonly else 0x10000000
    extent = words * (4 if readonly else 8)
    last = base + extent - (4 if readonly else 8)
    vectors = []

    def request(cmd, addr=0, data=0, strobe=0, fail=0, reset=0):
        vectors.append((cmd, addr, data, strobe, fail, reset))

    request(3)
    request(0, base)
    request(0, base)
    request(0, last)
    request(0, last)
    if readonly:
        request(1, base, 0xDEADBEEF, 15)
        request(0, base)
        request(0, base + 1)
    else:
        for lane in range(8):
            request(1, base, (0x80 + lane) << (lane * 8), 1 << lane)
            request(0, base)
        request(1, base, 0xFFFFFFFFFFFFFFFF, 0)
        request(0, base)
        request(1, last, 0x7FEDCBA987654321, 255)
        request(0, last)
    request(0, base - 1 if base else 0xFFFFFFFFFFFFFFFF)
    request(0, base + extent)
    request(0, base + (1 << 32))
    collision = base + lines * 32
    if collision < base + extent:
        if not readonly:
            request(1, base, 0xF123456789ABCDEF, 255)
        request(0, collision)
        request(0, base)
    request(2)
    request(0, base)
    request(3)
    request(0, base)
    for beat in range(1, min(4, (extent + 7) // 8) + 1):
        request(3)
        request(0, base, fail=beat)
        request(0, base)
        if not readonly:
            request(1, base, 0x876543210FEDCBA9 ^ beat, 255)
            request(2, fail=beat)
            request(0, base)
            request(2)
            if collision < base + extent:
                request(1, base, 0x1234567887654321 ^ beat, 255)
                request(0, collision, fail=beat)
                request(0, base)
                request(0, collision)
    request(3)
    request(0, base, reset=4)
    request(0, base)
    request(0, base)
    request(2)
    request(3)
    request(0, last)
    return vectors


def cache_case(run, name, lines, words, readonly, simulator="verilator", source_root=ROOT,
               focused_invalidation=False):
    case = run.directory / name
    case.mkdir()
    vectors = cache_vectors(lines, words, readonly)
    if focused_invalidation:
        if not readonly:
            raise AssertionError("focused invalidation fixture is instruction-cache only")
        vectors = [(3, 0, 0, 0, 0, 0), (0, 0, 0, 0, 0, 0),
                   (0, 0, 0, 0, 0, 0), (3, 0, 0, 0, 0, 0),
                   (0, 0, 0, 0, 0, 0)]
    vector_path = case / "vectors.txt"
    vector_path.write_text("".join(
        f"{cmd:x} {addr:016x} {data:016x} {strobe:02x} {fail} {reset}\n"
        for cmd, addr, data, strobe, fail, reset in vectors))
    rtl = [run.relative(source_root / "rtl" / name) for name in (
        "hammer_v2_cache.sv", "hammer_v2_icache.sv", "hammer_v2_dcache.sv")]
    rtl.append("tests/cache_bridge.sv")
    config = {"LINES": lines, "WORDS": words, "READ_ONLY": int(readonly)}
    if simulator == "iverilog":
        binary = case / "sim.vvp"
        argv = ["iverilog", "-g2012", "-Wall", "-s", "cache_bridge",
                "-o", run.relative(binary)]
        argv.extend(f"-Pcache_bridge.{key}={value}" for key, value in config.items())
        run.command(f"{name}-compile", [*argv, *rtl])
        executable = ["vvp", run.relative(binary)]
    else:
        obj = case / "compile-obj"
        argv = ["verilator", "--binary", "--timing", "-Wno-fatal",
                "--top-module", "cache_bridge", "--Mdir", run.relative(obj), "-j", "2"]
        argv.extend(f"-G{key}={value}" for key, value in config.items())
        run.command(f"{name}-compile", [*argv, *rtl])
        binary = case / "simulator"
        shutil.copyfile(obj / "Vcache_bridge", binary)
        binary.chmod(0o755)
        executable = [run.relative(binary)]
        shutil.rmtree(obj)
    events = case / "events.txt"
    run.command(f"{name}-simulate", [
        *executable, f"+vectors={run.relative(vector_path)}",
        f"+events={run.relative(events)}",
    ], timeout=60 if simulator == "iverilog" else 3600)
    counts = compare_cache(events, vectors, lines, words, readonly)
    required_counts = ("read_hits", "misses", "refill_beats", "maintenance",
                       "responses", "memory_stalled_edges", "response_stalled_edges")
    if not focused_invalidation:
        required_counts += ("errors", "reset_outstanding", "invalid_requests")
    for required in required_counts:
        if not counts[required]:
            raise AssertionError(f"{name}: required cache comparison not reached: {required}")
    if not readonly and (not counts["write_hits"] or not counts["writeback_beats"]):
        raise AssertionError(f"{name}: data mutation/cleaning was not compared")
    if lines * 32 < words * (4 if readonly else 8):
        if not counts["dirty_evictions" if not readonly else "clean_evictions"]:
            raise AssertionError(f"{name}: collision eviction was not compared")
    run.receipt["comparisons"][name] = {
        "configuration": config, "focused_invalidation_fixture": focused_invalidation, **counts}
    run.save()
    return counts


def sensitivity_cases(run, compact=False):
    mutations = (
        ("numerical-W-extension", "hammer_v2_alu.sv",
         "{{32{word_result[31]}}, word_result}", "{32'b0, word_result}", "smoke"),
        ("forwarding-priority", "hammer_v2_hazard.sv",
         "mem_we && mem_ready_result && mem_rd != 0 && mem_rd == ex_rs1 ? 2'b10 :\n"
         "        wb_we && wb_rd != 0 && wb_rd == ex_rs1 ? 2'b01",
         "wb_we && wb_rd != 0 && wb_rd == ex_rs1 ? 2'b01 :\n"
         "        mem_we && mem_ready_result && mem_rd != 0 && mem_rd == ex_rs1 ? 2'b10",
         "smoke"),
        ("CSR-privilege", "hammer_v2_csr.sv",
         "wire privilege_denied = priv_q < csr_addr[9:8];",
         "wire privilege_denied = 1'b0;", "faults"),
        ("trap-EPC", "hammer_v2_trap.sv",
         "epc = sync_pc;", "epc = sync_pc + 64'd4;", "terminal-fault"),
        ("timer-comparison", "hammer_v2_clint.sv",
         "time_q >= cmp_q", "time_q <= cmp_q", "masked-timer"),
        ("reservation-SC-result", "hammer_v2_atomic.sv",
         "result_q <= 64'd1;", "result_q <= 64'd0;", "atomic"),
        ("AMO-signedness", "hammer_v2_atomic.sv",
         "$signed(old_q) < $signed(operand_q)", "old_q < operand_q", "atomic"),
        ("dirty-writeback-tag", "hammer_v2_cache.sv",
         "victim_q <= tag_q;", "victim_q <= wanted_base;", "dcache"),
        ("I-cache-invalidation", "hammer_v2_cache.sv",
         "if (cmd_q == 3) valid[scan] <= 1'b0;",
         "if (cmd_q == 3 && !READ_ONLY) valid[scan] <= 1'b0;", "icache"),
    )
    if compact == "remaining":
        mutations = tuple(mutations[index] for index in (2, 3, 4, 5, 6))
    elif compact:
        mutations = tuple(mutations[index] for index in (0, 1, 7, 8))
    config = {"IMEM_WORDS": 4096, "DMEM_WORDS": 128, "PRED_MODE": 1,
              "BTB_ENTRIES": 16, "ICACHE_LINES": 16, "DCACHE_LINES": 4,
              "LEGACY_TRAPS": 0}
    programs = {"smoke": smoke_program, "faults": fault_program,
                "timer": timer_program, "atomic": atomic_program,
                "terminal-fault": lambda: [ri(1, 0, 9), 0xFFFFFFFF, 0x00100073],
                "masked-timer": lambda: [ri(1, 0, 128), csr_insn(0x304, 0, 1),
                                         ri(1, 0, 8), csr_insn(0x300, 0, 1),
                                         ri(2, 0, 7), 0x00100073]}
    baselines = {}
    mutants = run.directory / "mutants"
    mutants.mkdir()
    results = []
    accepted_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in (ROOT / "rtl").glob("*.sv")}

    def execute(name, workload, source_root):
        if workload in ("dcache", "icache"):
            return cache_case(run, name, 1, 17 if workload == "dcache" else 3,
                              workload == "icache", source_root=source_root,
                              focused_invalidation=workload == "icache")
        case_config = {**config, "LEGACY_TRAPS": 1} if workload in (
            "terminal-fault", "masked-timer") else config
        return top_case(run, name, programs[workload](), "verilator", case_config,
                        source_root=source_root)

    for category, filename, old, new, workload in mutations:
        if workload not in baselines:
            baselines[workload] = execute("baseline-" + workload, workload, ROOT)
        source = (ROOT / "rtl" / filename).read_text()
        if old not in source:
            raise AssertionError(f"{category}: mutation anchor absent; mutation requires maintenance")
        # The first matching expression is the intended site for repeated
        # writeback assignments; all other source bytes remain unchanged.
        mutated = source.replace(old, new, 1)
        mutation_hash = hashlib.sha256(mutated.encode()).hexdigest()
        variant = mutants / (category + "-" + mutation_hash[:12])
        (variant / "rtl").mkdir(parents=True)
        for original in sorted((ROOT / "rtl").glob("*.sv")):
            target = variant / "rtl" / original.name
            if original.name == filename:
                target.write_text(mutated)
            else:
                shutil.copyfile(original, target)
        record = {"category": category, "source": "rtl/" + filename,
                  "original_sha256": accepted_hashes[filename],
                  "mutation_sha256": mutation_hash, "old": old, "new": new,
                  "variant_root": run.relative(variant), "workload": workload,
                  "baseline_compared": baselines[workload], "detected": False}
        results.append(record)
        run.receipt["mutations"] = results
        run.save()
        try:
            execute("mutant-" + category, workload, variant)
        except AssertionError as mismatch:
            detail = str(mismatch)
            if not detail.startswith(("edge ", "trap expected=", "transaction ")):
                raise AssertionError(f"{category}: unrelated checker failure does not count: {detail}") from mismatch
            record.update(detected=True, first_mismatch=detail)
        else:
            raise AssertionError(f"{category}: mutant survived the architectural/protocol checker")
        record["compile_and_simulation_exits"] = [
            command["exit_status"] for command in run.receipt["commands"]
            if command["stdout"].split("/")[-1].startswith("mutant-" + category + "-")]
        if record["compile_and_simulation_exits"] != [0, 0]:
            raise AssertionError(f"{category}: compile failure/timeout/startup failure is not detection")
        run.save()
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (ROOT / "rtl").glob("*.sv")}
    if after != accepted_hashes:
        raise AssertionError("accepted RTL changed during disposable mutation execution")
    run.receipt["comparisons"]["sensitivity"] = {
        "categories_required": len(mutations), "reached_and_detected": len(results),
        "scope": "bounded subset" if compact else "all nine admitted mutation categories",
        "accepted_rtl_unchanged": True,
    }
    run.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=(*SUITES, "all"), default="all")
    parser.add_argument("--probe", choices=("smoke", "integer", "atomic", "privilege", "timer", "faults", "memory", "synthesis",
                                           "portable", "clean-copy-child", "parameters", "cache-leaf",
                                           "parent", "mutants", "mutants-remaining",
                                           "interrupts", "random-matrix"),
                        help="bounded preparation only; never full-suite acceptance")
    parser.add_argument("--repair-of", help="project-relative earlier failed receipt, retained unchanged")
    args = parser.parse_args()
    run = Run(args.suite + ("-" + args.probe if args.probe else ""), bool(args.probe))
    try:
        if args.repair_of:
            previous = ROOT / args.repair_of
            if not previous.is_file() or not previous.resolve().is_relative_to(ROOT / "evidence"):
                raise RuntimeError("--repair-of must name an existing project evidence receipt")
            run.receipt["repair_of"] = args.repair_of
            run.save()
        run.receipt["comparisons"]["model_analytical_cases"] = model_selfcheck()
        run.save()
        if args.probe == "random-matrix":
            run.tools(("python3", "verilator", "make", "g++"))
            random_case(run, "A-seed17", 17, configuration("A"))
            random_case(run, "B-seed29", 29, configuration("B"))
        elif args.probe == "interrupts":
            run.tools(("python3", "verilator", "make", "g++"))
            config = configuration("B")
            program, trigger_pc = interrupt_program()
            counts = top_case(run, "six-source-priority", program, "verilator", config,
                              irq_trigger_pc=trigger_pc)
            expected = [[cause, 3] for cause in (11, 3, 7, 9, 1, 5)]
            if counts["interrupt_sequence"] != expected or counts["returns"] != 6:
                raise AssertionError(f"six-source interrupt priority/returns: {counts}")
            counts = top_case(run, "delegated-STIP", supervisor_timer_program(),
                              "verilator", config)
            if counts["interrupt_sequence"] != [[5, 1]] or counts["returns"] != 2:
                raise AssertionError(f"delegated STIP entry/SRET: {counts}")
        elif args.probe in ("mutants", "mutants-remaining") or (
                args.suite == "sensitivity" and not args.probe):
            run.tools(("python3", "verilator", "make", "g++"))
            sensitivity_cases(run, compact="remaining" if args.probe == "mutants-remaining"
                              else bool(args.probe))
        elif args.probe == "parent":
            run.tools(("python3", "verilator", "make", "g++"))
            parent_differential(run, "parent-B", integer_program(looped=True),
                                configuration("B", legacy=1))
        elif args.probe == "cache-leaf":
            run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++"))
            cache_case(run, "D-singleton", 1, 17, False, "iverilog")
            cache_case(run, "I-partial", 1, 3, True, "verilator")
        elif args.probe == "parameters":
            run.tools(("python3", "iverilog", "vvp"))
            parameter_cases(run, compact=True)
        elif args.probe == "clean-copy-child":
            run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++", "yosys"))
            top_case(run, "compact-icarus", smoke_program())
            top_case(run, "compact-verilator", smoke_program(), "verilator")
            synthesis_case(run, "C", configuration("C"))
        elif args.probe == "portable" or (args.suite == "portable" and not args.probe):
            run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++", "yosys"))
            portable_case(run)
        elif args.probe == "smoke":
            run.tools(("python3", "iverilog", "vvp"))
            top_case(run, "compact", smoke_program())
        elif args.probe == "synthesis":
            run.tools(("python3", "yosys"))
            synthesis_case(run, "C", configuration("C"))
        elif args.probe:
            run.tools(("python3", "verilator", "make", "g++"))
            program = {"integer": integer_program, "atomic": atomic_program,
                       "privilege": privilege_program,
                       "timer": timer_program,
                       "faults": fault_program,
                       "memory": memory_control_program}[args.probe]()
            config = {"IMEM_WORDS": 4096, "DMEM_WORDS": 128, "PRED_MODE": 1,
                      "BTB_ENTRIES": 16, "ICACHE_LINES": 16,
                      "DCACHE_LINES": 4, "LEGACY_TRAPS": 1}
            if args.probe in ("timer", "faults"):
                config["LEGACY_TRAPS"] = 0
            counts = top_case(run, args.probe, program, "verilator", config)
            if args.probe == "timer" and (
                    counts["timer_interrupts"] != 3 or counts["returns"] != 3):
                raise AssertionError(f"timer probe requires three acknowledged entries/returns: {counts}")
        elif args.suite == "synthesis":
            run.tools(("python3", "yosys"))
            for name in ("A", "C", "D"):
                synthesis_case(run, name, configuration(name))
        else:
            raise RuntimeError("verification matrix construction incomplete; no suite acceptance claimed")
    except Exception as error:
        run.finish(error)
        print(f"FAIL: {error}\nreceipt: {run.relative(run.directory / 'receipt.json')}", file=sys.stderr)
        return 1
    run.finish()
    scope = "bounded preparation" if args.probe else args.suite
    print(f"PASS {scope}; receipt: {run.relative(run.directory / 'receipt.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
