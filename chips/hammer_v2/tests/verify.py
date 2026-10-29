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
from cache_model import compare_cache, compare_integrated_cache
import clint_model

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
            "start": now(), "end": None, "timeout_s": 86400,
            "patrol_target_s": 2700, "compact_vvp_limit_s": 60,
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
        remaining = 2700 - (time.monotonic() - self.started)
        if remaining <= 50:
            raise RuntimeError("2700-second patrol scheduling target exhausted; "
                               "86400-second outer ceiling does not extend it")
        timeout = min(timeout, remaining - 30)
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
            if name in self.receipt["tool_versions"]:
                continue
            if not shutil.which(name):
                raise RuntimeError(f"missing required executable: {name}; installation is not permitted")
            output = self.command(f"version-{name.replace('+', 'p')}", [name, *flags[name]])
            error_output = self.directory / f"version-{name.replace('+', 'p')}.stderr.txt"
            self.receipt["tool_versions"][name] = (
                output.read_text(errors="replace") + error_output.read_text(errors="replace")).strip()
        self.save()

    def finish(self, error=None):
        if error is None:
            current = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in source_files()}
            if current != self.receipt["source_sha256"]:
                error = RuntimeError("verification sources changed during execution; evidence is not source-bound")
            elif time.monotonic() - self.started > 2700:
                error = RuntimeError("check exceeded the 2700-second patrol scheduling target")
        if error is not None:
            for suite, status in self.receipt["coverage"].get("suite_status", {}).items():
                if status == "running":
                    self.receipt["coverage"]["suite_status"][suite] = "failed"
            for rows in self.receipt["coverage"].get("matrices", {}).values():
                for row in rows:
                    if row["status"] == "running":
                        row["status"] = "failed"
        self.receipt.update(end=now(), duration_s=time.monotonic() - self.started,
                            exit_status=int(error is not None), failure=str(error) if error else None)
        self.save()
        return error


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
        8: ("IQQIQII", ("write", "address", "data", "mask", "read", "error", "order")),
        9: ("III", ("aw", "w", "ar")),
        10: ("IIQI", ("imem", "address", "data", "strobe")),
        11: ("", ()),
        13: ("", ()),
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


def compare_top(run, path, program, dwords, legacy=True, reference=False, terminal_cause=3,
                clint_operations=None):
    program = list(program)
    model = Machine(program, dwords, clint_operations)
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
    counts["operand_samples"] = {}
    counts["result_samples"] = {}
    counts["retire_edges"] = {}
    counts["csr_forms"] = {}
    counts["branch_outcomes"] = {}
    counts["fences"] = 0
    counts["fence_i"] = 0
    counts["halt_resume_epochs"] = 0
    counts["host_execution_writes"] = 0
    counts["host_intermediate_reads"] = 0
    counts["reset_epochs"] = 0
    counts["axi_transactions"] = 0
    counts["axi_errors"] = 0
    counts["axi_write_order"] = {}
    complete = False
    stopped = False
    for kind, edge, event in read_events(path):
        if kind == 1:
            if stopped:
                raise AssertionError("retirement after terminal trap")
            insn = event["insn"]
            operands = [model.regs[(insn >> 15) & 31],
                        model.regs[(insn >> 20) & 31]]
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
            edges = counts["retire_edges"].setdefault(pc_key, [])
            if len(edges) < 64:
                edges.append(edge)
            if insn & 127 == 0x73 and (insn >> 12) & 7:
                form = str((insn >> 12) & 7)
                counts["csr_forms"][form] = counts["csr_forms"].get(form, 0) + 1
            if insn & 127 == 0x63:
                outcome = f"{(insn >> 12) & 7}-{int(event['next_pc'] != event['pc'] + 4)}"
                counts["branch_outcomes"][outcome] = counts["branch_outcomes"].get(outcome, 0) + 1
            if insn & 127 == 0x0F:
                counts["fence_i" if (insn >> 12) & 7 == 1 else "fences"] += 1
            samples = counts["operand_samples"].setdefault(pc_key, [])
            if operands not in samples and len(samples) < 16:
                samples.append(operands)
            results = counts["result_samples"].setdefault(pc_key, [])
            result = [event["rd_we"], event["rd"], event["rd_data"], event["mem_write"]]
            if result not in results and len(results) < 16:
                results.append(result)
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
            stopped = legacy or event["cause"] == terminal_cause
            counts["traps"] += 1
            cause = str(event["cause"])
            counts["trap_causes"][cause] = counts["trap_causes"].get(cause, 0) + 1
        elif kind == 3:
            if event["imem"]:
                expected = program[event["address"] // 4]
            else:
                off = event["address"]
                expected = int.from_bytes(model.memory[off:off + 8], "little")
                if stopped:
                    counts["memory_beats"] += 1
                elif counts["halt_resume_epochs"]:
                    counts["host_intermediate_reads"] += 1
                else:
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
        elif kind == 8:
            model.bus_events.append(event)
            counts["axi_transactions"] += 1
            counts["axi_errors"] += event["error"]
            if event["write"]:
                order = str(event["order"])
                counts["axi_write_order"][order] = counts["axi_write_order"].get(order, 0) + 1
        elif kind == 9:
            counts["axi_stall_edges"] = event
        elif kind == 10:
            if event["imem"]:
                index = event["address"] // 4
                image = bytearray(model.instructions[index].to_bytes(4, "little"))
                for lane in range(4):
                    if event["strobe"] & (1 << lane):
                        image[lane] = (event["data"] >> (lane * 8)) & 255
                model.instructions[index] = program[index] = int.from_bytes(image, "little")
            else:
                offset = event["address"]
                for lane in range(8):
                    if event["strobe"] & (1 << lane):
                        model.memory[offset + lane] = (event["data"] >> (lane * 8)) & 255
            model.reservation = None
            counts["host_execution_writes"] += 1
        elif kind == 11:
            model.reservation = None
            counts["halt_resume_epochs"] += 1
        elif kind == 13:
            if model.bus_events:
                raise AssertionError("reset unexpectedly interrupted the MMIO oracle")
            if any(model.memory):
                raise AssertionError("running-reset fixture requires unchanged zero backing data")
            backing = model.memory
            model = Machine(program, dwords)
            model.memory[:] = backing
            stopped = False
            counts["reset_epochs"] += 1
    if not complete or counts["registers"] != 32 or counts["memory_beats"] != dwords:
        raise AssertionError(f"incomplete public comparison: {counts}, complete={complete}")
    if not counts["retirements"] or not counts["traps"]:
        raise AssertionError(f"missing architectural comparisons: {counts}")
    if model.bus_events:
        raise AssertionError(f"unretired/squashed MMIO transactions: {model.bus_events[:4]}")
    if clint_operations is not None and model.clint_consumed != len(clint_operations):
        raise AssertionError("unretired/squashed CLINT transactions")
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
                if width == 2 and index in (4, 5):
                    old, rhs = ((1 << 31, (1 << 64) - 1) if index == 4 else
                                ((1 << 31) - 1, 1 << 31))
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
    code.extend((0x30200073, csr_insn(0x300, 3, 0, 2), csr_insn(0x180, 3, 0, 2),
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
    code.extend((csr_insn(0x100, 3, 0, 2), 0x30200073, 0x10200073, 0x12000073,
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
            *constant(1, (1 << 11) | 2 | 8), csr_insn(0x300, 0, 1),
            ri(1, 0, 96), csr_insn(0x341, 0, 1), 0x30200073]
    code.extend([0] * (24 - len(code)))
    code.extend((ri(4, 0, 7), 0x00100073))
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x142, 25, 0, 2), csr_insn(0x100, 26, 0, 2),
                 ri(1, 0, 32), csr_insn(0x104, 0, 1, 3),
                 ri(22, 22, 1), 0x10200073))
    return code


OPERAND_PAIRS = (
    (0, 0), (1, 1), ((1 << 64) - 1, 1), (1, (1 << 64) - 1),
    (1 << 63, (1 << 64) - 1), ((1 << 63) - 1, 1 << 63),
    (1 << 31, 31), ((1 << 32) - 1, 32),
    (123, 0), ((1 << 64) - 1, 63),
)


def integer_directed_cases(run, name, config):
    """Pack independently specified operand experiments into legal B-sized images."""
    snippets = []
    for word in (False, True):
        pairs = list(OPERAND_PAIRS)
        if word:
            pairs[4:6] = [(1 << 31, (1 << 64) - 1), ((1 << 31) - 1, 1 << 31)]
        opcode = 0x3B if word else 0x33
        operations = [(0, 0), (0, 32), (1, 0), (5, 0), (5, 32)]
        if not word:
            operations += [(f3, 0) for f3 in (2, 3, 4, 6, 7)]
        operations += [(f3, 1) for f3 in ((0, 4, 5, 6, 7) if word else range(8))]
        for f3, f7 in operations:
            operation = f"R-{opcode:02x}-{f7:02x}-{f3}"
            for a, b in pairs:
                prefix = [*constant(1, a), *constant(2, b)]
                snippets.append((operation, prefix, rr(3, 1, 2, f3, f7, opcode), [a, b]))
        for f3, high in ((0, 0), (1, 0), (5, 0), (5, 0x400)):
            operation = f"I-{0x1B if word else 0x13:02x}-{f3}-{high}"
            for index, (a, _) in enumerate(pairs):
                immediate = (-2048, -1, 0, 1, 31, 32, 63, 2047)[index % 8]
                if f3:
                    immediate &= 31 if word else 63
                    immediate |= high
                snippets.append((operation, constant(1, a),
                                 ri(3, 1, immediate, f3, 0x1B if word else 0x13), [a]))
    for f3 in (2, 3, 4, 6, 7):
        for index, (a, _) in enumerate(OPERAND_PAIRS):
            snippets.append((f"I-13-{f3}", constant(1, a),
                             ri(3, 1, (-2048, -1, 0, 1, 31, 32, 63, 2047)[index % 8], f3), [a]))

    denominator = {}
    compared = {}
    program, obligations = [], []
    part = 0

    def execute():
        nonlocal part
        counts = top_case(run, f"{name}-{part:02d}", [*program, 0x00100073],
                          "verilator", config)
        for operation, pc, expected in obligations:
            actual = counts["operand_samples"].get(str(pc), [])
            if counts["retire_pc_hits"].get(str(pc)) != 1 or len(actual) != 1:
                raise AssertionError(f"{name}: directed site {pc:#x} did not retire exactly once")
            if actual[0][:len(expected)] != expected:
                raise AssertionError(f"{name}: directed {operation} operand precondition: "
                                     f"expected={expected}, observed={actual}")
            compared[operation] = compared.get(operation, 0) + 1
        part += 1

    for operation, prefix, instruction, operands in snippets:
        if len(program) + len(prefix) + 2 > config["IMEM_WORDS"]:
            execute()
            program, obligations = [], []
        program.extend(prefix)
        obligations.append((operation, len(program) * 4, operands))
        program.append(instruction)
        denominator[operation] = denominator.get(operation, 0) + 1
    if program:
        execute()
    if compared != denominator or any(value < 8 for value in compared.values()):
        raise AssertionError(f"{name}: incomplete directed operand denominator: {compared}")
    result = {"required": denominator, "compared": compared, "images": part,
              "scope": "RV64 register/immediate integer and M-extension operations"}
    run.receipt["coverage"][name] = result
    run.save()
    return result


def memory_control_directed_cases(run, name, config):
    snippets = []
    for f3 in range(7):
        for index, (value, _) in enumerate(OPERAND_PAIRS):
            offset = (index & 7) & ~((1 << (f3 & 3)) - 1)
            snippets.append((f"load-{f3}", [*constant(1, value), store(20, 1)],
                             ri(3, 20, offset, f3, 3), [0x10000000], []))
    for f3 in range(4):
        for index, (value, _) in enumerate(OPERAND_PAIRS):
            offset = (index & 7) & ~((1 << f3) - 1)
            snippets.append((f"store-{f3}", constant(1, value),
                             store(20, 1, offset, f3), [0x10000000, value],
                             [ri(3, 20, 0, 3, 3)]))
    for f3 in (0, 1, 4, 5, 6, 7):
        for a, b in OPERAND_PAIRS:
            snippets.append((f"branch-{f3}", [*constant(1, a), *constant(2, b)],
                             branch(1, 2, 8, f3), [a, b], [store(20, 1)]))
    for index, (value, _) in enumerate(OPERAND_PAIRS):
        imm = (value >> 12) & 0xFFFFF
        snippets.extend(((f"LUI", [], (imm << 12) | (3 << 7) | 0x37, [], []),
                         (f"AUIPC", [], (imm << 12) | (3 << 7) | 0x17, [], []),
                         (f"JAL", [], (8 << 20) | (3 << 7) | 0x6F, [], [store(20, 1)])))
    for mask in (0x00, 0x11, 0x22, 0x44, 0x88, 0x0F, 0xF0, 0xFF):
        snippets.append(("FENCE", [ri(1, 0, mask), store(20, 1)],
                         (mask << 20) | 0x0F, [], []))
    program, obligations, denominator, compared = [0x10000A37], [], {}, {}
    part = 0

    def execute():
        nonlocal part
        counts = top_case(run, f"{name}-{part:02d}", [*program, 0x00100073],
                          "verilator", config)
        for operation, pc, expected in obligations:
            actual = counts["operand_samples"].get(str(pc), [])
            if counts["retire_pc_hits"].get(str(pc)) != 1 or len(actual) != 1 or (
                    actual[0][:len(expected)] != expected):
                raise AssertionError(f"{name}: {operation} operand/completion denominator at {pc:#x}")
            compared[operation] = compared.get(operation, 0) + 1
        part += 1

    for operation, prefix, instruction, operands, suffix in snippets:
        if len(program) + len(prefix) + len(suffix) + 2 > config["IMEM_WORDS"]:
            execute()
            program, obligations = [0x10000A37], []
        program.extend(prefix)
        obligations.append((operation, len(program) * 4, operands))
        program.extend((instruction, *suffix))
        denominator[operation] = denominator.get(operation, 0) + 1
    # JALR targets depend on the packed image position.
    for index in range(8):
        if len(program) + 4 > config["IMEM_WORDS"]:
            execute()
            program, obligations = [0x10000A37], []
        target = (len(program) + 3) * 4
        program.append(ri(1, 0, target | (index & 1)))
        obligations.append(("JALR", len(program) * 4, [target | (index & 1)]))
        program.extend((ri(3, 1, 0, 0, 0x67), store(20, 1)))
        denominator["JALR"] = denominator.get("JALR", 0) + 1
    execute()
    if compared != denominator or any(value < 8 for value in compared.values()):
        raise AssertionError(f"{name}: memory/control directed denominator not met")
    result = {"required": denominator, "compared": compared, "images": part}
    run.receipt["coverage"][name] = result
    run.save()
    return result


def amo(op, rd, rs1=20, rs2=2, width=3, ordering=0):
    return ((op << 27) | (ordering << 25) | (rs2 << 20) |
            (rs1 << 15) | (width << 12) | (rd << 7) | 0x2F)


def lock_program(width=3):
    code = [0x10000A37, ri(2, 0, 1), ri(22, 0, 32)]
    loop = len(code)
    code.extend((
        amo(2, 3, rs2=0, width=width, ordering=3),
        store(20, 0, f3=width),
        amo(3, 4, width=width, ordering=3),
        amo(2, 3, rs2=0, width=width, ordering=3),
        amo(3, 5, width=width, ordering=3),
        ri(6, 20, 0, width, 3),
        store(20, 0, f3=width),
        ri(22, 22, -1),
        branch(22, 0, (loop - len(code) - 8) * 4, 1),
        0x0000000F, 0x00100073,
    ))
    return code, ((loop + 2) * 4, (loop + 4) * 4)


def reservation_program():
    code = [0x10000A37, ri(21, 20, 4), ri(23, 20, 8), ri(2, 0, 7)]
    outcomes = []

    def sequence(lr_width, sc_width, intervention=(), sc_address=20, lr_address=20,
                 success=False):
        code.append(amo(2, 3, rs1=lr_address, rs2=0, width=lr_width))
        code.extend(intervention)
        outcomes.append((len(code) * 4, int(not success)))
        code.append(amo(3, 4, rs1=sc_address, width=sc_width))

    sequence(2, 3)
    sequence(3, 2)
    sequence(2, 2, sc_address=21)
    sequence(2, 2, sc_address=20, lr_address=21)
    sequence(2, 2, sc_address=21, lr_address=21, success=True)
    sequence(3, 3, (amo(2, 3, rs1=23, rs2=0),))
    for lane in range(8):
        sequence(3, 3, (store(20, 2, lane, 0),))
    for width in (2, 3):
        sequence(width, width, (amo(0, 0, width=width),))
        sequence(width, width, (store(23, 2),), success=True)
        outcomes.append((len(code) * 4, 1))
        code.append(amo(3, 4, width=width))
        sequence(width, width, success=True)
        code.append(amo(2, 0, rs2=0, width=width))
        outcomes.append((len(code) * 4, 0))
        code.append(amo(3, 0, width=width))
    code.extend((0x0000000F, 0x00100073))
    return code, outcomes


def counter_program():
    code = []
    for address in (0xB00, 0xB02):
        for value in (0, (1 << 64) - 1, 19):
            code.extend(constant(1, value))
            code.extend((csr_insn(address, 2, 1), csr_insn(address, 3, 0, 2),
                         csr_insn(0xC00 if address == 0xB00 else 0xC02, 4, 0, 2)))
    for address in (0x301, 0x180, 0x300, 0x302, 0x303, 0x305, 0x105, 0x341, 0x141,
                    0x140, 0x340, 0x342, 0x343, 0x142, 0x143):
        code.extend((ri(1, 0, -1), csr_insn(address, 0, 1),
                     csr_insn(address, 2, 0, 2), csr_insn(address, 0, 0)))
    # All six CSR forms, zero-source suppression and read-only identity reads.
    for f3 in (1, 2, 3, 5, 6, 7):
        code.extend((ri(1, 0, 5), csr_insn(0x340, 3, 1, f3),
                     csr_insn(0x340, 4, 0, 2), csr_insn(0x340, 5, 0, f3)))
    for address in (0xF11, 0xF12, 0xF13, 0xF14):
        code.extend((csr_insn(address, 2, 0, 2), csr_insn(address, 3, 0, 3),
                     csr_insn(address, 4, 0, 6), csr_insn(address, 5, 0, 7)))
    code.extend((*constant(1, 2 << 11), csr_insn(0x300, 0, 1),
                 csr_insn(0x300, 2, 0, 2), csr_insn(0x300, 0, 0)))
    for address in (0x305, 0x105):
        for value in (512, 513, 514, 515):
            code.extend((ri(1, 0, value), csr_insn(address, 0, 1),
                         csr_insn(address, 2, 0, 2)))
    code.extend((ri(1, 0, -1), csr_insn(0x344, 0, 1), csr_insn(0x344, 2, 0, 2),
                 ri(1, 0, 0x222), csr_insn(0x303, 0, 1),
                 csr_insn(0x104, 0, 1), csr_insn(0x104, 2, 0, 2),
                 ri(1, 0, -1), csr_insn(0x144, 0, 1), csr_insn(0x144, 2, 0, 2),
                 csr_insn(0x144, 0, 0), csr_insn(0x344, 2, 0, 2),
                 csr_insn(0x344, 0, 0), csr_insn(0x144, 2, 0, 2),
                 csr_insn(0x303, 0, 0), csr_insn(0x304, 0, 0)))
    code.extend((*constant(1, 1 << 20), csr_insn(0x300, 0, 1, 2), 0x12000073,
                 csr_insn(0x300, 0, 1, 3), 0x12000073))
    code.append(0x00100073)
    return code


def cache_pressure_program(config, seed):
    rng = random.Random(seed)
    code = [0x10000A37, *constant(1, config["DCACHE_LINES"] * 32),
            rr(21, 20, 1), *constant(2, rng.getrandbits(64)), ri(22, 0, 32)]
    loop = len(code)
    code.extend((store(20, 2), ri(3, 20, 0, 3, 3), store(20, 3),
                 store(21, 2), ri(4, 21, 0, 3, 3), ri(5, 20, 0, 3, 3)))
    for lane in range(8):
        code.extend((store(20, 2, lane, 0), ri(6, 20, lane, 4, 3)))
    code.extend((ri(2, 2, 1), 0x0000000F, 0x0000100F, ri(22, 22, -1)))
    code.append(branch(22, 0, (loop - len(code)) * 4, 1))
    code.extend((0x0000000F, 0x00100073))
    return code


def delegated_exception_program(source_priv=0):
    code = [ri(1, 0, 512), csr_insn(0x105, 0, 1),
            ri(1, 0, 1), ri(1, 1, 8 + source_priv, 1), csr_insn(0x302, 0, 1)]
    if source_priv:
        code.extend((*constant(1, 1 << 11), csr_insn(0x300, 0, 1)))
    code.extend((ri(1, 0, 64), csr_insn(0x341, 0, 1), 0x30200073))
    code.extend([0] * (16 - len(code)))
    code.extend((0x00000073, ri(4, 0, 99), 0x00100073))
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x142, 25, 0, 2), csr_insn(0x143, 26, 0, 2),
                 csr_insn(0x141, 27, 0, 2), ri(27, 27, 4),
                 csr_insn(0x141, 0, 27), 0x10200073))
    return code


def counter_permission_program():
    code = [ri(1, 0, 7), csr_insn(0x306, 0, 1), csr_insn(0x106, 0, 1),
            *constant(1, 1 << 11), csr_insn(0x300, 0, 1)]
    s_jump = len(code)
    code.extend((0, csr_insn(0x341, 0, 1), 0x30200073))
    code[s_jump] = ri(1, 0, len(code) * 4)
    for address in (0xC00, 0xC01, 0xC02):
        code.append(csr_insn(address, 3, 0, 2))
    u_jump = len(code)
    code.extend((0, csr_insn(0x141, 0, 1), 0x10200073))
    code[u_jump] = ri(1, 0, len(code) * 4)
    for address in (0xC00, 0xC01, 0xC02):
        code.append(csr_insn(address, 4, 0, 2))
    code.append(0x00100073)
    return code


def return_state_program():
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1),
            *constant(1, (1 << 17) | (1 << 11) | (1 << 7) | (1 << 5)),
            csr_insn(0x300, 0, 1)]
    u_jump = len(code)
    code.extend((0, csr_insn(0x141, 0, 1)))
    s_jump = len(code)
    code.extend((0, csr_insn(0x341, 0, 1), 0x30200073))
    code[s_jump] = ri(1, 0, len(code) * 4)
    code.extend((0x12000073, 0x0000100F, 0x00000073, 0x10200073))
    code[u_jump] = ri(1, 0, len(code) * 4)
    code.extend((0x0000100F, 0x00000073, 0x00100073))
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x300, 7, 0, 2), csr_insn(0x341, 1, 0, 2),
                 ri(1, 1, 4), csr_insn(0x341, 0, 1), 0x30200073))
    return code


def machine_return_program(supervisor=False):
    status = ((1 << 17) | (1 << 8) | (1 << 5) | (1 << 22)) if supervisor else (
        (1 << 17) | (3 << 11) | (1 << 7))
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1),
            *constant(1, status), csr_insn(0x300, 0, 1)]
    destination = len(code)
    code.extend((0, csr_insn(0x141 if supervisor else 0x341, 0, 1),
                 0x10200073 if supervisor else 0x30200073))
    code[destination] = ri(1, 0, len(code) * 4)
    if supervisor:
        code.extend((0x00000073, 0x00100073))
        code.extend([0] * (128 - len(code)))
        code.extend((csr_insn(0x300, 7, 0, 2), csr_insn(0x341, 1, 0, 2),
                     ri(1, 1, 4), csr_insn(0x341, 0, 1), 0x30200073))
    else:
        code.extend((csr_insn(0x300, 7, 0, 2), 0x00100073))
    return code


def machine_delegation_program():
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1), ri(1, 0, 768),
            csr_insn(0x105, 0, 1), ri(1, 0, -1), csr_insn(0x302, 0, 1),
            0xFFFFFFFF, 0x00100073]
    return recovering_handler(code)


def jump(offset, rd=0):
    offset &= (1 << 21) - 1
    return ((((offset >> 20) & 1) << 31) | (((offset >> 1) & 1023) << 21) |
            (((offset >> 11) & 1) << 20) | (((offset >> 12) & 255) << 12) |
            (rd << 7) | 0x6F)


def vectored_interrupt_program():
    code, trigger_pc = interrupt_program()
    code[2] = ri(1, 0, 513)
    handler = code[128:]
    code = code[:128]
    for cause in range(12):
        code.append(jump((160 - (128 + cause)) * 4))
    code.extend([ri(0, 0, 0)] * (160 - len(code)))
    code.extend(handler)
    return code, trigger_pc


def wfi_program(global_enable):
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1),
            *constant(1, 1 << 11), csr_insn(0x304, 0, 1)]
    if global_enable:
        code.extend((ri(1, 0, 8), csr_insn(0x300, 0, 1)))
    trigger_pc = len(code) * 4
    code.extend((0x10500073, ri(4, 0, 99), csr_insn(0x304, 0, 0), 0x00100073))
    code.extend([0] * (128 - len(code)))
    code.extend((csr_insn(0x342, 25, 0, 2), csr_insn(0x304, 0, 0), 0x30200073))
    return code, trigger_pc


def predictor_program(entries):
    stride = max(4, entries)
    code = [ri(1, 0, 8), 0x10000A37]
    code.extend([ri(0, 0, 0)] * (16 - len(code)))
    code.extend((ri(1, 1, -1), branch(0, 0, (stride - 1) * 4), store(20, 1)))
    code.extend([ri(0, 0, 0)] * (16 + stride - len(code)))
    code.extend((ri(5, 5, 1), branch(1, 0, -(stride + 1) * 4, 1), 0x00100073))
    return code, (17 * 4, (17 + stride) * 4)


def recovering_handler(code):
    if len(code) > 128:
        raise AssertionError("program overlaps architectural trap handler")
    code = [*code, *([0] * (128 - len(code)))]
    code.extend((csr_insn(0x342, 25, 0, 2), branch(25, 0, 24, 4),
                 csr_insn(0x341, 26, 0, 2), ri(26, 26, 4),
                 csr_insn(0x341, 0, 26), 0x30200073,
                 ri(0, 0, 0), ri(22, 22, 1), csr_insn(0x304, 0, 0), 0x30200073))
    return code


def mmio_program(seed=17, interrupts=False):
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1),
            0x40000A37, 0x40010AB7, ri(21, 21, -16),
            *constant(2, random.Random(seed).getrandbits(64))]
    if interrupts:
        code.extend((*constant(1, 1 << 11), csr_insn(0x304, 0, 1),
                     ri(1, 0, 8), csr_insn(0x300, 0, 1)))
    for lane in range(8):
        code.extend((store(20, 2, lane, 0), ri(3, 20, lane, 0, 3),
                     ri(4, 20, lane, 4, 3), ri(2, 2, 1)))
    for size in (1, 2, 3):
        for offset in range(0, 8, 1 << size):
            code.extend((store(20, 2, offset, size), ri(5, 20, offset, size, 3),
                         ri(2, 2, -1)))
    code.extend((branch(0, 0, 8), store(20, 0), ri(6, 21, 0, 3, 3),
                 store(21, 2), ri(7, 20, 0, 3, 3), 0x00100073))
    return recovering_handler(code)


def interrupted_muldiv_program():
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1),
            *constant(2, (1 << 63) - 1), ri(3, 0, 17),
            *constant(1, 1 << 11), csr_insn(0x304, 0, 1),
            ri(1, 0, 8), csr_insn(0x300, 0, 1),
            rr(4, 2, 3, 4, 1), rr(5, 4, 3, 0, 1),
            ri(6, 6, 1), branch(22, 0, -4), 0x00100073]
    return recovering_handler(code)


def clint_program(register, seed):
    base, length = clint_model.REGISTERS[register]
    code = [ri(1, 0, 512), csr_insn(0x305, 0, 1),
            *constant(20, base), *constant(2, random.Random(seed).getrandbits(64))]
    for size in range(4):
        if (1 << size) > length:
            continue
        for offset in range(0, length, 1 << size):
            code.extend((store(20, 2, offset, size), ri(3, 20, offset, size, 3),
                         csr_insn(0xC01, 4, 0, 2)))
    if register == 0:
        code.extend((store(20, 2), ri(3, 20, 0, 3, 3)))
    code.extend((ri(23, 20, length), ri(3, 23, 0, 2 if register == 0 else 3, 3),
                 store(23, 2, f3=2 if register == 0 else 3),
                 *constant(23, base + (1 << 32)),
                 ri(3, 23, 0, 3, 3), store(23, 2),
                 0x02004AB7, store(21, 0), csr_insn(0x344, 7, 0, 2),
                 ri(1, 0, -1), store(21, 1), csr_insn(0x344, 7, 0, 2),
                 0x02000C37, ri(1, 0, 1), store(24, 1, f3=2),
                 csr_insn(0x344, 7, 0, 2), store(24, 0, f3=2),
                 csr_insn(0x344, 7, 0, 2)))
    if register == 2:
        code.extend((ri(1, 0, -3), store(20, 1), csr_insn(0xC01, 8, 0, 2)))
    code.append(0x00100073)
    return recovering_handler(code)


def squashed_effects_program():
    code = [0x10000A37, ri(23, 20, 8), 0x40000AB7, 0x40010C37, ri(24, 24, -16),
            ri(2, 0, 7), store(20, 2), csr_insn(0x340, 0, 2), ri(2, 0, 99)]
    for instruction in (csr_insn(0x340, 0, 2), csr_insn(0xFFF, 3, 0, 2),
                        amo(0, 3), store(21, 2), ri(3, 24, 0, 3, 3), 0x0000100F):
        code.extend((branch(0, 0, 8), instruction))
    for instruction in (amo(2, 3, rs1=23, rs2=0), amo(3, 3)):
        code.extend((amo(2, 3, rs2=0), branch(0, 0, 8), instruction, amo(3, 4)))
    code.extend((csr_insn(0x340, 5, 0, 2), ri(6, 20, 0, 3, 3),
                 0x0000000F, 0x00100073))
    return code


def control_fault_cases(run, name, config):
    results = []
    for label, program, cause in (
            ("branch-misaligned", [ri(2, 0, 9), branch(0, 0, 2), 0x00100073], 0),
            ("jalr-misaligned", [ri(1, 0, 2), ri(3, 1, 0, 0, 0x67), 0x00100073], 0),
            ("fetch-high-alias", [*constant(1, 1 << 32), ri(3, 1, 0, 0, 0x67)], 1),
            ("fetch-limit", [*constant(1, config["IMEM_WORDS"] * 4),
                              ri(3, 1, 0, 0, 0x67)], 1),
            ("illegal-before-alignment", [*constant(20, 0x10000001),
                                          store(20, 2, 0, 4), 0x00100073], 2)):
        counts = top_case(run, name + "-" + label, program, "verilator", config,
                          terminal_cause=cause)
        if counts["trap_causes"] != {str(cause): 1}:
            raise AssertionError(f"{name}: control/fetch/decode priority fault denominator")
        results.append({"case": label, "cause": cause, "compared": True})
    counts = top_case(run, name + "-squashed-effects", squashed_effects_program(),
                      "verilator", config, cache_traffic=True)
    if counts["axi_transactions"] != 0 or counts["dcache"]["command_2"] != counts["fences"] + 1 or (
            counts["icache"]["runtime_command_3"] != 0):
        raise AssertionError(f"{name}: wrong-path MMIO/fence side effects escaped")
    results.append({"case": "squashed-store-CSR-atomic-MMIO-fence", "compared": True})
    run.receipt["coverage"][name] = {"required": len(results), "compared": results}
    run.save()
    return results


def precise_store_program():
    code = [0x10000A37, ri(2, 0, 7), store(20, 2), ri(2, 0, 99),
            ri(1, 0, 512), csr_insn(0x305, 0, 1), 0xFFFFFFFF,
            store(20, 2), ri(3, 20, 0, 3, 3), 0x00100073]
    code.extend([0] * (128 - len(code)))
    code.extend((ri(4, 20, 0, 3, 3), csr_insn(0x341, 1, 0, 2),
                 ri(1, 1, 8), csr_insn(0x341, 0, 1), 0x30200073))
    return code


def atomic_directed_cases(run, name, config):
    compared = {}
    pairs = OPERAND_PAIRS
    for width in (2, 3):
        for op in (0, 1, 4, 8, 12, 16, 20, 24, 28):
            program = [0x10000A37]
            obligations = []
            for index, (old, rhs) in enumerate(pairs):
                if width == 2 and index in (4, 5):
                    old, rhs = ((1 << 31, (1 << 64) - 1) if index == 4 else
                                ((1 << 31) - 1, 1 << 31))
                program.extend((*constant(1, old), *constant(2, rhs), store(20, 1)))
                obligations.append((len(program) * 4, rhs))
                program.extend((amo(op, 3, width=width, ordering=index & 3),
                                ri(4, 20, 0, 3, 3)))
            program.extend((amo(op, 0, width=width, ordering=3), 0x00100073))
            label = f"{name}-amo-{width}-{op}"
            counts = top_case(run, label, program, "verilator", config)
            for pc, rhs in obligations:
                if counts["retire_pc_hits"].get(str(pc)) != 1 or (
                        counts["operand_samples"].get(str(pc)) != [[0x10000000, rhs]]):
                    raise AssertionError(f"{label}: required operand pair did not execute at {pc:#x}")
            compared[f"{width}-{op}"] = len(obligations)
        program = [0x10000A37]
        obligations = []
        for index, (old, rhs) in enumerate(pairs):
            if width == 2 and index in (4, 5):
                old, rhs = ((1 << 31, (1 << 64) - 1) if index == 4 else
                            ((1 << 31) - 1, 1 << 31))
            program.extend((*constant(1, old), *constant(2, rhs), store(20, 1)))
            lr_pc = len(program) * 4
            program.extend((amo(2, 3, rs2=0, width=width, ordering=index & 3),
                            amo(3, 4, width=width, ordering=index & 3),
                            amo(3, 5, width=width, ordering=index & 3)))
            obligations.append(lr_pc)
        program.append(0x00100073)
        counts = top_case(run, f"{name}-lr-sc-{width}", program, "verilator", config)
        for pc in obligations:
            if any(counts["retire_pc_hits"].get(str(site)) != 1 for site in (pc, pc + 4, pc + 8)):
                raise AssertionError(f"{name}: LR/SC operand denominator did not retire")
            if counts["result_samples"].get(str(pc + 4)) != [[1, 4, 0, 1]] or (
                    counts["result_samples"].get(str(pc + 8)) != [[1, 5, 1, 0]]):
                raise AssertionError(f"{name}: successful/failed SC result denominator")
        compared[f"{width}-LR"] = compared[f"{width}-SC"] = len(obligations)
    if len(compared) != 22 or any(value < 8 for value in compared.values()):
        raise AssertionError(f"{name}: atomic width/operation denominator incomplete")
    run.receipt["coverage"][name] = {"required": {key: 8 for key in compared},
                                    "compared": compared, "aq_rl_combinations_per_operation": 4}
    run.save()
    return compared


def atomic_fault_cases(run, name, config):
    results = []
    addresses = (0x10000001, 0x10000000 + config["DMEM_WORDS"] * 8,
                 0x110000000, 0x02000000, 0x40000000, 0)
    for width in (2, 3):
        for operation in (2, 3, 0):
            for index, address in enumerate(addresses):
                cause = (4 if operation == 2 else 6) if address & ((1 << width) - 1) else (
                    5 if operation == 2 else 7)
                program = [*constant(20, address), ri(2, 0, 7),
                           amo(operation, 3, rs2=0 if operation == 2 else 2, width=width),
                           0x10000B37, store(22, 2), 0x00100073]
                label = f"{name}-{width}-{operation}-{index}"
                counts = top_case(run, label, program, "verilator", config, terminal_cause=cause)
                if counts["trap_causes"] != {str(cause): 1} or counts["axi_transactions"]:
                    raise AssertionError(f"{label}: atomic fault classification/no-MMIO requirement")
                results.append({"width": width, "operation": operation, "address": address,
                                "cause": cause, "compared": True})
    for index, instruction in enumerate((amo(2, 3, rs2=2), amo(7, 3), amo(0, 3, width=0),
                                         amo(2, 3, rs2=1, width=2), amo(31, 3, width=2))):
        counts = top_case(run, f"{name}-encoding-{index}",
                          [0x10000A37, ri(2, 0, 7), instruction, store(20, 2), 0x00100073],
                          "verilator", config, terminal_cause=2)
        if counts["trap_causes"] != {"2": 1}:
            raise AssertionError(f"{name}: reserved atomic instruction did not fault precisely")
        results.append({"illegal_encoding": f"{instruction:08x}", "cause": 2, "compared": True})
    run.receipt["coverage"][name] = {"required": len(results), "compared": results}
    run.save()
    return results


def halt_reset_reservation_cases(run, name, config):
    program = [0x10000A37, ri(2, 0, 7), amo(2, 3, rs2=0),
               amo(3, 4), ri(5, 20, 0, 3, 3), 0x00100073]
    for write in (0, 1, 2):
        counts = top_case(run, f"{name}-halt-host-{write}", program, "verilator",
                          config, pause_pc=8, pause_write=write)
        if counts["halt_resume_epochs"] != 1 or counts["host_execution_writes"] != int(write != 0):
            raise AssertionError(f"{name}: halt/host/resume sequence not observed")
        expected = [1, 4, 99 if write == 2 else 1, 0]
        if counts["result_samples"].get("12") != [expected]:
            raise AssertionError(f"{name}: halt invalidation/instruction coherency result not compared")
    counts = top_case(run, name + "-running-reset", program, "verilator", config, reset_pc=8)
    if counts["reset_epochs"] != 1 or counts["halt_resume_epochs"] != 0 or (
            counts["result_samples"].get("12") != [[1, 4, 1, 0]]):
        raise AssertionError(f"{name}: running reset did not independently invalidate reservation")
    program = [0x10000A37, ri(2, 0, 7), ri(1, 0, 512), csr_insn(0x305, 0, 1),
               amo(2, 3, rs2=0), 0x00000073, amo(3, 4), 0x00100073]
    counts = top_case(run, name + "-trap", recovering_handler(program), "verilator", config)
    if counts["result_samples"].get("24") != [[1, 4, 1, 0]] or counts["returns"] != 1:
        raise AssertionError(f"{name}: trap-entry reservation invalidation was not compared")


def host_coherence_case(run, name, config):
    program = [0x10000A37, *constant(2, 0x1122334455667788), store(20, 2)]
    pause_pc = len(program) * 4
    program.extend((amo(2, 3, rs2=0), ri(5, 20, 0, 3, 3), 0x00100073))
    counts = top_case(run, name, program, "verilator", config, pause_pc=pause_pc,
                      pause_write=3, pause_early=True)
    if counts["halt_resume_epochs"] != 1 or counts["host_execution_writes"] != 8 or (
            counts["host_intermediate_reads"] != 8):
        raise AssertionError(f"{name}: eight partial host writes/readbacks were not compared")
    return counts


def boundary_cases(run, name):
    results = {}
    results["C"] = top_case(run, name + "-C-fetch-end", [ri(1, 0, 7)], "verilator",
                            configuration("C"), terminal_cause=1)
    for label, config in (("D", configuration("D")), ("A", configuration("A")),
                          ("three", {**configuration("C"), "IMEM_WORDS": 3, "DMEM_WORDS": 3})):
        if label == "three":
            program = [0x10000A37, store(20, 0, 16), 0x00100073]
        else:
            program = [*constant(20, 0x10000000 + config["DMEM_WORDS"] * 8 - 8),
                       ri(1, 0, -1), store(20, 1), ri(2, 20, 0, 3, 3),
                       0x0000100F, 0x00100073]
        results[label] = top_case(run, name + "-" + label + "-last-beat", program,
                                 "verilator", config)
    return results


def reservation_case(run, name, config):
    program, outcomes = reservation_program()
    counts = top_case(run, name, program, "verilator", config)
    for pc, expected in outcomes:
        insn = program[pc // 4]
        rd = (insn >> 7) & 31
        result = [int(rd != 0), rd, expected if rd else 0, int(expected == 0)]
        if counts["retire_pc_hits"].get(str(pc)) != 1 or (
                counts["result_samples"].get(str(pc)) != [result]):
            raise AssertionError(f"{name}: reservation result at {pc:#x}, "
                                 f"required={result}, observed={counts['result_samples'].get(str(pc))}")
    counts["reservation_outcomes_required"] = len(outcomes)
    counts["reservation_outcomes_compared"] = len(outcomes)
    run.save()
    return counts


def lock_case(run, name, config, width):
    program, (failed_pc, successful_pc) = lock_program(width)
    counts = top_case(run, name, program, "verilator", config)
    for pc, expected in ((failed_pc, [1, 4, 1, 0]), (successful_pc, [1, 5, 0, 1])):
        if counts["retire_pc_hits"].get(str(pc)) != 32 or (
                counts["result_samples"].get(str(pc)) != [expected]):
            raise AssertionError(f"{name}: 32-lock denominator/result not met at {pc:#x}")
    counts.update(lock_acquisitions_required=32, lock_acquisitions_compared=32,
                  sc_retry_failures_compared=32, scope="single-hart competing-store interference")
    run.save()
    return counts


def cache_pressure_case(run, name, config, seed):
    counts = top_case(run, name, cache_pressure_program(config, seed), "verilator",
                      config, cache_traffic=True)
    thresholds = {"icache": {"read_hits": 16, "misses": 16},
                  "dcache": {"read_hits": 16, "write_hits": 16,
                             "misses": 16, "dirty_evictions": 8}}
    for channel, required in thresholds.items():
        for item, minimum in required.items():
            if counts[channel][item] < minimum:
                raise AssertionError(f"{name}: monitored {channel}.{item}: "
                                     f"required>={minimum}, observed={counts[channel][item]}")
    expected_cleans = counts["fences"] + counts["fence_i"] + 1
    if counts["dcache"]["command_2"] != expected_cleans:
        raise AssertionError(f"{name}: retired fences plus halt require {expected_cleans} D cleans; "
                             f"observed={counts['dcache']['command_2']}")
    if counts["icache"]["runtime_command_3"] != counts["fence_i"]:
        raise AssertionError(f"{name}: each retired FENCE.I requires one observed I invalidation")
    counts["cache_thresholds"] = thresholds
    counts["seed"] = seed
    run.save()
    return counts


def clint_case(run, name, seed=17, simulator="verilator"):
    case = run.directory / name
    case.mkdir()
    stimulus = clint_model.vectors(seed)
    vector_path = case / "vectors.txt"
    vector_path.write_text("".join(
        f"{reset} {valid} {write} {size} {address:016x} {data:016x} {strobe:02x} {ready}\n"
        for reset, valid, write, size, address, data, strobe, ready in stimulus))
    sources = ["rtl/hammer_v2_clint.sv", "tests/clint_bridge.sv"]
    if simulator == "iverilog":
        binary = case / "sim.vvp"
        run.command(name + "-compile", ["iverilog", "-g2012", "-Wall", "-s", "clint_bridge",
                                        "-o", run.relative(binary), *sources])
        executable = ["vvp", run.relative(binary)]
    else:
        key = ("clint", simulator)
        if key in run.build_cache:
            executable = run.build_cache[key]
        else:
            obj = case / "compile-obj"
            run.command(name + "-compile", ["verilator", "--binary", "--timing", "-Wno-fatal",
                        "--top-module", "clint_bridge", "--Mdir", run.relative(obj),
                        "-j", "2", *sources])
            binary = case / "simulator"
            shutil.copyfile(obj / "Vclint_bridge", binary)
            binary.chmod(0o755)
            shutil.rmtree(obj)
            executable = [run.relative(binary)]
            run.build_cache[key] = executable
    event_path = case / "events.txt"
    run.command(name + "-simulate", [*executable, f"+vectors={run.relative(vector_path)}",
                f"+events={run.relative(event_path)}"],
                timeout=60 if simulator == "iverilog" else 3600)
    counts = clint_model.compare(event_path, stimulus)
    run.receipt["comparisons"][name] = counts
    run.save()
    return counts


def advanced_privilege_cases(run, name, config):
    results = {}
    results["permissions"] = top_case(run, name + "-counter-permissions",
                                    counter_permission_program(), "verilator", config)
    if set(results["permissions"]["privileges"]) != {"0", "1", "3"}:
        raise AssertionError(f"{name}: allowed counter reads did not exercise M/S/U")
    counts = top_case(run, name + "-return-state", return_state_program(), "verilator", config)
    if counts["returns"] != 4 or counts["retire_pc_hits"].get("512") != 2:
        raise AssertionError(f"{name}: return status/MPRV stack observations not compared")
    results["returns"] = counts
    for supervisor in (False, True):
        counts = top_case(run, name + f"-M-return-{int(supervisor)}",
                          machine_return_program(supervisor), "verilator", config)
        if counts["returns"] != (2 if supervisor else 1):
            raise AssertionError(f"{name}: M-mode return/MPRV/TSR behavior was not compared")
        results[f"M-return-{int(supervisor)}"] = counts
    counts = top_case(run, name + "-M-never-delegates", machine_delegation_program(),
                      "verilator", config)
    if counts["trap_causes"] != {"2": 1, "3": 1} or counts["returns"] != 1:
        raise AssertionError(f"{name}: M-mode exception delegation suppression not compared")
    results["M-never-delegates"] = counts
    program, trigger_pc = vectored_interrupt_program()
    counts = top_case(run, name + "-vectored", program, "verilator", config,
                      irq_trigger_pc=trigger_pc, clint_traffic=True)
    if counts["interrupt_sequence"] != [[cause, 3] for cause in (11, 3, 7, 9, 1, 5)]:
        raise AssertionError(f"{name}: vectored six-source priority not compared")
    if counts["returns"] != 6:
        raise AssertionError(f"{name}: vectored handler returns incomplete")
    results["vectored"] = counts
    for enabled in (False, True):
        program, trigger_pc = wfi_program(enabled)
        label = f"{name}-wfi-global-{int(enabled)}"
        counts = top_case(run, label, program, "verilator", config,
                          irq_trigger_pc=trigger_pc, irq_delay=20)
        expected = [[11, 3]] if enabled else []
        if counts["interrupt_sequence"] != expected:
            raise AssertionError(f"{label}: WFI wake/global enable result")
        observed = list(read_events(run.directory / label / "events.bin"))
        changes = [edge for kind, edge, event in observed if kind == 7 and event["meip"]]
        retires = [edge for kind, edge, event in observed
                   if kind == 1 and event["pc"] == trigger_pc + 4]
        wfi_edges = counts["retire_edges"].get(str(trigger_pc), [])
        if len(changes) != 1 or len(retires) != 1 or len(wfi_edges) != 1 or not (
                wfi_edges[0] < changes[0] < retires[0]):
            raise AssertionError(f"{label}: WFI did not retire, wait, then wake on local pending")
        results[f"wfi-{int(enabled)}"] = counts
    return results


def mmio_case(run, name, config, seed=17, interrupts=False):
    counts = top_case(run, name, mmio_program(seed, interrupts), "verilator", config,
                      irq_source=2 if interrupts else 0)
    if counts["axi_transactions"] != 41 or counts["axi_errors"] != 2:
        raise AssertionError(f"{name}: MMIO exact transaction/error denominator: "
                             f"{counts['axi_transactions']}, {counts['axi_errors']}")
    if not all(counts["axi_write_order"].get(order) for order in ("1", "2")):
        raise AssertionError(f"{name}: independent W-before-AW/AW-before-W not observed")
    if not all(counts["axi_stall_edges"].values()):
        raise AssertionError(f"{name}: MMIO independent channel stalls not observed")
    if counts["interrupt_sequence"] != ([[11, 3]] if interrupts else []):
        raise AssertionError(f"{name}: interrupt around outstanding MMIO mismatch")
    if interrupts:
        pending = []
        interrupted_operation = None
        trap_edge = None
        irq_edge = None
        for kind, edge, event in read_events(run.directory / name / "events.bin"):
            if kind == 8:
                pending.append(event)
            elif kind == 7 and event["meip"] and irq_edge is None:
                irq_edge = edge
            elif kind == 1 and event["mem_valid"] and 0x40000000 <= event["mem_addr"] < 0x40010000:
                if interrupted_operation is None:
                    interrupted_operation = edge
            elif kind == 2 and event["interrupt"]:
                trap_edge = edge
        if not pending or not (irq_edge < interrupted_operation < trap_edge):
            raise AssertionError(f"{name}: MMIO side effect must retire before interrupt entry")
    return counts


def interrupted_muldiv_case(run, name, config):
    counts = top_case(run, name, interrupted_muldiv_program(), "verilator", config, irq_source=1)
    events = list(read_events(run.directory / name / "events.bin"))
    irq_edges = [edge for kind, edge, event in events if kind == 7 and event["meip"]]
    div_edges = [edge for kind, edge, event in events
                 if kind == 1 and event["insn"] == rr(4, 2, 3, 4, 1)]
    trap_edges = [edge for kind, edge, event in events if kind == 2 and event["interrupt"]]
    if counts["interrupt_sequence"] != [[11, 3]] or not counts["muldiv_stall"] or (
            len(irq_edges) != 1 or len(div_edges) != 1 or len(trap_edges) != 1 or not
            irq_edges[0] < div_edges[0] < trap_edges[0]):
        raise AssertionError(f"{name}: stalled divide completion before IRQ entry was not compared")
    return counts


def integrated_clint_cases(run, name, config, seed):
    results = []
    for register in range(3):
        counts = top_case(run, f"{name}-{register}", clint_program(register, seed), "verilator",
                          config, clint_traffic=True)
        expected = 3 if register == 0 else 2
        if counts["trap_causes"] != {"5": expected, "7": expected, "3": 1}:
            raise AssertionError(f"{name}: integrated CLINT hole/width/high-alias fault denominator")
        for item in ("mtip_rises", "mtip_falls", "msip_rises", "msip_falls"):
            if not counts["clint"][item]:
                raise AssertionError(f"{name}: CLINT level transition did not execute: {item}")
        results.append(counts["clint"])
    return results


def predictor_cases(run, compact=False):
    ledger = []
    for prediction in (0, 1):
        for entries in ((1, 64) if compact else (1, 4, 16, 64)):
            for legacy in (0, 1):
                config = {**configuration("B", legacy), "PRED_MODE": prediction,
                          "BTB_ENTRIES": entries}
                program, sites = predictor_program(entries)
                name = f"predictor-{prediction}-{entries}-legacy-{legacy}"
                counts = top_case(run, name, program, "verilator", config)
                if any(counts["retire_pc_hits"].get(str(pc)) != 8 for pc in sites):
                    raise AssertionError(f"{name}: colliding branch sites not each compared eight times")
                if counts["branch_outcomes"].get("1-0") != 1 or (
                        counts["branch_outcomes"].get("1-1") != 7):
                    raise AssertionError(f"{name}: predictor taken/not-taken transitions not compared")
                # Dependency and forwarding behavior is checked independently
                # from collision behavior, with the same compiled configuration.
                dependency = top_case(run, name + "-dependencies", smoke_program(),
                                      "verilator", config)
                pipeline_latency_case(run, name + "-dependencies")
                for item in ("ex_mem_forward", "mem_wb_forward", "load_use", "muldiv_stall"):
                    if not dependency[item]:
                        raise AssertionError(f"{name}: required public pipeline event not observed: {item}")
                ledger.append({"configuration": config, "branch_sites": sites,
                               "branch_site_visits": [8, 8],
                               "dependency_compared": dependency["retirements"]})
    result = {"required": 8 if compact else 16, "compared": len(ledger),
              "ledger": ledger, "scope": "bounded subset" if compact else "all predictor/trap-policy pairs"}
    run.receipt["coverage"]["predictors"] = result
    run.save()
    return result


def pipeline_latency_case(run, name):
    observed = list(read_events(run.directory / name / "events.bin"))
    execute = [edge for kind, edge, event in observed
               if kind == 5 and event["pc"] == 0 and event["flags"] & 8]
    commit = [edge for kind, edge, event in observed if kind == 1 and event["pc"] == 0]
    if len(execute) != 1 or len(commit) != 1 or commit[0] - execute[0] != 3:
        raise AssertionError(f"{name}: unstalled ID/EX through EX/MEM, MEM/WB, commit "
                             f"requires three edges; execute={execute}, commit={commit}")
    stalls = [edge for kind, edge, event in observed if kind == 5 and
              execute[0] <= edge <= commit[0] and event["flags"] & 7]
    if stalls:
        raise AssertionError(f"{name}: latency fixture unexpectedly stalled at {stalls}")
    run.receipt["coverage"][name + "-pipeline"] = {
        "id_ex_edge": execute[0], "commit_edge": commit[0],
        "required_edges": 3, "observed_edges": 3,
    }
    run.save()


def top_case(run, name, program, simulator="iverilog", config=None, reference=False,
             source_root=ROOT, irq_trigger_pc=None, cache_traffic=False,
             terminal_cause=3, pause_pc=None, pause_write=False, irq_delay=0, irq_source=0,
             reset_pc=None, pause_early=False, clint_traffic=False):
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
        argv += [*rtl, "tests/axi_slave.sv", "tests/top_bridge.sv"]
        run.command(f"{name}-compile", argv)
        executable = ["vvp", run.relative(binary)]
    else:
        obj = case / "compile-obj"
        argv = ["verilator", "--binary", "--timing", "-Wno-fatal",
                "--top-module", "top_bridge", "--Mdir", run.relative(obj), "-j", "2"]
        argv += [f"-G{k}={v}" for k, v in config.items()]
        if reference:
            argv.append("-DPARENT_REFERENCE")
        observers = [] if reference else ["tests/cache_observer.sv", "tests/clint_observer.sv"]
        run.command(f"{name}-compile", [*argv, *rtl, "tests/axi_slave.sv",
                                      "tests/top_bridge.sv", *observers])
        binary = case / "simulator"
        shutil.copyfile(obj / "Vtop_bridge", binary)
        binary.chmod(0o755)
        executable = [run.relative(binary)]
        shutil.rmtree(obj)
    run.build_cache[key] = executable
    event_path = case / "events.bin"
    extra_args = [] if irq_trigger_pc is None else [f"+irq_trigger_pc={irq_trigger_pc:x}"]
    extra_args.append(f"+terminal_cause={terminal_cause:x}")
    extra_args.append(f"+irq_delay={irq_delay}")
    extra_args.append(f"+irq_source={irq_source}")
    if pause_pc is not None:
        extra_args += [f"+pause_pc={pause_pc:x}", f"+pause_write={int(pause_write)}"]
        extra_args.append(f"+pause_early={int(pause_early)}")
    if reset_pc is not None:
        extra_args.append(f"+reset_pc={reset_pc:x}")
    if cache_traffic:
        if simulator != "verilator" or reference:
            raise AssertionError("bound public-cache-pin monitors require V2 compiled simulation")
        extra_args += [f"+icache_events={run.relative(case / 'icache.txt')}",
                       f"+dcache_events={run.relative(case / 'dcache.txt')}"]
    if clint_traffic:
        if simulator != "verilator" or reference or reset_pc is not None:
            raise AssertionError("integrated CLINT observer requires one V2 compiled reset epoch")
        extra_args.append(f"+clint_events={run.relative(case / 'clint.txt')}")
    run.command(f"{name}-simulate", [
        *executable, f"+program={run.relative(case / 'program.hex')}",
        f"+data={run.relative(case / 'data.hex')}",
        f"+events={run.relative(event_path)}", "+cycles=200000", *extra_args,
    ], timeout=60 if simulator == "iverilog" else 3600)
    clint_operations, clint_counts = (clint_model.compare_integrated(case / "clint.txt")
                                      if clint_traffic else (None, None))
    counts = compare_top(run, event_path, padded, config["DMEM_WORDS"],
                         bool(config["LEGACY_TRAPS"]), reference=reference,
                         terminal_cause=terminal_cause, clint_operations=clint_operations)
    if clint_traffic:
        counts["clint"] = clint_counts
    if cache_traffic:
        for prefix, lines, image, readonly in (
                ("i", config["ICACHE_LINES"],
                 b"".join(word.to_bytes(4, "little") for word in padded), True),
                ("d", config["DCACHE_LINES"], bytes(config["DMEM_WORDS"] * 8), False)):
            counts[prefix + "cache"] = compare_integrated_cache(
                case / (prefix + "cache.txt"), lines, image, readonly)
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
    memory_inference = []
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
                memory_inference.append({
                    "module": original_name(key, module), "type": typ,
                    "width": width, "size": size,
                    "read_ports": int(parameters.get("RD_PORTS", "0"), 2),
                    "read_clock_enable": parameters.get("RD_CLK_ENABLE"),
                    "write_ports": int(parameters.get("WR_PORTS", "0"), 2),
                    "write_clock_enable": parameters.get("WR_CLK_ENABLE"),
                })
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
    minimum_state = {
        "hammer_v2_csr": 1000, "hammer_v2_regfile": 31 * 64,
        "hammer_v2_cache": 256 * (config["ICACHE_LINES"] + config["DCACHE_LINES"]),
        "hammer_v2_ram": config["IMEM_WORDS"] * 32 + config["DMEM_WORDS"] * 64,
    }
    for module, minimum in minimum_state.items():
        if module_state.get(module, 0) < minimum:
            raise AssertionError(f"{name}: {module} state bits required>={minimum}, "
                                 f"observed={module_state.get(module, 0)}")
    result = {"configuration": config, **totals, "state_by_original_module": module_state,
              "state_bits_required": minimum_state, "memory_inference": memory_inference}
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
        ("private absolute path", re.compile(
            r"(?<![\w./-])(?:/(?:data|home|Users|root|tmp)/|[~]/)[^\s\"']+")),
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
    run.receipt["coverage"]["mutation_categories_required"] = [entry[0] for entry in mutations]
    run.save()
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


def initialize_suites(run, suites):
    run.receipt["coverage"]["suite_status"] = {suite: "not_run" for suite in suites}
    run.receipt["coverage"]["matrices"] = {
        suite: [{"configuration": label, "parameters": configuration(label), "seed": seed,
                 "status": "not_run", "experiments": []}
                for label in ("A", "B") for seed in (17, 29, 53)]
        for suite in suites if suite in ("compatibility", "privileged", "atomic", "cache")
    }
    run.save()


def full_matrix(run, suite, execute):
    rows = run.receipt["coverage"]["matrices"][suite]
    if len(rows) != 6:
        raise AssertionError(f"{suite}: frozen full matrix requires exactly six rows")
    for row in rows:
        row["status"] = "running"
        run.save()
        name = f"{suite}-{row['configuration']}-seed{row['seed']}"
        before = set(run.receipt["comparisons"])
        execute(name, row["parameters"], row["seed"])
        row["experiments"] = sorted(set(run.receipt["comparisons"]) - before)
        if not row["experiments"]:
            raise AssertionError(f"{name}: no actual comparisons were recorded")
        row["status"] = "passed"
        run.save()
    if any(row["status"] != "passed" for row in rows):
        raise AssertionError(f"{suite}: full matrix incomplete")


def compatibility_suite(run):
    run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++"))
    top_case(run, "compatibility-compact-icarus", smoke_program())
    pipeline_latency_case(run, "compatibility-compact-icarus")
    parameter_cases(run)
    predictor_cases(run)

    def execute(name, config, seed):
        random_case(run, name + "-random", seed, config)
        integer_directed_cases(run, name + "-integer-directed", config)
        memory_control_directed_cases(run, name + "-memory-directed", config)
        mmio_case(run, name + "-mmio", config, seed)
        control_fault_cases(run, name + "-control-faults", config)
        parent_differential(run, name + "-parent",
                            integer_program(seed=seed, count=2000, looped=True),
                            {**config, "LEGACY_TRAPS": 1})

    full_matrix(run, "compatibility", execute)
    boundary_cases(run, "compatibility-boundaries")


def privileged_suite(run):
    run.tools(("python3", "verilator", "make", "g++"))
    for seed in (17, 29, 53):
        clint_case(run, f"privileged-clint-seed{seed}", seed)

    def execute(name, config, seed):
        counts = top_case(run, name + "-faults", fault_program(), "verilator", config)
        required_causes = {"2", "3", "4", "5", "6", "7", "8", "9", "11"}
        if not required_causes <= set(counts["trap_causes"]) or (
                set(counts["privileges"]) != {"0", "1", "3"}):
            raise AssertionError(f"{name}: privilege/exception denominator incomplete")
        counts = top_case(run, name + "-csr-counters", counter_program(), "verilator", config)
        if set(counts["csr_forms"]) != {"1", "2", "3", "5", "6", "7"}:
            raise AssertionError(f"{name}: all six CSR forms were not compared")
        advanced_privilege_cases(run, name + "-advanced", config)
        program, trigger_pc = interrupt_program()
        counts = top_case(run, name + "-direct-priority", program, "verilator", config,
                          irq_trigger_pc=trigger_pc, clint_traffic=True)
        if counts["interrupt_sequence"] != [[cause, 3] for cause in (11, 3, 7, 9, 1, 5)] or (
                counts["returns"] != 6):
            raise AssertionError(f"{name}: six-source direct interrupt priority/returns")
        counts = top_case(run, name + "-MTIP", timer_program(), "verilator", config,
                          clint_traffic=True)
        if counts["timer_interrupts"] != 3 or counts["returns"] != 3:
            raise AssertionError(f"{name}: three separately acknowledged MTIP returns required")
        counts = top_case(run, name + "-STIP", supervisor_timer_program(), "verilator", config)
        if counts["interrupt_sequence"] != [[5, 1]] or counts["returns"] != 2:
            raise AssertionError(f"{name}: delegated STIP/SRET required")
        for source in (0, 1):
            counts = top_case(run, f"{name}-delegated-ECALL-{source}",
                              delegated_exception_program(source), "verilator", config)
            if counts["trap_causes"].get(str(8 + source)) != 1 or counts["returns"] != 2:
                raise AssertionError(f"{name}: delegated U/S exception entry/return required")
        top_case(run, name + "-precise-younger-store", precise_store_program(), "verilator", config)
        mmio_case(run, name + "-MMIO-interrupt", config, seed, interrupts=True)
        interrupted_muldiv_case(run, name + "-muldiv-interrupt", config)
        integrated_clint_cases(run, name + "-CLINT", config, seed)

    full_matrix(run, "privileged", execute)


def atomic_suite(run):
    run.tools(("python3", "verilator", "make", "g++"))

    def execute(name, config, seed):
        atomic_directed_cases(run, name + "-directed", config)
        reservation_case(run, name + "-reservations", config)
        for width in (2, 3):
            lock_case(run, name + f"-lock-{width}", config, width)
        atomic_fault_cases(run, name + "-faults", config)
        halt_reset_reservation_cases(run, name + "-epochs", config)

    full_matrix(run, "atomic", execute)


def cache_suite(run):
    run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++"))
    cache_case(run, "cache-compact-icarus-D", 1, 17, False, "iverilog")
    cache_case(run, "cache-compact-icarus-I", 1, 3, True, "iverilog")
    clint_case(run, "cache-compact-icarus-CLINT", simulator="iverilog")
    for label in ("A", "B", "C", "D"):
        config = configuration(label)
        cache_case(run, "cache-leaf-" + label + "-I", config["ICACHE_LINES"],
                   config["IMEM_WORDS"], True)
        cache_case(run, "cache-leaf-" + label + "-D", config["DCACHE_LINES"],
                   config["DMEM_WORDS"], False)

    def execute(name, config, seed):
        cache_pressure_case(run, name + "-traffic", config, seed)
        host_coherence_case(run, name + "-host-partial", config)
        program = [0x10000A37, ri(2, 0, 7), amo(2, 3, rs2=0),
                   amo(3, 4), ri(5, 20, 0, 3, 3), 0x00100073]
        counts = top_case(run, name + "-host-I-invalidation", program, "verilator", config,
                          pause_pc=8, pause_write=2)
        if counts["result_samples"].get("12") != [[1, 4, 99, 0]]:
            raise AssertionError(f"{name}: host instruction rewrite did not retire the new instruction")

    full_matrix(run, "cache", execute)
    boundary_cases(run, "cache-boundaries")


def execute_suite(run, suite):
    run.receipt["coverage"]["suite_status"][suite] = "running"
    run.save()
    if suite == "compatibility":
        compatibility_suite(run)
    elif suite == "privileged":
        privileged_suite(run)
    elif suite == "atomic":
        atomic_suite(run)
    elif suite == "cache":
        cache_suite(run)
    elif suite == "sensitivity":
        run.tools(("python3", "verilator", "make", "g++"))
        sensitivity_cases(run)
    elif suite == "synthesis":
        run.tools(("python3", "yosys"))
        run.receipt["coverage"]["synthesis_configurations_required"] = ["A", "C", "D"]
        run.save()
        for name in ("A", "C", "D"):
            synthesis_case(run, name, configuration(name))
    elif suite == "portable":
        run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++", "yosys"))
        portable_case(run)
    else:
        raise AssertionError(f"unknown mandatory suite: {suite}")
    run.receipt["coverage"]["suite_status"][suite] = "passed"
    run.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=(*SUITES, "all"), default="all")
    parser.add_argument("--probe", choices=("smoke", "integer", "atomic", "privilege", "timer", "faults", "memory", "synthesis",
                                           "portable", "clean-copy-child", "parameters", "cache-leaf",
                                           "parent", "mutants", "mutants-remaining",
                                           "interrupts", "random-matrix", "parameter-matrix",
                                           "directed-integer", "reservations", "locks", "counters",
                                           "delegated-exception", "cache-pressure", "clint",
                                           "halt-reservation", "boundaries", "directed-memory",
                                           "atomic-denominators", "precise-store",
                                           "advanced-privilege", "predictors", "mmio",
                                           "stalled-interrupts", "atomic-faults", "reservation-epochs",
                                           "final-leaves", "host-coherence", "integrated-clint",
                                           "control-faults"),
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
        if not args.probe:
            suites = SUITES if args.suite == "all" else (args.suite,)
            initialize_suites(run, suites)
            for suite in suites:
                execute_suite(run, suite)
        elif args.probe == "control-faults":
            run.tools(("python3", "verilator", "make", "g++"))
            control_fault_cases(run, "B-control", configuration("B"))
        elif args.probe == "integrated-clint":
            run.tools(("python3", "verilator", "make", "g++"))
            integrated_clint_cases(run, "B-integrated-CLINT", configuration("B"), 17)
            counts = top_case(run, "B-observed-MTIP", timer_program(), "verilator",
                              configuration("B"), clint_traffic=True)
            if counts["timer_interrupts"] != 3 or counts["returns"] != 3:
                raise AssertionError("accepted-edge timer model requires three acknowledged interrupts")
        elif args.probe == "host-coherence":
            run.tools(("python3", "verilator", "make", "g++"))
            for name in ("A", "B"):
                host_coherence_case(run, name + "-host-coherence", configuration(name))
        elif args.probe == "final-leaves":
            run.tools(("python3", "verilator", "make", "g++"))
            for name in ("C", "D"):
                config = configuration(name)
                for readonly, prefix in ((True, "I"), (False, "D")):
                    cache_case(run, f"{name}-{prefix}", config[prefix + "CACHE_LINES"],
                               config["IMEM_WORDS" if readonly else "DMEM_WORDS"], readonly)
            top_case(run, "B-new-counter-rules", counter_program(), "verilator", configuration("B"))
            top_case(run, "B-S-delegation", delegated_exception_program(1),
                     "verilator", configuration("B"))
        elif args.probe in ("atomic-faults", "reservation-epochs"):
            run.tools(("python3", "verilator", "make", "g++"))
            if args.probe == "atomic-faults":
                atomic_fault_cases(run, "B-atomic-faults", configuration("B"))
            else:
                halt_reset_reservation_cases(run, "B-epochs", configuration("B"))
        elif args.probe in ("mmio", "stalled-interrupts"):
            run.tools(("python3", "verilator", "make", "g++"))
            if args.probe == "mmio":
                mmio_case(run, "B-mmio", configuration("B"))
            else:
                mmio_case(run, "B-mmio-interrupt", configuration("B"), interrupts=True)
                interrupted_muldiv_case(run, "B-muldiv-interrupt", configuration("B"))
        elif args.probe in ("advanced-privilege", "predictors"):
            run.tools(("python3", "verilator", "make", "g++"))
            if args.probe == "advanced-privilege":
                advanced_privilege_cases(run, "B-advanced", configuration("B"))
            else:
                predictor_cases(run, compact=True)
        elif args.probe in ("directed-memory", "atomic-denominators", "precise-store"):
            run.tools(("python3", "verilator", "make", "g++"))
            if args.probe == "directed-memory":
                memory_control_directed_cases(run, "B-memory-control", configuration("B"))
            elif args.probe == "atomic-denominators":
                atomic_directed_cases(run, "B-atomic-directed", configuration("B"))
            else:
                top_case(run, "B-precise-store", precise_store_program(), "verilator",
                         configuration("B"))
        elif args.probe == "halt-reservation":
            run.tools(("python3", "verilator", "make", "g++"))
            program = [0x10000A37, ri(2, 0, 7), amo(2, 3, rs2=0),
                       amo(3, 4), ri(5, 20, 0, 3, 3), 0x00100073]
            for write in (False, True):
                counts = top_case(run, f"B-halt-host-{int(write)}", program, "verilator",
                                  configuration("B"), pause_pc=8, pause_write=write)
                if counts["halt_resume_epochs"] != 1 or counts["host_execution_writes"] != int(write):
                    raise AssertionError("halt/host/resume sequence not observed")
        elif args.probe == "boundaries":
            run.tools(("python3", "verilator", "make", "g++"))
            boundary_cases(run, "bounds")
        elif args.probe == "clint":
            run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++"))
            clint_case(run, "clint-icarus", simulator="iverilog")
            clint_case(run, "clint-verilator")
        elif args.probe == "cache-pressure":
            run.tools(("python3", "verilator", "make", "g++"))
            for name in ("A", "B"):
                cache_pressure_case(run, name + "-cache-seed17", configuration(name), 17)
        elif args.probe in ("directed-integer", "reservations", "locks", "counters",
                            "delegated-exception"):
            run.tools(("python3", "verilator", "make", "g++"))
            config = configuration("B")
            if args.probe == "directed-integer":
                integer_directed_cases(run, "B-directed", config)
            elif args.probe == "reservations":
                reservation_case(run, "B-reservations", config)
            elif args.probe == "locks":
                for width in (2, 3):
                    lock_case(run, f"B-locks-{width}", config, width)
            elif args.probe == "counters":
                top_case(run, "B-counters", counter_program(), "verilator", config)
            else:
                counts = top_case(run, "B-delegated-exception", delegated_exception_program(),
                                  "verilator", config)
                if counts["trap_causes"].get("8") != 1 or counts["returns"] != 2:
                    raise AssertionError("delegated ECALL/SRET comparison not reached")
        elif args.probe == "random-matrix":
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
        elif args.probe in ("mutants", "mutants-remaining"):
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
        elif args.probe in ("parameters", "parameter-matrix"):
            run.tools(("python3", "iverilog", "vvp"))
            parameter_cases(run, compact=args.probe == "parameters")
        elif args.probe == "clean-copy-child":
            run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++", "yosys"))
            top_case(run, "compact-icarus", smoke_program())
            top_case(run, "compact-verilator", smoke_program(), "verilator")
            synthesis_case(run, "C", configuration("C"))
        elif args.probe == "portable":
            run.tools(("python3", "iverilog", "vvp", "verilator", "make", "g++", "yosys"))
            portable_case(run)
        elif args.probe == "smoke":
            run.tools(("python3", "iverilog", "vvp"))
            top_case(run, "compact", smoke_program())
            pipeline_latency_case(run, "compact")
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
    except Exception as error:
        run.finish(error)
        print(f"FAIL: {error}\nreceipt: {run.relative(run.directory / 'receipt.json')}", file=sys.stderr)
        return 1
    error = run.finish()
    if error is not None:
        print(f"FAIL: {error}\nreceipt: {run.relative(run.directory / 'receipt.json')}", file=sys.stderr)
        return 1
    scope = "bounded preparation" if args.probe else args.suite
    print(f"PASS {scope}; receipt: {run.relative(run.directory / 'receipt.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
