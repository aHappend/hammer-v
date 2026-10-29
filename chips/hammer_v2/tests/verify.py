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

    def command(self, label, argv, cwd=ROOT, timeout=3600):
        if time.monotonic() - self.started >= 2650:
            raise RuntimeError("check safeguard: 2700-second execution budget nearly exhausted")
        stdout = self.directory / f"{label}.stdout.txt"
        stderr = self.directory / f"{label}.stderr.txt"
        record = {"argv": [str(x) for x in argv], "cwd": self.relative(cwd),
                  "start": now(), "timeout_s": timeout,
                  "stdout": self.relative(stdout), "stderr": self.relative(stderr),
                  "exit_status": None, "timed_out": False}
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
        if code or record["timed_out"]:
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


def compare_top(run, path, program, dwords, legacy=True):
    model = Machine(program, dwords)
    counts = {"retirements": 0, "traps": 0, "registers": 0, "memory_beats": 0,
              "host_initial_reads": 0, "ex_mem_forward": 0, "mem_wb_forward": 0,
              "load_use": 0, "muldiv_stall": 0}
    counts["timer_interrupts"] = 0
    counts["returns"] = 0
    counts["trap_causes"] = {}
    counts["privileges"] = {}
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
            else:
                try:
                    next_event = model.step(edge)
                except Fault as fault:
                    expected = model.trap(fault)
                else:
                    raise AssertionError(f"unexpected DUT trap {event}; next expected retirement {next_event}")
            actual = tuple(event[x] for x in ("pc", "cause", "tval", "target", "interrupt"))
            if actual != expected:
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


def integer_program(seed=17, count=2000):
    rng = random.Random(seed)
    code = []
    boundaries = (0, 1, (1 << 64) - 1, 1 << 63, (1 << 63) - 1,
                  1 << 31, (1 << 32) - 1, 63)
    for rd, value in enumerate(boundaries, 1):
        code.extend(constant(rd, value))
    for _ in range(count):
        word = rng.choice((False, True))
        rd, a, b = (rng.randrange(1, 32) for _ in range(3))
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


def top_case(run, name, program, simulator="iverilog", config=None):
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
    rtl = [str(p.relative_to(ROOT)) for p in sorted((ROOT / "rtl").glob("*.sv"))]
    if simulator == "iverilog":
        binary = case / "sim.vvp"
        argv = ["iverilog", "-g2012", "-Wall", "-s", "top_bridge", "-o", run.relative(binary)]
        argv += [f"-Ptop_bridge.{k}={v}" for k, v in config.items()]
        argv += [*rtl, "tests/top_bridge.sv"]
        run.command(f"{name}-compile", argv)
        executable = ["vvp", run.relative(binary)]
    else:
        obj = case / "compile-obj"
        argv = ["verilator", "--binary", "--timing", "-Wno-fatal",
                "--top-module", "top_bridge", "--Mdir", run.relative(obj), "-j", "2"]
        argv += [f"-G{k}={v}" for k, v in config.items()]
        run.command(f"{name}-compile", [*argv, *rtl, "tests/top_bridge.sv"])
        executable = [run.relative(obj / "Vtop_bridge")]
    event_path = case / "events.bin"
    run.command(f"{name}-simulate", [
        *executable, f"+program={run.relative(case / 'program.hex')}",
        f"+data={run.relative(case / 'data.hex')}",
        f"+events={run.relative(event_path)}", "+cycles=200000",
    ], timeout=60 if simulator == "iverilog" else 3600)
    counts = compare_top(run, event_path, padded, config["DMEM_WORDS"],
                         bool(config["LEGACY_TRAPS"]))
    run.receipt["comparisons"][name] = counts
    run.save()
    if simulator != "iverilog":
        shutil.rmtree(obj)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=(*SUITES, "all"), default="all")
    parser.add_argument("--probe", choices=("smoke", "integer", "atomic", "privilege", "timer", "faults", "memory", "synthesis"),
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
        if args.probe == "smoke":
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
