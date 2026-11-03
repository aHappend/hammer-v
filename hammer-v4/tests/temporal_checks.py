#!/usr/bin/env python3
"""Real-firmware timer delivery at three pre-frozen idle eligible boundaries.

This compact integration test is not the independent full-Linux timed oracle.
The deadline expectation uses released edges only, never DUT time values.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from firmware_checks import CC, ISA, OBJCOPY, PREFIX
from reproduction_diff import sections
from temporal_replay import verify_run


PAYLOAD = r"""
.option norvc
.option norelax
.section .text.entry,"ax"
.globl _start
_start:
    li sp,0x803f0000
    la t0,supervisor_trap
    csrw stvec,t0
    li s0,0
    li s1,1048576
    mv a0,s1
    li a7,0x54494d45
    li a6,0
    ecall
    bnez a0,failed
    bnez a1,failed
    li t0,32
    csrs sie,t0
    csrsi sstatus,2
    csrr s2,time
.globl sleeping
sleeping:
    wfi
    j failed
supervisor_trap:
    csrr t0,scause
    li t1,0x8000000000000005
    bne t0,t1,failed
    addi s0,s0,1
    li t0,3
    beq s0,t0,finished
    li t0,1048576
    add s1,s1,t0
    mv a0,s1
    li a7,0x54494d45
    li a6,0
    ecall
    bnez a0,failed
    bnez a1,failed
    la t0,sleeping
    csrw sepc,t0
    csrr s2,time
    sret
finished:
    li a0,-1
    li a7,0x54494d45
    li a6,0
    ecall
    bnez a0,failed
    bnez a1,failed
    la s2,passed
    j print
failed:
    la s2,failure
print:
    lbu a0,0(s2)
    beqz a0,park
    li a7,1
    li a6,0
    ecall
    addi s2,s2,1
    j print
park:
    wfi
    j park
.section .rodata,"a"
passed: .asciz "TEMPORAL timer boundaries passed\r\n"
failure: .asciz "TEMPORAL FAILURE\r\n"
"""


def symbol(blob, name):
    maps = sections(blob)
    symbols, strings = maps[".symtab"], maps[".strtab"]
    table = blob[strings["offset"]:strings["offset"] + strings["bytes"]]
    matches = []
    for offset in range(symbols["offset"], symbols["offset"] + symbols["bytes"], 24):
        index, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", blob, offset)
        if table[index:table.index(0, index)] == name.encode():
            matches.append(value)
    if len(matches) != 1:
        raise AssertionError(f"Payload symbol missing/ambiguous: {name}")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--rtl", default="rtl")
    args = parser.parse_args()
    relative, rtl = Path(args.out), Path(args.rtl)
    for name, path in (("--out", relative), ("--rtl", rtl)):
        if path.is_absolute() or ".." in path.parts or (
            path != Path("rtl") and path.parts[:1] != ("build",)
        ):
            parser.error(f"{name} must be a project-relative build/ path or rtl")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((ROOT / args.manifest).read_text())
    for item in manifest["images"].values():
        if hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() != item["sha256"]:
            raise AssertionError("Temporal software image hash mismatch")
    (out / "payload.S").write_text(PAYLOAD)
    (out / "payload.ld").write_text(
        "OUTPUT_ARCH(riscv)\nENTRY(_start)\nSECTIONS {\n"
        " . = 0x80200000; .text : { *(.text.entry) *(.text*) }\n"
        " .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) }\n}\n"
    )
    expected = PREFIX + b"TEMPORAL timer boundaries passed\r\n"
    (out / "expected-uart.bin").write_bytes(expected)
    (out / "expectations.json").write_text(json.dumps({
        "machine_timer_edges": [1048576, 2097152, 3145728],
        "supervisor_timer_count": 3, "time_read_count": 3, "bound": 8388608,
        "uart_sha256": hashlib.sha256(expected).hexdigest(),
        "scope": "quiescent integrated timer boundaries, not full-system timing",
    }, indent=2) + "\n")
    commands = []

    def run(argv):
        index = len(commands)
        record = {"argv": [str(arg) for arg in argv], "cwd": ".",
                  "started_unix": time.time()}
        commands.append(record)
        with (out / f"{index}.stdout.log").open("wb") as so, (
            out / f"{index}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(record["argv"], cwd=ROOT, stdout=so, stderr=se,
                                    check=False)
        record.update(exit_code=result.returncode, ended_unix=time.time())
        (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(f"Temporal command {index} failed: {relative}")

    run([CC, f"-march={ISA}", "-mabi=lp64", "-mno-relax", "-c",
         relative / "payload.S", "-o", relative / "payload.o"])
    run([CC, f"-march={ISA}", "-mabi=lp64", "-nostdlib", "-static",
         "-Wl,--build-id=none", "-Wl,--no-relax", "-T", relative / "payload.ld",
         relative / "payload.o", "-o", relative / "payload.elf"])
    run([OBJCOPY, "-O", "binary", relative / "payload.elf", relative / "payload.bin"])
    sleeping = symbol((out / "payload.elf").read_bytes(), "sleeping")
    model = out / "compile-obj"
    try:
        run(["verilator", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
             "--top-module", "hammer_v4_top", "--Mdir", model,
             "-GIMEM_WORDS=32", "-GDMEM_WORDS=3", "-CFLAGS", "-O2 -std=c++17",
             *[p.relative_to(ROOT) for p in sorted((ROOT / rtl).glob("*.sv"))],
             ROOT / "tests/temporal_probe.cpp"])
        executable = out / "temporal-probe"
        shutil.copyfile(model / "Vhammer_v4_top", executable)
        executable.chmod(0o755)
        run([executable, ROOT / manifest["images"]["fw_jump.bin"]["path"],
             out / "payload.bin", ROOT / manifest["images"]["hammer-v4.dtb"]["path"],
             out, out / "expected-uart.bin", f"{sleeping:x}"])
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in model.glob(pattern):
                path.unlink()
    text = (out / "4.stdout.log").read_text()
    if "COMPARED exact_machine_deadlines=3" not in text:
        raise AssertionError("Missing temporal functional comparisons")
    verify_run(out)
    print(text, end="")


if __name__ == "__main__":
    main()
