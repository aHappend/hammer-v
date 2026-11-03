#!/usr/bin/env python3
"""Generate independent SBI/Sv39 directed payloads for the real firmware.

This is a compact privileged-software check, not a Linux boot or timed oracle.
All comparisons and expected public events are derived before RTL execution.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CC = "/usr/bin/riscv64-unknown-elf-gcc"
OBJCOPY = "/usr/bin/riscv64-unknown-elf-objcopy"
ISA = "rv64ima_zicsr_zifencei"
PREFIX = (
    b"HAMMER-V4 OpenSBI-compatible fw_jump (SBI v0.2)\r\n"
    b"HAMMER firmware: hart=0 dtb=0x87e00000 next=0x80200000 S-mode\r\n"
)


def payload():
    lines = [
        ".option norvc", ".option norelax", '.section .text.entry,"ax"',
        ".globl _start", "_start:", "li sp,0x803f0000",
        "la t0,supervisor_trap", "csrw stvec,t0", "li s7,0", "li s11,0",
    ]
    events = []
    cases = []

    def emit(*instructions):
        lines.extend(instructions)

    def mark(name, user=False):
        ordinal = len(cases) + 1
        cases.append({"id": ordinal, "requirement": name})
        address = 0x4000B000 if user else 0x80310000
        events.append({"kind": "signature", "id": ordinal, "address": address})
        emit(f"li t0,{address}", f"li t1,{ordinal}", "sd t1,0(t0)")

    def check(register, value, name):
        emit(f"li t5,{value}", f"bne {register},t5,failed")
        mark(name)

    def call(eid, fid=0, argument=None):
        if argument is not None:
            emit(f"li a0,{argument}")
        emit(f"li a7,{eid}", f"li a6,{fid}", "ecall")

    def fault(instructions, cause, address, name):
        label = f"recover_{len(cases)}"
        emit(f"li s8,{cause}", f"li s9,{address}", f"la s10,{label}")
        events.append({"kind": "fault", "cause": cause, "tval": address, "target": 1})
        emit(*instructions, "j failed", f"{label}:")
        mark(name)

    for fid, value in ((0, 2), (1, 0x48414D4D), (2, 0x40000),
                       (4, 0), (5, 0), (6, 0)):
        call(0x10, fid)
        check("a0", 0, f"SBI base function {fid} success")
        check("a1", value, f"SBI base function {fid} value")
    for extension, implemented in (
        (0, 1), (1, 1), (2, 1), (0x10, 1), (0x54494D45, 1),
        (0x4442434E, 0), (0x7FFFFFFF, 0),
    ):
        call(0x10, 3, extension)
        check("a0", 0, f"SBI probe {extension:#x} error")
        check("a1", implemented, f"SBI probe {extension:#x} value")
    for eid, fid in ((0x10, 7), (0x54494D45, 1), (0x7FFFFFFF, 0)):
        call(eid, fid)
        check("a0", -2, f"SBI unsupported {eid:#x}/{fid} error")
        check("a1", 0, f"SBI unsupported {eid:#x}/{fid} value")

    # Give every caller-saved register a distinct canary across a real M trap.
    canaries = ("ra", "gp", "tp", "t0", "t1", "t2", "t3", "t4",
                "t5", "t6", "a2", "a3", "a4", "a5")
    for index, register in enumerate(canaries):
        emit(f"li {register},{0x5100 + index}")
    call(0x10, 0)
    # Compare before mark() uses t0/t1 and before any checker uses t5.
    for index, register in enumerate(canaries):
        emit(f"li s0,{0x5100 + index}", f"bne {register},s0,failed")
    mark("M trap preserves non-result integer register context")

    # Immediate deadline and two later deadlines exercise real MTIP -> STIP.
    call(0x54494D45, 0, 0)
    check("a0", 0, "SBI immediate timer error")
    check("a1", 0, "SBI immediate timer value")
    emit("li t0,32", "csrs sie,t0", "csrsi sstatus,2",
         "timer_wait:", "li t0,3", "bltu s7,t0,timer_wait",
         "csrci sstatus,2", "li t0,32", "csrc sie,t0")
    check("s7", 3, "three supervisor timer deliveries and rearming")
    call(0x54494D45, 0, -1)
    check("a0", 0, "SBI UINT64_MAX deadline error")
    check("a1", 0, "SBI UINT64_MAX deadline value")

    # Set up tables in ordinary addressed RAM, using the specified software A/D
    # policy. There are no hierarchical writes or simulator-only page tables.
    emit("la t2,root_table", "li t0,207", "sd t0,0(t2)",
         "li t0,0x200000cf", "sd t0,16(t2)",
         "li t0,0x200000c7", "sd t0,24(t2)",
         "li t0,0x200800c7", "sd t0,32(t2)",
         "la t0,middle_table", "srli t0,t0,12", "slli t0,t0,10",
         "ori t0,t0,1", "sd t0,8(t2)", "la t2,middle_table",
         "la t0,leaf_table", "srli t0,t0,12", "slli t0,t0,10",
         "ori t0,t0,1", "sd t0,0(t2)",
         "li t0,0x201000c7", "sd t0,8(t2)",
         "li t0,0x201004c7", "sd t0,16(t2)")

    def mapping(index, label, flags):
        emit("la t2,leaf_table", f"la t0,{label}", "srli t0,t0,12",
             "slli t0,t0,10", f"ori t0,t0,{flags}", f"sd t0,{index * 8}(t2)")

    for index, label, flags in (
        (0, "data_a", 0xC7), (1, "execute_page", 0x49),
        (3, "data_a", 0xC5), (4, "data_a", 0x03),
        (5, "data_a", 0x47), (6, "data_a", 0xD7),
        (8, "data_b", 0xC7), (10, "user_page", 0xDF),
    ):
        mapping(index, label, flags)
    emit("la t2,leaf_table", "li t0,0x200c40d7", "sd t0,88(t2)",
         "la t0,root_table", "srli t0,t0,12", "li t1,0x8000000000000000",
         "or t0,t0,t1", "csrw satp,t0", "sfence.vma")
    emit("li t0,0x40000000", "ld t3,0(t0)")
    check("t3", 0x1122334455667788, "Sv39 three-level 4 KiB translation")
    emit("li t0,0x40200000", "li t1,0x55667788", "sd t1,0(t0)", "ld t3,0(t0)")
    check("t3", 0x55667788, "Sv39 aligned 2 MiB leaf")
    emit("li t0,0xc0400000", "ld t3,0(t0)")
    check("t3", 0x55667788, "Sv39 aligned 1 GiB leaf")
    fault(("li t0,0x40400000", "ld t3,0(t0)"), 13, 0x40400000,
          "Sv39 misaligned 2 MiB leaf fault")
    fault(("li t0,0x100000000", "ld t3,0(t0)"), 13, 0x100000000,
          "Sv39 misaligned 1 GiB leaf fault")
    fault(("li t0,0x4000000000", "ld t3,0(t0)"), 13, 0x4000000000,
          "Sv39 noncanonical address fault")
    fault(("li t0,0x40002000", "ld t3,0(t0)"), 13, 0x40002000,
          "Sv39 invalid bottom PTE fault")
    fault(("li t0,0x40003000", "ld t3,0(t0)"), 13, 0x40003000,
          "Sv39 W without R fault")
    fault(("li t0,0x40004000", "ld t3,0(t0)"), 13, 0x40004000,
          "Sv39 software accessed-bit fault")
    fault(("li t0,0x40005000", "sd zero,0(t0)"), 15, 0x40005000,
          "Sv39 software dirty-bit fault")
    fault(("li t0,0x40001000", "ld t3,0(t0)"), 13, 0x40001000,
          "Sv39 execute-only load denied without MXR")
    emit("li t0,0x80000", "csrs sstatus,t0", "li t0,0x40001000", "ld t3,0(t0)")
    check("t3", 0x0000806704D00513, "Sv39 MXR execute-only data read")
    emit("li t0,0x80000", "csrc sstatus,t0")
    fault(("li t0,0x40006000", "ld t3,0(t0)"), 13, 0x40006000,
          "Sv39 supervisor user-page load denied without SUM")
    emit("li t0,0x40000", "csrs sstatus,t0", "li t0,0x40006000", "ld t3,0(t0)")
    check("t3", 0x1122334455667788, "Sv39 SUM user-page data access")
    fault(("li t0,0x4000a000", "jalr ra,0(t0)"), 12, 0x4000A000,
          "Sv39 S-mode cannot execute U page even with SUM")
    emit("li t0,0x40000", "csrc sstatus,t0")

    # A cached global mapping survives ASID-scoped sfence, then full-VA
    # invalidation exposes the independently written replacement PTE.
    mapping(0, "data_a", 0xE7)
    emit("sfence.vma", "li t0,0x40000000", "ld t3,0(t0)")
    check("t3", 0x1122334455667788, "Sv39 global mapping initial fill")
    mapping(0, "data_b", 0xE7)
    emit("li t3,0x40000000", "li t4,0", "sfence.vma t3,t4", "ld t3,0(t3)")
    check("t3", 0x1122334455667788, "Sv39 ASID sfence global preservation")
    emit("li t3,0x40000000", "sfence.vma t3,zero", "ld t3,0(t3)")
    check("t3", 0x8877665544332211, "Sv39 full-VA sfence invalidates globals")
    mapping(0, "data_a", 0xC7)
    emit("sfence.vma")

    # U executes a real translated page, takes load/fetch faults against
    # supervisor-only pages, and returns via an actual U ecall.
    emit("li t0,0x4000a000", "csrw sepc,t0", "li t0,0x100", "csrc sstatus,t0", "sret",
         "supervisor_after_user:")
    check("s11", 12, "Sv39 directed page-fault count including U faults")
    mark("U ecall nested M trap and restored S context")
    emit("la s0,success", "j print_string", "failed:", "la s0,failure",
         "print_string:", "lbu a0,0(s0)", "beqz a0,finished",
         "li a7,1", "li a6,0", "ecall", "addi s0,s0,1", "j print_string",
         "finished:", "wfi", "j finished")

    saved = ("t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a6", "a7", "ra")
    emit(".balign 4", "supervisor_trap:", "addi sp,sp,-96")
    for index, register in enumerate(saved):
        emit(f"sd {register},{index * 8}(sp)")
    emit("csrr t0,scause", "li t1,0x8000000000000005", "beq t0,t1,timer_handler",
         "li t1,8", "beq t0,t1,user_ecall_handler", "bne t0,s8,failed",
         "csrr t0,stval", "bne t0,s9,failed", "csrw sepc,s10",
         "addi s11,s11,1", "j nested_machine_call", "user_ecall_handler:",
         "csrr t0,stval", "bnez t0,failed", "la t0,supervisor_after_user",
         "csrw sepc,t0", "li t0,0x100", "csrs sstatus,t0",
         "nested_machine_call:", "li a7,16", "li a6,0", "ecall",
         "bnez a0,failed", "li t0,2", "bne a1,t0,failed", "j restore_trap",
         "timer_handler:", "addi s7,s7,1", "li t0,3", "bgeu s7,t0,last_timer",
         "csrr a0,time", "li t0,10000", "add a0,a0,t0", "j rearm_timer",
         "last_timer:", "li a0,-1", "rearm_timer:", "li a7,0x54494d45", "li a6,0",
         "ecall", "bnez a0,failed", "bnez a1,failed", "restore_trap:")
    for index, register in enumerate(saved):
        emit(f"ld {register},{index * 8}(sp)")
    emit("addi sp,sp,96", "sret", '.section .rodata,"a"', "success:",
         '.asciz "DIRECTED SBI/Sv39 checks passed\\r\\n"', "failure:",
         '.asciz "DIRECTED FAILURE\\r\\n"', '.section .data,"aw"')
    for label in ("root_table", "middle_table", "leaf_table"):
        emit(".balign 4096", f"{label}:", ".zero 4096")
    emit(".balign 4096", "data_a:", ".dword 0x1122334455667788", ".zero 4088",
         "data_b:", ".dword 0x8877665544332211", ".zero 4088",
         "execute_page:", ".word 0x04d00513,0x00008067", ".zero 4088",
         ".balign 4096", "user_page:")
    emit("li t0,0x40006000", "ld t3,0(t0)", "li t5,0x1122334455667788",
         "bne t3,t5,user_failed", "li s8,13", "li s9,0x40000000",
         "la s10,user_after_load",
         "li t0,0x40000000", "ld t3,0(t0)", "j user_failed", "user_after_load:")
    user_events = [
        {"kind": "fault", "cause": 13, "tval": 0x40000000, "target": 1},
        {"kind": "fault", "cause": 12, "tval": 0x40001000, "target": 1},
        {"kind": "fault", "cause": 8, "tval": 0, "target": 1},
    ]
    emit("li s8,12", "li s9,0x40001000",
         "la s10,user_after_fetch",
         "li t0,0x40001000", "jalr ra,0(t0)", "j user_failed",
         "user_after_fetch:", "ecall", "user_failed:", "j user_failed")
    # U events occur before the supervisor-after-user signature records.
    index = next(i for i, event in enumerate(events)
                 if event.get("id") == len(cases) - 1)
    events[index:index] = user_events
    return "\n".join(lines) + "\n", cases, events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--rtl", default="rtl")
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((ROOT / args.manifest).read_text())
    for image in manifest["images"].values():
        if hashlib.sha256((ROOT / image["path"]).read_bytes()).hexdigest() != image["sha256"]:
            raise AssertionError(f"Image hash mismatch: {image['path']}")
    source, cases, events = payload()
    (out / "directed.S").write_text(source)
    (out / "directed.ld").write_text(
        'OUTPUT_ARCH(riscv)\nENTRY(_start)\nSECTIONS {\n'
        ' . = 0x80200000;\n .text : { *(.text.entry) *(.text*) }\n'
        ' .rodata : { *(.rodata*) }\n .data : { *(.data*) }\n'
        ' .bss : { *(.bss*) *(COMMON) }\n}\n'
    )
    commands = [
        [CC, "-march=" + ISA, "-mabi=lp64", "-nostdlib", "-static",
         "-Wl,--no-relax", "-T", str(relative / "directed.ld"),
         str(relative / "directed.S"), "-o", str(relative / "directed.elf")],
        [OBJCOPY, "-O", "binary", str(relative / "directed.elf"),
         str(relative / "directed.bin")],
    ]
    for index, argv in enumerate(commands):
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
        (out / f"{index}.stdout.log").write_bytes(result.stdout)
        (out / f"{index}.stderr.log").write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(f"Directed payload compilation failed: {relative}")
    expected = PREFIX + b"DIRECTED SBI/Sv39 checks passed\r\n"
    (out / "expected-uart.bin").write_bytes(expected)
    (out / "expectations.json").write_text(json.dumps({
        "cases": cases, "events": events, "supervisor_timers": 3,
        "uart_sha256": hashlib.sha256(expected).hexdigest(),
    }, indent=2) + "\n")
    # Simple whitespace records are consumed by the public-pin C++ transactor.
    with (out / "expected-events.txt").open("w") as stream:
        for event in events:
            if event["kind"] == "signature":
                stream.write(f"S {event['address']:x} {event['id']:x}\n")
            else:
                stream.write(f"T {event['cause']:x} {event['tval']:x}\n")
    manifest["images"]["Image"] = {
        "path": (relative / "directed.bin").as_posix(),
        "sha256": hashlib.sha256((out / "directed.bin").read_bytes()).hexdigest(),
    }
    (out / "image-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    print(f"Generated {len(cases)} directed comparisons and {len(events)} public events",
          flush=True)
    if args.generate_only:
        return
    rtl_relative = Path(args.rtl)
    if rtl_relative.is_absolute() or ".." in rtl_relative.parts or \
            (rtl_relative != Path("rtl") and rtl_relative.parts[:1] != ("build",)):
        parser.error("--rtl must be rtl or a project-relative disposable build/ copy")
    rtl_sources = sorted((ROOT / rtl_relative).glob("*.sv"))
    if len(rtl_sources) < 40:
        raise AssertionError("Directed simulation requires the complete RTL hierarchy")
    model = out / "compile-obj"
    commands.extend([
        ["verilator", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
         "--top-module", "hammer_v4_top", "--Mdir", str(model),
         "-GIMEM_WORDS=32", "-GDMEM_WORDS=3", "-CFLAGS", "-O2 -std=c++17",
         *[str(p.relative_to(ROOT)) for p in rtl_sources],
         str(ROOT / "tests/directed_probe.cpp")],
        [str(out / "directed-probe"),
         str(ROOT / manifest["images"]["fw_jump.bin"]["path"]),
         str(out / "directed.bin"),
         str(ROOT / manifest["images"]["hammer-v4.dtb"]["path"]),
         str(out), str(out / "expected-uart.bin"), str(out / "expected-events.txt"),
         "8388608"],
    ])
    executable = out / "directed-probe"
    try:
        for index in (2, 3):
            if index == 3:
                shutil.copyfile(model / "Vhammer_v4_top", executable)
                executable.chmod(0o755)
            with (out / f"{index}.stdout.log").open("wb") as so, (
                out / f"{index}.stderr.log"
            ).open("wb") as se:
                result = subprocess.run(commands[index], cwd=ROOT, stdout=so,
                                        stderr=se, check=False)
            (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(
                    f"Directed {'compilation' if index == 2 else 'comparison'} "
                    f"failed with exit {result.returncode}: {relative}"
                )
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in model.glob(pattern):
                path.unlink()
    result_text = (out / "3.stdout.log").read_text()
    if "COMPARED directed_events=" not in result_text:
        raise AssertionError("Missing functional comparison result")
    print(result_text, end="")


if __name__ == "__main__":
    main()
