#!/usr/bin/env python3
"""Independently exercise V4 compatibility and unchanged parent public contracts."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from parameters import ports


PROGRAM = r"""
.option norvc
.option norelax
.globl _start
_start:
    li t0,0x80020000
    li s0,0x80020400
    li t1,0x1122334455667788
    sd t1,0(t0)
    ld t2,0(t0)
    bne t2,t1,failed
    li t2,1
    sd t2,0(s0)
wait_first:
    ld t2,8(t0)
    beqz t2,wait_first
    ld t2,0(t0)
    li t1,0x2233445566778899
    bne t2,t1,failed
    li t2,2
    sd t2,0(s0)
    lr.d t3,(t0)
wait_second:
    ld t2,8(t0)
    li t1,2
    bne t2,t1,wait_second
    li t1,0x445566778899aabb
    sc.d t4,t1,(t0)
    li t2,1
    bne t4,t2,failed
    ld t2,0(t0)
    li t5,0x33445566778899aa
    bne t2,t5,failed
    lr.d t3,(t0)
    bne t3,t5,failed
    sc.d t4,t1,(t0)
    bnez t4,failed
    ld t2,0(t0)
    bne t2,t1,failed
    li t2,3
    sd t2,0(s0)
done:
    j done
failed:
    ebreak
"""


def adapter(parent):
    declarations = ports()
    header = ",\n".join(f"    {direction} wire {width} {name}"
                        for direction, width, name in declarations)
    instance_ports = ", ".join(
        f".{name}({name})" for _, _, name in declarations
        if not parent or name not in ("boot_ready", "boot_error")
    )
    module = "hammer_v3_top" if parent else "hammer_v4_top"
    parameters = ".IMEM_WORDS(32), .DMEM_WORDS(3)"
    if not parent:
        parameters += ", .BOOT_ENABLE(0)"
    outputs = "assign boot_ready=rst_n; assign boot_error=1'b0;" if parent else ""
    return (f"module compatibility_top (\n{header}\n);\n{outputs}\n"
            f"{module} #({parameters}) tested ({instance_ports});\nendmodule\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rtl", default="rtl")
    parser.add_argument("--v4-only", action="store_true")
    args = parser.parse_args()
    relative = Path(args.out)
    rtl = Path(args.rtl)
    for path in (relative, rtl):
        if path.is_absolute() or ".." in path.parts or (
            path != Path("rtl") and path.parts[:1] != ("build",)
        ):
            parser.error("Use project-relative build/ output and rtl or disposable build/ RTL")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    (out / "program.S").write_text(PROGRAM)
    records = []

    def run(argv, directory, name):
        with (directory / f"{name}.stdout.log").open("wb") as so, (
            directory / f"{name}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
        records.append({"argv": argv, "cwd": ".", "exit_code": result.returncode})
        (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(f"Compatibility {name} failed: {directory.relative_to(ROOT)}")

    run(["/usr/bin/riscv64-unknown-elf-gcc", "-march=rv64ima_zicsr_zifencei", "-mabi=lp64",
         "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-Ttext=0x80000000",
         str(relative / "program.S"), "-o", str(relative / "program.elf")], out, "assemble")
    run(["/usr/bin/riscv64-unknown-elf-objcopy", "-O", "binary",
         str(relative / "program.elf"), str(relative / "program.bin")], out, "image")
    for parent in ((False,) if args.v4_only else (False, True)):
        directory = out / ("parent" if parent else "v4")
        directory.mkdir()
        (directory / "adapter.sv").write_text(adapter(parent))
        source_dir = ROOT / ("hammer_v3_reference/rtl" if parent else rtl)
        sources = sorted(source_dir.glob("*.sv"))
        model = directory / "compile-obj"
        try:
            run(["verilator", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
                 "--top-module", "compatibility_top", "--prefix", "Vhammer_v4_top",
                 "--Mdir", str(model), "-CFLAGS", "-O2 -std=c++17",
                 *[str(p.relative_to(ROOT)) for p in sources],
                 str(directory / "adapter.sv"), str(ROOT / "tests/compatibility_probe.cpp")],
                directory, "compile")
            run([str(model / "Vhammer_v4_top"), str(out / "program.bin"), str(directory)],
                directory, "simulate")
        finally:
            for pattern in ("*.o", "*.a", "*.gch"):
                for path in model.glob(pattern):
                    path.unlink()
        stdout = (directory / "simulate.stdout.log").read_text()
        if "COMPARED compatibility stages=3 lr=2 sc=2" not in stdout:
            raise AssertionError("Missing functional compatibility result")
        print(("PARENT " if parent else "V4 ") + stdout, end="")
    if not args.v4_only:
        for name in ("events.log", "simulate.stdout.log"):
            if (out / "v4" / name).read_bytes() != (out / "parent" / name).read_bytes():
                raise AssertionError(f"Parent/V4 observable compatibility differs: {name}")
    (out / "summary.json").write_text(json.dumps({
        "parent_comparison": not args.v4_only,
        "program_sha256": hashlib.sha256((out / "program.bin").read_bytes()).hexdigest(),
        "compared_stages": 3, "lr": 2, "sc": 2,
        "source_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for d in (ROOT / rtl, ROOT / "hammer_v3_reference/rtl")
                          for p in sorted(d.glob("*.sv"))},
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
