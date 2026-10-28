"""Discover real RV64IM compilation and load actual ELF64 segments/symbols."""

import os
from pathlib import Path
import shutil
import struct

from retention import ROOT, ToolFailure, fresh


def discover():
    requested = os.environ.get("RISCV_CC")
    candidates = [requested] if requested is not None else [
        "riscv64-unknown-elf-gcc", "riscv64-linux-gnu-gcc", "clang",
        *[f"clang-{version}" for version in range(23, 7, -1)]]
    available = []
    for candidate in candidates:
        resolved = shutil.which(candidate) if candidate else None
        if resolved and resolved not in available:
            available.append(resolved)
    if available:
        return available
    raise ToolFailure(
        "PREREQUISITE_MISSING: RV64IM C compiler; require riscv64-unknown-elf-gcc, "
        "riscv64-linux-gnu-gcc, or clang with RISC-V target and linker "
        "(alternatively set RISCV_CC to an existing compiler); "
        f"checked={candidates!r}; no tools were installed")


def compile_benchmark(evidence, number):
    failures = []
    for compiler in discover():
        directory = fresh(evidence.directory, "compiled-c")
        output = directory / "benchmark.elf"
        argv = [compiler]
        if "clang" in Path(compiler).name:
            argv += ["--target=riscv64-unknown-elf", "-fuse-ld=lld"]
        argv += ["-march=rv64im", "-mabi=lp64", "-mcmodel=medany", "-mno-relax",
                 "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-msmall-data-limit=0", "-nostdlib",
                 "-static", "-O1", "-Wl,--no-relax", "-Wl,-T,tests/link.ld",
                 f"-DBENCH={number}", "tests/start.S", "tests/bench.c",
                 "-o", str(output.relative_to(ROOT))]
        folder, record = evidence.command(argv, expect_failure=True)
        if record["exit_code"] == 0:
            return load_elf(output)
        failures.append(str((folder / "receipt.json").relative_to(ROOT)))
    raise ToolFailure(
        "RV64IM_COMPILATION_FAILED: no discovered compiler linked the requested "
        f"workload; retained failed command receipts={failures!r}")


def load_elf(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ToolFailure("compiled benchmark is not little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[2] != 243 or header[4] != 0 or header[7] & 7:
        raise ToolFailure("compiled ELF requires RISC-V, entry PC=0, no compressed code and LP64 integer ABI")
    code = bytearray(16384 * 4)
    memory = bytearray(8192 * 8)
    for index in range(header[10]):
        ph = struct.unpack_from("<IIQQQQQQ", data, header[5] + index * header[9])
        kind, _, offset, virtual, _, filesz, memsz, _ = ph
        if kind != 1 or not memsz:
            continue
        target, base = (code, 0) if virtual < 65536 else (memory, 0x10000000)
        if filesz > memsz or offset + filesz > len(data) or virtual < base or virtual + memsz > base + len(target):
            raise ToolFailure(f"ELF segment outside frozen scratchpads: {virtual:#x}+{memsz}")
        start = virtual - base
        target[start:start + filesz] = data[offset:offset + filesz]
        target[start + filesz:start + memsz] = bytes(memsz - filesz)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + index * header[11])
                for index in range(header[12])]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        names_section = sections[section[6]]
        strings = data[names_section[4]:names_section[4] + names_section[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, offset)
            end = strings.find(b"\0", name)
            symbols[strings[name:end].decode("ascii")] = value
    for required in ("results", "_halt"):
        if required not in symbols:
            raise ToolFailure(f"ELF missing required symbol {required}")
    instructions = [int.from_bytes(code[pos:pos + 4], "little") for pos in range(0, len(code), 4)]
    words = [int.from_bytes(memory[pos:pos + 8], "little") for pos in range(0, len(memory), 8)]
    return instructions, words, symbols, path
