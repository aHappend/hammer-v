"""Discover real RV64IM compilation and load actual ELF64 segments/symbols."""

import os
from pathlib import Path
import shutil
import struct

from retention import ROOT, ToolFailure, fresh


def discover():
    requested = os.environ.get("RISCV_CC")
    candidates = [requested] if requested is not None else [
        "riscv64-unknown-elf-gcc", "riscv64-linux-gnu-gcc",
        *[f"{prefix}-gcc-{version}"
          for prefix in ("riscv64-unknown-elf", "riscv64-linux-gnu")
          for version in range(16, 7, -1)],
        "clang",
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

    def file_span(offset, size, label):
        if offset > len(data) or size > len(data) - offset:
            raise ToolFailure(f"compiled ELF {label} outside file")
        return data[offset:offset + size]

    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise ToolFailure("compiled benchmark is not little-endian ELF64")
    file_span(0, 64, "header")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1:5] != (2, 243, 1, 0) or header[7] != 0:
        raise ToolFailure("compiled ELF requires executable RISC-V version 1, entry PC=0 and zero flags "
                          "(uncompressed RV64IM with LP64 integer ABI)")
    if header[8] != 64 or header[9] != 56 or header[11] != 64:
        raise ToolFailure("compiled ELF invalid header/table entry sizes")
    file_span(header[5], header[10] * header[9], "program table")
    file_span(header[6], header[12] * header[11], "section table")
    code = bytearray(16384 * 4)
    memory = bytearray(8192 * 8)
    executable = []
    data_ranges = []
    for index in range(header[10]):
        ph = struct.unpack_from("<IIQQQQQQ", data, header[5] + index * header[9])
        kind, flags, offset, virtual, _, filesz, memsz, _ = ph
        if kind != 1 or not memsz:
            continue
        target, base = (code, 0) if virtual < 65536 else (memory, 0x10000000)
        if filesz > memsz or offset + filesz > len(data) or virtual < base or virtual + memsz > base + len(target):
            raise ToolFailure(f"ELF segment outside frozen scratchpads: {virtual:#x}+{memsz}")
        start = virtual - base
        target[start:start + filesz] = file_span(offset, filesz, "load segment")
        target[start + filesz:start + memsz] = bytes(memsz - filesz)
        if base == 0 and flags & 1:
            executable.append((virtual, virtual + filesz))
        if base == 0x10000000:
            data_ranges.append((virtual, virtual + memsz))
    if not any(start <= 0 and 4 <= end for start, end in executable):
        raise ToolFailure("compiled ELF entry is not in a loaded executable instruction segment")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + index * header[11])
                for index in range(header[12])]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ToolFailure("compiled ELF invalid symbol table size or string-table index")
        file_span(section[4], section[5], "symbol table")
        names_section = sections[section[6]]
        if names_section[1] != 3:
            raise ToolFailure("compiled ELF symbol names require a string table")
        strings = file_span(names_section[4], names_section[5], "string table")
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, _, _, defined, value, _ = struct.unpack_from("<IBBHQQ", data, offset)
            if name >= len(strings):
                raise ToolFailure("compiled ELF symbol name outside string table")
            end = strings.find(b"\0", name)
            if end < 0:
                raise ToolFailure("compiled ELF unterminated symbol name")
            try:
                label = strings[name:end].decode("ascii")
            except UnicodeDecodeError as error:
                raise ToolFailure("compiled ELF non-ASCII symbol name") from error
            if defined:
                symbols[label] = value
    for required in ("results", "_halt"):
        if required not in symbols:
            raise ToolFailure(f"ELF missing required symbol {required}")
    halt = symbols["_halt"]
    if halt & 3 or not any(start <= halt and halt + 4 <= end for start, end in executable):
        raise ToolFailure("compiled ELF _halt is not a loaded aligned instruction")
    if not any(start <= symbols["results"] < end for start, end in data_ranges):
        raise ToolFailure("compiled ELF results is not in a loaded data segment")
    instructions = [int.from_bytes(code[pos:pos + 4], "little") for pos in range(0, len(code), 4)]
    words = [int.from_bytes(memory[pos:pos + 8], "little") for pos in range(0, len(memory), 8)]
    return instructions, words, symbols, path
