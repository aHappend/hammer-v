"""Compiled integrated ISA workloads with public retirement comparisons."""
import os
import random
import shutil

from boot import HARNESS, compile_model
from compressed import decode, iword, rword, sword
from evidence import digest


def program(seed, count=1000):
    code = bytearray()
    families = []
    base = 0x80000000

    def emit(word, size=4):
        code.extend(word.to_bytes(size, "little"))

    def constant(rd, value):
        chunks = [(value >> shift) & 2047 for shift in range(55, -1, -11)]
        emit(iword(0x13, rd, 0, 0, chunks[0]))
        for chunk in chunks[1:]:
            emit(iword(0x13, rd, 1, rd, 11))
            emit(iword(0x13, rd, 6, rd, chunk))

    representatives = {}
    for half in range(65536):
        word, illegal, family = decode(half)
        if illegal or family == "ebreak" or word == 0x13:
            continue
        if family == "j":
            offset = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) | (
                ((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1)
            if offset != 4:
                continue
        if family in ("beqz", "bnez"):
            offset = ((word >> 31) << 12) | (((word >> 7) & 1) << 11) | (
                ((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1)
            if offset != 4:
                continue
        representatives.setdefault(family, half)
    for family, half in sorted(representatives.items()):
        for rd in (1, 2, *range(8, 16)):
            constant(rd, 0x80010000)
        word, _, _ = decode(half)
        if family in ("beqz", "bnez"):
            emit(iword(0x13, (word >> 15) & 31, 0, 0, family == "bnez"))
        if family in ("jr", "jalr"):
            rs1 = (word >> 15) & 31
            emit(rs1 << 7 | 0x17)
            emit(iword(0x13, rs1, 0, rs1, 12))
        families.append((base + len(code), half, family))
        emit(half, 2)
        emit(0x0001, 2)
        emit(0x0001, 2)
    # Zero-immediate hints must also execute, not merely classify in the table.
    for half in (0x0001, 0x0005, 0x4001, 0x8001, 0x8401, 0x0002, 0x8006):
        word, illegal, _ = decode(half)
        if illegal or word != 0x13:
            raise AssertionError("hint fixture must be legal and side-effect free")
        families.append((base + len(code), half, "hint-" + f"{half:04x}"))
        emit(half, 2)
    rng = random.Random(seed)
    endpoints = (0, 1, (1 << 64) - 1, 1 << 63, (1 << 63) - 1,
                 0xFFFFFFFF80000000, 0x7FFFFFFF)
    for a in endpoints:
        for b in endpoints:
            constant(5, a)
            constant(6, b)
            for opcode, f3s in ((0x33, range(8)), (0x3B, (0, 4, 5, 6, 7))):
                for f3 in f3s:
                    emit(rword(opcode, 7, f3, 5, 6, 1))
    for _ in range(count):
        constant(5, rng.getrandbits(64))
        constant(6, rng.getrandbits(64))
        opcode = rng.choice((0x33, 0x3B))
        f7 = rng.choice((0, 32, 1))
        f3 = rng.choice((0, 5)) if f7 == 32 else (
            rng.choice((0, 4, 5, 6, 7)) if opcode == 0x3B and f7 == 1 else
            rng.choice((0, 1, 5)) if opcode == 0x3B else rng.randrange(8))
        emit(rword(opcode, rng.randrange(32), f3, 5, 6, f7))
    constant(8, 0x80010000)
    constant(9, 0x8877665544332211)
    for f3 in range(4):
        emit(sword(8, 9, f3, 0))
        emit(iword(0x03, 10, f3, 8, 0))
        if f3 < 3:
            emit(iword(0x03, 10, f3 + 4, 8, 0))
    for width in (2, 3):
        for operation in (0, 1, 4, 8, 12, 16, 20, 24, 28, 2, 3):
            emit((operation << 27) | ((0 if operation == 2 else 9) << 20) |
                 (8 << 15) | (width << 12) | (10 << 7) | 0x2F)
    end = base + len(code)
    emit(0x9002, 2)
    return code, families, end


def architectural_probe(ev, count=1000, seeds=(17, 43, 89), compact_only=False):
    observations = []
    configurations = [{"IMEM_WORDS": 32, "DMEM_WORDS": 1, "BTB_ENTRIES": 1,
                       "ICACHE_LINES": 1, "DCACHE_LINES": 1, "ITLB_ENTRIES": 1,
                       "DTLB_ENTRIES": 1, "L2_SETS": 1}]
    if not compact_only:
        configurations.append({})
    empty = ev.directory / "empty.bin"
    empty.write_bytes(b"")
    for geometry, parameters in enumerate(configurations):
        for seed in seeds:
            code, families, end = program(seed, count)
            image = ev.directory / f"isa-{geometry}-{seed}.bin"
            image.write_bytes(code)
            checks = "\n".join(
                f"if(d.retire_pc==0x{pc:x}ULL) {{ if(d.retire_insn!=0x{half:04x} "
                f"|| family_seen[{i}]++) throw std::runtime_error(\"C family dropped/duplicated\"); }}"
                for i, (pc, half, _) in enumerate(families))
            text = HARNESS.replace(
                "uint64_t cycles=0,retired=0", f"unsigned family_seen[{len(families)}]={{}};\n"
                " uint64_t cycles=0,retired=0")
            text = text.replace("isa.compare(d,cycles);", "isa.compare(d,cycles);\n" + checks)
            text = text.replace("traps++;", "traps++;\n" +
                                f"if(d.trap_pc!=0x{end:x}ULL || d.trap_cause!=3 "
                                "|| d.trap_interrupt) throw std::runtime_error(\"unexpected ISA trap\");\n"
                                "done=true;")
            text = text.replace("if(!sretired)", "if(goal!=\"isa\" && !sretired)")
            text = text.replace("if(!done) throw", "\n".join(
                f'if(family_seen[{i}]!=1) throw std::runtime_error("unwitnessed {family}");'
                for i, (_, _, family) in enumerate(families)) + "\nif(!done) throw")
            ev.record.setdefault("generated_sha256", {})[ev.relative(image)] = digest(image)
            objects = compile_model(ev, text, parameters)
            try:
                ev.run(["./compile-obj/boot-sim", image.name, empty.name, empty.name,
                        "10000000", "isa"], f"isa-{geometry}-{seed}", cwd=ev.directory)
                import json
                result = json.loads((ev.directory / "boot-observed.json").read_text())
                observations.append({"parameters": parameters, "seed": seed,
                                     "families": [name for _, _, name in families],
                                     "random_arithmetic": count, "observed": result})
                ev.record["architectural_observed"] = observations
                ev.save()
            finally:
                shutil.rmtree(objects)
            # Preserve each workload's outputs rather than reuse its namespace.
            destination = ev.directory / f"isa-output-{geometry}-{seed}-{digest(image)[:16]}"
            destination.mkdir()
            for name in ("boot.cpp", "decode.bin", "uart.txt", "milestones.txt",
                         "retirement-tail.txt", "boot-observed.json"):
                (ev.directory / name).rename(destination / name)
            ev.record["generated_sha256"].pop(ev.relative(ev.directory / "boot.cpp"), None)
            ev.record["generated_sha256"].pop(ev.relative(ev.directory / "decode.bin"), None)
            for name in ("boot.cpp", "decode.bin"):
                path = destination / name
                ev.record["generated_sha256"][ev.relative(path)] = digest(path)
            ev.save()
