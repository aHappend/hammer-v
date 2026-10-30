#!/usr/bin/env python3
"""Independent source/build/ELF/FDT checks for the declared platform images."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fdt(blob):
    """Bounds-checked v17 flattened tree parser with no dependency on Designer."""
    require(len(blob) >= 40, "FDT truncated header")
    magic, total, tree, strings, reserve, version, compatible, hart, ns, nt = \
        struct.unpack_from(">10I", blob)
    require(magic == 0xD00DFEED, "FDT magic")
    require(total == len(blob), "FDT total size")
    require(version == 17 and compatible <= version and hart == 0, "FDT version/hart")
    require(tree % 4 == 0 and 40 <= tree <= total and nt <= total - tree, "FDT tree bounds")
    require(40 <= strings <= total and ns <= total - strings, "FDT string bounds")
    require(reserve % 8 == 0 and 40 <= reserve <= total - 16, "FDT reserve bounds")
    require(tree + nt <= strings or strings + ns <= tree, "FDT overlapping blocks")
    reservations = []
    while True:
        require(reserve <= total - 16, "FDT unterminated reservations")
        base, length = struct.unpack_from(">QQ", blob, reserve)
        reserve += 16
        if not base and not length:
            break
        require(length and base + length <= 1 << 64, "FDT reservation overflow")
        reservations.append((base, length))
    require(reserve <= tree or reserve <= strings, "FDT reservation overlap")
    stack = []
    properties = {}
    offset, limit = tree, tree + nt
    ended = False
    while offset < limit:
        require(offset <= limit - 4, "FDT truncated token")
        token, = struct.unpack_from(">I", blob, offset)
        offset += 4
        if token == 1:
            end = blob.find(b"\0", offset, limit)
            require(end >= offset, "FDT unterminated node")
            name = blob[offset:end].decode("ascii")
            require("/" not in name, "FDT invalid node name")
            require(stack or name == "", "FDT root name")
            stack.append(name)
            offset = (end + 4) // 4 * 4
        elif token == 2:
            require(bool(stack), "FDT unmatched end node")
            stack.pop()
        elif token == 3:
            require(bool(stack) and offset <= limit - 8, "FDT property header")
            size, nameoff = struct.unpack_from(">II", blob, offset)
            offset += 8
            require(nameoff < ns, "FDT property name offset")
            end = blob.find(b"\0", strings + nameoff, strings + ns)
            require(end >= strings + nameoff, "FDT property name termination")
            name = blob[strings + nameoff:end].decode("ascii")
            require(size <= limit - offset, "FDT property extent")
            path = "/" + "/".join(stack[1:])
            key = path, name
            require(key not in properties, "FDT duplicate property")
            properties[key] = blob[offset:offset + size]
            offset = (offset + size + 3) // 4 * 4
        elif token == 4:
            pass
        elif token == 9:
            require(not stack, "FDT END with unclosed nodes")
            require(all(byte == 0 for byte in blob[offset:limit]), "FDT trailing structure data")
            ended = True
            break
        else:
            raise AssertionError(f"FDT invalid token {token}")
    require(ended, "FDT missing END token")
    return properties, reservations


def elf(blob):
    require(len(blob) >= 64 and blob[:7] == b"\x7fELF\x02\x01\x01", "ELF64 little endian")
    kind, machine = struct.unpack_from("<HH", blob, 16)
    entry, phoff, shoff = struct.unpack_from("<QQQ", blob, 24)
    flags, = struct.unpack_from("<I", blob, 48)
    ehsize, phsize, phnum, shsize, shnum, _ = struct.unpack_from("<6H", blob, 52)
    require(kind == 2 and machine == 243 and flags == 0 and ehsize == 64,
            "ELF RV64 executable, non-RVC, soft-float ABI")
    require(phsize == 56 and phnum and phoff + phsize * phnum <= len(blob),
            "ELF program header bounds")
    require(shsize == 64 and shoff + shsize * shnum <= len(blob), "ELF section bounds")
    loads = []
    for index in range(phnum):
        segment = struct.unpack_from("<IIQQQQQQ", blob, phoff + index * phsize)
        segment_kind, permissions, offset, virtual, physical, filesz, memsz, alignment = segment
        if segment_kind != 1:
            continue
        require(filesz <= memsz and offset + filesz <= len(blob), "ELF load bounds")
        require(virtual + memsz <= 1 << 64 and physical + memsz <= 1 << 64,
                "ELF load overflow")
        if alignment > 1:
            require(alignment & (alignment - 1) == 0 and virtual % alignment == offset % alignment,
                    "ELF load alignment")
        loads.append({"virtual": virtual, "physical": physical, "bytes": memsz,
                      "file_bytes": filesz, "permissions": permissions})
    require(any(load["permissions"] & 1 and load["virtual"] <= entry <
                load["virtual"] + load["bytes"] for load in loads), "ELF executable entry")
    return {"entry": entry, "loads": loads}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest_path = ROOT / args.manifest
    manifest = json.loads(manifest_path.read_text())
    source = json.loads((ROOT / "software/source-manifest.json").read_text())
    require(manifest["platform"] == source, "Build source manifest identity")
    for path, expected in manifest["sources"].items():
        require(digest(ROOT / path) == expected, f"Source hash: {path}")
    for name, image in manifest["images"].items():
        path = ROOT / image["path"]
        require(path.stat().st_size == image["bytes"] and digest(path) == image["sha256"],
                f"Image identity: {name}")
    build = manifest_path.parent
    record = json.loads((build / "build-record.json").read_text())
    require(record["status"] == "built" and all(c["exit_code"] == 0 for c in record["commands"]),
            "Build did not complete successfully")
    require(record["sources"] == manifest["sources"], "Build/source hash identity")
    required_prefix = "-march=rv64ima_zicsr_zifencei"
    commands = record["commands"]
    for compiler, source_file in (
        ("/usr/bin/riscv64-unknown-elf-gcc", "software/fw_jump.c"),
        ("/usr/bin/riscv64-linux-gnu-gcc", "software/init.c"),
    ):
        require(any(c["argv"][0] == compiler and source_file in c["argv"] and
                    required_prefix in c["argv"] and "-mabi=lp64" in c["argv"] and
                    c["exit_code"] == 0 for c in commands), f"Actual cross-compilation: {source_file}")
    linux_commands = [
        c for c in commands if c["argv"][0] == "make" and "vmlinux" in c["argv"]
    ]
    require(len(linux_commands) == 1, "Missing real Linux build")
    log = (ROOT / linux_commands[0]["stdout"]).read_text()
    require("/usr/bin/riscv64-linux-gnu-gcc" in log and required_prefix in log,
            "Kernel log lacks actual cross-compiler invocation")
    config = (ROOT / manifest["images"]["linux.config"]["path"]).read_text()
    require("\nCONFIG_RANDOM_TRUST_BOOTLOADER=y\n" in "\n" + config,
            "Bootloader entropy trust not enabled")
    require("\n# CONFIG_RANDOM_TRUST_CPU is not set\n" in "\n" + config,
            "CPU entropy trust not disabled")
    blob = (ROOT / manifest["images"]["hammer-v4.dtb"]["path"]).read_bytes()
    properties, reservations = fdt(blob)
    require((0x80000000, 0x200000) in reservations and
            (0x87e00000, 0x200000) in reservations, "Required reserved memory")
    required_properties = {
        ("/cpus/cpu@0", "riscv,isa"): b"rv64ima\0",
        ("/cpus/cpu@0", "mmu-type"): b"riscv,sv39\0",
        ("/cpus", "timebase-frequency"): struct.pack(">I", 100000000),
        ("/memory@80000000", "reg"): struct.pack(">4I", 0, 0x80000000, 0, 0x8000000),
        ("/soc/clint@2000000", "reg"): struct.pack(">4I", 0, 0x2000000, 0, 0x10000),
        ("/soc/interrupt-controller@c000000", "reg"): struct.pack(">4I", 0, 0xc000000, 0, 0x4000000),
        ("/soc/serial@10010000", "compatible"): b"ns16550a\0",
        ("/soc/serial@10010000", "reg"): struct.pack(">4I", 0, 0x10010000, 0, 0x100),
        ("/soc/serial@10010000", "reg-shift"): bytes(4),
        ("/soc/serial@10010000", "reg-io-width"): struct.pack(">I", 1),
    }
    for key, expected in required_properties.items():
        require(properties.get(key) == expected, f"FDT platform property {key}")
    rejected = 0
    for offset, value in ((0, 0), (4, len(blob) + 1), (8, len(blob) - 1),
                          (12, len(blob) + 1), (16, 41), (32, len(blob) + 1),
                          (36, len(blob) + 1)):
        corrupt = bytearray(blob)
        struct.pack_into(">I", corrupt, offset, value)
        try:
            fdt(corrupt)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"Independent FDT parser accepted corrupt header offset {offset}")
    executables = {}
    for name in ("fw_jump.elf", "vmlinux", "init"):
        path = ROOT / manifest["images"][name]["path"]
        executables[name] = elf(path.read_bytes())
        argv = ["/usr/bin/riscv64-linux-gnu-readelf", "-A", path.relative_to(ROOT).as_posix()]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
        (out / f"{name}.attributes.log").write_bytes(result.stdout + result.stderr)
        require(result.returncode == 0, f"ELF ISA attributes unavailable: {name}")
        attributes = result.stdout.decode()
        architecture = [line.split('"')[1] for line in attributes.splitlines()
                        if "Tag_RISCV_arch:" in line]
        require(len(architecture) == 1, f"Missing ELF ISA declaration: {name}")
        extensions = architecture[0].split("_")
        require(extensions[0].startswith("rv64i") and all(
            item.startswith(("m2p", "a2p", "zicsr2p", "zifencei2p")) for item in extensions[1:]
        ), f"Unsupported ELF ISA extensions: {name} {architecture}")
    require(executables["fw_jump.elf"]["entry"] == 0x80000000, "Firmware ELF entry")
    kernel = (ROOT / manifest["images"]["Image"]["path"]).read_bytes()
    require(kernel[48:56] == b"RISCV\0\0\0", "Linux Image magic")
    offset, extent = struct.unpack_from("<QQ", kernel, 8)
    require(offset == 0x200000 and len(kernel) <= extent and 0x80200000 + extent <= 0x87e00000,
            "Linux Image physical entry and DTB overlap")
    loaded = sorted(
        (item["address"], item["address"] + (ROOT / item["path"]).stat().st_size)
        for item in manifest["memory_loads"]
    )
    require([start for start, _ in loaded] == [0x80000000, 0x80200000, 0x87e00000],
            "Platform load addresses")
    require(all(0x80000000 <= start < end <= 0x88000000 for start, end in loaded) and
            all(previous[1] <= following[0] for previous, following in zip(loaded, loaded[1:])),
            "Loaded image overflow/overlap")
    summary = {"executables": executables, "fdt_properties_compared": len(required_properties),
               "malformed_fdt_headers_rejected": rejected, "sources_compared": len(manifest["sources"]),
               "images_compared": len(manifest["images"])}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
