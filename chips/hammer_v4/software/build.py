#!/usr/bin/env python3
"""Build the shipped firmware, real Linux Image, DTB and static init."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path("software")
ISA = "rv64ima_zicsr_zifencei"
BARE_CC = "/usr/bin/riscv64-unknown-elf-gcc"
LINUX_CC = "/usr/bin/riscv64-linux-gnu-gcc"
BARE_OBJCOPY = "/usr/bin/riscv64-unknown-elf-objcopy"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def elf_entry(path):
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError(f"{path}: expected little-endian ELF64")
    elf_type, machine = struct.unpack_from("<HH", header, 16)
    flags = struct.unpack_from("<I", header, 48)[0]
    if machine != 243 or elf_type != 2 or flags != 0:
        raise ValueError(f"{path}: expected RV64 soft-float, non-RVC executable")
    return struct.unpack_from("<Q", header, 24)[0]


def require_config(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
    required = {
        "CONFIG_64BIT": "y", "CONFIG_MMU": "y", "CONFIG_NONPORTABLE": "y",
        "CONFIG_SMP": "n", "CONFIG_FPU": "n", "CONFIG_RISCV_ISA_C": "n",
        "CONFIG_RISCV_ISA_V": "n", "CONFIG_RISCV_ISA_ZBB": "n",
        "CONFIG_RISCV_ISA_SVNAPOT": "n", "CONFIG_RISCV_ISA_SVPBMT": "n",
        "CONFIG_RISCV_ISA_ZICBOM": "n", "CONFIG_RISCV_ISA_ZICBOZ": "n",
        "CONFIG_RISCV_ISA_FALLBACK": "y",
        "CONFIG_EFI": "n", "CONFIG_RISCV_SBI": "y",
        "CONFIG_PRINTK": "y", "CONFIG_PRINTK_TIME": "n",
        "CONFIG_RANDOMIZE_BASE": "n", "CONFIG_LOCALVERSION_AUTO": "n",
        "CONFIG_HZ_100": "y", "CONFIG_HZ_PERIODIC": "y",
        "CONFIG_SERIAL_8250": "y", "CONFIG_SERIAL_8250_CONSOLE": "y",
        "CONFIG_SERIAL_EARLYCON": "y", "CONFIG_SERIAL_OF_PLATFORM": "y",
        "CONFIG_RISCV_INTC": "y", "CONFIG_RISCV_TIMER": "y",
        "CONFIG_SIFIVE_PLIC": "y", "CONFIG_BLK_DEV_INITRD": "y",
        "CONFIG_BINFMT_ELF": "y", "CONFIG_RANDOM_TRUST_BOOTLOADER": "y",
        "CONFIG_LOCALVERSION": '"-hammer-v4"',
        "CONFIG_INITRAMFS_SOURCE": '"../initramfs.list"',
    }
    mismatches = [
        f"{key}: required {value}, got {values.get(key, 'absent')}"
        for key, value in required.items()
        if values.get(key, "n") != value
    ]
    if mismatches:
        raise ValueError("Kernel configuration contract failed:\n" + "\n".join(mismatches))


def image_layout(images, facts):
    fw_entry = elf_entry(images / "fw_jump.elf")
    if fw_entry != facts["firmware_entry"]:
        raise ValueError("Firmware ELF entry must be 0x80000000")
    elf_entry(images / "init")
    kernel_elf_entry = elf_entry(images / "vmlinux")
    fw_size = (images / "fw_jump.bin").stat().st_size
    if not 0 < fw_size <= 0x200000:
        raise ValueError("Firmware file overlaps kernel or is empty")
    kernel_file = images / "Image"
    with kernel_file.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[48:56] != b"RISCV\0\0\0":
        raise ValueError("Invalid upstream RISC-V Linux Image header")
    offset, extent = struct.unpack_from("<QQ", header, 8)
    if offset != 0x200000 or facts["ram_base"] + offset != facts["kernel_entry"]:
        raise ValueError("Linux physical entry must be 0x80200000")
    if extent < kernel_file.stat().st_size or extent == 0:
        raise ValueError("Invalid kernel memory extent")
    if facts["kernel_entry"] + extent > facts["dtb_address"]:
        raise ValueError("Linux image/BSS overlaps reserved DTB")
    dtb = (images / "hammer-v4.dtb").read_bytes()
    if len(dtb) < 40:
        raise ValueError("Truncated DTB")
    magic, total, structure, strings, reserve, version, compat, hart, ss, st = \
        struct.unpack_from(">10I", dtb)
    if magic != 0xD00DFEED or total != len(dtb) or total > 0x200000:
        raise ValueError("DTB magic/extent mismatch")
    if version != 17 or compat > 17 or hart != 0:
        raise ValueError("DTB version/hart mismatch")
    if structure < 40 or structure & 3 or structure > total or st > total - structure:
        raise ValueError("DTB structure bounds")
    if strings < 40 or strings > total or ss > total - strings:
        raise ValueError("DTB string bounds")
    if reserve < 40 or reserve & 7 or reserve > total - 16:
        raise ValueError("DTB reservation bounds")
    reservations = []
    while True:
        if reserve > total - 16:
            raise ValueError("DTB reservation table is unterminated")
        base, length = struct.unpack_from(">QQ", dtb, reserve)
        reserve += 16
        if base == 0 and length == 0:
            break
        reservations.append([base, length])
    for pair in [[facts["firmware_entry"], 0x200000],
                 [facts["dtb_address"], facts["dtb_reserved_size"]]]:
        if pair not in reservations:
            raise ValueError(f"DTB missing required reservation {pair}")
    return {
        "firmware_elf_entry": fw_entry,
        "linux_elf_virtual_entry": kernel_elf_entry,
        "linux_physical_entry": facts["kernel_entry"],
        "linux_memory_extent": extent,
        "init_elf_entry": elf_entry(images / "init"),
        "dtb_reservations": reservations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="build/software", help="fresh project-relative directory")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    os.chdir(ROOT)
    out = Path(args.out)
    if out.is_absolute() or ".." in out.parts or not out.parts:
        parser.error("--out must be a nonempty project-relative path without '..'")
    if any(part in {".vulcan", ".git", ".tooling", "VULCAN", "evidence",
                    "rtl", "software", "design", "tests", "hammer_v3_reference"}
           for part in out.parts):
        parser.error("--out must not overlap owned sources, evidence or runtime metadata")
    resolved_out = (ROOT / out).resolve()
    if not resolved_out.is_relative_to(ROOT):
        parser.error("--out resolves outside the delivered project")
    if any(part in {".vulcan", ".git", ".tooling", "VULCAN", "evidence",
                    "rtl", "software", "design", "tests", "hammer_v3_reference"}
           for part in resolved_out.relative_to(ROOT).parts):
        parser.error("--out resolves into owned sources, evidence or runtime metadata")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if out.exists():
        parser.error("--out already exists; preserve it and select a fresh directory")
    out.mkdir(parents=True)
    commands = out / "commands"
    commands.mkdir()
    record = {"schema": 1, "status": "incomplete", "cwd": ".",
              "started_unix": time.time(), "commands": []}
    environment = os.environ.copy()
    facts = json.loads((SOURCE / "source-manifest.json").read_text())
    environment.update({
        "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
        "SOURCE_DATE_EPOCH": str(facts["source_date_epoch"]),
        "KBUILD_BUILD_TIMESTAMP": facts["kbuild_build_timestamp"],
        "KBUILD_BUILD_USER": facts["kbuild_build_user"],
        "KBUILD_BUILD_HOST": facts["kbuild_build_host"],
        "KBUILD_BUILD_VERSION": facts["kbuild_build_version"],
        "KBUILD_ABS_SRCTREE": "0", "LOCALVERSION": "",
    })
    for key in ["KCONFIG_CONFIG", "KCONFIG_ALLCONFIG", "KBUILD_OUTPUT", "ARCH",
                "CROSS_COMPILE", "KCFLAGS", "KAFLAGS", "KCPPFLAGS", "LDFLAGS",
                "CFLAGS", "CPPFLAGS", "MAKEFLAGS", "MFLAGS", "KBUILD_SRC"]:
        environment.pop(key, None)

    def run(argv):
        argv = [str(arg) for arg in argv]
        ordinal = len(record["commands"])
        stdout = commands / f"{ordinal:04d}.stdout.log"
        stderr = commands / f"{ordinal:04d}.stderr.log"
        entry = {"argv": argv, "cwd": ".", "stdout": stdout.as_posix(),
                 "stderr": stderr.as_posix(), "started_unix": time.time()}
        record["commands"].append(entry)
        write_json(out / "build-record.json", record)
        print(f"BUILD {ordinal:04d}: {' '.join(argv)}", flush=True)
        with stdout.open("wb") as so, stderr.open("wb") as se:
            result = subprocess.run(argv, env=environment, stdout=so, stderr=se)
        entry.update(exit_code=result.returncode, ended_unix=time.time())
        write_json(out / "build-record.json", record)
        if result.returncode:
            raise RuntimeError(f"Build command {ordinal:04d} failed ({result.returncode}); "
                               f"see {stdout} and {stderr}")
        return stdout.read_text()

    try:
        required = ["make", "gcc", "g++", "dtc", "cpio", "tar", "xz", "bash", "bc",
                    "bison", "flex", "perl", BARE_CC, LINUX_CC, BARE_OBJCOPY,
                    "/usr/bin/riscv64-linux-gnu-objcopy",
                    "/usr/bin/riscv64-unknown-elf-ld", "/usr/bin/riscv64-linux-gnu-ld"]
        missing = [tool for tool in required if shutil.which(tool) is None]
        if missing:
            raise RuntimeError("Missing build prerequisites (no tools installed): " +
                               ", ".join(missing))
        versions = {}
        for role, compiler in [("firmware", BARE_CC), ("linux_and_init", LINUX_CC)]:
            version = run([compiler, "-dumpfullversion"]).strip()
            expected = facts["toolchains"][role]["version"]
            if version != expected:
                raise RuntimeError(f"{compiler}: version {version}, required {expected}")
            versions[role] = {"version": version,
                              "description": run([compiler, "--version"]).splitlines()[0]}
        versions["dtc"] = run(["dtc", "--version"]).strip()
        versions["bison"] = run(["bison", "--version"]).splitlines()[0]
        versions["flex"] = run(["flex", "--version"]).strip()
        for prefix in ["/usr/bin/riscv64-unknown-elf-", "/usr/bin/riscv64-linux-gnu-"]:
            for name in ["ld", "objcopy"]:
                executable = prefix + name
                description = run([executable, "--version"]).splitlines()[0]
                if description.split()[-1] != facts["binutils_version"]:
                    raise RuntimeError(f"{executable}: required binutils "
                                       f"{facts['binutils_version']}, got {description}")
                versions[executable] = description
        for tool in ["make", "gcc", "g++", "cpio", "tar", "xz", "bash", "bc"]:
            versions[tool] = run([tool, "--version"]).splitlines()[0]
        versions["python"] = run(["python3", "--version"]).strip()
        versions["perl"] = run(["perl", "-e", 'printf "%vd\\n", $^V;']).strip()
        archive = SOURCE / facts["linux"]["archive"]
        if sha256(archive) != facts["linux"]["sha256"]:
            raise ValueError("Pinned Linux source archive SHA-256 mismatch")
        input_files = sorted(p for p in SOURCE.iterdir() if p.is_file())
        inputs = {p.as_posix(): sha256(p) for p in input_files}
        images = out / "images"
        images.mkdir()
        common = [f"-march={ISA}", "-mabi=lp64", "-mcmodel=medany", "-mno-relax",
                  "-msmall-data-limit=0", "-mstrict-align", "-O2",
                  "-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-stack-protector",
                  "-fno-asynchronous-unwind-tables", "-nostdlib", "-static",
                  "-Wl,--build-id=none", "-Wl,--no-relax", "-Wall", "-Wextra", "-Werror"]
        run([BARE_CC, *common, "-T", SOURCE / "fw_jump.ld",
             SOURCE / "fw_entry.S", SOURCE / "fw_jump.c",
             "-o", images / "fw_jump.elf"])
        run([BARE_OBJCOPY, "-O", "binary", images / "fw_jump.elf", images / "fw_jump.bin"])
        run([LINUX_CC, *common, "-no-pie", "-T", SOURCE / "init.ld",
             SOURCE / "init_entry.S", SOURCE / "init.c", "-o", images / "init"])
        run(["dtc", "-I", "dts", "-O", "dtb", "-V", "17", "-b", "0",
             "-o", images / "hammer-v4.dtb", SOURCE / "hammer-v4.dts"])
        run(["tar", "--extract", "--xz", "--no-same-owner", "--no-same-permissions",
             "--file", archive, "--directory", out])
        linux = out / "linux-6.6.1"
        kernel = out / "linux-build"
        kernel.mkdir()
        cpio_spec = (
            "dir /dev 0755 0 0\n"
            "nod /dev/console 0600 0 0 c 5 1\n"
            "nod /dev/null 0666 0 0 c 1 3\n"
            "dir /proc 0555 0 0\n"
            "dir /sys 0555 0 0\n"
            "file /init ../images/init 0755 0 0\n"
        )
        (out / "initramfs.list").write_text(cpio_spec)
        config = (SOURCE / "linux.config").read_text()
        config += '\nCONFIG_INITRAMFS_SOURCE="../initramfs.list"\n'
        config += 'CONFIG_INITRAMFS_ROOT_UID=0\nCONFIG_INITRAMFS_ROOT_GID=0\n'
        (out / "kernel-all.config").write_text(config)
        make = ["make", "--no-print-directory", "-C", linux, "O=../linux-build",
                "ARCH=riscv", "CROSS_COMPILE=/usr/bin/riscv64-linux-gnu-",
                f"KCFLAGS=-march={ISA} -mabi=lp64 -mno-relax",
                f"KAFLAGS=-march={ISA} -mabi=lp64 -mno-relax"]
        run([*make, "KCONFIG_ALLCONFIG=../kernel-all.config", "allnoconfig"])
        require_config(kernel / ".config")
        run([*make, f"-j{args.jobs}", "V=1", "Image", "vmlinux"])
        for source, target in [
            (kernel / "arch/riscv/boot/Image", images / "Image"),
            (kernel / "vmlinux", images / "vmlinux"),
            (kernel / ".config", images / "linux.config"),
            (kernel / "System.map", images / "System.map"),
            (kernel / "usr/initramfs_data.cpio", images / "initramfs.cpio"),
        ]:
            shutil.copyfile(source, target)
        layout = image_layout(images, facts)
        output_files = sorted(p for p in images.iterdir() if p.is_file())
        manifest = {
            "schema": 1, "source_manifest": "software/source-manifest.json",
            "sources": inputs, "tools": versions, "platform": facts,
            "layout": layout,
            "images": {p.name: {"path": p.as_posix(), "bytes": p.stat().st_size,
                               "sha256": sha256(p)} for p in output_files},
            "memory_loads": [
                {"path": (images / "fw_jump.bin").as_posix(), "address": facts["firmware_entry"]},
                {"path": (images / "Image").as_posix(), "address": facts["kernel_entry"]},
                {"path": (images / "hammer-v4.dtb").as_posix(), "address": facts["dtb_address"]},
            ],
            "unloaded_external_ram_fill": 0,
            "boot_enable": 1, "reset_pc": 0,
        }
        write_json(out / "image-manifest.json", manifest)
        record["status"] = "built"
        record["image_manifest_sha256"] = sha256(out / "image-manifest.json")
        print(f"Built real Linux platform: {out / 'image-manifest.json'}")
    finally:
        record["ended_unix"] = time.time()
        write_json(out / "build-record.json", record)


if __name__ == "__main__":
    main()
