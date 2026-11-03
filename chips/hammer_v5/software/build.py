#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline genuine OpenSBI/Linux/initramfs build; no simulation or synthesis."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
INPUTS = ROOT / "software"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def relative(path):
    return path.resolve().relative_to(ROOT).as_posix()


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def extract(archive, destination, source_root):
    destination.mkdir()
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        for member in members:
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or name.parts[0] != source_root:
                raise ValueError(f"unsafe archive member: {member.name}")
            if member.isdev() or member.isfifo():
                raise ValueError(f"unexpected special archive member: {member.name}")
            if member.issym() or member.islnk():
                link = Path(member.linkname)
                base = destination / (name.parent if member.issym() else Path())
                resolved = (base / link).resolve()
                if not resolved.is_relative_to(destination.resolve()):
                    raise ValueError(f"unsafe archive link: {member.name}")
        stream.extractall(destination, members=members, filter="tar")
    return destination / source_root


def initramfs(path, elf):
    entries = [
        ("dev", stat.S_IFDIR | 0o755, b"", 0, 0),
        ("proc", stat.S_IFDIR | 0o755, b"", 0, 0),
        ("sys", stat.S_IFDIR | 0o755, b"", 0, 0),
        ("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1),
        ("init", stat.S_IFREG | 0o755, elf.read_bytes(), 0, 0),
        ("TRAILER!!!", 0, b"", 0, 0),
    ]
    with path.open("wb") as stream:
        for inode, (name, mode, data, major, minor) in enumerate(entries, 1):
            encoded = name.encode() + b"\0"
            fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0,
                      major, minor, len(encoded), 0)
            header = b"070701" + "".join(f"{v:08x}" for v in fields).encode()
            stream.write(header + encoded)
            stream.write(b"\0" * (-(110 + len(encoded)) & 3))
            stream.write(data)
            stream.write(b"\0" * (-len(data) & 3))
        stream.write(b"\0" * (-stream.tell() & 511))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    output = args.output or Path("evidence") / f"software-build-{stamp()}"
    if output.is_absolute() or ".." in output.parts:
        parser.error("--output must be a project-relative new directory")
    out = ROOT / output
    out.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema": 1, "kind": "software-build", "start": stamp(),
        "argv": ["python3", "software/build.py"] + sys.argv[1:],
        "cwd": ".", "network": "no network operations in build recipe",
        "tools": {}, "inputs": {}, "commands": [], "exit": None,
        "stdout": relative(out / "stdout.txt"),
        "stderr": relative(out / "stderr.txt"),
    }
    env = os.environ.copy()
    env.update({
        "SOURCE_DATE_EPOCH": "1700000000", "KBUILD_BUILD_TIMESTAMP": "@1700000000",
        "KBUILD_BUILD_USER": "hammer", "KBUILD_BUILD_HOST": "reproducible",
        "KBUILD_BUILD_VERSION": "1", "LC_ALL": "C", "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    for key in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
                "KCONFIG_CONFIG", "KCONFIG_ALLCONFIG", "CROSS_COMPILE", "ARCH"):
        env.pop(key, None)
    stdout = (out / "stdout.txt").open("wb")
    stderr = (out / "stderr.txt").open("wb")

    def run(argv, cwd=ROOT):
        command = {"argv": argv, "cwd": relative(cwd), "start": stamp(),
                   "timeout": None, "exit": None,
                   "stdout": receipt["stdout"], "stderr": receipt["stderr"]}
        receipt["commands"].append(command)
        stdout.write(("\nCOMMAND " + json.dumps(command) + "\n").encode())
        stdout.flush()
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr)
        command.update(end=stamp(), exit=result.returncode)
        if result.returncode:
            raise RuntimeError(f"command failed ({result.returncode}): {argv[0]}")

    try:
        manifest = json.loads((INPUTS / "boot_manifest.json").read_text())
        minimum_python = tuple(manifest["minimum_python"])
        if sys.version_info[:2] < minimum_python:
            raise RuntimeError(
                f"required Python {minimum_python[0]}.{minimum_python[1]}+ missing: "
                f"running {sys.version_info.major}.{sys.version_info.minor}")
        for item in manifest["software_inputs"]:
            path = INPUTS / item
            if not path.is_file():
                raise FileNotFoundError(f"required boot input missing: software/{item}")
            receipt["inputs"][relative(path)] = digest(path)
        for source in manifest["sources"]:
            path = INPUTS / source["file"]
            if not path.is_file():
                raise FileNotFoundError(f"required pinned source missing: software/{source['file']}")
            actual = digest(path)
            receipt["inputs"][relative(path)] = actual
            if actual != source["sha256"]:
                raise ValueError(f"pinned source checksum mismatch: software/{source['file']}")
        for tool in manifest["required_tools"]:
            if shutil.which(tool) is None:
                raise FileNotFoundError(f"required installed build tool missing: {tool}")
            argv = [tool, "--version"] if tool != "perl" else [tool, "-v"]
            start = stamp()
            version = subprocess.run(argv, cwd=ROOT, env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            end = stamp()
            version_out = out / f"{tool}.version.stdout.txt"
            version_err = out / f"{tool}.version.stderr.txt"
            version_out.write_bytes(version.stdout)
            version_err.write_bytes(version.stderr)
            text = version.stdout + version.stderr
            stdout.write(b"\nVERSION " + tool.encode() + b"\n" + text)
            receipt["tools"][tool] = {"argv": argv, "cwd": ".", "start": start,
                                     "end": end, "exit": version.returncode,
                                     "stdout": relative(version_out),
                                     "stderr": relative(version_err),
                                     "version": text.decode(errors="replace")}
            if version.returncode:
                raise RuntimeError(f"tool version query failed: {tool}")
        for tool in manifest["host_utilities"]:
            if shutil.which(tool) is None:
                raise FileNotFoundError(f"required installed host utility missing: {tool}")

        sources = []
        for source in manifest["sources"]:
            sources.append(extract(INPUTS / source["file"], out / source["root"],
                                   source["root"]))
        linux, opensbi = sources
        spec = importlib.util.spec_from_file_location("hammer_source_patch",
                                                      INPUTS / "patch_sources.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.apply(linux, opensbi, INPUTS)
        shutil.copyfile(INPUTS / "opensbi.config",
                        opensbi / "platform/generic/configs/hammer_v5_defconfig")
        patched = {}
        for source_dir in sources:
            for path in sorted(source_dir.rglob("*")):
                if path.is_file():
                    patched[relative(path)] = digest(path)
        (out / "source_hashes.json").write_text(json.dumps(patched, indent=2) + "\n")

        init = out / "init.elf"
        prefix = ["riscv64-unknown-elf-gcc", "-O2", "-std=gnu11", "-ffreestanding",
                  "-fno-builtin", "-fno-stack-protector", "-nostdlib", "-static",
                  "-mabi=lp64", "-march=rv64im_zicsr_zifencei", "-mstrict-align",
                  "-mno-relax", "-mcmodel=medany", "-fno-tree-loop-distribute-patterns",
                  "-Wall", "-Wextra", "-Werror",
                  "-Wl,--build-id=none", "-Wl,-e,_start",
                  f"-ffile-prefix-map={relative(INPUTS)}=software",
                  "-Isoftware"]
        run(prefix + ["software/init_start.S", "software/init.c",
                      "software/hammer_v5_context.S", "-o", relative(init)])
        initramfs(out / "initramfs.cpio", init)

        kbuild = out / "linux-build"
        kbuild.mkdir()
        shutil.copyfile(INPUTS / "linux.config", kbuild / ".config")
        config = kbuild / ".config"
        with config.open("a") as stream:
            # Kbuild executes recipes from the O= output directory.
            cpio_relative = os.path.relpath(out / "initramfs.cpio", kbuild)
            stream.write(f'CONFIG_INITRAMFS_SOURCE="{cpio_relative}"\n')
        kernel_make = ["make", "-C", relative(linux),
                       "O=" + os.path.relpath(kbuild, linux), "ARCH=riscv",
                       "CROSS_COMPILE=riscv64-linux-gnu-"]
        run(kernel_make + ["olddefconfig"])
        resulting_config = config.read_text()
        required = {
            "CONFIG_SOC_HAMMER_V5": "y", "CONFIG_MMU": "y", "CONFIG_PREEMPT": "y",
            "CONFIG_RISCV_ISA_C": "y", "CONFIG_SERIAL_8250_CONSOLE": "y",
            "CONFIG_SERIAL_OF_PLATFORM": "y", "CONFIG_BINFMT_ELF": "y",
            "CONFIG_BLK_DEV_INITRD": "y", "CONFIG_RISCV_SBI": "y",
            "CONFIG_CRYPTO": "y", "CONFIG_CRYPTO_MANAGER_DISABLE_TESTS": "y",
            "CONFIG_EXPERT": "y", "CONFIG_INIT_STACK_NONE": "y",
            "CONFIG_PROC_FS": "y", "CONFIG_SYSFS": "y",
            "CONFIG_DEVTMPFS": "y", "CONFIG_DEVTMPFS_MOUNT": "y",
            "CONFIG_TMPFS": "y", "CONFIG_POSIX_TIMERS": "y",
            "CONFIG_HIGH_RES_TIMERS": "y", "CONFIG_RISCV_TIMER": "y",
            "CONFIG_HZ_100": "y", "CONFIG_FUTEX": "y", "CONFIG_MULTIUSER": "y",
            "CONFIG_PREEMPTION": "y", "CONFIG_SIGNALFD": "y",
            "CONFIG_TTY": "y", "CONFIG_SERIAL_8250": "y",
            "CONFIG_SERIAL_CORE_CONSOLE": "y", "CONFIG_SERIAL_EARLYCON": "y",
            "CONFIG_OF": "y", "CONFIG_OF_FLATTREE": "y",
            "CONFIG_OF_EARLY_FLATTREE": "y", "CONFIG_OF_ADDRESS": "y",
            "CONFIG_OF_IRQ": "y", "CONFIG_OF_KOBJ": "y",
            "CONFIG_OF_RESERVED_MEM": "y", "CONFIG_TIMER_OF": "y",
            "CONFIG_RISCV_INTC": "y", "CONFIG_SIFIVE_PLIC": "y",
        }
        for name, value in required.items():
            if f"{name}={value}\n" not in resulting_config:
                raise ValueError(f"boot configuration did not enable {name}={value}")
        for name in ("CONFIG_VT", "CONFIG_LEGACY_PTYS"):
            if f"# {name} is not set\n" not in resulting_config:
                raise ValueError(f"boot configuration did not disable {name}")
        disabled = (
            "CONFIG_SMP", "CONFIG_FPU", "CONFIG_RISCV_ISA_V", "CONFIG_COMPAT",
            "CONFIG_PERF_EVENTS", "CONFIG_RISCV_PMU_SBI",
            "CONFIG_DEBUG_KERNEL", "CONFIG_DEBUG_MISC", "CONFIG_SLUB_DEBUG",
            "CONFIG_SLUB_DEBUG_ON", "CONFIG_RCU_TRACE",
            "CONFIG_INIT_STACK_ALL_ZERO", "CONFIG_INIT_STACK_ALL_PATTERN",
            "CONFIG_INPUT", "CONFIG_INPUT_KEYBOARD", "CONFIG_KEYBOARD_ATKBD",
            "CONFIG_INPUT_MOUSE", "CONFIG_MOUSE_PS2", "CONFIG_INPUT_VIVALDIFMAP",
            "CONFIG_SERIO", "CONFIG_SERIO_SERPORT", "CONFIG_SERIO_LIBPS2",
            "CONFIG_HID_SUPPORT", "CONFIG_HID", "CONFIG_HID_GENERIC",
            "CONFIG_HWMON", "CONFIG_USB_SUPPORT", "CONFIG_USB",
            "CONFIG_USB_ARCH_HAS_HCD", "CONFIG_USB_GADGET",
            "CONFIG_SUSPEND", "CONFIG_SUSPEND_FREEZER", "CONFIG_HIBERNATION",
            "CONFIG_PM", "CONFIG_PM_SLEEP", "CONFIG_PM_CLK",
        )
        resolved = {}
        for line in resulting_config.splitlines():
            if line.startswith("CONFIG_") and "=" in line:
                name, value = line.split("=", 1)
                resolved[name] = value
            elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
                resolved[line[2:-11]] = "n"
        for name in disabled:
            # Kconfig omits symbols whose dependencies make them unavailable.
            if resolved.get(name, "n") != "n":
                raise ValueError(f"boot configuration did not disable {name}")
        receipt["resolved_kernel_settings"] = {
            name: resolved.get(name, "n")
            for name in sorted(set(required) | set(disabled) |
                               {"CONFIG_VT", "CONFIG_LEGACY_PTYS"})
        }
        run(kernel_make + [f"-j{args.jobs}", "Image", "scripts_dtc"])
        run([relative(kbuild / "scripts/dtc/dtc"), "-I", "dts", "-O", "dtb",
             "-p", "4096", "-o", relative(out / "hammer_v5.dtb"),
             "software/hammer_v5.dts"])

        obuild = out / "opensbi-build"
        firmware_make = ["make", "-C", relative(opensbi), "O=" + relative(obuild),
                         "PLATFORM=generic", "PLATFORM_DEFCONFIG=hammer_v5_defconfig",
                         "CROSS_COMPILE=riscv64-unknown-elf-",
                         "PLATFORM_RISCV_XLEN=64", "PLATFORM_RISCV_ABI=lp64",
                         "PLATFORM_RISCV_ISA=rv64imac_zicsr_zifencei",
                         "FW_TEXT_START=0x80000000", "FW_JUMP_ADDR=0x80200000",
                         "FW_JUMP_FDT_ADDR=0x87e00000", "FW_DYNAMIC=n", "FW_PAYLOAD=n"]
        # OpenSBI's relative O is interpreted after make -C.
        firmware_make[3] = "O=" + os.path.relpath(obuild, opensbi)
        run(firmware_make + [f"-j{args.jobs}"])
        artifacts = {
            "opensbi.bin": obuild / "platform/generic/firmware/fw_jump.bin",
            "opensbi.elf": obuild / "platform/generic/firmware/fw_jump.elf",
            "Image": kbuild / "arch/riscv/boot/Image",
            "vmlinux": kbuild / "vmlinux",
            "linux.config": config,
            "opensbi.config": obuild / "platform/generic/kconfig/.config",
        }
        for name, source in artifacts.items():
            shutil.copyfile(source, out / name)
        if (out / "opensbi.bin").stat().st_size > 0x200000:
            raise ValueError("OpenSBI image overlaps Linux entry")
        if (out / "Image").stat().st_size > 0x7c00000:
            raise ValueError("Linux image overlaps fixed ROM DTB address")
        images = [
            {"file": "opensbi.bin", "address": "0x80000000"},
            {"file": "Image", "address": "0x80200000"},
            {"file": "hammer_v5.dtb", "address": "0x87e00000"},
        ]
        for image in images:
            image["sha256"] = digest(out / image["file"])
            image["bytes"] = (out / image["file"]).stat().st_size
        product = {
            "schema": 1, "top": "hammer_v5_top", "images": images,
            "inputs": receipt["inputs"], "init_sha256": digest(init),
            "initramfs_sha256": digest(out / "initramfs.cpio"),
            "linux_config_sha256": digest(out / "linux.config"),
            "opensbi_config_sha256": digest(out / "opensbi.config"),
            "tools": receipt["tools"], "memory": manifest["memory"],
        }
        (out / "images.json").write_text(json.dumps(product, indent=2) + "\n")
        receipt["outputs"] = {
            relative(out / name): digest(out / name)
            for name in ("images.json", "opensbi.bin", "opensbi.elf", "Image",
                         "vmlinux", "hammer_v5.dtb", "init.elf", "initramfs.cpio",
                         "linux.config", "opensbi.config", "source_hashes.json")
        }
        receipt["exit"] = 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        receipt["error"] = str(error)
        receipt["exit"] = 1
        stderr.write((str(error) + "\n").encode())
    finally:
        stdout.close()
        stderr.close()
        receipt["end"] = stamp()
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"exit": receipt["exit"], "receipt": relative(out / "receipt.json")}))
    return receipt["exit"]


if __name__ == "__main__":
    sys.exit(main())
