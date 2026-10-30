# Reproducible HAMMER-V4 software inputs

This package builds an original HAMMER OpenSBI-compatible firmware, actual
upstream Linux 6.6.1, the platform DTB and a static Linux-ABI `/init`. It is not
upstream OpenSBI and does not replace Linux with a demonstration supervisor.

From the delivered root, using a fresh output directory:

```
python3 software/build.py --out build/software --jobs 4
```

The builder refuses an occupied directory instead of overwriting retained
results. Choose a new project-relative directory for a new build, for example
`build/software-rebuild`. No download, installation, runtime metadata, JTAG
cable or PCIe device identifier is required by this command.

## Dependencies and pinned source

Required compilers are `/usr/bin/riscv64-unknown-elf-gcc` 13.2.0 and
`/usr/bin/riscv64-linux-gnu-gcc` 13.3.0, with cross-binutils 2.42.
Other build prerequisites are Python >=3.9, make, host gcc/g++, dtc, cpio,
tar, xz, bash, bc, bison, flex and perl. The observed dtc/bison/flex versions
are 1.7.0/3.8.2/2.6.4; actual builder tool versions are retained with each
build. No tools are installed by the builder. Earlier missing-tool reports do
not override a fresh inventory; at this source handoff those three names were
available on PATH.

The legally redistributable upstream source archive
`software/linux-6.6.1.tar.xz` is supplied, not fetched by the build. Its
recorded SHA-256 is:

```
da1ed7d47c97ed72c9354091628740aa3c40a3c9cd7382871f3cedbd60588234
```

It was obtained from the public kernel.org URL recorded in
`software/source-manifest.json`. The archive contains upstream `COPYING`,
`LICENSES/` and per-file license notices; preserve them on redistribution.
No third-party source is represented as original HAMMER code. No Linux source
patch is currently applied; `linux_patches` is explicitly empty.

The architecture is `rv64ima_zicsr_zifencei`, ABI `lp64`; firmware and init use
no libc, libgcc, dynamic linker, compressed instructions or floating point.
The Linux config disables EFI (which would select C), SMP, FPU, vector,
optional instruction-extension alternatives, measured LPJ and printk timestamps.
Upstream Linux's DT earlycon path honors the real 100 MHz UART clock without a
patch. `CONFIG_RISCV_ISA_FALLBACK=y` intentionally enables the admitted legacy
`riscv,isa="rv64ima"` DT property.

Kbuild identity, timestamp, version, localversion and SOURCE_DATE_EPOCH are
frozen in the source manifest. The initramfs uses a fixed ordered specification
with UID/GID zero and the fixed Kbuild timestamp. `/dev/console` and `/dev/null`
are included as device nodes; no external root filesystem is needed.
The DT rng-seed is public test data and must never be treated as secure entropy.

## Build outputs and platform loading

`build/software/image-manifest.json` contains actual software source hashes,
compiler/tool identities, image hashes/sizes, Linux Image memory extent,
virtual/physical entry distinctions, DT reservations and addressed memory loads.
`build-record.json` retains the exact outer build commands, relative cwd,
timestamps, exit codes and raw stdout/stderr locations, including a failed
command if one occurs. Kbuild runs with verbose compiler invocations so the
independent Verifier can inspect actual cross-compiler use. These generated
records are not acceptance evidence by themselves.

| Generated image | Load address / purpose |
|---|---|
| images/fw_jump.bin | 0x80000000, machine firmware |
| images/Image | 0x80200000, unmodified Linux Image format, physical entry at its start |
| images/hammer-v4.dtb | 0x87e00000, FDT handoff |
| images/init | Static ELF embedded in Linux's built-in initramfs, not independently injected into DUT state |
| images/fw_jump.elf, images/vmlinux | Symbols and independent ELF inspection |
| images/linux.config, images/System.map, images/initramfs.cpio | Exact generated build inputs/results for reproduction |

Initialize the platform's 128 MiB external RAM deterministically to zero,
then populate the three addressed raw images before asserting `start`.
Do not load `vmlinux` at its linked virtual ELF entry or place kernel images
in the small on-chip memories. Firmware's first 2 MiB and DTB's final 2 MiB
are reserved. Linker/image checks reject entry mismatch, overlap or overflow.

With `BOOT_ENABLE=1`, assert active-low reset, release it on the single 100 MHz
clock, keep start low until `boot_ready=1` and `boot_error=0`, then assert start
using the parent's host-priority rule. Serial is 6250000 baud, divisor one,
8N1, LSB first, idle high. UART is 0x10010000, not the common virt-platform
0x10000000 address. Accelerator requests must wait for boot_ready.

`/init` uses actual Linux write, uname, getpid and exit calls, plus mmap,
munmap, nanosleep and a UART read. Verification scenarios must deliver the
ASCII line `v4\n` as valid UART RX frames at their independently frozen
edge-indexed times. No physical operator input is required. The program checks
its data and API results before exit. Successful exit status zero from PID 1
causes Linux's real init-exit panic; complete panic output is required.

## Independent reproduction and acceptance

The independent Verifier owns and supplies the unchanged entry point:

```
python3 tests/verify.py
```

It must build missing fresh artifacts itself, execute the independent timed
oracle before DUT runs, run complete Linux boots for seeds 11/29/47, compare
all serialized UART bytes, exercise directed/mutation/compatibility cases,
perform full-hierarchy synthesis and reproduce a default-seed boot in a
fresh directory from the declared deliverable inputs. See `design/SPEC.md`
and `design/ARCHITECTURE.md` for exact requirements and continuous edge budgets.
The absence of a Verifier-authored script at Designer handoff is not a pass.
Do not replace it with a source-inventory check or a software-only boot.

Only the shared runtime executes native timing/HIL gates. The final product
PDF is generated after engineering acceptance. The source handoff does not
claim a kernel build, functional boot or physical result. Generated Kbuild
trees and command logs are not source deliverables; package only declared
sources, legally required notices and independently approved product/evidence
outputs. Do not include private host paths or runtime metadata.
