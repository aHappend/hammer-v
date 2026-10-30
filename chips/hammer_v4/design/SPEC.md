# HAMMER-V4 implementation contract

## Authority and scope

Implement a single-hart, little-endian RV64IMA Linux platform, not a Linux-like
supervisor. The authoritative work order and independently admitted timed-oracle
contract remain mandatory. This document describes the design interfaces; it
does not certify implementation, software execution, synthesis or hardware.
Designer owns `rtl/`, `software/` and design documentation. Independent Verifier
owns tests, architectural/timing models and all functional/synthesis results.
The shared runtime owns STA, physical hardware gates and the final product PDF.

The immutable parent is `hammer_v3_reference/rtl/`. Working inherited sources
are copied into `rtl/`; differences must be listed in ARCHITECTURE.md.
`GENERATIONAL_HANDOFF.md` reports historical parent setup WNS 0.288 ns,
Fmax 102.97 MHz and hold WNS 0.038 ns. Parent resource counts are unavailable.
These are not V4 results.

## Interface and legal parameters

`hammer_v4_top` retains every named parameter, port, width, direction and
unsigned interpretation of `hammer_v3_top`. It literally instantiates that
module as `u_v3`. Only `BOOT_ENABLE=1` and output wires `boot_ready` and
`boot_error` are added. All AXI4 memory, AXI-Lite peripheral, coherent
accelerator, debug, retirement and interrupt interfaces are retained.

| Parameter | Default | Legal values |
|---|---:|---|
| IMEM_WORDS | 16384 | 1 through 16384 |
| DMEM_WORDS | 8192 | 1 through 8192 |
| PRED_MODE | 1 | 0, 1 |
| BTB_ENTRIES | 16 | 1, 4, 16, 64 |
| ICACHE_LINES, DCACHE_LINES | 64 | 1, 4, 16, 64 |
| LEGACY_TRAPS | 0 | 0, 1 |
| ITLB_ENTRIES, DTLB_ENTRIES | 8 | 1, 4, 8, 16 |
| BOOT_ENABLE | 1 | 0, 1 |

Boot mode additionally requires IMEM_WORDS >= 32 and LEGACY_TRAPS=0.
Illegal configurations have a guarded datapath and an executable
`PARAMETER ERROR` fatal diagnostic, not silently clamped hardware.
Compatibility mode retains singleton and non-power-of-two memory depths.

## Cycle & Degenerate-Boundary Table

All handshakes sample pre-edge values. State/status updates are post-edge.
The only clock is 100 MHz; reset is active-low asynchronous.

| Boundary/event | Pre-edge condition | Post-edge behavior |
|---|---|---|
| Active reset | rst_n=0 | IDLE, boot flags 0, no loader/host/start acceptance; inherited halted=1 and UART idle high |
| First released edge, boot | IDLE | ISSUE for ROM word 0; no queued external start |
| First released edge, compatibility | IDLE | boot_ready=1; parent operation becomes available |
| ISSUE, not ready | internal valid=1 | address/data/mask and word index unchanged |
| ISSUE acceptance | parent host_valid && host_ready | exactly one write; enter WAIT |
| WAIT without response | parent host_rsp_valid=0 | no request and no index change |
| Successful response, words 0..30 | parent host_rsp_valid && !error | increment index, enter ISSUE |
| Successful response, word 31 | same | boot_ready=1, DONE; final internal response remains hidden |
| Error response | parent host_rsp_valid && error | boot_error=1, FAILED; prohibit launch until reset |
| External host/start during boot | boot_ready=0 | host_ready=0; no external response, no queued start |
| Ready host and start together | host_valid=1 | retain parent's host priority |
| Reset during ISSUE/WAIT | falling rst_n | cancel loader transaction and parent work |
| IMEM_WORDS=1 or 3 | BOOT_ENABLE=0 | explicit parent index/range logic; no power-of-two wrap assumption |
| IMEM_WORDS=32 | BOOT_ENABLE=1 | write exactly addresses 0 through 124, no wrap |
| Maximum legal memories/caches | legal tuple | identical protocol; latency is not fixed to one cycle |
| Accelerator during boot | wrapper not ready | request channels blocked; no boot-loader interference |

The wrapper installs 32 instruction words through the parent's halted host
protocol. The ROM trampoline sets a0=0, a1=0x87e00000 and jumps to 0x80000000.
Unused words are valid RV64 NOPs. Platform software images must already be
populated in external RAM before `start`; the wrapper does not load external
RAM, fabricate software state or inject UART bytes.

## Architecture and platform

One RV64 hart, hartid 0, M/S/U, Sv39, I/M/A and privileged CSR/fence
instructions; no C/F/D/V or SMP. XLEN arithmetic wraps at 64 bits, word
operations sign-extend, and M-extension division includes zero/overflow cases.
Multiply/divide are sequential. No combinational division/modulo operators,
mixed assignment styles in sequential blocks, inferred latches, or unbounded
combinational arithmetic are permitted. Physical target is Arria 10 GX
10AX115N2F45E1SG, <=10.0 ns with no admitted timing waiver.

Sv39 has 4 KiB pages, 512-entry tables, three levels, 44-bit satp PPN and
16-bit ASID, canonical sign extension from bit 38, and 2 MiB/1 GiB leaves.
Preserve V/R/W/X/U/G/A/D, SUM/MXR, alignment, fault causes/tval and scoped/global
sfence behavior. The inherited A/D policy faults when A=0 or a write sees D=0;
hardware does not update PTE A/D bits. Linux must service those faults.

| Resource | Physical address / behavior |
|---|---|
| RAM | 0x80000000, 128 MiB |
| Firmware | [0x80000000, 0x80200000), entry 0x80000000 |
| Kernel | physical entry 0x80200000, built-in initramfs |
| DTB | 0x87e00000; final 2 MiB reserved against allocation |
| CLINT | 0x02000000: msip +0, mtimecmp +0x4000, mtime +0xbff8 |
| Timebase | mtime increments once every released edge, 100000000 Hz |
| PLIC | 0x0c000000, 32 sources, priority 0..7, M/S contexts |
| UART | 0x10010000, ns16550a, byte registers, reg-shift=0, reg-io-width=1 |
| UART clock | 100000000 Hz, divisor 1, 8N1, 6250000 baud |
| Interrupts | UART ID 1, external plic_sources bits map to IDs 2..32 |

Equal-priority PLIC ties select the lowest ID. AXI payload/valid remain stable
under stalls; independent AW/W, IDs, burst geometry, strobes, errors and coherent
maintenance ordering remain inherited contracts. The external memory platform
must honor the full exposed byte addresses, not alias the Linux image into
on-chip instruction or data memory.

## Software

Ship actual upstream Linux 6.6.1 and its actual archive SHA-256, explicit
compatibility patches, deterministic configuration, a static RV64IMA `/init`,
firmware, DTS, linker scripts and a project-relative build entry point.
Use `/usr/bin/riscv64-unknown-elf-gcc` for firmware and
`/usr/bin/riscv64-linux-gnu-gcc` for Linux/userland. Loaded code must not contain
unsupported instructions. FDT is built with dtc, has magic 0xd00dfeed, valid
bounds/reservations/phandles and declares the exact platform above.

Firmware is identified as HAMMER OpenSBI-compatible fw_jump functionality, not
upstream OpenSBI. Provide SBI v0.2 base EID 0x10 functions 0..6, TIME function 0,
legacy console putchar/getchar, signed SBI errors and truthful extension
probing. Do not advertise DBCN without implementing it. Keep supervisor ecalls
in M-mode, delegate appropriate exceptions/interrupts, preserve full trap
contexts, transfer MTIP to software STIP, clear/rearm correctly and mret with
a0=hartid/a1=DTB_PA into S-mode entry 0x80200000.

Linux parses the in-memory DTB, enables its real Sv39 page tables and sfence,
initializes UART/PLIC/timer, enters U-mode through sret, and handles actual page
faults and syscalls. `/init` exercises demand allocation and write=64,
uname=160, getpid=172, exit=93. A successful PID-1 exit is followed by Linux's
real init-exit panic. The complete panic is part of acceptance, not an
artificial successful halt.

Linux's actual unaligned-access probe remains enabled. A source-controlled
compatibility patch provides delegated S-mode RV64 integer misalignment
emulation, selected by enforced `CONFIG_RISCV_SMODE_MISALIGNED_EMULATION=y`.
It must decode standard integer loads/stores, preserve signedness and x0,
use fault-safe instruction/data accesses, handle page boundaries and access
failures, and advance saved EPC only after successful emulation. Unsupported
instructions and AMOs retain their normal fault/fixup behavior. Kernel user
accesses require saved SUM; nofault kernel accesses may not sleep. Independent
directed cases and a fresh real Linux boot must establish the repair, not a
disabled probe or a fabricated successful result.

Freeze PRINTK=y, PRINTK_TIME=n, SMP=n, RANDOMIZE_BASE=n,
LOCALVERSION_AUTO=n, HZ_100=y, RISCV_SBI=y, SERIAL_8250=y,
SERIAL_8250_CONSOLE=y, SERIAL_EARLYCON=y and BLK_DEV_INITRD=y.
Freeze timestamp, build user/host/version, SOURCE_DATE_EPOCH, localversion,
compiler versions and initramfs order/ownership/timestamps. Bootargs are:

```
console=ttyS0,6250000n8 earlycon rdinit=/init loglevel=7 printk.time=0 nokaslr lpj=500000 panic=0
```

Use the actual 100 MHz earlycon clock. A fixed public test-only DT rng-seed and
RANDOM_TRUST_BOOTLOADER=y provide reproducible test input, not secure entropy.
Do not patch Linux to print expected outcomes or suppress warnings/failures.

## Independent acceptance and execution limits

The unchanged required command is `python3 tests/verify.py`; independent
Verifier supplies it. Do not add a dependency on the downstream product PDF.
All mandatory checks remain mandatory, including clean reproduction and native
timing/HIL. No current source or parent provenance is passing evidence.

The independent Python RV64IMA privileged/Sv39 interpreter and discrete-event
timing model execute the actual loaded images. Its interface is:

```
python3 tests/system_oracle.py --manifest <manifest> --scenario <scenario.json> --out <fresh-run-directory>
```

Only immutable images/build facts, timing rules and independently generated
stimuli may generate expectations. Generate and hash each complete expected
UART stream before its DUT execution. No observed UART, time, retirement
timestamp or DUT scheduling may flow into oracle expectation generation.
Model fetch queue, pipeline dependencies/redirects, cache/TLB/PTW, sequential
arithmetic, CSR/fence/return serialization, fabric, AXI and peripheral timing.
Do not translate RTL algorithms or fit timing to DUT observations.

Pre-edge state c=0 is the first released edge, with mtime=0. Released edges
increment time modulo 2^64 unless an accepted legal mtime write overrides it.
CLINT reads snapshot at request acceptance; time CSR samples at its CSR
commit edge, not the later observed retirement. Compare unsigned mtime>=cmp,
MTIP/STIP and delegation at real eligible interrupt boundaries, including drain
latency. Model UART two-flop RX synchronization, framing, FIFOs and PLIC.

Require full real Linux+/init RTL boots for seeds 11,29,47. Scenarios freeze
reset/start schedules, image hashes, 10 ns clock, AXI readiness/responses,
external IRQ and RX transitions. Channel-separated SHA-256 counter draws keyed
by seed/channel/transaction ordinal/beat yield 0..7-edge stalls; AW/W are
independent. Models count their own transactions, never resynchronize to DUT.
UART arrivals may be scheduled from an oracle-only preliminary setup edge
plus fixed margin/seed jitter, then frozen before a final oracle rerun.

Each preliminary oracle, final oracle, full boot and clean reproduction has a
separate continuous bound of 4294967296 released edges from c=0; no milestone
resets or inactivity watchdogs. Completion includes all milestones and the
entire serialized PID-1 panic. Compare the full UART byte stream, framing and
order without normalization, omitted lines, regex substitutions or DUT goldens.
Publish `evidence/uart_linux_boot.log` only from verified actual RTL UART
capture, after retaining immutable per-run provenance.

Observe M-to-S mret at 0x80200000 with correct a0/a1; successful FDT parse;
satp.MODE=8 and sfence; S-to-U sret; U retirement; a demand fault and successful
retried memory access; all four syscalls/results; >=3 delivered/rearmed
supervisor timer interrupts; and a UART-originated PLIC claim/complete cycle.
Labels and printed milestones are not architectural coverage.

Directed coverage includes bad FDT magic/bounds, unsupported SBI IDs/functions,
timer edge/wrap cases, nested context preservation, Sv39 permissions,
canonicality, superpages and invalidation, divide corner cases, reservations and
coherent accelerator interactions. Independent ELF/ISA/layout/build inspection
must reject unsupported code, overlap, overflow and incorrect entries.

Disposable compiled mutants must compile and fail actual targeted comparisons:
DTB handoff corruption, Sv39 permission bypass, SBI timer result/delivery
corruption, UART corruption, coherent invalidation breakage, time CSR mtime+1,
and one-edge delayed timer pending/delivery at an eligible boundary. Require an
unchanged passing control and control-bounded mutant mismatches, not syntax
failure or timeout. Comparator replay mutations independently alter a read value
and interrupt timestamp while expected hashes remain unchanged.

Use Icarus only for compact <=500000-cycle smoke/leaf/compatibility work with
expected runtime <60 s; use compiled Verilator for all boots, seed sweeps and
mutations. Stream comparisons and bounded mismatch context; no per-cycle
logging/flushing. Each mandatory command must settle within the 2700 s patrol
budget. Infrastructure settlement timeouts are not numerical pass criteria.
Any append-only sharding needs independent admission and retains the original
required command.

Real Yosys synthesis must retain the full top/core/MMU/coherent hierarchy,
state/connectivity and zero latches, without blackboxing or leaf substitution.
Independently regress BOOT_ENABLE=0 host/start/halt/retirement/AXI/coherence.
Clean reproduction rebuilds all images from declared inputs in a fresh
directory and executes the default seed without prior build/runtime artifacts.
Native runtime gates require L1.5 timing lint, Quartus 17.1 STA WNS>=0 at
100 MHz and Arria 10 GX PCIe Gen3x8 HIL with >=3 deterministic consecutive
passes. They are not duplicated by software tests.

Exclude `.vulcan/`, `.git/`, `.tooling/` and `VULCAN/` from source/output
selectors. Never ship private host paths, credentials or runtime transcripts.
