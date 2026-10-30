# HAMMER-V4 architecture and implementation timing

## Composition and source provenance

The new hardware is `rtl/hammer_v4_top.sv` and
`rtl/hammer_v4_boot_rom.sv`. All 40 inherited `.sv` files in `rtl/` were derived
from the identically named `hammer_v3_reference/rtl/` files without intentional
modification. There is no replacement CPU, MMU, cache, UART, PLIC or coherent
bridge. The parent reference remains immutable. Compile `rtl/*.sv` for V4;
do not also compile the duplicate reference module definitions in that command.
Compatibility comparisons compile the parent separately.

The supplied generational handoff's private origin-directory spelling is
replaced with the project-relative reference location for delivery. Historical
timing figures, module inventory and byte-lane inference guidance are unchanged.

The hierarchy is:

```
hammer_v4_top
  g_legal.u_boot_rom                 hammer_v4_boot_rom
  g_legal.u_v3                       hammer_v3_top
    g_legal.u_core                  hammer_v3_core
      u_decode/u_regfile/u_hazard/u_alu/u_muldiv/u_predictor
      u_csr/u_trap/u_atomic
    g_legal.u_mmu                    hammer_v3_mmu
      u_itlb/u_dtlb/u_ptw
    g_legal.u_fetch_path/u_data_path/u_data_router
    g_legal.u_i_arbiter/u_d_arbiter/u_icache/u_dcache
    g_legal.u_fabric/u_mem_axi/u_accel
    g_legal.u_clint/u_plic/u_uart/u_axi
```

Inherited RAM/cache storage uses synchronous byte lanes with `nomem2reg` and
M20K inference attributes, including odd/singleton instruction depths.
The new ROM is a six-entry constant decode with NOP default, not a loaded RAM.
No new large memory or arithmetic operator is introduced. Wrapper muxing,
five-bit indexing and registered control add bounded logic but are not proof
that the parent timing margin survives placement.

The generational handoff's 0.288 ns setup WNS, 102.97 MHz Fmax and 0.038 ns
hold WNS are historical parent figures only. No V4 STA, resource estimate or
physical hardware result is established by this document. Current target remains
100 MHz, Arria 10 GX 10AX115N2F45E1SG, with no timing waiver.

## Boot sequencing and ownership

Reset PC is the inherited address zero. Instead of changing the core reset
path, the wrapper writes exactly 32 words of instruction RAM using the normal
halted host interface, waiting for each response and its cache maintenance.
Only one loader operation can be outstanding. ROM index, request and strobes
remain stable until acceptance. Each successful response advances the index;
the last enables host/start, while any error latches a reset-only failure.
The reset/start/degenerate table in SPEC.md is normative.

| Word | Instruction | Result |
|---:|---|---|
| 0 | `addi a0,zero,0` | hart ID zero |
| 1 | `lui a1,0x043f0` | positive intermediate 0x043f0000 |
| 2 | `slli a1,a1,5` | DTB PA 0x87e00000, without RV64 LUI sign extension |
| 3 | `addi t0,zero,1` | positive intermediate one |
| 4 | `slli t0,t0,31` | firmware PA 0x80000000 |
| 5 | `jalr zero,0(t0)` | transfer to real external-memory firmware |
| 6..31 | `addi zero,zero,0` | valid padding |

External host readiness is zero until boot completion. Internal responses
are not exposed. An early start is neither accepted nor queued. At completion,
the final internal response is consumed by the parent on the same edge that
sets wrapper readiness, so it cannot become a host response. Host/start priority
after readiness is unchanged. Accelerator AW/W/AR valid and ready are blocked
before readiness so no external master can interfere with ROM maintenance.
Compatibility mode makes the same transparent connections after its first
released edge; no ROM writes occur.

The external platform, not the wrapper, populates actual firmware/Image/DTB
bytes in 128 MiB of external RAM before start. The image manifest records
addresses and SHA-256 values. Unloaded external RAM has deterministic zero
initial contents for this platform workload; this is platform initialization,
not data derived from expected results. On-chip RAM contents are not replaced
from software expectations. Firmware clears its own BSS; Linux initializes
its own state, builds page tables and unpacks its built-in initramfs.

## Clock contracts for an independent scheduler

These are implementation interfaces for timing prediction, not a model or a
translation of RTL into a reference algorithm. All tables refer to pre-edge
handshake sampling; an output produced post-edge c can first be consumed at
edge c+1. A response remains valid until its specified acceptance edge. There
is no same-edge combinational response bypass through registered boundaries.
Clock-dependent state advances during stalls, host loading and sleeping.

### Core and retirement

One instruction-fetch request is outstanding at a time. The fetch response
includes the saved request PC and the predictor's pre-edge state. Accepted
responses enter a four-entry queue; initially it accumulates four entries
before releasing decode. Release remains set until consuming the last queued
entry without replacement. Stop/halt/eligible pending interrupts also permit
draining a partially filled queue. Simultaneous queue push/pop preserves count;
redirect/trap/serial flush has priority and empties the queue.

The execution resources are decode, execute, memory and writeback valid slots.
An ordinary instruction takes one edge per advancing stage, with a registered
retirement observation at writeback commit. Memory operands forward before
writeback only for ready non-load/non-atomic/non-CSR results; writeback can
forward a committed value. A load-use dependency interlocks decode. Occupied
memory prevents younger execution advancement. Loads/stores wait until older
memory and writeback are empty before leaving execute and serialize younger
decode while active; actual memory response is variable-latency.

CSR, atomics, fences, returns, WFI and sfence enter decode only after older
execute/memory/writeback drain. They block younger admission, discard/consume
outstanding speculative fetches, and refetch from committed next PC on commit.
CSR/time data samples on its writeback commit edge. Exposed `retire_*` signals
are registered observations of that edge, not the next clock's CSR sample.
A satp CSR write first performs a full MMU fence handshake while retained in
writeback. The changed satp value then causes the MMU's context-change drain
before accepting another translation.

An execute redirect compares actual next PC to the saved prediction, flushes
younger queue/decode work and kills an outstanding fetch response without
canceling an accepted lower-level memory transaction. Synchronous faults
commit as traps, never as retired faulting instructions. Trap entry takes
priority over return, normal slot movement and serial commit; it records
epc/cause/tval/target and redirects fetch to the actual vector.

Pending eligible interrupts stop new fetches, drain the queue/pipeline and
accepted fetch, and enter only with all decode/execute/memory/writeback and
queue entries empty, no fetch outstanding, and no halt/stop/legacy stop.
Interrupt EPC is the last committed next PC. Global privilege enables and
delegation use pre-edge CSR state. WFI sleeps only if no wake condition at its
commit; time/peripherals continue and a pending wake condition clears sleep.
The scheduler must account for the drained boundary, not assert a trap merely
because a timer comparator changes.

Default prediction uses a direct-mapped tagged BTB, indexed by PC instruction
index and initialized invalid with weakly-not-taken two-bit counters.
No hit predicts PC+4. Conditional taken resolution allocates a missing entry;
an existing counter saturates on taken/not-taken. Unconditional resolution
allocates a target. Update occurs on execute advancement, so same-edge fetch
prediction sees pre-update state. PRED_MODE=0 instead statically predicts
backward branches and direct JAL targets.

The multiply/divide resource accepts only with no older memory operation and
no uncommitted older writeback. Its acceptance edge initializes operands.
Exactly 64 iteration edges follow; the next edge registers result/done.
Execute may consume done on a subsequent edge. Signed/word correction is
included in the registered result; no single-cycle divide shortcut exists.

### Translation and cache paths

| Resource | Acceptance and subsequent registered phases |
|---|---|
| Fetch path | accept; translation request; wait translation; cache request; wait cache; response |
| Data path | accept; translation request; wait translation; router request; wait router; response |
| Atomic translation | priority over normal data at idle; translate; return PA/error without a data transaction |
| Physical atomic/maintenance path | bypass translation only as selected by core protocol; issue downstream normally |
| TLB | accept at idle; lookup edge; registered response; consume |
| MMU hit/bypass | accept concurrently with TLB; wait TLB response; register MMU response; consume |
| PTW | accept; address edge; memory request; wait PTE; classify; finalize leaf/fault; response |
| Cache hit | accept and synchronous RAM lookup; lookup/permission edge; response |
| Router/arbiter/fabric | capture owner/payload; issue downstream; wait response; register owner response; consume |

Instruction/data translations have separate TLB ports. Each keeps at most one
MMU transaction. A shared PTW chooses a waiting data miss if no instruction
miss, or when data has preference; a completed arbitration reverses preference.
Walks start at level two and request one 64-bit PTE through the data cache.
An ordinary nonleaf classification decrements level, then repeats the address
and memory phases; a leaf/fault takes finalize then response. Successful walk
completion refills the proper TLB. M-mode/Bare bypass still passes through
the registered TLB/MMU scheduling path.

TLB entries include VA page, ASID, level, physical PPN and flags. Lookup chooses
the first matching valid entry, respecting global mappings and leaf level.
Refill chooses the lowest invalid slot, otherwise round-robin replacement;
overlapping mappings are removed. A/D faults are software-managed. Permission
checks apply again on hits, including current SUM/MXR and privilege snapshots.
Scoped invalidation preserves globals when an ASID is specified; full/context
invalidation includes globals. Invalidation wins over refill. An MMU fence
blocks new requests, drains both ports and PTW, invalidates, then acknowledges.

Caches are direct mapped, 32-byte lines, four 64-bit words per line, physically
tagged. Instruction cache is read-only; data cache is write-back/write-allocate.
The index is the low line-index bits and the tag compares full line base.
On a hit, byte write enables update RAM and mark dirty. On a miss, a dirty
victim is read synchronously and written back one word at a time, waiting for
each response. Refill similarly performs four independent word reads and
registered store edges, then a relookup before servicing the original request.
No critical-word bypass is present. An error aborts into a registered error
response. Partial terminal on-chip lines avoid nonexistent addresses instead
of wrapping them; legal external-RAM lines use all four words.

Maintenance scans indices in increasing order with registered lookup/check/
next phases; dirty data is written back. Command 2 cleans, command 3 also
invalidates. Parent host writes wait for data clean+invalidate, then instruction
invalidate, before responding; launch waits for maintenance idle. New wrapper
loading uses precisely this path for every instruction word.

Each cache arbiter starts with owner preference zero and rotates preference to
one past the selected requester on acceptance. Instruction owners are core
fetch then maintenance. Data owners are routed core data, PTW, then maintenance.
The backing fabric likewise rotates over instruction refill, data refill/
writeback and coherent accelerator. It owns a transaction until its response
is accepted, so other requesters wait rather than bypassing an occupied owner.
On-chip backing RAM captures synchronous read data at request acceptance,
passes through its pending edge, then exposes a response; host reads use their
separate synchronous RAM read and parent response pipeline.

### External AXI and coherent accelerator

The memory master captures a backing request before asserting AR or AW/W.
It emits aligned, 64-bit, single-beat INCR transfers, ID=0, size=3, len=0,
cache=0xf, qos=0, lock=0, and preserves the requested protection. AW and W have
separate accepted flags. BREADY starts only after both accept; RREADY starts
after AR accepts. B/R responses capture into an internal registered response.
Unexpected response IDs, missing RLAST and non-OKAY status become errors.
Legal address decoding is the parent's 0x80000000..0xffffffff external window;
the delivered platform provisions only its declared 128 MiB subset.

The coherent slave accepts one burst, with AW/AR round-robin preference
(initially write). Write data is collected after AW, never assumed coincident
with it. Geometry/address checks and WLAST/strobes are retained. The bridge
requests exclusive fabric ownership, halts/drains the core, completes D/I
maintenance, then performs backing operations. Write beats have a synchronous
buffer-load edge before issue; reads return registered masked data one beat
at a time under R backpressure. Ownership lasts through final accepted B/R.
Core restart retains parent resume/progress-token fairness; atomic reservations
are invalidated through the inherited maintenance/trap/store/fence rules.

### Clock-dependent peripherals

CLINT reset state is mtime=0, mtimecmp=all ones, msip=0. On every released edge,
time increments modulo 2^64 unless a legal accepted byte-strobed mtime write
overrides that increment. Bus reads snapshot pre-edge register state and
respond registered. MTIP is unsigned pre-edge mtime>=cmp. No divide, scaling,
host-time clock or retired-instruction clock is substituted.

CSR mcycle increments on every released edge with a CSR write override;
minstret increments on commit with its own write override. Counter access obeys
mcounteren/scounteren. The firmware enables all three architectural counters
for S-mode. STIP is a software-writable mip bit, not an alias of MTIP.

UART MMIO accesses capture/read side effects at acceptance and produce a
registered response. Byte address and strobe select the same 64-bit bus lane.
THR readiness can stall when full; RBR reads pop at acceptance. FIFO-disabled
capacity is one, FIFO-enabled capacity sixteen. Simultaneous pop/push leaves
count unchanged; clears take precedence. Status uses pre-edge counts.

TX moves a buffered byte from idle into start on a pop edge, latching format
and divisor. A push into an empty buffer cannot pop on that same edge.
Each start/data/parity bit lasts 16*divisor clocks, LSB first; default stop is
one bit. After its stop interval, TX enters idle before another pop edge.
Divisor zero is the preserved effective-one policy. THRE means holding FIFO
empty, TEMT also requires serializer idle. Break/loopback behavior is inherited.
The boot setting is 8N1/divisor one, not a directly injected byte stream.

RX first passes through meta and sync flip-flops, each updated from pre-edge
values. Idle detects the synchronized low start; half a bit later validates
start, then samples each data bit one full bit apart, LSB first, and validates
stop. RX_COMMIT is a separate edge that pushes the received byte/error flags.
Line-status, RX threshold, RX timeout, THRE, then modem status is IRQ priority.
FIFO RX timeout counts four character times without RX arrival/pop/clear.
The complete legal parity/word-length/stop/divisor behavior remains inherited.

PLIC has two source synchronizers. Its pending bits latch synchronized level
sources while not in service; current selection is highest priority above
threshold and enabled, with lowest ID winning ties. Its outgoing context IRQ
is registered from pre-edge selection. Claim reads snapshot selection and mark
that source in service, clearing pending on the same edge. Completion requires
a matching in-service source/context; an asserted source can pend again after
service is cleared. Bus responses and claim results are registered. Source
one is UART; bits 0..30 of the external vector are sources 2..32.

The independently predicted event ledger must distinguish CSR sample,
registered retirement observation, MTIP/STIP transition, pipeline boundary,
trap update and serialized UART bit events. None is interchangeable with a
nearby timestamp. See SPEC.md for final/preliminary scenario separation,
seeded AXI scheduling and the continuous 4294967296-edge bound.

## Software execution path

`fw_entry.S` establishes a boot stack, clears firmware BSS, installs mtvec and a
separate 16 KiB trap stack, and calls the original HAMMER firmware implementation.
Firmware initializes the real UART, checks handoff/FDT header bounds, enables
counter access, reserves machine timer handling and delegates S interrupts and
appropriate synchronous exceptions. S ecalls remain in M-mode.

The trap frame contains all 32 integer register slots, mepc, mstatus, mcause
and mtval, on a 16-byte-aligned stack. mscratch selects the lower-privilege
trap stack; a zero sentinel during M handling preserves nesting on the active
machine stack. Full context is restored except architecturally defined SBI
return registers and the advanced ecall EPC. Unexpected M traps print actual
cause/EPC/tval and park rather than fabricate success.

SBI v0.2 base functions report the actual supported interfaces and a distinct
HAMMER implementation ID, 0x48414d4d, version 0x00040000. TIME set_timer masks
MTIE, clears STIP, writes the 64-bit CLINT comparator, fences and reenables
MTIE. MTIP handling masks MTIE and sets delegated STIP. Repeated rearming and
deadlines already in the past retain the real comparator behavior. Legacy
set_timer/putchar/getchar are implemented; no HSM, reset, IPI, RFENCE, PMU or
DBCN support is claimed or advertised.

The mret handoff is physical entry 0x80200000, a0=0, a1=0x87e00000, satp=Bare.
The upstream Linux Image header retains text offset 2 MiB. `vmlinux` has its
upstream linked virtual ELF entry; the loader does not confuse that address
with the physical Image entry. Upstream hardware probing rejects unsupported
Sv57/Sv48 satp modes and uses Sv39 with folded upper software page-table levels.
Page table construction, satp writes, sfence, FDT parse, interrupt drivers,
exec, user page faults and system calls are actual Linux code.

Upstream 6.6.1 `of_setup_earlycon` already reads DT `clock-frequency` and
`current-speed` before the 8250 divisor calculation. No earlycon clock patch
is required. The source manifest lists the local
`linux-6.6.1-random-trust-config.patch` compatibility patch: it restores boolean
Kconfig controls for CPU and bootloader entropy trust and uses them as the
initial values in `drivers/char/random.c`. Existing early command-line
overrides remain intact. The build requires explicit bootloader trust enabled
and CPU trust disabled, verifies the archive/patch hashes, and applies patches
in manifest order to a freshly extracted tree before configuration. The
original upstream archive is not modified. Patch provenance/hashes accompany
the recorded build inputs; this repair does not establish a successful build
or boot.
The build forces RV64IMA/Zicsr/Zifencei and LP64 for both C and assembly,
disables C/F/D/V and optional instruction-extension alternatives, and disables
EFI, which would otherwise select compressed entry code. Zicsr/Zifencei names
represent the already required privileged CSR/fence subset. The encoded PAUSE
hint in upstream cpu_relax is a legal base-I FENCE encoding and is handled as
the parent's conservative fence, not a new ISA execution unit.

The static `/init` has no libc, interpreter or dynamic linker. Its freestanding
startup uses the Linux-provided user stack. It checks uname/getpid, maps three
anonymous pages, writes/reads every 64-bit word, unmaps, sleeps 50 ms, reads the
scenario-supplied `v4\n` line through the real UART driver and exits zero.
This intentionally causes the upstream PID-1 exit panic, whose complete
serialized output remains required. Default TTY echo/output processing is not
stripped from UART comparison. Three timer deliveries must be independently
observed, not inferred from the sleep duration or a printed label.

The public DT rng-seed is reproducible test input only. Fixed clock, LPJ,
build identity, config, timestamp and initramfs ordering remove selected
legitimate variability at the source. Remaining clock/entropy/logging behavior
must still be computed by the independent timed oracle, never normalized away.

## Dependency boundaries

| Producer guarantee | Consumer obligation |
|---|---|
| Wrapper installs trampoline and isolates host while loading | Platform waits for boot_ready and preloads all addressed images before start |
| External images and DT reservations describe one memory map | Linux allocator must not reuse firmware/DTB reservations |
| Parent emits stable AXI payload through acceptance | External RAM holds B/R valid/payload until accepted; tracks AW/W independently |
| MMU enforces A/D and privilege rules | Linux handles real page faults and executes sfence after PTE changes |
| Firmware converts MTIP into STIP | Linux enables/rearms SBI timer and services supervisor timer traps |
| Real UART RX and PLIC route input to Linux | Independent scenario supplies valid timed serial frames and captures TX bits |
| Build writes actual image/source hashes and layout | Verifier independently inspects compiler invocations, ELF/ISA and memory events |

No producer in this table guarantees a fixed total instruction latency.
Software builders and models must not import runtime state, private paths or
past approvals as product predicates.

## Claim-to-evidence status

| Claim | Design input | Required independent evidence |
|---|---|---|
| Compatible wrapper and legal/reset boundaries | rtl/hammer_v4_top.sv; SPEC.md | Verifier compact startup, parameter and parent regressions |
| Genuine firmware/FDT/Linux/init images | software/build.py; source-manifest.json; pinned archive | Fresh build hashes, ELF/ISA/layout inspection and clean reproduction |
| Complete real Linux boot and panic | software sources; ARCHITECTURE.md timing rules | Seeds 11/29/47, independent timed oracle and full TX-stream comparisons |
| Permission/timer/coherence defect sensitivity | inherited RTL and software ABI | Unchanged controls and each required compiled functional/temporal mutant |
| Full hierarchy and zero latches | rtl/*.sv | Real Verifier Yosys netlist/log checks |
| 100 MHz physical implementation and deterministic hardware | all design inputs | Native L1.5, Quartus 17.1 STA and >=3 PCIe HIL runs |
| Product PDF | accepted engineering results | Runtime generation and independent review after acceptance |

These evidence entries are requirements, not results. No functional simulation,
synthesis, oracle, boot transcript, clean build, STA or hardware pass is claimed
by the design source handoff. No tests or reference-model files are supplied
by Designer.
