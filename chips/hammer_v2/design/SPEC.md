# HAMMER-V2 specification

## Authority and implementation status

The admitted work order is a single-hart, little-endian RV64IMA+Zicsr
extension of the supplied HAMMER-V1 five-stage processor. This document fixes
the design contract; it is not evidence of functional or physical acceptance.
The immutable compatibility inputs are `hammer_v1_reference/rtl/*.sv`.
Implementation is incremental: the extension leaves are implemented first;
core and top-level integration remain required before a ready handoff.

## Platform

The entry point is `hammer_v2_top`. Preserve every parent top port, direction
and width. Add unsigned inputs `halt_req`, `irq_meip`, `irq_seip`; unsigned
outputs `retire_priv[1:0]`, `trap_tval[63:0]`, `trap_target_priv[1:0]`,
and `trap_interrupt`. Tie unused new inputs low.

The supported OS boundary is physical-address, Bare-mode M/S/U execution with
traps, scheduling and atomic synchronization. There is no Sv39, Linux boot,
PMP isolation, floating point, compressed instruction, multicore, coherent DMA
or Sstc claim. `satp` is WARL Bare-only. Privilege encodings are U=0, S=1,
M=3; 2 is never architectural.

| Parameter | Default | Legal values |
|---|---:|---|
| IMEM_WORDS | 16384 | 1 through 16384, including non-powers of two |
| DMEM_WORDS | 8192 | 1 through 8192, including non-powers of two |
| PRED_MODE | 1 | 0, 1 |
| BTB_ENTRIES | 16 | 1, 4, 16, 64 |
| ICACHE_LINES | 64 | 1, 4, 16, 64 |
| DCACHE_LINES | 64 | 1, 4, 16, 64 |
| LEGACY_TRAPS | 0 | 0, 1 |

Both caches are direct-mapped with fixed 32-byte lines. Invalid parameters must
elaborate safely and terminate at time zero with a specific `PARAMETER ERROR`;
diagnostic storage does not authorize executing a clamped configuration.

Instruction memory is `[0,4*IMEM_WORDS)`. Data memory is
`[0x10000000,0x10000000+8*DMEM_WORDS)`. Uncached AXI-Lite is
`[0x40000000,0x4000ffff]`, with parent zero protection bits.
CLINT registers are MSIP at `0x02000000`, MTIMECMP at `0x02004000` and
MTIME at `0x0200bff8`. All addresses are checked at full 64-bit width.
Host addresses are store-relative byte offsets, with the parent validation:
instruction addresses must be four-byte aligned, upper write-data and strobe
bits must be zero even for reads; data addresses must be eight-byte aligned.
Invalid requests respond with an error and do not mutate memory.

## Cycle and degenerate-boundary table

Every handshake samples **pre-edge** valid and ready. State and events below
are **post-edge**. One rising-edge clock and active-low asynchronous control
reset are used; unreset RAM read/write ports are synchronous.

| Boundary/event | Required behavior |
|---|---|
| Active reset | All public outputs zero except halted=1; host_ready=0; RAM contents unspecified and not reset |
| First nonreset edge | Timer/cycle counters increment from zero; no spontaneous request, retirement or trap |
| Host acceptance E0 | Pending set, response absent; read samples RAM and valid writes occur once |
| Host E1 | Exactly one response pulse; no new acceptance |
| Host E2 | Acceptance may resume after response clears |
| Unstalled IF/ID acceptance E0 | ID/EX E1, EX/MEM E2, MEM/WB E3, retirement and register write E4 |
| Cache acceptance E0 | Synchronous lookup; hit response first appears after E1, never combinationally at E0 |
| Backing acceptance E0 | Registered response after the next rising edge; stable until consumed |
| Simultaneous retirement/trap | Faulting instruction never retires; interrupts are selected only at an instruction boundary after older side effects commit |
| Synchronous fault and interrupt | Synchronous fault wins for its instruction |
| Counter write and increment | Legal machine write overrides increment; CSR reads observe the pre-edge value |
| MTIME write and increment | Nonzero strobe write overrides increment using pre-edge merge; zero strobe does not stop time |
| Reservation set and invalidate | Reset/trap/halt/host invalidation wins over a set |
| Singleton cache | Constant-zero index; all four line beats still processed, including maintenance |
| Partial last line | Zero-fill absent refill lanes and skip absent writeback lanes; requested address itself must be in range |
| Non-power-of-two RAM | Exact comparison, no binary-mask address aliasing |
| Backpressure | Hold valid and payload stable; execute no duplicate side effect |
| Reset with outstanding work | Abort protocol state and invalidate caches/reservation; dirty contents may be lost |

Initial start begins at zero. Accept start only while halted, no host request,
pending transaction or response, and no held halt request. Sticky legacy traps
also inhibit start. Normal halt stops fetch, drains the pipeline and outstanding
transactions, cleans D-cache and saves next PC. Resume retains architectural
state. Time and cycle counters advance while halted. Host accesses occur only
when fully halted. Host instruction writes invalidate I-cache before resumption;
host data writes invalidate D-cache and reservations. Reset does not preserve
dirty data; halt/clean first when persistence is needed.

## Numerical and memory semantics

RV64 results wrap modulo 2^64. W operations use low 32 bits and sign-extend.
Shift masks are 63 or 31. Signed comparisons are two's complement.
DIV/REM truncate toward zero; zero divisors and MIN/-1 follow RISC-V rules,
including W forms. No deliverable RTL combinational division/modulo operators
are permitted. Iterative multiply/divide steps are registered.

Natural alignment is mandatory. Faults precede mutations. Loads return the
properly extended architectural value. Stores use lane-aligned data and masks.
FENCE cleans D-cache; FENCE.I additionally invalidates I-cache before retirement.
D-cache is write-back/write-allocate; dirty victims write ascending 64-bit beats
before ascending refill. Validity is installed only after complete successful
refill. Failed writeback must not discard dirty data. Maintenance preserves valid
lines unless clean-and-invalidate was requested.

Implement LR.W/D, SC.W/D and SWAP, ADD, XOR, AND, OR, MIN, MAX, MINU,
MAXU AMOs in W/D forms. W old values sign-extend. Reserved encodings,
including LR with nonzero rs2, are illegal. Atomics are serialized before and
after, honoring all aq/rl combinations by stronger ordering. Atomics are legal
only in data RAM. Reservation granule is an aligned eight-byte beat, with exact
LR address and width required for SC. New LR replaces it; every SC clears it.
Overlapping committed store/AMO, trap, reset, halt entry and host data write
invalidate it. SC checks access/alignment even on reservation failure and
returns 0/1; a failed SC performs no write.

Retirement reports LR as read, successful SC as write, failed SC as memory-valid
but not write with zero memory payload/mask and rd result 1. AMO reports both
old architectural data and aligned new write data. Only actual non-x0 register
writes assert retire_rd_we.

## Privilege, traps and interrupts

Implement RISC-V privileged v1.12 for the admitted subset. The six Zicsr forms
return pre-write data and enforce encoded privilege, existence and read-only
checks. CSRRW rd=x0 suppresses reading; CSRRS/CSRRC zero source suppresses
writing. Illegal instructions/CSR operations have no partial effects.

CSRs: mstatus/sstatus, misa, medeleg/mideleg, mie/sie, mtvec/stvec,
mscratch/sscratch, mepc/sepc, mcause/scause, mtval/stval, mip/sip,
mcounteren/scounteren, satp, mcycle/minstret and cycle/time/instret.
Identification CSRs mvendorid/marchid/mimpid/mhartid are read-only zero.
misa has MXL=2 and I/M/A/S/U; writes ignored. satp reads zero, writes ignored.
Writable mstatus bits are SIE/SPIE/SPP/MIE/MPIE/MPP/MPRV/TVM/TW/TSR.
SXL/UXL read 2; reset writable bits zero, including MPP=U. Invalid MPP=2
coerces to U. Supervisor aliases expose only their applicable fields.
EPC writes clear bits 1:0. Vectors permit modes 0/1; modes 2/3 coerce to
direct. Synchronous traps use BASE; vectored interrupts use BASE+4*cause.

medeleg supports bits 0..9. mideleg supports bits 1,5,9.
mie supports 1,3,5,7,9,11; supervisor aliases are delegation-masked.
MSIP/MTIP are from CLINT; MEIP/SEIP are external; SSIP/STIP are
machine-writable. sip writes only delegated SSIP. Interrupt priority is
MEIP, MSIP, MTIP, SEIP, SSIP, STIP. Global and privilege rules apply;
delegated interrupts cannot interrupt M. Trap entry updates complete context
and status atomically, changes mode and kills younger work.
MRET/SRET restore privilege/interrupt state and clear MPRV as required.
TSR restricts SRET, TVM restricts satp/SFENCE.VMA, TW restricts non-M WFI;
U SRET/SFENCE.VMA are illegal. SFENCE.VMA is a serializing Bare-mode no-op.
WFI retires before waiting and wakes on locally enabled pending interrupts,
even when global interrupt enable is clear.

Counters and counter-enable CSRs reset zero. mcycle advances each nonreset
clock; minstret counts successful retirements including returns/WFI.
S/U counter reads obey mcounteren/scounteren. time reads CLINT MTIME.

Synchronous causes are instruction misalignment/access, illegal, breakpoint,
load misalignment/access, store/AMO misalignment/access and U/S/M ECALL.
Ordering is oldest instruction, then fetch/decode fault, alignment, access.
tval is bad address, raw zero-extended illegal instruction, EBREAK PC,
or zero for ECALL/interrupt. Normal traps pulse and redirect without halting;
trap_pc/cause/tval/target/interrupt describe that event. Legacy mode holds
the terminal trap until reset. retire_priv is pre-instruction privilege.

CLINT permits naturally aligned 1/2/4/8-byte accesses contained within a
register, rejects holes/crossings, and returns acceptance-edge snapshots.
MSIP exposes bit zero only. Reset MTIME=0, MTIMECMP=all ones, MSIP=0.
MTIP is unsigned MTIME>=MTIMECMP, not sticky. Supervisor timer delivery
is through machine-written STIP and delegation.

## Timing and independent acceptance

Target: Intel Arria 10 GX `10AX115N2F45E1SG`, clock period <=10.0 ns.
No mixed blocking/nonblocking state assignments in clocked processes.
Backing and cache RAM must use synchronous dataports without reset loops.
Tag lookup, decisions, refill/writeback, execute and commit are registered
boundaries. Generic synthesis is not timing evidence.

Designer may perform only fast static elaboration. Verifier owns `tests/*`,
including independently derived Python reference semantics, simulator bridges,
functional stimuli, mutation sweeps and synthesis checks. No functional
simulation or synthesis result is asserted here. No tools are installed by
the design sources. Required L1 dependencies are Python 3, Icarus/vvp,
Verilator, make, a C++ compiler and Yosys; actual versions belong in run receipts.

From the delivered root the mandatory independent entry points are:

```
python3 tests/verify.py --suite compatibility
python3 tests/verify.py --suite privileged
python3 tests/verify.py --suite atomic
python3 tests/verify.py --suite cache
python3 tests/verify.py --suite sensitivity
python3 tests/verify.py --suite synthesis
python3 tests/verify.py --suite portable
```

Default invocation executes all suites. These commands are the required
Verifier-owned interface, not a claim that the files already exist.
All seven suites remain mandatory and self-contained. Preserve every failed
receipt in fresh `evidence/<suite>-<timestamp_or_hash>/` directories.
Portable reproduction copies only RTL, these two documents, flat tests and
immutable parent RTL, with no build products or runtime metadata.

The frozen full matrix is A=(16384,8192,1,16,64,64) and
B=(256,128,0,64,16,4), seeds 17/29/53; >=2,000 independently checked
random RV64IM retirements per tuple/seed plus all directed cases.
C=(1,1,0,1,1,1) and D=(33,17,1,4,4,16) cover boundaries.
Exercise all eight predictor tuples and both trap policies; elaborate all 128
predictor/cache tuples; cover RAM sizes 1,3,max and explicit invalid parameters.
Each legal integer/atomic operation/width has >=8 directed operand pairs.
Observe forwarding priority, load-use, branches/predictor collisions, mul/div,
MMIO stalls/errors and wrong-path kills. Parent differential is secondary,
architectural and uses LEGACY_TRAPS=1.

Each A/B seed requires >=3 acknowledged MTIP entries/returns, >=1 delegated
STIP entry and >=32 single-hart lock acquisitions with SC retries. Exercise
all six interrupts/priority/masking, privilege transitions/returns, all ECALL
modes, delegation, CSR suppression/access, counter enables, TVM/TW/TSR,
WFI, precise stores and interrupts around stalls. Atomic cases include every
reservation invalidator, width/address mismatches, faults, x0, aq/rl and signed
boundaries. Each A/B seed needs >=16 I hits,16 I misses,16 D read hits,
16 D write hits,16 D misses,8 dirty evictions, observed on real channels.
Cover refill/writeback order, byte lanes, partial lines, singleton maintenance,
host coherence, FENCE/FENCE.I, backpressure, errors and outstanding reset.

Executed, reached defect sensitivity is required for numerical/W extension,
forwarding, CSR, precise trap, timer, reservation/SC, AMO signedness, dirty
writeback/tag and I-cache invalidation mutations. Compile failure, startup
failure or timeout is not detection. Yosys must perform real hierarchy/proc/
memory/optimization/check passes for A/C/D, preserve preflatten evidence,
assert zero latches, drivers/resolution correctness, no divide/modulo cells,
substantive state and connected literal hierarchy. Do not blackbox function.

Icarus is limited to compact <500,000-cycle smoke, <60 s per run; full sweeps
use compiled Verilator with bounded event records and no per-cycle flushing.
The shared runtime separately requires timing lint, Quartus 17.1 STA with
WNS>=0 at <=10 ns and three consecutive deterministic PCIe Gen3x8 HIL passes.
There is no timing waiver. Do not embed local cable/BDF choices in L1.
The runtime authors and independently reviews the product PDF only after
engineering acceptance; the PDF is not a verification prerequisite.
