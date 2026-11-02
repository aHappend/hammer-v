# HAMMER-V5 frozen engineering contract

## Authority and status

This document records the independently admitted HAMMER-V5 contract. It is not
verification evidence. The required product is the integrated `hammer_v5_top`,
not a standalone accelerator. Parent acceptance is historical, not acceptance of
V5. Implementation progress and missing inputs are recorded in ARCHITECTURE.md.
The immutable parent is `hammer_v4_reference/rtl/`.

The target is Intel Arria 10 GX `10AX115N2F45E1SG`, at least 100 MHz (period at
most 10.0 ns). RTL must be synthesizable, use bounded registered arithmetic,
contain no combinational division/modulo operators, and use nonblocking
assignments for sequential state. Generic synthesis does not establish timing.

Designer owns `rtl/*.sv`, `design/*.md`, and flat `software/*` inputs. Independent
Verifier owns `tests/*.py`, simulation harnesses, numerical models, mutation
checks, synthesis checks and verification receipts. The shared runtime owns
timing lint, Quartus STA, physical hardware gates and final product reporting.
The final independently approved PDF is produced after engineering acceptance,
not used as a prerequisite to verification.

## Compatibility, parameters and hierarchy

Retain every port name, direction and width from
`hammer_v4_reference/rtl/hammer_v4_top.sv`, all inherited memory/interrupt maps,
host-loading semantics and accelerator quiescence. Preserve RV64IMA, M/S/U,
Sv39, OpenSBI, S-mode Linux and U-mode `/init`; add integer RV64C, custom-0,
unified L2/prefetch and HPM.

| Parameter | Default | Legal values |
|---|---:|---|
| IMEM_WORDS | 16384 | 1..16384 |
| DMEM_WORDS | 8192 | 1..8192 |
| PRED_MODE | 1 | 0,1 |
| LEGACY_TRAPS | 0 | 0,1 |
| BTB_ENTRIES | 16 | 1,4,16,64 |
| ICACHE_LINES, DCACHE_LINES | 64 | 1,4,16,64 |
| ITLB_ENTRIES, DTLB_ENTRIES | 8 | 1,4,8,16 |
| BOOT_ENABLE | 1 | 0,1 |
| L2_SETS | 64 | 1,4,16,64 |
| PREFETCH_ENABLE | 1 | 0,1 |

Boot requires IMEM_WORDS >= 32 and LEGACY_TRAPS=0. Illegal configurations
must produce `PARAMETER ERROR`, using generate guards and safe diagnostic
widths, not an earlier reversed-select or zero-width elaboration failure.
No silent parameter clamping is allowed.

Required hierarchy:

```
hammer_v5_top
  u_boot_rom: hammer_v4_boot_rom
  u_soc: hammer_v5_soc
    u_core: hammer_v5_core
      u_csr: hammer_v5_csr
      u_vector: hammer_v5_vector
        u_int8: hammer_v5_int8
        u_bf16: hammer_v5_bf16
    u_mmu: hammer_v3_mmu
    u_fetch_path: hammer_v5_fetch_path
      u_decompress: hammer_v5_decompress
    u_l2: hammer_v5_l2
```

Inherited caches, memory, UART, interrupts and AXI interfaces remain functional.
Every RTL dependency of the shipped top must reside in `rtl/`.

## Cycle & Degenerate-Boundary Table

One rising-edge `clk`, asynchronous active-low `rst_n`. During reset all valid,
ready, error and inactive payload outputs are zero; inherited exceptions are
`halted=1` and UART TX idle-high. Reset discards pending transactions and prevents
late responses. RAM contents need not reset when valid metadata hides them.
Leaf requests transfer only on pre-edge `req_valid && req_ready`; responses
transfer only on pre-edge `rsp_valid && rsp_ready`. New post-edge valid cannot
transfer at that edge. One transaction per leaf; payloads are held under stalls.

| Boundary | Required behavior |
|---|---|
| Active reset | No request, response, retirement, trap or architectural update |
| First edge after reset release | Old idle readiness may accept a request; no inherited pending response |
| E0, accepted INT8/RMS | Capture request, remove readiness |
| E1 | Capture eight vector operand lanes |
| E2 | Register eight signed products |
| E3 | Register four widened pair sums |
| E4 | Register two widened partial sums |
| E5 | Register full reduction |
| E6 | Register scalar result, assert response valid |
| E7 or later | Earliest INT8/RMS response transfer |
| E0, accepted BF16 | Capture packed operands |
| E1..E4 | Unpack/classify; multiply significands; normalize; round products |
| E5..E8 | Align; add; normalize; round the two pair sums |
| E9..E12 | Align; add; normalize; round final sum and assert response |
| E13 or later | Earliest BF16 response transfer |
| L2 resident hit E0..E3 | Capture/start synchronous reads; capture outputs; select way; register response |
| L2 E4 or later | Earliest resident-hit response transfer |
| vload/vstore, miss, maintenance | Event-driven; complete only after accepted downstream response |
| Response stall | Hold response and associated payload without recomputation |
| Completed vector operation | Architectural vector update/MAC pulse only on commit; abort discards it |
| Commit and response transfer together | Commit the completed operation once; no duplicate update |
| CSR write and increment together | Legal explicit counter write wins |
| Counter inhibit write | Old inhibit value governs that edge's increment |
| Flush/quiesce versus prefetch | Suppress unaccepted speculative work; drain accepted transfer |
| One-entry cache/TLB/predictor/set | No zero-width indices; singleton remains reachable |
| IMEM_WORDS=DMEM_WORDS=1, boot off | First/last word coincide; a partial line never reads outside local bounds |
| IMEM_WORDS=33, DMEM_WORDS=3 | Compare actual bounds, not a power-of-two mask |
| One-beat transaction | First and last coincide; one response, one ownership update |

Commit and abort are mutually exclusive. Arithmetic results and vector loads
remain pending until in-order core commitment. Vector requests must be serialized
against older potentially faulting instructions; stores may issue only after
older operations cannot squash them. No speculative state or fault can partially
commit a vector operation.

## RV64C

`hammer_v5_decompress(insn16[15:0])` produces `insn32[31:0]` and `illegal`.
Implement the ratified integer RV64C subset, without F/D. RV64 uses C.ADDIW,
not RV32 C.JAL. Legal hints have no architectural side effects. Reserved
encodings, unsupported floating compressed instructions and non-compressed
quadrant-3 halfwords are illegal to the decompressor. The fetch path invokes it
only for compressed instructions.

Instruction alignment is two bytes. Fetch a second halfword only for a 32-bit
instruction; independently translate a second page. Support word, line and page
crossings. A second-half fetch fault uses the original instruction PC and failing
halfword VA as tval. Preserve zero-extended raw compressed bits for retire_insn
and illegal-instruction tval. Carry raw bits and length through the pipeline.
Fallthrough, links, prediction, recovery and trap return use two/four-byte
length. JALR clears bit zero only; mepc/sepc preserve bit one. Odd targets fault.
Squashed instructions do not retire or update state. misa advertises C plus
inherited I/M/A/S/U, not standard V or F.

## Custom-0 ISA and context

All encodings use opcode `0x0b`, funct7=0. Lane zero occupies low bits.

| funct3 | Instruction | Operand fields |
|---|---|---|
| 000 | vload | scalar rs1=VA, rs2=0, rd[4:3]=0, rd[2:0]=vector destination |
| 001 | vdot.i8 | rs1[4:3]=rs2[4:3]=0; low three bits select vectors; scalar rd |
| 010 | vdot.bf16 | same vector field rules as vdot.i8 |
| 011 | vrms.acc | rs1[4:3]=0 selects vector; scalar rs2=seed, scalar rd |
| 100 | vstore | scalar rs1=VA, rs2[4:3]=0 selects vector source, rd=0 |

All other encodings are illegal, including unsupported high vector-index bits.
There are eight real 64-bit architectural vector registers, reset to zero;
vr0 is writable. Scalar x0 keeps standard semantics. Loads/stores transfer eight
little-endian bytes through the ordinary translated, permission-checked coherent
data path, with eight-byte alignment. Misalignment/access/page faults use normal
load/store causes and original VA tval; faulting loads do not update a vector.

Vector request ports are clk,rst_n,req_valid,req_ready,req_insn[31:0],
req_rs1_data[63:0],req_rs2_data[63:0]. Response ports are rsp_valid,rsp_ready,
rsp_data[63:0],rsp_illegal,rsp_mem_error,rsp_page_fault,rsp_tval[63:0].
Disposition inputs are commit_valid,abort_valid. Memory ports are
mem_req_valid,mem_req_ready,mem_req_write,mem_req_addr[63:0],
mem_req_wdata[63:0],mem_req_wstrb[7:0],mem_rsp_valid,mem_rsp_ready,
mem_rsp_error,mem_rsp_page_fault,mem_rsp_rdata[63:0]. Addresses are VAs.

CSR vxctl=0x800, bit zero enables U-mode custom instructions; reset disables.
M/S may use custom instructions for context management. U cannot write vxctl.
Disabled U execution traps before any request or memory side effect. A minimal
documented kernel patch must save/restore all eight vectors using vstore/vload
across task switches, signals and interrupted execution. Do not bypass this by
disabling preemption or assuming one task. This is custom ISA, not standard RVV
or a vendor-specific RoCC pinout.

## Numerical rules

INT8 dot is the exact sum of eight signed 8x8 products, sign-extended to 64 bits.
RMS is the scalar seed plus eight exact signed lane squares, modulo 2^64; no
implicit mean, division or square root.

BF16 dot widens four BF16 lanes exactly to binary32, rounds each multiplication
to binary32 using round-to-nearest-ties-to-even, and computes
`((p0+p1)+(p2+p3))`, rounding each addition independently. It is non-fused.
Return the binary32 encoding in bits 31:0 and zero bits 63:32. Support gradual
underflow, signed zero, infinity, canonical quiet NaN 0x7fc00000, invalid
infinity operations, ties and cancellation. Do not flush, saturate, depend on
host float semantics or add scalar F/fflags/fcsr. The independent oracle must
use exact integer/rational IEEE rounding, not a transcription of RTL.
Tensor coverage includes actual repeated dot/accumulate matrix tiles.

## L2, prefetch and coherence

Four ways, fixed 32-byte lines, physically indexed/tagged, L2_SETS=64 by default
(8 KiB). Place it after arbitration of instruction/data refills, page-table
traffic and accelerator traffic, before the existing external AXI master.
Local boot/scratchpad and MMIO remain uncached. Synchronous tag/data reads;
lowest-invalid-way allocation, then per-set round-robin replacement.
Write-through/write-allocate, preserving all byte masks. Failed refills install
no valid line. Failed writes invalidate possibly modified matching lines.
Serialize misses, fills, writes and maintenance; preserve downstream errors and
SoC bridge decode-error classification.

Upstream ports match the parent cache-style interface:
req_valid,req_ready,req_cmd[1:0],req_addr[63:0],req_wdata[63:0],
req_wstrb[7:0],rsp_valid,rsp_ready,rsp_error,rsp_rdata[63:0].
Commands 00=read, 01=masked write, 10=clean-all, 11=clean/invalidate-all.
Downstream: mem_valid,mem_ready,mem_write,mem_addr[63:0],mem_wdata[63:0],
mem_wstrb[7:0],mem_rsp_valid,mem_rsp_ready,mem_error,mem_rdata[63:0].
event_l2_access/event_l2_hit pulse only for actual demand lookups.

After a demand read-line miss completes, prefetch exactly the following absent
32-byte DRAM line if enabled and inside accessible DRAM. Never chain, cross
regions, prefetch MMIO or raise architectural speculative faults. Demand wins
before speculative request acceptance; accepted transfers complete normally.
Failed prefetches install no line. Define races with demand/write/maintenance,
backpressure and reset, and suppress new prefetch work during quiescence.

Preserve L1 writeback, FENCE/FENCE.I, SFENCE.VMA, LR/SC invalidation, host and
accelerator ownership transitions. Fence/quiesce completion drains all relevant
preceding transactions. Mandatory scenarios include self-modifying code through
fences and bidirectional CPU/accelerator coherence.

## Performance counters

64-bit mcycle/minstret remain; writable mhpmcounter3..6 at 0xb03..0xb06,
read-only aliases 0xc03..0xc06, mhpmevent3..6 at 0x323..0x326. Selectors:
0=disabled, 1=L1 demand lookups, 2=L1 demand hits, 3=L2 demand lookups,
4=L2 demand hits, 5=committed vector lane MACs. Defaults are 1,2,3,4.
INT8/RMS commit contributes eight, BF16 four; faults, squashes, loads/stores zero.
Cache counts measure accepted lookups, including speculative instruction demand,
not retirement; exclude maintenance and prefetch lookups.

Addition wraps at 64 bits; explicit legal write wins over increment.
mcounteren/scounteren extend through bit six; implement mcountinhibit for
supported counters. Aliases require privilege enables. Denied CSR access traps
without state change. Linux explicitly permits user counter reads. Report hit
rates as selected hits/lookups and report zero denominator as unavailable, not
100 percent. Verify programming, inhibition, privilege and directed rollover.

## Independent acceptance and delivery

Required portable entry commands, each self-contained:

```
python3 tests/verify.py --suite behavior
python3 tests/verify.py --suite synthesis
python3 tests/verify.py --suite linux
python3 tests/verify.py --suite reproduce
```

These are required interfaces, not a claim that the entrypoint already exists.
Verifier must author them independently and regenerate stale/missing artifacts.
Bind results to hashes of all consumed RTL, models, manifests and software.
Retain exact commands, working directories, tool versions, times, exit/timeout
and raw logs in new run directories ending in timestamps/hashes; preserve
failures. Never use runtime metadata as product or verification source.

Behavior: real Icarus compact startup/leaf/integration smoke (at most 500000
cycles, targeted below 60 seconds); compiled Verilator for substantial workloads.
Exhaust all 65536 compressed halfwords and execute every legal family, cross-page
faults and variable links. Preserve integer/M corner cases, AMO/LR-SC,
privilege/trap/delegation, Sv39 permission/SUM/MXR/A/D/superpage/ASID/fence,
AXI, host and interrupts. For seeds 17,43,89 at compact and representative
default geometry, compare at least 1000 each INT8/BF16/RMS and 2000 randomized
cache/memory operations per seed, stalls/errors, directed IEEE classes, all
register indices/aliases, exact counters, no active X/Z and no response loss.
Witness all directed cases, including singleton and maximal L2, four conflicting
ways and fifth eviction, all byte masks, memory endpoints and reset during stalls.

Disposable source mutants must compile and execute to reject wrong instruction
length, INT8 lane/sign, BF16 rounding/order, fault/squash vector writes, L2
tag/way selection, mask/coherence and counter increments. Compiler failure,
timeout, log keywords, forced failures or changed expectations do not count.

Synthesis: real Yosys over actual integrated top at default and smallest legal
geometry, substantive retained hierarchy/state, no latches, unresolved/blackbox
cells, undriven active controls or combinational division/modulo.
Parameter elaboration includes every legal discrete value, both prefetch states,
minimum boot, singleton, non-power-of-two memories, maximum geometry and explicit
illegal cases independently (including invalid booleans and both boot violations).

Linux: provenance-pinned local OpenSBI/Linux/user sources or reproducible images,
configs, hashes and licensing; networking disabled. `software/build.py` must
use declared existing tools and fail specifically if required inputs are absent.
The real compiled RTL top plus AXI DRAM model must boot OpenSBI, enter S-mode
Linux and run `/init` in U-mode under Sv39, using the actual UART at 0x10010000.
Retain image hashes/configs, UART, privilege/translation milestones and actual
user result records, not only banners or a synthetic PASS string.

User kernels cover bit-exact scalar RV64IM versus custom dot/tensor/RMS, mapping
and protection faults, failed/successful vloads, two tasks with distinct vector
state plus signals. INT8 tiles are 8x8 with K=64; BF16 tiles 4x4 with K=32.
Scalar BF16 uses integer arithmetic. Seeds 17,43,89 run with prefetch on and off.
For each seed and each INT8/BF16 warm-cache dot of length 256, require
scalar_cycles > vector_cycles with at least 32 repetitions and median matched
measurements, including required vector loads/accumulation within the interval.
Match operands, semantics, residency and boundaries; distinguish complete-kernel
and arithmetic-only cycles. Use hardware counter reads, never predicted tables,
host time or printed constants. Report configured hit rates and committed MACs.

Fresh-directory reproduction, networking disabled, must run bounded Icarus,
compiled Verilator custom/coherence smoke and real Yosys, independently compare
results and need no old generated binaries or private runtime state.
The shared runtime additionally requires all-RTL timing lint, Quartus 17.1
full-target fit/STA at <=10.0 ns with nonnegative setup slack and no unconstrained
functional paths/false-path masking, plus three consecutive deterministic
physical Arria 10 PCIe Gen3x8 integrated boot/coherence/kernel passes.
No portable check hardcodes a JTAG cable or PCIe BDF or duplicates hardware gates.
No missing input, unsuccessful command or unexecuted stage is a pass.

Deliver modular self-contained `rtl/*.sv`, this specification,
`design/ARCHITECTURE.md`, independent `tests/verify.py` and Python sources,
minimal software/build inputs and the subsequently approved runtime PDF.
All shipped commands/paths are project-relative; exclude credentials, private
host/account paths, runtime transcripts and runtime-owned directories.
