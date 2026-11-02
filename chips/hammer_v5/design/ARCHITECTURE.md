# HAMMER-V5 architecture and implementation handoff

## Current implementation boundary

This is a **partial Designer implementation**, not an integrated or accepted SoC.
The frozen acceptance contract is SPEC.md. No simulation, numerical comparison,
synthesis, boot, benchmark, timing, physical HIL or independent verification is
claimed here.

The supplied 42-file V4 reference is unchanged. Current V5 files implement the
decompressor, halfword fetch path, vector execution/commit leaf, INT8 reduction,
BF16/FP32 arithmetic pipeline, CSR/HPM leaf and unified L2 leaf. They are not yet
instantiated by a V5 core/SoC/top. Their presence does not satisfy integrated
hierarchy, CPU execution, Linux or coherence acceptance.

`hammer_v5_core`, `hammer_v5_soc`, `hammer_v5_top`, inherited standalone RTL
dependencies, genuine boot software/build recipe and the kernel context patch
remain to be implemented. `tests/*.py` belongs to independent Verifier and is
not authored by Designer.

Repository intake supplied no linked source index. The requested
`design/GENERATIONAL_HANDOFF.md` was absent at inspection. No parent timing/PPA
values are invented. The inspected V4 boot ROM transfers control to external
memory; it is not OpenSBI/Linux. No genuine local OpenSBI, Linux, initramfs,
image/configuration manifests or minimal userland sources were supplied.
The authentic handoff and provenance-pinned genuine boot inputs remain open
prerequisites, not skipped tests or successful baseline evidence.

## Ancestry and integration plan

| Delivered/current module | Ancestry and role |
|---|---|
| hammer_v5_decompress | New combinational integer RV64C expander |
| hammer_v5_fetch_path | Replaces V3 fetch controller, preserving translation/cache handshake patterns |
| hammer_v5_int8 | New registered signed reduction/RMS datapath |
| hammer_v5_bf16 | New transactional controller and four-product/two-level addition tree |
| hammer_v5_bf16_mul | New four-stage internal BF16-to-binary32 multiplier |
| hammer_v5_fp32_add | New four-stage internal binary32 adder |
| hammer_v5_fp32_round | Shared combinational integer IEEE rounding primitive |
| hammer_v5_vector | New eight-vector architectural state and disposition controller |
| hammer_v5_csr | Derived from V3 CSR; retains trap/status logic, extends EPC/misa/HPM/vxctl |
| hammer_v5_l2 | New four-way synchronous write-through unified DRAM cache |

Future ancestors must be derived from actual supplied parent sources, not an
older checkout. Copy needed inherited modules into `rtl/` without editing the
reference. Rename the modified V3 core/top to V5 core/SoC and the V4 wrapper to
V5 top. Wire the literal hierarchy in SPEC.md; do not instantiate new leaves
beside an unchanged V3 processor.

The parent core requires coordinated queue/ID/execute/memory/writeback changes:
carry raw instruction, expanded instruction, byte length, fetch fault tval and
compressed illegality separately. Its predictor currently sees a fixed-width
instruction and assumes four-byte fallthrough. Update predictor fallthrough
and link/recovery logic, branch alignment and return paths, not only decode.
The parent CSR clears EPC bit one; the V5 CSR now clears only bit zero.

The vector instruction must drain older potentially faulting pipeline operations
before its accepting edge. Decode scalar dependencies from the custom encoding,
not the vector register field numbers: loads/stores read scalar rs1, RMS reads
scalar rs2, dots read neither scalar source. Gate U instructions using
vector_user_enable before issuing the leaf request. Serialize interrupts,
fences and ownership transitions until vector completion/disposition.
Route memory through the translated ordinary data path with size=8 bytes,
load/store access classification and non-physical addresses. Detect/retain
misalignment separately when mapping the vector response to architectural
causes. Select GPR writeback only for successful arithmetic; loads/stores do
not write a GPR.

The parent fabric provides deterministic three-requester round-robin arbitration
and routes only external DRAM traffic toward its AXI master. Insert L2 between
that DRAM output and the inherited master. Retain AXI protection and decode-error
classification around this insertion; the L2's boolean error is not permission
to discard DECERR. L1 instruction/data refills, page-table traffic and accelerator
traffic must all traverse this point. UART/CLINT/PLIC bypass it.
Connect L2 maintenance after L1 drain and before acknowledging fences or
host/accelerator ownership changes. FENCE.I and coherent ownership must invalidate
stale instruction/data lines as required. `prefetch_block` must reflect reset,
halt drain, host maintenance and accelerator quiescence. It is an integration
control, not an independent clock or permission to interrupt accepted writes.

## Interfaces and cycle boundaries

The transactional ports and frozen timing are in SPEC.md. All payloads are
gated to zero when inactive, with asynchronous reset of control/valid state.
The simple arithmetic leaves have the common request/response handshake and
packed 64-bit operands:

| Leaf | Request payload | Response payload |
|---|---|---|
| hammer_v5_int8 | req_a,req_b,req_seed[63:0], req_square | rsp_data[63:0] |
| hammer_v5_bf16 | req_a,req_b[63:0] | rsp_data[63:0], upper word zero |

INT8 uses exactly E1 operands, E2 products, E3 pair sums, E4 partial sums,
E5 full reduction and E6 final result after the E0 accepting edge.
Product/pair/partial/full widths are 16/17/18/19 signed bits. Each addition
explicitly widens both operands before summation. The final addition sign
extends the reduction to 64 bits and adds the RMS seed modulo 2^64. Dot ignores
the seed; square mode uses the first vector for both signed multiplicands.

The BF16 top captures packed operands at E0 and advances internal arithmetic
only at E1..E12. Four parallel multiplier outputs register at E4, the fixed
pair sums at E8, and the final sum at E12. Response valid asserts after E12;
its data is the final adder's registered output, not an extra thirteenth
pipeline register. Stop internal advance during response stalls, preserving
the result exactly. Internal arithmetic helpers use `advance` as a clock
enable, not a transactional interface. They cannot accept independent operations.

For finite BF16, `value = (-1)^sign * mantissa * 2^(E-7)`, where mantissa is
eight bits including the hidden bit (zero for subnormals) and E is exponent-127
or -126 for subnormals. The product stage multiplies unsigned significands,
then normalizes the exact 16-bit product and signed exponent. Normalized
significands retain 24 bits plus guard/round/sticky. FP32 add stage one orders
finite magnitudes and aligns with right-shift-jam; stage two adds/subtracts
extended significands; stage three normalizes using a bounded binary leading
zero detector; stage four rounds. Subnormal rounding shifts with sticky before
RNE, including a possible carry into minimum normal. Overflow produces signed
infinity. NaN classification dominates infinity; exact cancellation uses
positive zero except adding two negative zeros. No host floating arithmetic
or division/modulo operators are used.

## Vector state and disposition

`vr[0:7]` is the architectural 8x64-bit state, reset to zero, including writable
vr0. No load or arithmetic request changes this array. A completed load has a
staged destination and result until commit. Fault/illegal flags prevent commit
updates. Arithmetic leaves share the vector unit's accepting edge and expose
their response directly, preserving the specified E6/E12 latency.

The core must transfer the response, then supply one mutually exclusive commit
or abort pulse. Disposition may coincide with the response transfer. It must not
precede that transfer. Readiness remains low while awaiting disposition.
`event_macs[3:0]` is the combinational committed-lane count for the disposition
edge: eight INT8/RMS, four BF16, otherwise zero. It is zero on abort/fault/reset.
The core must connect it to CSR counting at that same commitment edge.

vload/vstore use one aligned eight-byte request. The unit captures store data
when accepting the instruction, holds the memory request under stalls, and waits
for an accepted response. Unaligned requests generate a local memory error and
no memory request; the core maps this condition to cause 4/6, not cause 5/7.
Page and access faults preserve the original VA in rsp_tval. Stores issue only
after the core has serialized older faults, since their external effects cannot
be rolled back by a later disposition pulse.

Privilege gating is owned by the core, not a duplicated privilege register in
the vector unit. vxctl is at 0x800, reset bit zero clear; U writes are illegal,
M/S writes select bit zero, other bits read zero. U may read it.
The kernel must save/restore every vector for task switch and signal context;
no kernel patch can be claimed complete against an unspecified Linux source.

## Fetch assembly

The fetch leaf retains the parent's req/tr/cache handshakes and adds
`rsp_insn_raw[31:0]`, `rsp_insn_bytes[2:0]`, `rsp_illegal` and `rsp_tval[63:0]`.
`rsp_rdata[31:0]` contains expanded decode bits, upper word zero. Both raw and
expanded outputs remain stable under response stalls. These extra outputs are
internal integration metadata, not changes to the fixed external top.

Translate the exact first halfword VA, then request its aligned four-byte word.
The inherited instruction cache returns that word in bits 31:0. Select its
lower/upper half using original PC bit one. A compressed instruction completes
without requesting the next word. An aligned 32-bit instruction uses both
halves of the returned word. A 32-bit instruction at offset two saves its first
half, translates original PC+2 independently and fetches the next aligned word.
This handles page and cache-line crossings without reading another page for a
compressed instruction. Fault tval is the current failing halfword VA, never
the physical cache-word address; the core retains the original PC.
Illegal compressed expansion produces NOP internally plus an explicit illegal
flag and raw bits; the core must trap on that flag, not execute the NOP.
Quadrant-3 halfwords are outside the decompressor's input domain for actual
fetch; the decompressor classifies them illegal if invoked directly.

## L2 storage, arbitration and maintenance

The L2 has four separately addressable ways of byte-enabled synchronous data
RAM and synchronous tag RAM. Only metadata resets. Tags store physical line
addresses; valid bits hide uninitialized RAM. Each line contains four 64-bit
beats; no dirty storage exists. Capacity is 4 * L2_SETS * 32 bytes.
SET=1 has a real two-bit word index, not a zero-width set slice.

Read hit timing: E0 starts way RAM/tag reads and captures valid metadata;
E1 captures those outputs; E2 parallel-compares four tags and selects the
matching word; E3 registers the response. Hits choose the lowest matching way
deterministically. Allocation chooses lowest invalid way, otherwise round-robin;
the pointer advances only when a complete successful line installs.

Miss refill invalidates the chosen victim before accepting downstream reads.
Each beat is requested and its response accepted before writing synchronous
RAM. Only the fourth successful stored beat installs the tag/valid bit.
Failure never installs partial data. Write misses first allocate the full line;
all writes then forward the original byte mask/address/data to external memory.
Successful write response updates matching cached byte lanes; failure invalidates
the potentially affected line and returns error. Zero masks remain real masked
transactions; no fabricated success hides downstream error.

Read-miss completion records one next-line candidate inside
0x80000000..0xffffffff. A separate lookup suppresses resident candidates.
No speculative lookup contributes HPM events or generates another prefetch.
Demand/maintenance wins at idle. A new demand or prefetch_block abandons
unaccepted speculative work; any already accepted beat drains before yielding.
Partially filled speculative victims stay invalid. A demand to the same line
may therefore restart a refill; it never consumes partial or failed data.

The inherited AXI master advertises request-ready from idle independently of
request-valid. Speculative mem_valid is offered only when that ready is high,
so no unaccepted stalled speculative valid must be withdrawn to favor demand.
Demand requests and writes use ordinary held-valid behavior. This downstream
ready contract must be preserved in integration; do not insert a bridge that
waits for speculative valid before asserting ready.

Clean-all has nothing dirty to write but remains serialized behind completed
transactions. Clean/invalidate scans all sets/ways, cancelling pending prefetch.
Upstream responses do not complete until this finishes. L2 rejects misaligned
or non-DRAM reads/writes; the SoC must keep MMIO/local traffic on the inherited
bypass paths, not send it to this leaf. All four ways and every byte lane remain
independently accessible.

## HPM and software requirements

CSR ports add event_l1_access/event_l1_hit[1:0] (allow concurrent instruction/data
lookups), event_l2_access/event_l2_hit, event_vector_macs[3:0] and
vector_user_enable. L1/L2 events must come from accepted demand lookups,
not instruction retirement or merely asserted requests. L2 pulses access after
the accepting lookup edge and hit after tag selection; they exclude prefetch,
maintenance and invalid requests. The core/SoC must account for these event
edges without duplicating them.

Four full-width counters select events 0..5 with reset selectors 1..4.
Unsupported mhpmevent writes are WARL to zero. Counter aliases require
mcounteren (and scounteren for U). mcountinhibit implements bits 0,2..6;
bit one is zero because the time source is external. Legal explicit counter
writes override that edge's increment. Other control writes affect subsequent
increments. Rollover is modulo 2^64. The inherited time/privilege/status/trap
register behavior is retained; new C support preserves EPC bit one.

Boot software must use the actual parent map: local instruction storage at
zero, local data at 0x10000000, UART at 0x10010000, external DRAM beginning at
0x80000000 and ending before 0x100000000. Exact CLINT/PLIC descriptions must be
taken from the inherited integration before writing a project-owned DTB.
Do not substitute a stock virtual-machine UART address.

Future software inputs must pin OpenSBI/Linux revisions, configurations,
checksums, licenses and compiler/build dependencies; `software/build.py` must
consume project-local inputs with networking disabled and report absent
prerequisites unsuccessfully. Genuine S-mode Linux and U-mode Sv39 execution,
task/signal context management, tensor tiles and measured benchmark speed remain
mandatory. Tool versions are not guessed from command discovery; record actual
versions with execution receipts.

## Evidence boundary

No preparation experiment is acceptance. Designer may perform only a fast
syntax/elaboration check, retained in a fresh project-relative preparation
directory. Independent Verifier must author and execute every functional,
reference, defect-sensitivity and synthesis suite from SPEC.md after integrated
design handoff. The shared runtime must then execute timing and hardware gates.
The missing authentic generational handoff and genuine software inputs do not
justify a simulated banner, bare-metal replacement or passing skipped check.
