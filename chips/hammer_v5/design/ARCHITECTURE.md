# HAMMER-V5 architecture and implementation handoff

## Current implementation boundary

This is a **Designer source handoff**, not a verified or accepted SoC.
The frozen acceptance contract is SPEC.md. No simulation, numerical comparison,
synthesis, boot, benchmark, timing, physical HIL or independent verification is
claimed here.

The supplied 42-file V4 reference is unchanged. The V5 core/SoC/top now instantiate
the decompressor/fetch path, vector commit unit, separate INT8/BF16 datapaths,
CSR/HPM and unified L2. All transitive RTL dependencies are present in `rtl/`;
the delivered top does not instantiate modules from the reference directory.
This is source integration, not evidence of correct execution or timing.

Pinned genuine OpenSBI 1.4 and Linux 6.6.1 source archives, the offline build
recipe, userland kernels and the dedicated Linux context integration are present
in `software/`. BOOT_SOFTWARE.md specifies their construction and ABI. They have
not been built or booted by Designer. `tests/*.py` belongs to independent
Verifier and is not authored by Designer. Independent software builds and
functional checks follow this handoff and remain required for acceptance.

Repository intake supplied no linked source index. The now-supplied
`design/GENERATIONAL_HANDOFF.md` has been read; it reports N/A for parent
Quartus STA, timing/PPA and physical HIL, not parent signoff. No parent values
are invented. The inspected V4 boot ROM transfers control to external memory;
it is not OpenSBI/Linux. The genuine release archives and software inputs are
now present at the URLs/checksums pinned in `software/boot_manifest.json`.
Their presence does not establish a parent or V5 boot result.

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
| hammer_v5_core | Derived from V3 core; raw/expanded instruction metadata, variable fallthrough/link length, serialized custom execution |
| hammer_v5_decode | Derived from V2 decoder; custom-0 legality and scalar operand dependencies |
| hammer_v5_predictor | Derived from V2 predictor; halfword-indexed BTB and actual instruction fallthrough |
| hammer_v5_soc | Derived from V3 top; translated vector memory, L1/L2 events and serialized maintenance integration |
| hammer_v5_top | Derived from V4 top; identical external ports, V4 boot ROM, V5 SoC and added L2 parameters |
| hammer_v5_cache, hammer_v5_icache, hammer_v5_dcache | Derived from V3 L1 modules; preserve writeback/refill behavior, add demand events and memory traffic classification |
| hammer_v5_fabric | Derived from V3 fabric; preserve arbitration, map and local memories, carry demand classification |
| hammer_v5_cache_maintenance | New L1-completion-to-L2-maintenance sequencing controller |
| hammer_v5_ram, hammer_v5_imem, hammer_v5_dmem | Derived from V2 backing RAM/wrappers; power-up initialization metadata hides untouched storage while retaining initialized RAM across reset |

The 21 unchanged inherited dependencies copied into `rtl/` are V2 ALU,
AXI-Lite, CLINT, hazard, iterative multiply/divide, scalar register file and
trap selection; V3 accelerator bridge, atomic
controller, AXI geometry/master, cache arbiter, data translation/router, MMU,
page-leaf, PLIC, PTW, TLB and UART; and V4 boot ROM. Modified ancestors retain V5
names rather than changing the supplied reference. The required instance names
from SPEC.md are retained inside the legal-geometry generate scopes.

The fetch queue and decode state carry raw instruction, expanded instruction,
byte length, fetch fault tval and compressed illegality separately. Execute
carries length through link/fallthrough calculation; memory/writeback carry raw
bits through retirement and illegal-instruction reporting. The V5 predictor uses
halfword address indexing and expanded instruction decoding with actual byte
length. Branch targets reject bit zero only; JALR clears bit zero. The V5 CSR
preserves EPC bit one. Faulting cross-page fetches retain the original PC and
the failing halfword VA supplied by the fetch leaf.

The queue-head transport uses an explicit 262-bit vector for Yosys 0.33 parser
compatibility: 128 PC/prediction bits, 64 expanded/raw instruction bits, three
length bits, three fault/classification bits and 64 tval bits. The packed
field order, queue storage and handshake behavior are unchanged.

Custom instructions are serializing decode operations: they advance only after
older execute/memory/writeback stages drain, block younger operations, issue from
memory stage, and remain serializing through writeback disposition. Loads/stores
read scalar rs1, RMS reads scalar rs2, and dots read neither scalar source.
U-mode permission is checked before issuing the leaf request. Vector memory
multiplexes into the same translated data path as scalar memory, with size=8
bytes, VA addressing and appropriate load/store access permissions. Alignment
errors map to causes 4/6, access errors to 5/7, page faults to 13/15, and illegal
encodings to cause 2. Loads/stores do not write a scalar GPR. Actual accepted
vector store data is captured for retirement rather than interpreting its vector
index field as a scalar operand. Writeback commits successful results/state or
aborts a completed faulting operation; committed lane counts feed CSR on that
same disposition edge. Interrupts remain at empty-pipeline boundaries.

The fabric's deterministic three-requester round-robin arbitration routes only
external DRAM toward L2. An inherited cache-style arbiter merges fabric requests
with instruction/data maintenance, then feeds `u_l2` before the AXI master.
Protection is captured from the admitted fabric transaction; downstream DECERR
is retained through L2 response and arbiter buffering rather than converted to
SLVERR. L1 refills/writebacks, page-table traffic and accelerator requests all
traverse this insertion; local RAM and UART/CLINT/PLIC retain their bypasses.

Each new L1 maintenance wrapper first consumes successful L1 completion, then
issues the same maintenance command to L2, waits for completion, and only then
responds to its original requester. An L1 failure responds as an error without
claiming a completed L2 flush. FENCE/FENCE.I, core halt cleaning and inherited
host/accelerator ownership cleaning therefore include L2 serialization. Host and
accelerator transitions retain the parent's data-then-instruction invalidation
sequence. Prefetch is blocked during core halt, explicit halt requests, exclusive
accelerator ownership, host access/dirty state and SoC maintenance. Accepted
downstream transfers still drain normally.

| Integration boundary | Registered sequencing and degenerate behavior |
|---|---|
| Custom decode acceptance | Older X/M/W empty; scalar dependencies follow opcode function, not vector indices |
| Vector memory request edge | Capture actual store bytes/mask for retirement; no vector register update |
| Vector response edge | Move result/fault to W once; leaf awaits disposition |
| Vector W commitment/trap edge | Exactly one commit/abort; faulting/unissued operations never produce MAC events |
| L1 maintenance response edge | Capture error, or start L2 maintenance on the following registered state |
| L2 maintenance acceptance | Serialize after accepted fabric traffic; no early upstream flush response |
| L2 maintenance response edge | Retain result until the original requester accepts it |
| Simultaneous I/D event pulses | Add two one-bit events into a two-bit count, not a bitmap |
| L1 retry after refill | One demand lookup event; internal relookup is not a second hit event |
| Singleton L1/L2 geometry | Explicit zero set index; four beats/ways and all maintenance requesters remain connected |
| Power-up untouched local RAM read | Word initialization metadata returns defined zero, never an uninitialized RAM value |
| First masked local RAM write | Initialize unselected lanes to zero, write selected lanes, then mark word initialized |
| Subsequent masked local RAM write | Preserve unselected initialized lanes; zero mask is a no-op |
| Local RAM read/write on one edge | Retain parent's read-before-write observation, including zero on a first write |
| Reset during pending local access | Discard responses and reset response visibility; retain initialized words and their metadata with RAM contents |

Source inspection found that the inherited backing RAM can return an
uninitialized value, including the read-before-write payload on the first host
write. This is a source-level reset-observability gap, not a demonstrated parent
simulation failure. V5's backing RAM defines untouched local words as zero using
one FPGA-power-up-initialized bit per instruction/data word. On the first nonzero
masked write, it initializes all remaining byte lanes to zero; thereafter it
preserves normal byte-mask behavior. Synchronous RAM reads and writes remain
in reset-free clocked blocks. The initialized bitmap has a synthesizable constant
FPGA power-up value, retains across functional reset alongside the parent RAM
contents, and changes only with an accepted nonzero masked write. Response
visibility capture is synchronous and asynchronously reset. This avoids changing
the parent's retention of initialized code/data across reset. Absent upper
instruction words remain padded
zero without out-of-range bank access. The maximum added initialization state
is IMEM_WORDS+DMEM_WORDS bits; its fit/timing remains a physical-check obligation.

The generational handoff requires explicit unpacked byte-lane storage for
byte-enabled memories of at least 2 KiB. V5 local RAM, L1 data and each L2 way
already use separate generated 8-bit arrays, with `ramstyle = "M20K"` and
`nomem2reg`, synchronous reads/writes and no asynchronous reset on the RAM
ports. Generated lane arrays implement the same byte-lane separation as the
handoff's named `mem_b0..bN` example. Actual M20K inference, fit, runtime and
100 MHz timing remain obligations of fresh native Quartus checks; neither the
guidance nor these attributes proves them.

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

The core transfers the response from M to W, then supplies one mutually exclusive
commit or abort pulse at W disposition. The leaf interface also permits
disposition to coincide with response transfer, but never to precede it.
Readiness remains low while awaiting disposition.
`event_macs[3:0]` is the combinational committed-lane count for the disposition
edge: eight INT8/RMS, four BF16, otherwise zero. It is zero on abort/fault/reset.
The core connects it to CSR counting at that same commitment edge.

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
The dedicated kernel integration targets only the manifest-pinned Linux 6.6.1
source. It saves/restores every vector at task switch, forks and signal contexts;
its actual execution and preservation must still be independently verified.

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
maintenance and invalid requests. The SoC adds concurrent I/D pulses as counts,
and the CSR consumes each registered event once. L1's initial accepted demand
lookup is counted; its refill relookup is not a second lookup/hit. Maintenance
writebacks carry non-demand classification through the V5 fabric. L2's access/hit
pulses are gated by the captured transaction classification so those writebacks
do not contribute demand counters. Accelerator demand transactions do contribute.

Four full-width counters select events 0..5 with reset selectors 1..4.
Unsupported mhpmevent writes are WARL to zero. Counter aliases require
mcounteren (and scounteren for U). mcountinhibit implements bits 0,2..6;
bit one is zero because the time source is external. Legal explicit counter
writes override that edge's increment. Other control writes affect subsequent
increments. Rollover is modulo 2^64. The inherited time/privilege/status/trap
register behavior is retained; new C support preserves EPC bit one.

The owned software inputs are:

| Input | Implemented content |
|---|---|
| software/hammer_v5_isa.h | GNU RISC-V custom-0 instruction macros and actual hardware cycle/retirement/HPM CSR reads; not a numerical reference model |
| software/hammer_v5_context.S | Save/restore of all eight vectors through aligned memory, used by both the kernel context hooks and /init |
| software/hammer_v5.dts | Actual UART, CLINT, PLIC and DRAM map, compiled with pinned Linux's built dtc |
| software/boot_manifest.json and release archives | Genuine pinned Linux 6.6.1/OpenSBI 1.4 sources, SHA-256, licensing, software inputs, tools and boot addresses |
| software/build.py, patch_sources.py, linux.config, opensbi.config | Offline fresh-output build and deterministic dedicated-kernel/firmware source integration; receipts and source/image hashes |
| software/linux_hammer_v5.h, linux_hammer_v5.c | Eager per-thread context hooks, custom signal ABI and privileged counter-configuration device |
| software/opensbi_hammer_v5.c | Compatible-matched platform override, counter permissions and vendor SBI service |
| software/init_start.S, user_syscall.h, init.c | Freestanding genuine Linux /init, two tasks/nested signals, Sv39 faults, numerical kernels, matrix tiles and hardware cycle measurements |
| software/hammer_ieee.h | Software-only exact integer IEEE reference, independent of RTL implementation; Verifier must additionally derive its own reference |

ISA macro vector indices must be unsuffixed literal tokens 0..7, matching the
instruction's vector field. The header uses C11 static assertions, GNU assembly
`.insn r` and RV64 integer registers; no scalar F or standard V is needed.
Vload/vstore pointers must be eight-byte aligned and accessible under the
executing privilege. The macros deliberately retain memory/compiler barriers
around custom operations and counter reads. U callers require kernel vxctl and
architectural counter permission setup; these inputs do not silently enable it.

The context helper ABI takes a pointer to eight aligned little-endian 64-bit
words in a0, clobbers only caller-saved a0, and returns through scalar ra.
Assembly x0..x7 source/destination fields name vectors; stores do not clobber
scalar x1/ra, and loads into vector vr1 do not clobber scalar ra. The helpers
must only receive mapped kernel storage, not unchecked user signal-frame
pointers. Kernel signal integration must copy and validate the entire saved
state before restoring it, with normal user-copy fault handling.

`patch_sources.py` adds eight words to thread_struct and wires eager state
switching, parent snapshot before fork, kernel-thread zero initialization, exec
clearing and an extensible signal record. Signal data is copied to a complete
kernel-local snapshot; sigreturn installs it only after record, terminator and
alternate-stack validation. Nested signals use distinct frame snapshots.
Preemption is enabled in linux.config. Only bounded snapshot/install sequences
disable preemption; neither benchmarks nor tasks suppress normal scheduling.
Context code never uses vector arithmetic. The compatible-matched kernel device
enables vxctl and scounteren bits 0..6 only after probing the firmware ABI.
The OpenSBI override restores mcounteren/scounteren permissions and default
event selectors after generic initialization and provides validated machine
event programming for the privileged kernel ioctl. These are implemented source
hooks, not claims that Linux ran or task/signal preservation passed.

The parent map is local instruction storage at zero, local data at 0x10000000,
UART at 0x10010000, CLINT at 0x02000000, PLIC at 0x0c000000, and external
DRAM at 0x80000000..0xffffffff. UART is an eight-byte register block, byte IO
without register shifts; UART is PLIC source one and the CPU has M/S contexts.
CLINT mtime increments on every clock edge, so its declared 100 MHz timebase
matches the target clock. The DTS describes the fixed 2 GiB accessible DRAM
aperture and limits this boot configuration's Linux managed RAM to 128 MiB via
`mem=128M`. Backing memory must support the declared DRAM aperture, including
next-line prefetches outside the Linux-managed subset. A sparse AXI backing
model can do this without a giant generated image. This description is not proof
of board memory availability.

The unchanged V4 ROM sets hart ID a0=0, DTB a1=0x87e00000 and jumps to
0x80000000. The genuine boot build must place firmware there, Linux at a declared
nonoverlapping entry (planned 0x80200000), and DTB at the ROM's actual address.
No stock virtual-machine UART or firmware banner replaces these interfaces.
The build uses firmware fw_jump at 0x80000000, Linux Image at 0x80200000,
an embedded deterministic initramfs and DTB at 0x87e00000. Its images.json binds
the actual resulting images to input/configuration hashes.
The recipe uses only project-local inputs and contains no download, installation,
simulation, synthesis, deployment or hardware-access operations. Missing inputs,
checksum mismatches and missing tools fail explicitly. Independent verification
must disable networking in its execution environment and record actual versions,
build/configuration hashes, privilege/translation observations and user records.
Genuine S-mode Linux/U-mode Sv39 execution, context preservation, tensor results
and measured speed remain mandatory.

## Evidence boundary

No preparation experiment is acceptance. Designer may perform only a fast
syntax/elaboration check, retained in a fresh project-relative preparation
directory. Independent Verifier must author and execute every functional,
reference, defect-sensitivity and synthesis suite from SPEC.md after integrated
design handoff. The shared runtime must then execute timing and hardware gates.
The supplied generational handoff and genuine software inputs do not justify
a simulated banner, bare-metal replacement or passing skipped check.

Actual Designer diagnostics:

| Receipt | Actual result and scope |
|---|---|
| evidence/preparation/v5-leaves-syntax-20261102T174500022778Z/receipt.json | Prior ten-leaf static Icarus elaboration exited zero; no integrated top |
| evidence/preparation/v5-integrated-syntax-20261102T175517006458Z/receipt.json | Icarus 12.0 default integrated top elaboration exited zero before V5 backing RAM visibility changes |
| evidence/preparation/v5-ram-visibility-syntax-20261102T175919706197Z/receipt.json | Icarus 12.0, `iverilog -g2012 -t null -s hammer_v5_top rtl/*.sv`, final default integrated RTL elaboration exited zero |
| evidence/preparation/v5-software-syntax-20261102T181354001989Z/receipt.json | GNU RISC-V unknown-elf GCC 13.2.0, `-fsyntax-only`, /init C and its three included headers exited zero before subsequent fault-sentinel and per-cell UART-result refinements; no object, binary or execution |

Retained independent failure
`evidence/preparation/v5-synthesis-minimum-20261102T182910707878Z/receipt.json`
records Yosys 0.33 rejecting `$bits(fetch_t)` at the queue-head declaration.
The explicit-width repair above requires an independent fresh rerun; no
synthesis success is claimed. The inherited PLIC enable-array range warning
must separately be classified for reachability by Verifier; its RTL is
unchanged from the parent.

The OpenSBI import failure and source repair are documented in
`design/BOOT_SOFTWARE.md`. Original failed receipts, reset-release and
mutant-classification failures and their linked repairs remain unchanged.

The RTL static receipts retain exact expanded argv, source snapshots/hashes,
reference hashes, tool version, timing, exit and raw stdout/stderr. The C receipt
retains its exact argv, four source snapshots/hashes, tool version, timing, exit
and raw stdout/stderr. No functional failure or repair experiment is claimed.
No software object/image was built; geometry,
numerical, coherence, context, Linux and speed checks remain independent Verifier
work. The backing RAM change follows a source-inspection finding, not a claimed
simulation failure/repair. Later documentation updates do not change the RTL
captured by the final RTL static receipt.
