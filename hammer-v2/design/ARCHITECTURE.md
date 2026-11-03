# HAMMER-V2 microarchitecture

## Structure and ownership

The retained architecture is IF/ID, ID/EX, EX/MEM, MEM/WB and architectural
commit, not an instruction-at-a-time interpreter. Ordinary integer instructions
overlap; oldest privileged, maintenance, atomic and uncached instructions
serialize architectural effects. The fixed hierarchy is:

```
hammer_v2_top
  u_core: hammer_v2_core
    u_decode: hammer_v2_decode
    u_regfile: hammer_v2_regfile
    u_alu: hammer_v2_alu
    u_hazard: hammer_v2_hazard
    u_predictor: hammer_v2_predictor
    u_muldiv: hammer_v2_muldiv
    u_csr: hammer_v2_csr
    u_trap: hammer_v2_trap
    u_atomic: hammer_v2_atomic
  u_icache: hammer_v2_icache
  u_dcache: hammer_v2_dcache
  u_imem: hammer_v2_imem
  u_dmem: hammer_v2_dmem
  u_clint: hammer_v2_clint
  u_axi: hammer_v2_axi_lite
```

I/D cache wrappers instantiate the same `hammer_v2_cache` engine with constant
read-only/base/size settings; neither wrapper is a bypass or stub.
The parent-compatible ALU/hazard/regfile/predictor/muldiv interfaces and
encodings are retained. The immutable parent is not modified.

## Private extension channels (defined before implementation)

All numerical buses below are unsigned bit vectors unless explicitly compared
as signed for architectural arithmetic. All channels use pre-edge handshakes
and hide inactive payloads. Complete oldest PC/instruction/privilege and fault
context stays in the pipeline; leaf modules never invent a second PC.

### CSR and trap

`hammer_v2_csr` owns current `priv[1:0]` and the implemented architectural CSR
registers. Its combinational commit query is `csr_valid`, `csr_addr[11:0]`,
`csr_op[2:0]` (instruction funct3), `csr_src[63:0]`, `csr_read`,
`csr_write`. It returns `csr_rdata[63:0]` and `csr_illegal`.
The source is rs1 data or zero-extended zimm; read/write suppression is decided
from instruction register indices, not the numerical source value.
`csr_commit` qualifies a legal unsquashed oldest query at the commit edge.
No CSR query alone mutates state.

`retire` increments instret at that same edge. Counter writes override the
increment. `mtime[63:0]`, `irq_msip`, `irq_mtip`, `irq_meip`, `irq_seip`
are live input sources. CSR exports status, interrupt enable/pending/delegation,
vectors and EPCs to `u_trap`/core; these are private architectural aliases.

`return_kind[1:0]` is 0=none,1=MRET,2=SRET.
`return_illegal`/`return_pc` are query outputs; `return_commit` alone updates
privilege/status. WFI, SFENCE.VMA and satp restrictions use exported status.

`hammer_v2_trap` is a combinational, stateless resolver. `sync_valid`,
`sync_pc[63:0]`, `sync_cause[63:0]`, `sync_tval[63:0]` describe the oldest
fault. `boundary_valid` and `boundary_pc[63:0]` permit interrupt entry only
after all older externally visible transactions have retired and younger
effects can be annulled. It returns `enter`, `interrupt`, `target_priv[1:0]`,
`epc/cause/tval/vector[63:0]`, and `wake`.
Synchronous context wins over interrupts. The core gates `enter` with actual
oldest-stage commit/kill qualification before driving CSR `trap_enter` and
publishing the trap pulse/redirect. CSR consumes `trap_target`, `trap_epc`,
`trap_cause`, `trap_tval` on that edge. Trap entry wins over CSR/return writes;
the core never qualifies both. Legacy terminal handling still captures complete
context but stops until reset.

### Atomic

`hammer_v2_atomic` accepts `start` only when `ready`, with
`op[4:0]` (funct5), `word_op`, `addr[63:0]`, `operand[63:0]`.
Only a legal, unsquashed, oldest instruction may start. Address/alignment
checks occur inside the leaf before any cache request, including failed SC.
Its `done` result is held until `consume`, with `error`, `cause[3:0]`,
`tval[63:0]`, `result[63:0]`, `mem_write`, `wmask[7:0]`,
`wdata[63:0]`, `old_data[63:0]`. The core retains PC/instruction/privilege.
The leaf uses the frozen cache req/rsp channel and exclusively owns it until
completion; the core cannot interleave another D-cache transaction.
LR sets a reservation only after successful read. SC checks then clears it.
AMO read, compute and write occupy separate registered phases.

`invalidate` handles reset-independent trap/halt/host invalidation.
`store_commit` plus `store_addr[63:0]` invalidates an overlapping reservation
beat for ordinary committed stores. Atomic writes invalidate the matching beat
internally. Invalidation wins over simultaneous LR completion.
The core serializes all aq/rl variants; no weaker ordering mode exists.

### Decode extensions

The parent decode fields retain meaning. Added fields are `csr`, `atomic`,
`fence`, `fence_i`, `mret`, `sret`, `wfi`, `sfence`, each one bit.
CSR address/funct3 and atomic funct5/width are carried in the original
instruction, not duplicated mutable architectural state. SYSTEM ECALL cause
is adjusted for the pre-instruction privilege in the core.

## Cache/backing channels

Both caches have inputs clk,rst_n,req_valid,req_cmd[1:0],req_addr[63:0],
req_wdata[63:0],req_wstrb[7:0],rsp_ready and outputs
req_ready,rsp_valid,rsp_rdata[63:0],rsp_error.
Commands: 00 read,01 write,10 clean,11 clean-and-invalidate.
I reads place the selected 32-bit instruction in low bits and zero the upper
half. D reads return the containing aligned 64-bit beat; data/strobes are
lane aligned. I writes error without mutation. Maintenance ignores payloads.

Backing outputs are mem_valid,mem_write,mem_addr[63:0],mem_wdata[63:0],
mem_wstrb[7:0],mem_rsp_ready; inputs are
mem_ready,mem_rsp_valid,mem_rdata[63:0],mem_error.
Single outstanding request, stable response, no speculative writebacks.
The backing RAM modules use these same channels under `req_*`/`rsp_*` names
plus the parent `h_*` host port. Host/core ownership is exclusive.
Backing acceptance samples synchronous RAM. A registered control phase makes
the response valid after the following edge, never at the acceptance edge.
Instruction RAM packs adjacent 32-bit words into one 64-bit refill beat,
zero-filling a missing upper final word. Host reads remain 32-bit.

### Physical RAM ports and inference boundaries

Backing and cache data storage is split into generated eight-bit lane arrays.
Each lane has one unreset rising-edge process containing a synchronous read
and a full-byte write; byte enables select lanes rather than variable slices
of stored words. `ramstyle` is only a target hint, not proof of RAM inference.
No backing contents are reset or forced into registers.

Instruction words are banked by word parity: even and odd banks have
`(WORDS+1)>>1` and `WORDS>>1` rows respectively. A core refill is eight-byte
aligned and reads one row from each populated bank. A host access selects
one bank with address bit 2 and a row with the remaining word-address bits.
Each bank multiplexes host/core ownership before its single read/write port.
The host bank selector is registered alongside the synchronous read, without
adding an interface cycle. An absent singleton odd bank has no storage.
Data backing RAM similarly multiplexes host/core ownership onto one address
per lane. Cache lookup and victim reads share one muxed synchronous read
port per lane; hit/refill writes share one synchronous write port.
Metadata and controller phases are unchanged.

| Cycle/degenerate boundary | Physical-port behavior |
|---|---|
| Pre-edge host/core acceptance | Select address, read enable and per-lane write enables before the edge; host excludes core acceptance |
| Post-E0 host acceptance | Selected bank/lane read registers contain pre-write bytes; enabled writes have occurred once |
| Post-E1 host response | Existing top-level response samples that read result; no added latency |
| Post-E0 backing acceptance | Both applicable instruction banks or the data lanes have captured the requested beat |
| Post-E1 backing response | Existing pending/response controller publishes the captured beat and holds it under backpressure |
| Read and write at the same address | Nonblocking full-byte writes preserve read-before-write sampling, including untouched lanes |
| Active reset/first nonreset edge | Port writes disabled during reset; unreset read registers hidden by reset/valid gates; speculative local cache reads may resume, but no unsolicited architectural or backing access |
| WORDS=1 | Row index is constant zero; instruction odd bank omitted and upper beat word zero |
| Odd/non-power-of-two WORDS | Full-width range checks precede port enables; absent upper final word is not read and is returned as zero |
| Cache singleton/partial final line | Original indexing and maintenance sequence retained; refill padding and skipped writeback lanes unchanged |

Cache lookup has a synchronous data/tag capture followed by a registered
decision. While IDLE, the local read port speculatively samples the request
address on each nonreset edge, independently of request valid, command and
acceptance. Other states select the registered request index/beat, except
MLOOK selects the registered maintenance scan index and WB_READ selects the
registered victim index/beat. RAM read enables depend only on reset and local
IDLE/RELOOK/MLOOK/WB_READ state; metadata samples the selected lookup index on
every nonreset edge. Neither metadata sampling nor lookup address selection
uses the upstream acceptance signal. Only an accepted request captures command
and architectural context or leaves IDLE, so unused samples have no effects.

| Lookup scheduling boundary | Local sampling and architectural qualification |
|---|---|
| IDLE edge without acceptance | Speculative tag/data samples only; no response, metadata mutation or backing request |
| Ordinary acceptance E0 | Request context and matching speculative tag/data snapshot captured together |
| LOOK edge E1 | Consume the E0 snapshot; hit response appears after E1, without an added stage |
| Maintenance acceptance E0 | Capture command and initialize scan; ignore the speculative request-address sample |
| MLOOK then MCHECK | Snapshot the registered scan index, then consume that snapshot on the next edge |
| Final refill store then RELOOK | Install the completed line, then resample it before LOOK decides |
| Backpressured response/writeback | Response registers and victim RAM read register hold their payloads; speculative metadata samples cannot alter them |
| Singleton/non-power-of-two backing | Constant-zero singleton index and exact backing range/padding rules remain unchanged |

Dirty victim and refill beats advance 0,1,2,3 explicitly.
Cache data uses synchronous unreset RAM; metadata reset invalidates all lines.
Victim addresses are reconstructed from the stored aligned line base, not
the replacing request tag. Failed dirty writeback preserves valid/dirty state;
failed refill leaves invalid state. Maintenance scans every index including
the singleton; no truncated counter wrap is used as completion.
Host writes trigger cache maintenance before start may be accepted; data
writes occur only after halt has already cleaned dirty lines.

CLINT uses the same req/rsp handshake with `req_size[1:0]` for byte/half/word/
doubleword validation. `req_addr` is the exact byte address, data and strobes
are 64-bit beat-lane aligned. The response is the containing register beat;
the core performs load extension. MSIP has a four-byte register extent;
MTIME/MTIMECMP each have eight. Holes, crossings and misalignment error.

## Pipeline integration constraints

Fetch uses one outstanding I-cache transaction with a captured PC and redirect
epoch/kill qualification; stale responses must drain without entering IF/ID.
An internal four-entry prefetch FIFO collects cache responses and releases
instruction batches into IF/ID. This decouples the single-outstanding cache's
lookup latency from consecutive pipeline issue, preserving real EX/MEM and
MEM/WB forwarding opportunities. A full FIFO starts a batch; halt or eligible
interrupt drains a partial batch. Redirects, precise faults and serializing
commit flush all younger queued entries. FIFO occupancy is included in drain
completion, and no new architectural/debug port is introduced.
IF/ID stores the instruction and fault with its PC rather than depending on a
changing RAM output. Decode-to-execute forwarding retains 00=register,
10=EX/MEM,01=MEM/WB, EX/MEM priority, x0 excluded.
Unavailable load data interlocks. A held EX instruction captures forwarded
operands so a retiring producer cannot disappear during a cache/muldiv stall.
An older fault blocks all younger starts and writes.

MEM captures cache/MMIO completion before WB; WB carries its own extended
load result and complete retirement payload. Ordinary RAM stores cannot
execute until older faults are resolved. Privilege-changing/CSR/maintenance
operations drain older instructions and kill/refetch younger instructions as
needed. Host writes and resume cannot race outstanding maintenance.
Interrupt entry uses the next architectural PC, never a speculative fetch PC.
WFI is a committed waiting state, not an unretired pipeline occupant.
halt_req remains latched through drain/clean; no half atomic/MMIO completion.
Diagnostic redirect outputs are registered pulses at the redirect decision
edge, aligned with the trap event for trap entry. Internal fetch annulment uses
the decision directly, without waiting for the diagnostic pulse.
Host invalidations coalesce while loading. An accepted start immediately lowers
top-level halted and reserves launch; if invalidation is still active, execution
waits internally for it to finish. This preserves pulse-start acceptance without
executing stale cache contents or delaying the fixed host E0/E1 response.
A halt-clean backing error emits a store-access trap at the saved next PC with
zero tval and does not assert halted or discard the dirty victim. Unexpected
halted host-maintenance errors latch a launch interlock and cause subsequent
host requests to return errors until reset.

## Dependencies and reset priority

| Consumer | Required producer guarantee |
|---|---|
| Host | Core halted implies all older D writes cleaned and no outstanding transaction |
| Cache | Backing request executes once and response is held |
| Core | Cache response belongs to its one outstanding request; errors are explicit |
| CSR/trap | Core supplies oldest complete context and mutually exclusive commit qualifications |
| Atomic | Core grants exclusive D-cache ownership through done/consume |
| Backing RAM | Top excludes concurrent host and cache ownership |

Reset dominates all state updates. Then trap dominates return/CSR. Counter
writes dominate automatic increments. Reservation invalidation dominates set.
All output payloads are reset/valid gated, including unreset RAM dataports.
The exact edge and degenerate cases are normative in `SPEC.md`.

## Claim-to-evidence map

No evidence is claimed by this design document. Independent compatibility
checks cover RV64IM/pipeline/host/AXI; privileged checks cover CSR/traps/timers;
atomic checks cover reservations/locks/numerics; cache checks cover traffic,
coherence/error/maintenance; sensitivity checks prove reached defect detection;
synthesis checks prove structural properties; portable checks prove clean-copy
reproduction. None replaces the separate runtime timing and HIL gates.
The final runtime-authored PDF follows, rather than precedes, acceptance.
