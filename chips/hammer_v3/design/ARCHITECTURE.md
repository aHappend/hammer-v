# HAMMER-V3 architecture

## Implementation boundary

The design derives from the supplied V2 implementation, not a replacement
instruction interpreter. Preserve its pipeline, forwarding, predictor, iterative
arithmetic, caches, CLINT, loader/debug and retirement/trap records.

The compatibility copies in `rtl/hammer_v2_*.sv` are unchanged. V3 extensions use
separate modules. Translation must precede physical address routing and atomic
reservation establishment; merely wrapping an unchanged V2 core is insufficient.
The parent CSR returns zero for satp, lacks SUM/MXR and page-fault delegation,
and the core/atomic unit reject non-legacy physical addresses before memory
issue. Those are explicit derivation points, not accepted V3 behavior.

The delivery connects the V2-derived V3 core, translation subsystem, extended
caches, CSR, PLIC, UART, external AXI master and buffered accelerator bridge.
Registered integration helpers preserve request/response ownership through
translation, physical routing, arbitration and maintenance. No functional,
synthesis or hardware result is claimed by this implementation description.

The cache arbiter and physical fabric response-lane loops use module-scope
`genvar` declarations and explicit `generate/endgenerate` regions for Quartus
17.1 parsing compatibility, preserving their `g_response` hierarchy and logic.

## Parent provenance

The intake supplied 19 RTL files, but no linked source index, parent
specification, parent tests or accepted receipts. No parent acceptance is
inferred. SHA-256 values were read before derivation:

| File in hammer_v2_reference/rtl | SHA-256 |
|---|---|
| hammer_v2_alu.sv | 89b5fe972c11dc15b0b1680b630a1f6b5f19029324e6d20c586e925785c4f939 |
| hammer_v2_atomic.sv | 91ed2b8c233062538de11e51b795e52e4091ce9348c17a22b43d53cdd4a2c591 |
| hammer_v2_axi_lite.sv | 5d9a2022d454d56bbb7b01e6f05d49f88f0edb667e5b53792f2dd55d889f8597 |
| hammer_v2_cache.sv | e862ed1f487b9b7abdfa123bfe47d9f0b5c3fe15aa3297df773353055d7aac84 |
| hammer_v2_clint.sv | de7b496c7fbac90143a892071427c78e78e33a2ae71614f04299d6ddd24ee447 |
| hammer_v2_core.sv | c160b5683aecf33ecc7bd240e42591fd8865b6f9c9122fac896876f77ef27613 |
| hammer_v2_csr.sv | 1f16aebac08de73f761aaf15f6153acbb256aa472523c9175c58a4971c047993 |
| hammer_v2_dcache.sv | 17010c830560f166302aac0ddf6068ad09f402ea138656d2b4edb9f5671bbda7 |
| hammer_v2_decode.sv | 2b81d3929eec31a2656bc3bea4a38b1dca86a158762820248d98c3dc5edfd572 |
| hammer_v2_dmem.sv | 2e8d9e9d97a59c870969de85597363e330f7963effacee46912833e0fd078249 |
| hammer_v2_hazard.sv | 90128fc0baf287f4e22ddb1ff7f8ff0671ddd2fc3d12300150debc6f54179aa1 |
| hammer_v2_icache.sv | 43a3b4910101e0b0b4555c7532388841c6d9e149d02272e4c84c8e903d21012d |
| hammer_v2_imem.sv | b5c8d22e069804f7eb1e55266762f4ca080d493ab3ef207320b8c62c260c67f1 |
| hammer_v2_muldiv.sv | a0abeb501a411ee781b11b5352d70521ec0fd06458055666ae9bdd4da598ce5b |
| hammer_v2_predictor.sv | 72b9adaf5781e44ae2f9e58efdcb6a318ab086a4cea12851adf03c395754591a |
| hammer_v2_ram.sv | cf21ea4cfc813ef61e392c6bdf324e2c41870798cd536dd8828655f04d2e6885 |
| hammer_v2_regfile.sv | ccf6176ff0e8c81309bf166c7cce12c741eec5cecf8264b565315ac95fa2ef6b |
| hammer_v2_top.sv | 7efe65cceeba03d41fcf4bdb8b801a95a6478742e68c7cb66cc7e98d48384776 |
| hammer_v2_trap.sv | cb96f9092b6025697e431681fc4f7649ae796cd47b50b44fabbd959fcfa29f00 |

## Translation architecture

Separate small fully associative TLBs feed a shared registered three-level
walker. Each client owns one pending translation and one held response.
The MMU latches satp, effective privilege, SUM and MXR at acceptance; no later
CSR change can modify an already accepted walk. A round-robin grant selects I/D
misses. Only successful leaves refill. Permissions are evaluated on every hit,
not only during a walk.

TLB entries store VPN, PPN, leaf level, ASID, G and R/W/X/U/A/D. Matching masks
follow the leaf span. A refill removes overlapping mappings in the applicable
ASID/global domain before inserting, preventing two possible hits after
superpage-size changes. Replacement uses first invalid, then explicit circular
round-robin, including the one-entry case.

The walker has distinct address/request, memory-response capture, PTE
classification and final-response stages. Nonleaf G propagates. Physical bus
failure remains an access fault. Svade faults on missing A/D and never writes
page tables. The coherent fabric must snoop/read CPU dirty D-cache PTE data or
perform ordered cleaning before the walker reads backing RAM.

Fences immediately block new admission, drain pre-fence client/walker activity,
invalidate both TLBs on a registered edge and acknowledge afterward. satp changes
use the same path with full invalidation. Because value comparison cannot detect
same-value writes, every legal satp write attempt first requests an all/all fence
through the existing core/MMU handshake. WB holds the instruction until the
acknowledgement; only then may the CSR, destination register and retirement
update. Illegal accesses trap without requesting this fence, and source-x0
read-only CSR forms do not request write invalidation. Unsupported MODE writes
remain WARL-ignored but conservatively fence. Changed values additionally invoke
the MMU's value-change invalidation before new-context requests are admitted.
Completion cannot race a late refill.
The core discards outstanding wrong-path fetch results and serializes context
commits with this boundary. Fetch queue entries retain a distinct page-fault bit
through ID/EX/MEM/WB. Data faults retain their original virtual address while
translation and routing use separately latched physical addresses.

The coherent PTE path arbitrates walker reads at the D-cache request
side, not its backing-memory side. This naturally observes dirty PTE bytes.
An ordinary data translation must finish before its data-cache request is
admitted, allowing a walker miss to use that cache without waiting on the
untranslated request. Arbitration must retain ownership until the response is
consumed, not merely until its request is accepted.

## Coherence and ownership

The physical fabric arbitrates cache backing, coherent PTE reads,
uncached peripheral traffic and accelerator ownership. A PTE read is not allowed
to bypass a preceding dirty CPU store. Accelerator admission stops new CPU
transactions, drains accepted traffic, cleans/invalidates D and invalidates I,
then executes the entire burst exclusively. Reservations clear before the burst.
Errors propagate before CPU resumption. This coarse-grained implementation
trades throughput for bounded, unambiguous single-hart ownership without ACE.

The accelerator bridge collects and checks all write beats before maintenance
or memory issue. Thus a malformed final strobe or LAST cannot leave earlier
write effects. It consumes unsupported AWLEN bursts through the declared count,
without allocating beyond 16 buffered beats. Reads return the declared count
even for rejected geometry. The bridge's `exclusive` requests precise core drain. Its `quiesce_valid` is
acknowledged only after both caches complete maintenance. `allow_transaction`
is connected to a retirement/trap progress token; exclusivity consumes that
token and a resumed running core must make architectural progress before the
next burst. An already stopped processor does not require a progress token.

`hammer_v3_atomic` is separately derived from the unchanged parent atomic unit.
The core first submits its virtual address and LR/SC/AMO access kind through
the real data MMU. Permission or bus faults complete the instruction precisely
without starting the atomic engine, including a failed SC. A successful
preflight latches the physical address before `u_atomic` starts; subsequent
read/modify/write requests use that physical address without a second walk.
Reservations therefore compare physical addresses across aliases. Traps,
context changes, halt/coherent maintenance and CPU stores conservatively clear
them. Ordinary loads/stores are serialized at the memory-stage boundary;
arithmetic forwarding and the original pipeline boundaries remain intact.

The physical data router decodes after translation, including MMIO; no virtual
address is rejected because it resembles an unmapped physical region. The
backing fabric arbitrates I-cache/D-cache/accelerator traffic round-robin,
retains the grant through the response handshake and checks the full address
and originating client before reaching RAM or AXI. The walker instead uses
the D-cache frontend to observe dirty PTE data. Host accesses use the RAM host
ports only after precise halt, and acknowledgements for successful host writes
wait for ordered invalidation of both caches.

The external-memory master is a full AXI4 single-beat subset. Separate AW/W
completion bits handle arbitrary independent acceptance. The caches retain the
parent synchronous payload RAM, lookup/relookup and maintenance states, adding
the external-RAM interval to request/refill/writeback region checks only.

PLIC selection is a balanced five-level rank tree carrying priority and inverse
ID, rather than a 32-source serial comparator chain. Gateway ownership is shared
across contexts. UART FIFOs retain per-character errors; TX/RX format/divisor are
latched per character. Separate serializers use divisor-counted oversample
intervals; no combinational divider is introduced.

| Consumer assumption | Producer obligation |
|---|---|
| Core sees one completion per request | MMU/cache/fabric retain ownership until response handshake |
| Walker reads recent PTEs | fabric orders dirty cache stores before physical PTE reads |
| No post-fence stale translations | MMU drains walks before invalidate/ack |
| Accelerator sees dirty data | maintenance completes before exclusive burst |
| CPU sees accelerator code/data writes | both caches invalidated before resumption |
| Host writes cannot race CPU | parent halt and maintenance ordering preserved |
| AXI response is real completion | master accepts independent AW/W, then B, or AR then R |

## Implementation and evidence discipline

The target is one active-low-reset 100 MHz clock domain. Peripheral asynchronous
inputs use two-register synchronization. Payload RAM uses synchronous reads and
does not asynchronously reset; validity, controls and architectural state do.
No divider/modulo datapath is introduced. Generic RTL synthesis and static
syntax do not establish Arria 10 timing.

Verifier independently authors all test sources and the Python ISA/Sv39 oracle.
The mandatory commands and coverage remain those in SPEC.md and the admitted
work order; none are replaced by leaf checks. The unchanged parent must also be
compared in Bare mode, distinguishing inherited defects from V3 regressions.
Report a Linux boot only with an actually executed identified image. Required
final PDF creation follows independent engineering acceptance.
