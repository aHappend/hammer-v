# HAMMER-V3 specification

## Status and authority

This specification implements the admitted HAMMER-V3 work order. The target is a
single-hart, little-endian RV64IMA processor with privileged architecture v1.12,
M/S/U modes, IALIGN=32, Sv39, PLIC, 16550A console and serialized coherent
accelerator access. No C/F/D/H extensions are included. Linux capability is an
architectural target, not a Linux boot result.

Implementation is in progress. Completed translation/peripheral leaves do not
constitute an integrated processor. No functional, synthesis, timing, board or
Linux-boot result is implied by this document. Independent verification owns
`tests/*`; engineering acceptance precedes the independently reviewed product PDF.

## Compatibility, parameters and public interface

The 19 `hammer_v2_*.sv` files under `rtl/` are unchanged copies of the supplied
parent. They provide the parent module/port/parameter contracts without depending
on the reference tree for normal compilation. Parent source hashes and derivation
boundaries are recorded in ARCHITECTURE.md. Parent provenance is not a passing
baseline. The reference directory must remain unchanged.

`hammer_v3_top` preserves every port of `hammer_v2_top`, including host loading,
halt/start, debug registers, retirement, traps, forwarding/stall/redirect
observations, external interrupts and the `m_axi_*` AXI-Lite master.

| Parameter | Default | Legal values |
|---|---:|---|
| IMEM_WORDS | 16384 | 1 through 16384 |
| DMEM_WORDS | 8192 | 1 through 8192 |
| PRED_MODE | 1 | 0, 1 |
| BTB_ENTRIES | 16 | 1, 4, 16, 64 |
| ICACHE_LINES | 64 | 1, 4, 16, 64 |
| DCACHE_LINES | 64 | 1, 4, 16, 64 |
| LEGACY_TRAPS | 0 | 0, 1 |
| ITLB_ENTRIES | 8 | 1, 4, 8, 16 |
| DTLB_ENTRIES | 8 | 1, 4, 8, 16 |

No other top-level parameters are permitted. Invalid values must elaborate to a
clear `PARAMETER ERROR` fatal, with invalid datapaths generate-guarded.

New pins are `uart_rx` (input), `uart_tx` (output), `plic_sources[30:0]`
(input), full AXI4 master `m_mem_axi_*` and full AXI4 slave `s_acc_axi_*`.
The accelerator is the master of the latter interface; the subsystem is its
slave. The subsystem is master of the outward external-RAM interface.

Both full AXI4 bundles use these lowercase suffixes:

| Channel | Payload fields and widths |
|---|---|
| AW, AR | id 4, addr 64, len 8, size 3, burst 2, lock 1, cache 4, prot 3, qos 4 |
| W | data 64, strb 8, last 1 |
| B | id 4, resp 2 |
| R | id 4, data 64, resp 2, last 1 |

Each channel has valid and ready. Directions follow AXI4 convention. There is no
WID, ACE snoop channel or additional clock. Names concatenate the prefix and
standard suffix, e.g. `m_mem_axi_awaddr`. AXI4 alone is not ACE coherence.

## Physical map

Decode all 64 input bits; implemented physical width is 56 bits. Never truncate
addresses to create aliases. Unmapped physical targets cause access errors.

| Region | Byte interval | Permissions |
|---|---|---|
| Legacy instruction RAM | [0, 4*IMEM_WORDS) | CPU instruction fetch, halted host |
| Legacy data RAM | [0x10000000, 0x10000000+8*DMEM_WORDS) | data, atomics, PTE reads, accelerator, halted host |
| CLINT msip | [0x02000000, 0x02000004) | parent semantics |
| CLINT mtimecmp | [0x02004000, 0x02004008) | parent semantics |
| CLINT mtime | [0x0200bff8, 0x0200c000) | parent semantics |
| PLIC | [0x0c000000, 0x10000000) | only implemented registers below |
| UART | [0x10010000, 0x10010100) | only offsets 0 through 7 |
| Legacy external MMIO | [0x40000000, 0x40010000) | AXI-Lite |
| External RAM | [0x80000000, 0x100000000) | executable, cacheable, data, atomics, PTEs, accelerator |

Host addresses remain 32-bit physical byte offsets into the selected legacy RAM.
Accept only while halted; preserve parent alignment, data/strobe validation and
cache-maintenance ordering. Misaligned ordinary CPU accesses trap, not split.
I/D caches remain physically indexed/tagged, direct mapped, 32-byte lines,
synchronous payload reads, with four 64-bit refill/writeback beats and partial
legacy boundary-line handling. The D-cache is write-back.

`hammer_v3_icache` and `hammer_v3_dcache` preserve the corresponding parent
cache-wrapper ports and `LINES,WORDS` parameters, and instantiate
`hammer_v3_cache` with fixed READ_ONLY=1/0. `hammer_v3_cache` retains the parent
cache interface and `LINES,WORDS,READ_ONLY` parameter contracts. Its only region
extension is the external-RAM interval in addition to the selected legacy RAM.
Every refill/writeback beat is independently bounded by those intervals; a
legacy partial line never generates an out-of-range backing request.

## Core and MMU contracts

The V3 core retains IF/ID/EX/MEM/WB and distinct `u_decode`, `u_regfile`,
`u_hazard`, `u_alu`, `u_predictor`, `u_muldiv`, `u_atomic`, `u_csr`, `u_trap`.
The top's required instances are `u_core`, `u_mmu`, `u_icache`, `u_dcache`,
`u_fabric`, `u_plic`, `u_uart`, `u_clint`, `u_accel`, `u_mem_axi`.
`u_clint` has type `hammer_v2_clint`; the others have corresponding `hammer_v3_*`
types. MMU children are `u_itlb`, `u_dtlb` (`hammer_v3_tlb`) and `u_ptw`
(`hammer_v3_ptw`).

Core instruction requests: `i_req_valid/ready`, `i_req_addr[63:0]`,
`i_req_cmd[1:0]`. Responses: `i_rsp_valid/ready`, `i_rsp_rdata[63:0]`,
`i_rsp_error`, `i_rsp_page_fault`.
Data requests add `d_req_wdata[63:0]`, `d_req_wstrb[7:0]`,
`d_req_size[1:0]`, `d_req_access[1:0]`; data responses have the analogous
data/error/page-fault fields. Commands are read=0, write=1, clean=2,
clean-invalidate=3. Access kinds are fetch=0, load/LR=1, store/SC=2,
AMO read-write=3. Maintenance bypasses translation.

The core outputs `mmu_satp[63:0]`, `mmu_priv[1:0]`, `mmu_mstatus[63:0]`,
`sfence_valid`, `sfence_va_valid`, `sfence_asid_valid`, `sfence_va[63:0]`,
`sfence_asid[15:0]` and receives `sfence_ready`.
The source-valid qualifiers describe the instruction's register numbers, not
whether their values are nonzero. Fence retirement waits for the handshake.
satp/CSR/return/context changes serialize outstanding translations and fetch.
Translate once before each atomic operation; reservations use physical addresses.
Even an unsuccessful SC must check translation/permission.

Atomic preflight is an internal integration helper, separate from the frozen
instruction/data channels: core outputs `at_req_valid, at_req_va[63:0],
at_req_access[1:0]`, receives `at_req_ready, at_rsp_valid,
at_rsp_pa[55:0], at_rsp_error, at_rsp_page_fault`, and outputs `at_rsp_ready`.
It uses the real MMU data client before starting `u_atomic`, including failed
SC. The top checks that the translated target is data RAM or external RAM.
Core output `d_req_physical` qualifies only subsequent requests from this
already-translated atomic engine. It does not bypass permission preflight.
These helper wires add no software-visible control or top-level pins.
`u_atomic` receives the physical preflight result, so reservations compare
physical addresses; any committed CPU store conservatively clears reservations.
The core's existing `host_data_write` input also carries coherent-maintenance
reservation invalidation. The top never begins accelerator memory traffic until
the processor has drained and this invalidation has occurred.

### Registered integration helpers

`hammer_v3_fetch_path` captures the core instruction channel, uses the MMU
instruction translation port, then issues the physical cache request. Maintenance
commands bypass translation. `hammer_v3_data_path #(DMEM_WORDS)` similarly owns
the data/MMU transaction, with exclusive atomic-preflight selection. Its physical
output retains command, size, access, data and mask; it never routes a fault.
The physical address is latched until the downstream response is consumed.

`hammer_v3_data_router #(DMEM_WORDS)` routes that registered physical channel to
five common request/response endpoints, in index order: D-cache, CLINT, PLIC,
UART, legacy AXI-Lite adapter. Endpoints share address[63:0], data[63:0],
mask[7:0], command[1:0] and size[1:0]; only the selected valid/ready bit is active.
Read masks are derived from size/address for peripherals. Requests outside the
full physical map produce a registered error without asserting an endpoint.

`hammer_v3_cache_arbiter` has three clients, with packed client vectors
valid/ready/error[2:0], command[5:0], address/data[191:0] and mask[23:0].
Client zero occupies the low slice. It captures a round-robin grant and retains
ownership through a held response. I-cache uses CPU, maintenance, unused clients;
D-cache uses CPU, coherent walker, maintenance clients. All backing requests
use a common aligned 64-bit physical transaction.

`hammer_v3_fabric #(IMEM_WORDS,DMEM_WORDS)` arbitrates three backing clients
(I-cache, D-cache, accelerator) with packed vectors as above, write[2:0] and
protection[8:0] instead of command. It contains the unchanged legacy RAM modules
and routes external RAM to `u_mem_axi`. It enforces client permissions before
issuing a target transaction. Response ownership, including DECERR, is retained
until consumption. `hammer_v3_axi_master` additionally outputs `rsp_decerr` to
distinguish external DECERR from SLVERR for the accelerator.

These are implementation-only helper contracts, not new public interfaces or
parameters. All capture, issue, target-response and client-response stages are
registered. Accelerator exclusivity requests a drain through the core's existing
halt path, then clean-invalidate of D and invalidation of I before acknowledging
maintenance. The core automatically resumes its committed PC after exclusivity
ends unless the external halt request remains asserted. A running core must
retire or trap between admitted bursts; a stopped core needs no progress token.

`hammer_v3_csr` derives from `hammer_v2_csr`, preserving its ports and adding
output `satp[63:0]`. It implements satp WARL, SUM/MXR and page-fault delegation;
the core remains responsible for serializing context commits.

### Frozen translation helper interfaces

All helper requests/responses use held valid/ready transactions and active-low
asynchronous reset. Unless stated otherwise, inactive output payloads are zero.
No helper port is test-only or hierarchical control.

`hammer_v3_mmu #(ITLB_ENTRIES=8, DTLB_ENTRIES=8)`:

| Direction | Signals |
|---|---|
| in | clk, rst_n, satp[63:0], priv[1:0], mstatus[63:0] |
| in/out | i_req_valid / i_req_ready, d_req_valid / d_req_ready |
| in | i_req_va[63:0], i_req_bypass; d_req_va[63:0], d_req_access[1:0], d_req_bypass |
| out/in | i_rsp_valid / i_rsp_ready, d_rsp_valid / d_rsp_ready |
| out | i_rsp_pa[55:0], i_rsp_page_fault, i_rsp_access_fault; analogous d fields |
| in/out | sfence_valid / sfence_ready |
| in | sfence_va_valid, sfence_asid_valid, sfence_va[63:0], sfence_asid[15:0] |
| out/in | pt_req_valid / pt_req_ready, pt_rsp_ready / pt_rsp_valid |
| out/in | pt_req_addr[55:0] / pt_rsp_rdata[63:0], pt_rsp_error |

`req_bypass` is for cache maintenance or already-translated atomic continuations,
not a software translation-disable input. Fetch ignores MPRV; data uses MPP when
MPRV is set in M mode. The MMU captures all context at acceptance. A satp change
automatically blocks new requests, drains work and invalidates both TLBs; an
explicit fence may be combined with this conservative invalidation. The system
must serialize a satp write with older memory effects before changing the port.
MMU physical output does not certify target-map permissions: routing must still
check physical regions and original access type.

`hammer_v3_tlb #(ENTRIES=8)`:

| Direction | Signals |
|---|---|
| in | clk, rst_n, req_valid, req_va[63:0], req_asid[15:0], req_access[1:0], req_priv[1:0], req_sum, req_mxr |
| out | req_ready, rsp_valid, rsp_hit, rsp_pa[55:0], rsp_fault |
| in | rsp_ready |
| in | refill_valid, refill_va[63:0], refill_asid[15:0], refill_ppn[43:0], refill_level[1:0], refill_flags[7:0] |
| in | invalidate_valid, invalidate_va_valid, invalidate_asid_valid, invalidate_va[63:0], invalidate_asid[15:0] |

Refill flags are PTE bits 7:0, including inherited G in bit 5. Level 0/1/2
means 4 KiB/2 MiB/1 GiB. Refill is an internal one-edge pulse for a valid,
successfully checked leaf, not another ready/valid channel. Invalidation wins
over refill; reset wins over both. Invalidation clears matching entries and the
replacement pointer. The caller must drain outstanding lookup responses first.
All/all includes globals; VA/all includes globals; either ASID-qualified form
excludes globals. A VA matches the entire cached superpage span.

Lookup captures at N, compares registered inputs and registers the result after
N+1. The enclosing MMU registers that result after N+2. TLB first-invalid then
round-robin replacement is deterministic. Refill removes overlapping entries
with matching ASID or either global mapping, including old differing-size leaves,
so no ambiguous matching pair survives. Hits recheck current U/S, SUM, MXR and
A/D permissions; misses are not negatively cached.

`hammer_v3_ptw` has no parameters:

| Direction | Signals |
|---|---|
| in | clk, rst_n, req_valid, req_va[63:0], req_root_ppn[43:0], req_asid[15:0], req_access[1:0], req_priv[1:0], req_sum, req_mxr |
| out | req_ready, rsp_valid, rsp_pa[55:0], rsp_page_fault, rsp_access_fault |
| out | rsp_ppn[43:0], rsp_level[1:0], rsp_flags[7:0], rsp_va[63:0], rsp_asid[15:0] |
| in | rsp_ready |
| out/in | mem_req_valid / mem_req_ready, mem_rsp_ready / mem_rsp_valid |
| out/in | mem_req_addr[55:0] / mem_rsp_rdata[63:0], mem_rsp_error |

Memory requests are aligned physical 64-bit reads, one outstanding. The coherent
fabric must make prior CPU dirty PTE stores visible. A bus failure is an access
fault, not a page fault. PTE response capture at P is separate from classification
at P+1; the next request cannot appear before P+2. Final classification and the
held walk result are separate register stages.

`hammer_v3_page_leaf` is a combinational shared leaf checker/PA assembler.
Inputs are `va[63:0],ppn[43:0],level[1:0],flags[7:0],access_kind[1:0],
priv[1:0],sum,mxr`; outputs are `pa[55:0],fault`. It checks canonical VA,
leaf/superpage legality, V/R/W/X/U/A/D and current access permissions. It has no
storage or handshake; enclosing TLB/PTW stages register its result.

### Sv39 semantics

satp supports Bare=0 and Sv39=8, ASID 16 bits, root PPN 44 bits, reset zero.
Unsupported MODE leaves the entire CSR unchanged. U access is illegal; S TVM
denies satp and SFENCE.VMA. sstatus exposes writable SUM/MXR; medeleg includes
page-fault causes 12, 13 and 15. M-effective and Bare accesses bypass translation.

Translated VAs must sign-extend bit 38 through 63. VPN indices are [38:30],
[29:21], [20:12]; an eight-byte PTE is at `(table_ppn << 12) + (index << 3)`.
Reject V=0, R=0/W=1, reserved upper bits 63:54, nonleaf U/A/D, bottom-level
nonleaves and misaligned superpages. Propagate ancestor G.

U needs U leaves. S may not fetch U leaves; S data may use them only with SUM.
MXR permits executable-only loads, not AMO reads. AMOs need R and W. A=0 or
store/AMO D=0 faults under the Svade policy; hardware never writes a PTE.
Software must set A/D and issue SFENCE.VMA. No negative TLB entries.

The shared walker is round-robin between simultaneous I/D misses, with latched
context and one walk at a time. Fence blocks admission, drains old lookup/walk
and response state, invalidates on an edge, then acknowledges on a later edge.
No stale refill can follow completion. The core kills old speculative fetches;
wrong-path faults never commit.

Instruction/load/store-AMO page faults are 12/13/15; physical read/access errors
are 1/5/7. tval is the original VA, epc the exact instruction PC. Preserve
misalignment causes 0/4/6, delegation, precise trap/return, WFI, interrupts and
CLINT. Faulting instructions have no retirement/register/memory effect.
Traps, context changes and interfering coherent writes clear reservations.

## Peripheral helper bus and registers

PLIC and UART share this leaf bus (not a public top port):
inputs `clk,rst_n,req_valid,req_write,req_addr[63:0],req_size[1:0],
req_wdata[63:0],req_wstrb[7:0],rsp_ready`; outputs
`req_ready,rsp_valid,rsp_rdata[63:0],rsp_error`.
Addresses are full physical byte addresses; data/strobes occupy addressed
64-bit lanes. Size encodes log2 bytes. Reads also specify the intended word/byte
in req_wstrb, so malformed lanes can be diagnosed consistently. Routing must
supply that mask for CPU reads. Payloads are captured exactly once; responses
are registered and held until consumed. Errors cannot cause register side
effects. Leaf buses allow one outstanding operation.

PLIC inputs `uart_irq,plic_sources[30:0]`, outputs `irq_meip,irq_seip`.
ID0 is reserved, UART is ID1, external bits 0..30 are IDs2..32.
All sources are level sensitive and two-register synchronized. Two contexts
are M=0 and S=1. Reset priority, threshold, enable, pending and service state
to zero. Priorities/thresholds store low three bits.

| PLIC offset from 0x0c000000 | Register |
|---|---|
| 4*ID, ID 0..32 | priority; ID0 reads zero, writes ignored |
| 0x1000, 0x1004 | shared pending words; read-only |
| 0x2000+0x80*context, +4 | enable words; bit0 reserved |
| 0x200000+0x1000*context | threshold |
| 0x200004+0x1000*context | claim read, completion write |

Accesses are aligned 32-bit with selected four strobes. Unimplemented addresses,
wrong size/alignment/lane or pending writes return errors. Selection is highest
enabled priority strictly above threshold, lowest ID on ties. Claim clears
shared pending and marks the gateway with owner; one source cannot be claimed
twice. Only completion by the owner releases it. Invalid completion is ignored,
not a successful source completion. Held levels re-pend on the cycle after
completion, not on the completion edge. IRQs OR with the existing external pins.

UART inputs `uart_rx`, outputs `uart_tx,irq`. Byte access, register shift zero.
Offsets 0 RBR/THR/DLL, 1 IER/DLM, 2 IIR/FCR, 3 LCR, 4 MCR, 5 LSR, 6 MSR,
7 SCR. DLAB selects divisor aliases. RX is two-register synchronized; TX reset
and idle level is high. Reset divisor=1, IER/LCR/MCR/SCR=0, FIFO empty,
THRE/TEMT set, IIR no-pending set, bus controls zero.

Required behavior: 16-byte TX/RX FIFOs; FCR enable/clear and trigger 1/4/8/14;
5..8 data bits; odd/even/stick parity; one/two stops and 1.5 stops for 5-bit mode;
break; loopback and MCR/MSR delta semantics; divisor timing clk/(16*divisor).
Divisor zero behaves as one while reading back zero. Inactive external modem
inputs are modeled without adding pins. Interrupt priority is line status,
receive data/timeout (four character times), THRE, modem, with standard read/
clear behavior. Preserve queued RX bytes on overflow and set overrun. A full
TX FIFO backpressures acceptance rather than dropping a byte. Invalid byte
geometry/offset returns an error.

UART implementation details: FIFO-disabled capacity is one byte; toggling FCR
enable clears both queues. RX clear also clears overrun; TX clear does not abort
an already shifting character. Shift engines latch format/divisor per character.
LSR read clears overrun and the current head's error flags, not later FIFO
entries. MSR read clears delta bits, with simultaneous new transitions winning.
FCR clear wins over FIFO push/pop. LSR FIFO-error summarizes the queued entries.
THRE clears on THR write or a selected THRE IIR read, and rearms when the holding
FIFO empties or its interrupt is enabled while empty. Loopback holds the external
TX pin high and feeds the internal serializer into RX; MCR RTS/DTR/OUT1/OUT2 map
to MSR CTS/DSR/RI/DCD, with trailing-edge-only RI delta. OUT2 does not gate the
interrupt pin (PC board glue is outside the UART). Baud-timeout counting uses
oversample ticks and the current programmed character format.

## External memory and accelerator

`hammer_v3_axi_master` uses an internal single-beat bus:
inputs `clk,rst_n,req_valid,req_write,req_addr[63:0],req_wdata[63:0],
req_wstrb[7:0],req_prot[2:0],rsp_ready`; outputs
`req_ready,rsp_valid,rsp_rdata[63:0],rsp_error`.
Its outbound ports have the exact `m_mem_axi_*` names above.
One naturally aligned 64-bit INCR beat, ID=0, LEN=0, SIZE=3, BURST=1,
LOCK=0, CACHE=0xf, QOS=0, LAST=1; PROT reflects originating privilege/access.
Only external-RAM addresses are accepted. Hold AW/W independently until their
individual handshakes; never require both READYs simultaneously. Hold all
channel payloads stable under backpressure. Real R/B errors propagate.

Accelerator requests are naturally aligned FIXED/INCR bursts, 1..16 beats,
size 0..3, legal byte strobes, no 4 KiB crossing, one transaction globally.
AW and W are independent; W may be backpressured before AW capture.
Preserve IDs/count/order. Read unused byte lanes are zero. Unsupported burst,
lock, geometry/address returns SLVERR/DECERR, with no unintended memory effects;
consume malformed writes through their announced beat count rather than hang.

`hammer_v3_accel_bridge #(DMEM_WORDS=8192)` has the complete `s_acc_axi_*`
bundle, plus these internal integration ports:

| Direction | Signals |
|---|---|
| in | clk, rst_n, allow_transaction |
| out | exclusive, quiesce_valid |
| in | quiesce_ready, quiesce_error |
| out/in | mem_req_valid / mem_req_ready, mem_rsp_ready / mem_rsp_valid |
| out | mem_req_write, mem_req_addr[63:0], mem_req_wdata[63:0], mem_req_wstrb[7:0] |
| in | mem_rsp_rdata[63:0], mem_rsp_error, mem_rsp_decerr |

`allow_transaction` is supplied by the top-level fairness controller, which must
allow CPU progress between bursts under fair external responses. `exclusive`
blocks new CPU traffic and remains asserted through the final accelerator
response. `quiesce_valid` requests drain, D clean-invalidate, I invalidate and
reservation clear; its ready handshake acknowledges completed maintenance, not
just request capture. On maintenance error no backing operation is issued.
The fabric accepts aligned 64-bit backing beats, with byte strobes; read
masking/byte lanes are handled in the bridge. `mem_rsp_decerr` distinguishes a
decode error from a slave error when `mem_rsp_error` is asserted.

The bridge buffers an entire legal write burst (at most 16 beats) and validates
all strobes and LAST markers before any memory effect. Malformed longer writes
are consumed through AWLEN+1 beats without indexing beyond the buffer. A bad
write is not partially executed. Bad reads produce ARLEN+1 held error beats.
AW/AR simultaneous admission alternates; W before AW is backpressured.
`hammer_v3_axi_geometry #(DMEM_WORDS=8192)` is a combinational shared checker:
inputs `addr[63:0],len[7:0],size[2:0],burst[1:0],lock`, outputs
`geometry_error,address_error`. It checks alignment, supported burst/size/length,
65-bit last-byte overflow, the 4 KiB boundary and full physical target intervals.

Before each admitted burst, stop new CPU memory/fetch, drain activity, clean/
invalidate D, invalidate I, clear reservations and give the accelerator exclusive
fabric ownership. Complete the real memory operation/error before resuming.
CPU dirty data is visible to accelerator reads; accelerator writes are visible
to later CPU loads and external-RAM fetches without software cache maintenance.
Only legacy data RAM and external RAM are accelerator accessible. PTE changes
still need SFENCE.VMA. This is serialized hardware coherence, not ACE.

## Cycle & Degenerate-Boundary Table

All handshakes sample values immediately before a rising edge. Outputs newly
registered after an edge cannot be consumed retroactively on that edge.
All externally active valid/ready/IRQ/retire/trap controls are zero in reset
except parent halted=1 and UART TX=1. Reset aborts outstanding protocol state.
The first post-reset edge may release ready; no old response may reappear.

| Operation | Pre-edge event | Post-edge state / earliest next event |
|---|---|---|
| Fetch | request accepted at N | latch VA/context; hold busy until response; wrong-path result discarded |
| ALU | EX advances with older stages clear | MEM then WB boundaries retained; retirement at WB only |
| Load miss | data request accepted | wait through cache/MMU/fabric; no fixed total latency assumed |
| MMU hit/bypass | accepted N | capture N; lookup N+1; response no earlier than after N+2 |
| MMU miss | registered lookup miss | queue walker after N+2, arbitrate registered ownership |
| PTW PTE | memory response captured P | classify P+1; next read no earlier than P+2; final result has extra register |
| Trap | precise WB fault or legal interrupt boundary | CSR entry and younger annul; no faulting retirement |
| SFENCE | first sampled valid F blocks admission | drain; registered invalidation; acknowledge only after effective |
| satp change | value differs from latched context | same drain and full invalidation; admission resumes with new context |
| Accelerator | burst admitted | stop/drain CPU, D clean-invalidate, I invalidate, exclusive burst, resume |
| FIFO push/pop | accept and dequeue sampled together | preserve order/count; full replacement only with same-edge dequeue |
| AXI write | AWREADY and/or WREADY with respective VALID | remember each separately; B only after both |
| AXI read | AR handshake | wait R; register result; consume response on later edge |
| Singleton TLB/cache | one slot | index width at least one, replacement wraps explicitly |
| Singleton/odd RAM | 1, 3 or odd word count | compare full byte bound; skip absent partial-line beats |
| Flush/refill/reset | coincident controls | reset > invalidation > refill; no stale post-fence refill |
| PLIC completion | valid owner completes | in-service clears; held synchronized source pends next edge |
| PLIC claim/pending | pending source selected | claim wins over level set for that source |

## Timing, software and independent acceptance

Target Intel Arria 10 GX 10AX115N2F45E1SG, Quartus 17.1, one 100 MHz clock,
period <=10 ns, WNS >=0. No combinational division/modulo, inferred latches,
mixed blocking/nonblocking sequential assignments, gated/generated clocks or
combinational ready/valid loops. Iterative multiply/divide is preserved.
Synchronous payload RAM is distinct from asynchronously reset validity/control.
Generic synthesis cannot establish physical timing. Native timing lint, Quartus
STA and three consecutive deterministic PCIe Gen3x8 HIL passes remain required.

Linux integration requires RV64IMA/Sv39-compatible firmware/SBI, an appropriate
device tree for this exact map, a kernel supporting the Svade software A/D
policy, initialized external RAM and a valid supervisor entry environment.
No unprovided Linux image or SBI implementation is asserted to have booted.

Portable commands, executed from the delivered root after verification sources
are supplied by Verifier:

```
python3 tests/verify.py
python3 tests/verify.py --suite smoke-boundaries
python3 tests/verify.py --suite system
python3 tests/verify.py --suite defects
python3 tests/verify.py --suite synthesis
python3 tests/verify.py --suite portable
```

Dependencies: python3, iverilog/vvp, verilator, C++ compiler, make, yosys.
Do not install or substitute missing tools. Required numerical coverage remains
the admitted four-configuration/three-seed matrix: >=1000 independently compared
translations, >=20 S/U/S round trips and >=100 coherent exchanges in each run,
plus the complete directed ISA/Sv39/MMIO/protocol/boundary matrix and nine
semantic mutation classes. No numerical threshold is relaxed here.

Claim-to-evidence guide: retirement/traps and the independent ISA/Sv39 oracle
establish architectural behavior; serial/MMIO/AXI comparisons establish system
integration; deliberate mutants establish checker sensitivity; real structural
synthesis establishes connected hierarchy, no latches/dividers; native STA
establishes timing; native HIL establishes board behavior. Preparation syntax
checks are advisory only. Every admitted check remains mandatory, with fresh
timestamp/hash-suffixed output directories and immutable execution receipts.
