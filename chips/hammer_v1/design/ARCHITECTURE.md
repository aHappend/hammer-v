# HAMMER-V1 architecture

## Frozen implementation boundary

`hammer_v1_top` implements RV64IM with five in-order logical stages and
Harvard synchronous scratchpads. The public contract is in `SPEC.md`.
No cache, privileged CSR, interrupt, compressed instruction, or virtual memory
behavior is implied. The target is Arria 10 GX 10AX115N2F45E1SG, period 10 ns.
This is a target, not a timing result. Independent functional verification,
native timing analysis and physical hardware acceptance remain required.

## Internal interfaces (fixed before RTL implementation)

All interfaces use the sole `clk`, active-low asynchronous `rst_n`, unsigned
vectors, and pre-edge transfer sampling. Memory arrays themselves have
clock-only processes, no reset initialization, and registered reads.

| Producer / consumer | Signals and widths | Transfer / ownership |
|---|---|---|
| top / core | `start`, `halted`, `trap_valid`, `trap_pc[63:0]`, `trap_cause[63:0]` | Start is qualified by top loader ownership. Terminal trap persists until reset. |
| core / imem | `i_req`, `i_addr[63:0]`, `i_data[31:0]`, `i_error` | Request at an edge replaces the held registered instruction response. Core ID metadata is captured at that same edge. No request means response storage holds. |
| core / dmem | `d_req`, `d_write`, `d_addr[63:0]`, `d_wdata[63:0]`, `d_wstrb[7:0]`, `d_rdata[63:0]` | Request at MEM transfer edge, registered read becomes WB data after edge. Top validates ranges before exposing the request. |
| core / AXI adapter | `a_valid`, `a_ready`, `a_write`, `a_addr[31:0]`, `a_wdata[63:0]`, `a_wstrb[7:0]`, `a_rsp_valid`, `a_rsp_ready`, `a_rdata[63:0]`, `a_error` | One accepted request owns adapter until response consumption; AW and W have separate pending state. |
| top / each scratchpad | `h_req`, `h_write`, `h_addr[31:0]`, `h_wdata[63:0]`, `h_wstrb[7:0]`, `h_rdata[63:0]` | Host and running CPU are mutually exclusive. Registered host data sampled by top on the next edge. |
| core / regfile | `rs1[4:0]`, `rs2[4:0]`, `rdata1[63:0]`, `rdata2[63:0]`, `we`, `rd[4:0]`, `wdata[63:0]`, debug address/data | Asynchronous reads, explicit same-edge retirement-to-ID bypass; only retirement writes state. x0 is zero. |
| core / decode | `insn[31:0]`, `illegal`, `use_rs1`, `use_rs2`, `rd_we`, `rs1[4:0]`, `rs2[4:0]`, `rd[4:0]`, `imm[63:0]`, `alu_op[3:0]`, `a_pc`, `b_imm`, `word_op`, `load`, `store`, `size[2:0]`, `branch`, `jump`, `jalr`, `branch_op[2:0]`, `muldiv`, `m_op[2:0]`, `system_cause[3:0]`, `system_trap` | Combinational exhaustive encoding validation. ID captures controls with operands. |
| core / ALU | `a[63:0]`, `b[63:0]`, `op[3:0]`, `word_op`, `result[63:0]` | Combinational 64-bit integer datapath; word results sign-extend. |
| core / hazard | source indices/usage, EX load producer, MEM/WB producer indices/readiness; `interlock`, operand selectors `[1:0]` | 00 register, 10 EX/MEM, 01 MEM/WB; EX/MEM ready non-load wins. Interlock uses decoded sources only. |
| core / predictor | `pc[63:0]`, `insn[31:0]`, `next_pc[63:0]`, `update`, `update_pc[63:0]`, `update_target[63:0]`, `update_taken`, `update_conditional` | ID lookup drives next synchronous IF address. Update only on accepted nonfaulting EX control transfer. Full-PC tags. |
| core / muldiv | `start`, `op[2:0]`, `word_op`, `a[63:0]`, `b[63:0]`, `busy`, `done`, `result[63:0]`, `consume` | Start at S, 64 iterations, finalize S+65, transfer no earlier than S+66. Done/result hold until consumed. |

Top instances are `u_core`, `u_imem`, `u_dmem`, `u_axi`. Core instances are
`u_regfile`, `u_decode`, `u_alu`, `u_hazard`, `u_predictor`, `u_muldiv`.
These names and module boundaries are part of the integration contract.

## Cycle & degenerate-boundary table

| Boundary | Pre-edge condition | Post-edge state |
|---|---|---|
| Reset asserted | No transfer permitted | halted=1, all other public outputs=0; registers/valids clear; memories unchanged |
| First released edge | Loader ready if idle; start requires no host request | Accepted host request owns one response slot; accepted start sets running, PC=0 |
| E0 IF | Fetch accepted, no older redirect/fault | Registered SRAM word plus PC/error metadata form ID |
| E1 ID | ID valid, EX accepts, no decoded dependency interlock | ID enters EX; predicted next fetch enters ID |
| E2 EX | EX complete, MEM can accept | EX result enters MEM |
| E3 MEM | Ordinary instruction, or synchronous scratchpad request | Instruction enters WB; SRAM read response supplies WB load data |
| E4 WB | WB valid, nonfaulting | Architectural register write and one-cycle retirement pulse |
| Isolated load-use | ID source depends on EX load at E2 | ID held for E2 only; consumer enters EX at E3 and uses MEM/WB at E4 |
| Redirect | Resolving EX next PC differs from its prediction | Younger ID killed; no fetch accepted at this edge; corrected fetch at next eligible edge |
| MEM bus wait | MMIO response absent | MEM and younger work hold; older WB drains |
| M engine S | Start accepted | Magnitudes and signs captured |
| M S+1..S+64 | Engine iterating | One radix-2 arithmetic iteration per edge |
| M S+65 | Iteration count exhausted | Signed/word-adjusted result and done registered |
| M S+66 | Done and MEM ready | EX transfers, result consumed |
| IMEM/DMEM depth=1 | Only index zero is legal | No zero-width declarations or wrap aliases |
| Non-power-of-two depth | Full-width address range checked before indexing | Last legal entry works, first illegal entry faults |
| Host H | Valid and ready | Registered RAM operation, outstanding request set |
| Host H+1 | Request outstanding | Single response pulse; no second acceptance |
| Host plus start | Valid host request | Host wins, start ignored |
| Illegal parameters | Diagnostic-safe minimum storage/index widths | Explicit `PARAMETER ERROR` fatal before operation |

Fetch is a synchronous SRAM-to-ID path, not an asynchronous array lookup. The
held ID instruction permits static immediate prediction and tagged dynamic
lookup before the next fetch edge. This introduces no extra correctly predicted
throughput bubble. A redirect deliberately suppresses that edge's fetch and
uses the saved corrected PC at the next eligible edge. The ID response storage
does not change while ID is backpressured.

## Transfer equations and precedence

`wb_retire = wb_valid && !wb_fault`; a fault in WB is terminal and kills all
younger stages. WB drains each edge. `mem_advance` requires valid MEM and,
for MMIO, an available completed response (or an already known fault).
`mem_ready = !mem_valid || mem_advance`. EX advances only when complete and
MEM ready. `ex_ready = !ex_valid || ex_advance`.
`id_advance = id_valid && ex_ready && !load_use`.
Fetch accepts only when running, ID has room, and no redirect, terminal
fault or older known fault is pending.

Priority is reset, WB terminal fault, known older fault suppression, older
memory backpressure, EX completion/redirect, data interlock, normal advance.
Faults travel with instruction metadata to WB. A MEM fault prevents younger
EX transfer and all younger memory requests; a new EX fault kills younger ID.
No faulting instruction retires. MEM requests are gated against older WB
faults. Architectural state changes only on retirement.

Forwarding is independently selected for rs1, rs2 and store data. A ready
non-load MEM result has priority over WB. WB selects either its saved result
or the synchronous data-memory response. A held EX instruction snapshots its
forwarded operands, so an older retiring producer cannot disappear during
backpressure or multicycle arithmetic. WB-to-ID bypass handles a producer
retiring on the consumer's ID-transfer edge.

## Arithmetic structure

The multiplier uses the combined 128-bit shift/add algorithm with a 65-bit
upper-half sum. The divider uses a 65-bit restoring remainder/subtract and
64-bit quotient. Both normalize signed operands, iterate 64 times, then
adjust signs. Word operands are explicitly extended before normalization.
Zero-divisor and overflow cases retain identical latency. There are no
combinational multiply, division or modulo operators in the M datapath.
All sequential state uses nonblocking assignments. Native STA, not this
description or generic synthesis, determines whether the target closes.

## Memory and ordering

Scratchpads use byte strobes and registered reads with held data. Dmem requests
occur exactly on MEM-to-WB transfer. Address classification and alignment are
resolved before requests; full 64-bit comparisons prevent high-address aliasing.
MMIO uses aligned eight-byte addresses and lane-shifted stores. The adapter
retains request payload, independently retires AW/W, and completes only on B/R.
FENCE drains naturally through the in-order single-outstanding pipeline.
External reset aborts bus ownership; the integration must also reset the slave.

## Evidence boundary

The independent Verifier owns `tests/*` and the executable suite commands.
Required suites are smoke, directed, random (17/89/2027), benchmarks, mutations,
synthesis and portable. Native timing lint, Quartus setup/hold and physical
bridge workload passes are separately mandatory. ECALL and EBREAK coverage
counts distinct terminal episodes, never retirements or held trap cycles.
No simulation, synthesis, timing, hardware or product-report result is claimed
by this architecture document.
