# HAMMER-V1 integration specification

## Scope and numerical behavior

Top: `hammer_v1_top`. ISA: little-endian RV64IM, fixed 32-bit instructions,
XLEN=64, modulo-2^64 integer arithmetic. All RV64I integer and RV64M instructions
and W variants are implemented. W results truncate then sign-extend bit 31.
Register shifts use six bits (five for W); immediate shift encodings are checked.
Signed divide truncates toward zero; remainder has the dividend sign.
Divide by zero returns all-one quotient and unchanged dividend remainder;
signed minimum divided by -1 returns minimum and zero. W exceptions use the
same truncation/sign-extension rule. x0 always reads zero.

FENCE is ordered; FENCE.I, CSR, compressed, atomic, floating-point, privileged
and reserved encodings are illegal. ECALL traps with cause 11, EBREAK with
cause 3; neither retires. No privileged CSR implementation is implied.

## Parameters

| Name | Default | Legal values |
|---|---:|---|
| IMEM_WORDS | 16384 | Every integer 1..16384 |
| DMEM_WORDS | 8192 | Every integer 1..8192 |
| PRED_MODE | 1 | 0,1 |
| BTB_ENTRIES | 16 | 1,4,16,64 |

Illegal values elaborate with diagnostic-safe widths and explicitly terminate
with `PARAMETER ERROR`. Non-power-of-two memory sizes do not alias.
Scratchpads are not reset-cleared: initialize every location software reads.

## Public ports

All ports are unsigned. Scalar inputs: `clk`, `rst_n`, `start`, `host_valid`,
`host_write`, `host_imem`. Host inputs: `host_addr[31:0]`,
`host_wdata[63:0]`, `host_wstrb[7:0]`; debug input `dbg_raddr[4:0]`.
Scalar outputs: `halted`, `host_ready`, `host_rsp_valid`, `host_rsp_error`;
data outputs `host_rdata[63:0]`, `dbg_rdata[63:0]`;
trap outputs `trap_valid`, `trap_pc[63:0]`, `trap_cause[63:0]`.

Retirement outputs: `retire_valid`, `retire_pc[63:0]`,
`retire_next_pc[63:0]`, `retire_insn[31:0]`, `retire_rd_we`,
`retire_rd[4:0]`, `retire_rd_data[63:0]`, `retire_mem_valid`,
`retire_mem_write`, `retire_mem_addr[63:0]`, `retire_mem_wmask[7:0]`,
`retire_mem_wdata[63:0]`, `retire_mem_rdata[63:0]`.

Pre-edge cycle observations: `stall_load_use`, `stall_mem`, `stall_muldiv`,
`redirect_valid`, `redirect_pc[63:0]`, `ex_valid`, `ex_pc[63:0]`,
`ex_rs1_sel[1:0]`, `ex_rs2_sel[1:0]`, `ex_store_sel[1:0]`.
Selectors: 00 register, 10 EX/MEM, 01 MEM/WB; 11 never occurs.

AXI4-Lite master outputs: `m_axi_awaddr[31:0]`, `m_axi_awprot[2:0]`,
`m_axi_awvalid`, `m_axi_wdata[63:0]`, `m_axi_wstrb[7:0]`,
`m_axi_wvalid`, `m_axi_bready`, `m_axi_araddr[31:0]`,
`m_axi_arprot[2:0]`, `m_axi_arvalid`, `m_axi_rready`.
Inputs: `m_axi_awready`, `m_axi_wready`, `m_axi_bresp[1:0]`,
`m_axi_bvalid`, `m_axi_arready`, `m_axi_rdata[63:0]`,
`m_axi_rresp[1:0]`, `m_axi_rvalid`.
AxPROT is zero. One MMIO operation is outstanding. AW and W are independent;
payloads hold until handshake. Any non-OKAY response faults the instruction.

## Address map and errors

| Region | CPU byte addresses | Use |
|---|---|---|
| Instruction SRAM | 0 .. 4*IMEM_WORDS-1 | Fetch only |
| Data SRAM | 0x10000000 .. 0x10000000+8*DMEM_WORDS-1 | Data and constants |
| MMIO | 0x40000000 .. 0x4000ffff | AXI4-Lite data |

PC/effective address arithmetic wraps at 64 bits. All range checks use the
full address. Instruction addresses require four-byte alignment. JALR first
clears bit zero. Misaligned taken targets fault the originating instruction;
unused untaken targets do not fault. Data alignment is natural for each
access width; no split access is supported. CPU data accesses to imem fault.

Causes: instruction misalignment 0, instruction access 1, illegal instruction
2, breakpoint 3, load misalignment 4, load access 5, store misalignment 6,
store access 7, machine ECALL 11. Faults become visible after older retirement;
faulting and younger instructions never retire or perform younger memory effects.
`trap_pc` identifies the faulting instruction. Trap and halted persist to reset.

## Reset, host loading and execution

Assert asynchronous active-low reset. During reset halted is one and all other
public outputs are zero. Release reset before host loading. `host_ready` is
available only while halted and without an outstanding request/response.
An accepted host request at H produces one response after H+1, no backpressure.
Host addresses are byte offsets within the selected scratchpad, not CPU addresses.
Imem requests require four-byte alignment, upper wdata/strobe bits zero, and
use four byte lanes. Dmem requests require eight-byte alignment and eight lanes.
Writes honor strobes; reads ignore strobes. Bad requests return error without
writing memory. Host and CPU never own SRAM concurrently.

Pulse start while halted, no trap, no outstanding host operation and
`host_valid=0`. Host requests take priority. Execution begins at PC zero;
start does not clear registers or loaded memories. A terminal trap requires
reset before restart. Debug reads are combinational architectural register
reads and never expose speculative results. Reset also aborts AXI ownership;
reset the attached slave consistently.

## Prediction and pipeline timing

See `ARCHITECTURE.md` for exact internal ports, transfer equations and edge table.
Five stages: IF, ID, EX, MEM, WB. Synchronous imem reads enter ID at fetch edge.
Unstalled ALU: E0 fetch/ID, E1 EX, E2 MEM, E3 WB, E4 retirement.
Load requested at E3 supplies registered WB data after E3 and retires E4.
An isolated directly dependent consumer is delayed exactly one edge.
Forwarding favors youngest ready older producer, independently for arithmetic,
branch, JALR and store operands, with an explicit retirement-to-ID bypass.

Mode 0 predicts conditional backward taken/forward not taken and direct JAL;
JALR predicts fall-through. Mode 1 is full-PC-tagged direct-mapped BTB with
two-bit conditional counters initially weakly not taken. Miss is fall-through;
taken branches and resolved jumps allocate. Conditional counters update once
per EX completion. A wrong target redirects even with correct direction.
Resolution kills younger ID work and suppresses fetch on that edge; the next
eligible edge fetches the corrected target.

M accepts at S, iterates S+1 through S+64, registers done/result S+65 and can
transfer S+66. Exceptional and W operations have identical latency. MEM/WB
may drain while EX holds. Retained results survive memory backpressure.

## Trace, reproduction and acceptance

Retirement pulses describe one committed instruction after its edge, including
architectural next PC. Actual register writes exclude x0. Nonapplicable fields
are zero. Memory fields contain effective address, aligned store mask/data,
or final extended load data. Architectural x1..x31 can be read without clocks.
Cycle observations are pre-edge decisions, not an expected-value oracle.

Run from the delivered root, with Python 3, Icarus/vvp, Verilator/C++/make,
Yosys and an RV64IM compiler available:

```
python3 tests/verify.py --suite smoke
python3 tests/verify.py --suite directed
python3 tests/verify.py --suite random --seed 17 --min-retirements 10000
python3 tests/verify.py --suite random --seed 89 --min-retirements 10000
python3 tests/verify.py --suite random --seed 2027 --min-retirements 10000
python3 tests/verify.py --suite benchmarks
python3 tests/verify.py --suite mutations
python3 tests/verify.py --suite synthesis
python3 tests/verify.py --suite portable
```

Verification sources and runner are independently authored under `tests/*`;
these commands define the admitted interface, not results from Designer.
All suites are mandatory: each normally retiring mnemonic >=32 retirements;
each conditional branch >=16 taken and >=16 untaken; ECALL and EBREAK each
>=32 distinct checked terminal episodes with reset between them, checking
cause, PC, older retirement, no faulting retirement and no younger effects.
The following acceptance matrix is mandatory in addition to those counts.

| Area | Required comparisons and coverage |
|---|---|
| Architectural oracle | Independent integer-only Python RV64IM ISS; every committed PC, next PC, instruction, x1..x31 and memory effect; independently compare actual SRAM writes and AXI handshakes to retired operations. Read all debug registers between edges without advancing the clock. Reject active X/Z. |
| Integer operands | Every load/store size, load signedness, legal byte lane, shift boundary, immediate sign boundary, x0 destination, source/destination overlap and dependent-use position. |
| M operands | For each M mnemonic, complete Cartesian product of bit patterns 0,1,2,all-ones,signed-minimum,signed-maximum,0x80000000,0xffffffff, with explicit W interpretations, plus seeded random values. Check every divide-zero/overflow result. |
| Random programs | Seeds 17,89,2027, each >=10000 retired randomized instructions checked by ISS and independent cycle model. Initialized memories, bounded valid control flow, no discarding inconvenient instructions. |
| Prediction | Directed execution for both modes and BTB sizes 1,4,16,64, observing correct/mispredicted direction, wrong-target correction and replacement/collision where applicable. Static tests explicitly observe backward-taken and forward-not-taken. |
| Memory configurations | Execute (IMEM_WORDS,DMEM_WORDS)=(1,1),(3,3),(769,257),(16384,8192). Singleton may terminate after its sole legal instruction, but host boundary behavior is separately exercised. |
| Elaboration | Cartesian product IMEM_WORDS={1,3,16384}, DMEM_WORDS={1,3,8192}, both modes and all four BTB sizes. |
| Parameter rejection | Independently reject IMEM_WORDS=0/16385, DMEM_WORDS=0/8193, PRED_MODE=-1/2, BTB_ENTRIES=0/2 with explicit diagnostic, retaining expected-negative failed subprocess results. |
| AXI schedules | Ready-always; independently delayed AW and W in both orders; delayed B, AR and R; delays 1,2,17 and seeded stalls; payload stability; every non-OKAY read/write response. Compare exact accepted counts, addresses, lane masks and data. |
| Traps | Every documented cause, last legal word, first illegal word, high-address alias attempts, misaligned taken and untaken control targets. Check precise older retirement and no younger effects. ECALL/EBREAK thresholds are separate from all retiring coverage. |
| C benchmarks | Fresh freestanding RV64IM compilation and execution of integer accumulation, overlapping-safe memory/data movement, signed/unsigned division, integer matrix multiplication, CRC32 and SHA-256. Use -march=rv64im -mabi=lp64, project startup/linker inputs, no compressed code or host libc. Read real ELF load segments, compare all retirements to ISS and exact result buffers to independent algorithms (zlib/hashlib for CRC/SHA). Discover a real RISC-V GCC or clang with explicit RISC-V target; missing compiler fails. No prebuilt substitute. |
| Defect sensitivity | At least six disposable mutants: ADD corruption, LW sign corruption, reversed forwarding priority, disabled load-use interlock, disabled wrong-path kill, wrong divide-zero result. Each must elaborate then fail a relevant executed architectural/cycle comparison. Compile error, timeout, log keyword or unrelated exception does not count. Never mutate accepted RTL in place. |
| Synthesis | Real Yosys hierarchy, process lowering, memory-preserving synthesis and consistency on default, singleton and non-power-of-two configurations. Zero latches, unresolved black boxes and divide/modulo cells; substantive pipeline/register/M state, real retained SRAM, literal hierarchy/connectivity before flattening, no stubs. Preserve raw logs and outputs; do not lower large SRAMs to flip-flop arrays to simplify checking. |
| Portability | Fresh temporary tree copied only from declared RTL/design/tests sources; compact RTL smoke, freshly compiled SHA-256 workload and representative Yosys synthesis, independent of original outputs and runtime directories. This does not replace full suites. |

The cycle checker independently predicts stage occupancy and transfer legality
from fetched instructions, synchronous memory latency, bus handshakes and fixed
M latency; DUT stall/forwarding outputs are observations, not the oracle.
Required observed cases are simultaneous same-rd EX/MEM versus MEM/WB priority,
rs1/rs2/store bypass, WB-to-ID bypass, exactly one isolated load-use edge,
no false interlock for unused fields/x0, dependent branch/JALR, consecutive
loads, dependent M, branch flush of wrong-path register/store/MMIO/fault,
redirect with held fetch, M completion under MEM stall, reset with outstanding
requests, and no duplicate commits/writes. Any additional synchronous-fetch
bubbles must be explicit, bounded and checked, not hidden by retirement-only
comparison.

Use real Icarus/vvp only for compact smoke/startup/memory/hazard/M tests,
at most 500000 cycles per process and designed below 60 seconds per process.
Use compiled Verilator for behavioral matrices, C workloads, random seeds and
mutations. Never flush traces per cycle/request. Functional cycle ceilings
must diagnose stalls; wall-clock performance is not numerical acceptance.
Each check must fit the shared runtime's 2700-second patrol budget; any necessary
split is independently admitted and append-only. Every admitted original check
remains mandatory. Missing prerequisites fail specifically; no skips, mocks or
success-shaped fallback paths.

The shared runtime separately owns timing lint, Quartus 17.1 setup/hold at
<=10 ns, and three deterministic physical-board workload passes. No board
identifier or credential is a source dependency. Tool versions, source hashes,
unique output paths and raw results must accompany actual executions.
Missing tools/hardware are blockers, not passing results. The runtime prepares
and independently reviews the required final PDF only after engineering
acceptance; it is not an input to design verification.
