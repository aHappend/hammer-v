# HAMMER-V: Pipelined & Privileged RISC-V Processor Family (`V1` / `V2` / `V3`)

[English](README.md) | [简体中文](README.zh-CN.md)

## 1. Architecture & Post-Place-and-Route PPA Summary (Intel Arria 10 GX `10AX115N2F45E1SG`)

All three cores in the `HAMMER-V` family are synthesized, placed, and routed using **Quartus Prime 17.1 Standard (`quartus_map` + `quartus_fit` + `quartus_sta`)** against a **100.0 MHz (`10.0 ns`)** clock constraint across Slow 900mV 100C / 0C and Fast 900mV 0C timing corners.

| Core | Architecture & ISA | RTL Scale | Logic Utilization (ALMs) | Dedicated Registers | Block Memory (M20K / Bits) | DSP Blocks | 100 MHz Setup Slack (WNS) | Post-Fit Fmax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **HAMMER-V1** | 5-Stage Pipelined `RV32I` + Forwarding + Hazard Unit | 17 files / 3,332 lines | **6,722 / 427,200 (2%)** | **6,458** | **128 M20K** (`2,097,152 bits`) | 0 | `+2.337 ns` | **130.50 MHz** |
| **HAMMER-V2** | 5-Stage Pipelined `RV64IMAC` + M/S/U Privileged CSR + CLINT | 29 files / 5,978 lines | **13,722 / 427,200 (3%)** | **17,765** | **74 M20K** (`1,081,344 bits`) | 0 | `+1.464 ns` | **117.15 MHz** |
| **HAMMER-V3** | `RV64IMA` + Hardware `Sv39` PTW/TLB + M/S/U + CLINT/PLIC + 16550A UART + AXI4 | 40 files / 7,369 lines | **17,986 / 427,200 (4%)** | **22,931** | **78 M20K** (`1,082,752 bits`) | 0 | `+3.191 ns` | **146.86 MHz** |

---

## 2. Explicit Verification Tier & Signoff Scope Matrix

To maintain strict **Claim-to-Evidence Alignment**, we explicitly separate RTL delivery, cycle-accurate functional/mutation regression, post-fit FPGA STA closure, physical board HIL probing, and OS image boot:

| Verification Tier | Scope & Methodology | HAMMER-V1 | HAMMER-V2 | HAMMER-V3 | Public Evidence Artifacts |
| --- | --- | --- | --- | --- | --- |
| **L1: Cycle-Accurate Functional, Privileged/MMU Oracle & Mutation Regression** | End-to-end ISA directed + randomized regressions, forwarding/hazard torture, M/S/U trap/CSR delegation (`V2/V3`), Sv39 3-level page-table walks / TLB shootdown / LR-SC-AMO atomics / I$-D$ coherence (`V3`), and RTL defect-injection mutation gates | **Passed** (`l1-core-verification`: 24 receipts, 100% mutation detection) | **Passed** (`l1-functional-and-privileged`: 40 receipts; `l1-mutation`: 9/9 mutations killed) | **Passed** (`l1-system-oracle`: 40 receipts, 900.6s; `l1-defect-sensitivity`: 8/8 mutations killed) | `chips/hammer_v{1,2,3}/evidence/verification-receipts.json` |
| **L1.5 & L2: RTL Timing Lint & 100 MHz Post-Fit Quartus STA** | Structural logic depth check + full `quartus_map` / `quartus_fit` / `quartus_sta` on Arria 10 GX `10AX115N2F45E1SG` (`VIRTUAL_PIN ON` standalone IP characterization) | **Passed** (`130.50 MHz`, `6,722 ALMs`, `128 M20K`) | **Passed** (`117.15 MHz`, `13,722 ALMs`, `74 M20K`) | **Passed** (`146.86 MHz`, `17,986 ALMs`, `78 M20K`) | `chips/hammer_v{1,2,3}/evidence/quartus-sta.json`, `ppa-resource-summary.json`, `top.fit.summary` |
| **L3: Physical FPGA Board HIL (`netsys17` Catapult Arria 10)** | Distinction between PCIe BAR0 hardware bridge connectivity probe (`L3_BRIDGE_CONNECTIVITY_PROBE_ONLY`, `reg 57`) and full per-chip Bedrock `.rpd` bitstream flash + on-board workload vector execution (`L3_BITSTREAM_AND_FUNCTIONAL_EXECUTION`) | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY` (Bridge health verified; Bedrock CPU role wrapper pending) | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY` (Bridge health verified; Bedrock CPU role wrapper pending) | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY` (Bridge health verified; Bedrock CPU role wrapper pending) | `chips/hammer_v{1,2,3}/evidence/board-hil.json` |
| **L4: System Software & Linux Kernel Boot** | Execution of compiled firmware (`OpenSBI`), Device Tree (`.dtb`), and `Linux` kernel image to console login | N/A (`RV32I` unprivileged core) | Bare-metal M/S/U firmware verified (`No MMU`) | **Hardware Architecture Verified** (Sv39 PTW + I/D-TLB + M/S/U + CLINT/PLIC/16550A UART verified via bare-metal privileged & virtual-memory oracles; **OpenSBI + Linux kernel image boot in progress**) | `chips/hammer_v3/design/SPEC.md`, `chips/hammer_v3/tests/run_system_oracle.py` |

