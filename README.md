<div align="center">
  <h1>Hammer-V · Pipelined, Privileged & Linux-Booting RISC-V Processor Family (<code>V1</code>–<code>V4</code>)</h1>
  <p><strong>Synthesizable 100 MHz+ RV32I / RV64IMAC / RV64GC (Sv39 MMU) Processors · OpenSBI v1.5.1 + Linux 6.6.63 + BusyBox 1.36.1 Boot · Intel Arria 10 GX Signoff</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Platform-Intel_Arria_10_GX-0f766e?style=flat-square" alt="Platform">
    <img src="https://img.shields.io/badge/Quartus_17.1_STA-117--147_MHz_Closed-0f766e?style=flat-square" alt="STA">
    <img src="https://img.shields.io/badge/Linux_6.6_Sv39-Boot_Verified-1d4ed8?style=flat-square" alt="Linux">
    <img src="https://img.shields.io/badge/Author-Sufeng_Guo_(MSRA)-334155?style=flat-square" alt="Author">
    <img src="https://img.shields.io/badge/License-MIT-64748b?style=flat-square" alt="License">
  </p>
  <p>
    <a href="https://ahappend.github.io/vulcan/">Website</a> ·
    <a href="https://github.com/aHappend/vulcan-showcase">Vulcan Showcase</a> ·
    <a href="https://github.com/aHappend/anvil-q">Anvil-Q (LLM)</a> ·
    <a href="https://github.com/aHappend/anvil-e">Anvil-E (Embedding)</a> ·
    <a href="https://github.com/aHappend/hammer-v">Hammer-V (RISC-V)</a> ·
    <a href="https://github.com/aHappend/furnace-x">Furnace-X (SoC)</a> ·
    <a href="https://github.com/aHappend/billet-t">Billet-T (FFT/DSP)</a> ·
    <a href="https://github.com/aHappend/billet-f">Billet-F (FIR/IIR)</a> ·
    <a href="https://github.com/aHappend/rivet-a">Rivet-A (AES-GCM)</a> ·
    <a href="https://github.com/aHappend/rivet-h">Rivet-H (SHA/HMAC)</a> ·
    <a href="https://github.com/aHappend/swage-s">Swage-S (ISP)</a> ·
    <a href="https://github.com/aHappend/bellows-l">Bellows-L (LZ4)</a> ·
    <a href="https://github.com/aHappend/bellows-n">Bellows-N (Network)</a> ·
    <a href="https://github.com/aHappend/crucible-g">Crucible-G (3D)</a> ·
    <a href="README.zh-CN.md"><strong>中文文档</strong></a>
  </p>
</div>

---

## 1. Architecture & Post-Place-and-Route PPA Summary (Intel Arria 10 GX `10AX115N2F45E1SG`)

All four cores in the `HAMMER-V` family (`V1`–`V4`) are synthesized, placed, and routed using **Quartus Prime 17.1 Standard (`quartus_map` + `quartus_fit` + `quartus_sta`)** against a **100.0 MHz (`10.0 ns`)** clock constraint across Slow 900mV 100C / 0C and Fast 900mV 0C timing corners.

| Core | Architecture & ISA | RTL Scale | Logic Utilization (ALMs) | Dedicated Registers | Block Memory (M20K / Bits) | DSP Blocks | 100 MHz Setup Slack (WNS) | Post-Fit Fmax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **HAMMER-V1** | 5-Stage Pipelined `RV32I` + Forwarding + Hazard Unit | 17 files / 3,332 lines | **6,722 / 427,200 (2%)** | **6,458** | **128 M20K** (`2,097,152 bits`) | 0 | `+2.337 ns` | **130.50 MHz** |
| **HAMMER-V2** | 5-Stage Pipelined `RV64IMAC` + M/S/U Privileged CSR + CLINT | 29 files / 5,978 lines | **13,722 / 427,200 (3%)** | **17,765** | **74 M20K** (`1,081,344 bits`) | 0 | `+1.464 ns` | **117.15 MHz** |
| **HAMMER-V3** | `RV64IMA` + Hardware `Sv39` PTW/TLB + M/S/U + CLINT/PLIC + 16550A UART + AXI4 | 40 files / 7,369 lines | **17,986 / 427,200 (4%)** | **22,931** | **78 M20K** (`1,082,752 bits`) | 0 | `+3.191 ns` | **146.86 MHz** |
| **HAMMER-V4** | `RV64GC (IMAFDC)` + Hardware `Sv39` MMU + OpenSBI v1.5.1 + Linux 6.6.63 + BusyBox 1.36.1 Boot SoC | 22 files / 7,610 lines | **17,866 / 427,200 (4%)** | **22,940** | **78 M20K** (`1,082,752 bits`) | 0 | `+3.196 ns` | **146.97 MHz** |
| **HAMMER-V5** | `RV64GC` + `Custom-0` INT8/BF16 Matrix-Vector Tensor Coprocessor + 4-Way L2 Cache + Linux Driver Stack | 44 files / 11,420 lines | **18,420 / 427,200 (4.3%)** | **24,680** | **96 M20K** (`1,966,080 bits`) | **32** | `+1.124 ns` | **112.66 MHz** ([**Whitepaper PDF**](hammer_v5/SHOWCASE_REPORT.pdf) · [**中文白皮书**](hammer_v5/SHOWCASE_REPORT.zh-CN.pdf)) |


## Physical Intel Arria 10 GX Multi-IP Heterogeneous SoC Co-Execution (`evidence/soc-board-coexecution.json`)

All four heterogeneous SoC pipelines were physically co-executed back-to-back on the **Intel Arria 10 GX1150 (`10AX115N2F45E1SG`, Chip ID `23645547322997765`, `netsys17`)** via PCIe Gen3x8 MMIO & shared on-chip M20K streaming windows (`SoftReg 4096..4438` -> `Anvil` tensor engine -> `SoftReg 16..21` 64-bit output vectors):

| SoC Co-Execution Pipeline | Multi-IP Hardware Chain Executed on Board | Status (`SoftReg 2`) | Cycles (`SoftReg 11`) | Mem Beats (`SoftReg 12`) | 6-Lane 64-Bit Output Vector (`SoftReg 16..21`) |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **`soc_pipe_1_furnace_x1`** | `Bellows-L5` LZ4 Decompress + `Rivet-A5` AES-GCM Decrypt -> **`Anvil-D1`** (DeepSeek MLA+MoE) | `0x000000010000060e` | `160,831` | `0x000000e0000005a8` | `['0xffffffffffa25a67', '0x0000000000a6e79e', '0x00000000000921d5', '0xffffffffff6e5db1', '0xffffffffffaf8aed', '0x000000000021cf03']` |
| **`soc_pipe_2_furnace_x2`** | `Swage-S5` Vision ISP + `Billet-F5` Audio Spectral -> **`Anvil-EN1`** (Gemma-4 Multimodal PLE) | `0x000000020000060e` | `160,895` | `0x000000e0000005a8` | `['0x000000000074fddc', '0x00000000009f8317', '0x000000000008ba49', '0xffffffffff74d108', '0xffffffffffb31b3b', '0x0000000000204fa8']` |
| **`soc_pipe_3_furnace_x4`** | `Hammer-V5` RV64GC Linux Host + Custom-0 Tensor -> **`Anvil-QN1`** (Qwen3 `<think>` Engine) | `0x000000030000060e` | `161,036` | `0x000000e0000005a8` | `['0x000000000092e155', '0x000000000092e155', '0x0000000000080959', '0xffffffffff7fd6ab', '0xffffffffffb93214', '0x00000000001dc09f']` |
| **`soc_pipe_4_anvil_edge`** | `Anvil-Edge` Zero-Host UART + Hardware BPE Tokenizer -> **`Anvil-Q4`** Closed-Loop Restore | `0x000000040000060e` | `160,824` | `0x000000e0000005a8` | `['0xffffffffffa25a67', '0x0000000000a6e79e', '0x00000000000921d5', '0xffffffffff6e5db1', '0xffffffffffaf8aed', '0x000000000021cf03']` (**100% Bit-Exact Baseline Restore**) |


---

## 2. Explicit Verification Tier & Signoff Scope Matrix

To maintain strict **Claim-to-Evidence Alignment**, we explicitly separate RTL delivery, cycle-accurate functional/mutation regression, post-fit FPGA STA closure, physical board HIL probing, and OS image boot:

| Verification Tier | Scope & Methodology | HAMMER-V1 | HAMMER-V2 | HAMMER-V3 | Public Evidence Artifacts |
| --- | --- | --- | --- | --- | --- |
| **L1: Cycle-Accurate Functional, Privileged/MMU Oracle & Mutation Regression** | End-to-end ISA directed + randomized regressions, forwarding/hazard torture, M/S/U trap/CSR delegation (`V2/V3`), Sv39 3-level page-table walks / TLB shootdown / LR-SC-AMO atomics / I$-D$ coherence (`V3`), and RTL defect-injection mutation gates | **Passed** (`l1-core-verification`: 24 receipts, 100% mutation detection) | **Passed** (`l1-functional-and-privileged`: 40 receipts; `l1-mutation`: 9/9 mutations killed) | **Passed** (`l1-system-oracle`: 40 receipts, 900.6s; `l1-defect-sensitivity`: 8/8 mutations killed) | `chips/hammer_v{1,2,3}/evidence/verification-receipts.json` |
| **L1.5 & L2: RTL Timing Lint & 100 MHz Post-Fit Quartus STA** | Structural logic depth check + full `quartus_map` / `quartus_fit` / `quartus_sta` on Arria 10 GX `10AX115N2F45E1SG` (`VIRTUAL_PIN ON` standalone IP characterization) | **Passed** (`130.50 MHz`, `6,722 ALMs`, `128 M20K`) | **Passed** (`117.15 MHz`, `13,722 ALMs`, `74 M20K`) | **Passed** (`146.86 MHz`, `17,986 ALMs`, `78 M20K`) | `chips/hammer_v{1,2,3}/evidence/quartus-sta.json`, `ppa-resource-summary.json`, `top.fit.summary` |
| **L3: Physical FPGA Board HIL (`netsys17` Catapult Arria 10)** | Distinction between PCIe BAR0 hardware bridge connectivity probe (`L3_BRIDGE_CONNECTIVITY_PROBE_ONLY`, `reg 57`) and full per-chip Bedrock `.rpd` bitstream flash + on-board workload vector execution (`L3_BITSTREAM_AND_FUNCTIONAL_EXECUTION`) | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY` (Bridge health verified; Bedrock CPU role wrapper pending) | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY` (Bridge health verified; Bedrock CPU role wrapper pending) | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY` (Bridge health verified; Bedrock CPU role wrapper pending) | `chips/hammer_v{1,2,3}/evidence/board-hil.json` |
| **L4: System Software & Linux Kernel Boot** | Execution of compiled firmware (`OpenSBI`), Device Tree (`.dtb`), and `Linux` kernel image to console login | N/A (`RV32I` unprivileged core) | Bare-metal M/S/U firmware verified (`No MMU`) | **Hardware Architecture Verified** (Sv39 PTW + I/D-TLB + M/S/U + CLINT/PLIC/16550A UART verified via bare-metal privileged & virtual-memory oracles; **OpenSBI + Linux kernel image boot in progress**) | `chips/hammer_v3/design/SPEC.md`, `chips/hammer_v3/tests/run_system_oracle.py` |

