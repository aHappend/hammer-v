# HAMMER-V：流水线与特权架构 RISC-V 处理器家族（`V1` / `V2` / `V3`）

[English](README.md) | [简体中文](README.zh-CN.md)

## 1. 架构演进与 Quartus 17.1 布局布线后真实 PPA 资源对比（Intel Arria 10 GX `10AX115N2F45E1SG`）

`HAMMER-V` 三代核心均通过 **Quartus Prime 17.1 Standard (`quartus_map` + `quartus_fit` + `quartus_sta`)** 完成综合、布局布线与多工艺角（Slow 900mV 100C / 0C、Fast 900mV 0C）100.0 MHz（`10.0 ns`）静态时序签核。

| 核心代号 | 架构与指令集配置 | RTL 代码规模 | 逻辑资源占用 (ALMs) | 专用寄存器 (Registers) | 片上存储 (M20K / Bits) | DSP 块 | 100 MHz 建立时间裕量 (WNS) | 布局布线后 Fmax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **HAMMER-V1** | 5 级流水线 `RV32I` + 全旁路转发 + 冒险控制 | 17 文件 / 3,332 行 | **6,722 / 427,200 (2%)** | **6,458** | **128 M20K** (`2,097,152 bits`) | 0 | `+2.337 ns` | **130.50 MHz** |
| **HAMMER-V2** | 5 级流水线 `RV64IMAC` + M/S/U 特权 CSR + CLINT | 29 文件 / 5,978 行 | **13,722 / 427,200 (3%)** | **17,765** | **74 M20K** (`1,081,344 bits`) | 0 | `+1.464 ns` | **117.15 MHz** |
| **HAMMER-V3** | `RV64IMA` + 硬件 `Sv39` 页表遍历/TLB + M/S/U + CLINT/PLIC + 16550A UART + AXI4 | 40 文件 / 7,369 行 | **17,986 / 427,200 (4%)** | **22,931** | **78 M20K** (`1,082,752 bits`) | 0 | `+3.191 ns` | **146.86 MHz** |

---

## 2. 验证分级与签核边界透明矩阵（Claim-to-Evidence Alignment）

为严格确保公开宣称与工程证据一一对应，本仓库明确区分 **L1 周期精确功能/突变回归**、**L2 100 MHz 布局布线时序与资源**、**L3 物理板卡验证等级** 以及 **L4 系统软件/Linux 引导状态**：

| 验证层级 | 验证内容与准入方法 | HAMMER-V1 | HAMMER-V2 | HAMMER-V3 | 公开可核验回执路径 |
| --- | --- | --- | --- | --- | --- |
| **L1：周期精确功能、特权/MMU Oracle 与缺陷突变回归** | 全指令集定向与随机回归、流水线转发/停顿冒险、M/S/U 异常委托与中断（`V2/V3`）、Sv39 三级页表硬件遍历 / Page Fault / TLB 刷新 / LR-SC-AMO 原子操作 / I$-D$ 一致性（`V3`）及 RTL 故障注入突变拦截 | **已通过**（`l1-core-verification`：24 份回执，100% 突变检出） | **已通过**（`l1-functional-and-privileged`：40 份回执；`l1-mutation`：9/9 突变全部拦截） | **已通过**（`l1-system-oracle`：40 份回执，耗时 900.6s；`l1-defect-sensitivity`：8/8 突变全部拦截） | `chips/hammer_v{1,2,3}/evidence/verification-receipts.json` |
| **L1.5 & L2：RTL 时序检查与 100 MHz 布局布线 STA** | RTL 组合逻辑级数检查 + Arria 10 GX `10AX115N2F45E1SG` 完整 `quartus_map` / `quartus_fit` / `quartus_sta`（独立 IP `VIRTUAL_PIN ON` 评估模式） | **已通过**（`130.50 MHz`, `6,722 ALMs`, `128 M20K`） | **已通过**（`117.15 MHz`, `13,722 ALMs`, `74 M20K`） | **已通过**（`146.86 MHz`, `17,986 ALMs`, `78 M20K`） | `chips/hammer_v{1,2,3}/evidence/quartus-sta.json`, `ppa-resource-summary.json`, `top.fit.summary` |
| **L3：物理 FPGA 实板 HIL（`netsys17` Catapult Arria 10）** | 严格区分 PCIe BAR0 硬件桥接连通性探针（`L3_BRIDGE_CONNECTIVITY_PROBE_ONLY`，读取 `reg 57`）与单芯片 Bedrock `.rpd` 比特流烧录及板级计算向量校验（`L3_BITSTREAM_AND_FUNCTIONAL_EXECUTION`） | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY`（仅验证 PCIe BAR0 桥接连通；CPU Role 比特流封装待接入） | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY`（仅验证 PCIe BAR0 桥接连通；CPU Role 比特流封装待接入） | `L3_BRIDGE_CONNECTIVITY_PROBE_ONLY`（仅验证 PCIe BAR0 桥接连通；CPU Role 比特流封装待接入） | `chips/hammer_v{1,2,3}/evidence/board-hil.json` |
| **L4：系统固件与 Linux 内核镜像启动** | 编译并挂载 `OpenSBI` 固件、设备树（`.dtb`）与 `Linux` 内核镜像完成串口引导 | 不适用（`RV32I` 无特权页表） | 已完成裸机 M/S/U 特权固件验证（无 MMU） | **已完成硬件特权与 Sv39 MMU 架构级回归**（裸机页表/异常/PLIC/16550A UART 全部通过；**OpenSBI + Linux 内核镜像引导验证推进中**） | `chips/hammer_v3/design/SPEC.md`, `chips/hammer_v3/tests/run_system_oracle.py` |
