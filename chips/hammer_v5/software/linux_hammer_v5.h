/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_HAMMER_V5_H
#define _ASM_HAMMER_V5_H

#include <linux/types.h>

#define HAMMER_V5_MAGIC 0x48563501
#define HAMMER_V5_SC_SIZE 72
#define HAMMER_V5_SBI_EXT 0x09000000

#ifdef CONFIG_SOC_HAMMER_V5
extern bool hammer_v5_present;
void hammer_vx_save(u64 *state);
void hammer_vx_restore(const u64 *state);
void hammer_v5_snapshot(u64 *state);
void hammer_v5_install(const u64 *state);
void hammer_v5_flush(void);
struct task_struct;
void hammer_v5_switch(struct task_struct *prev, struct task_struct *next);
void hammer_v5_fork(struct task_struct *src);
#else
#define hammer_v5_present false
static inline void hammer_v5_flush(void) {}
static inline void hammer_v5_switch(struct task_struct *p, struct task_struct *n) {}
static inline void hammer_v5_fork(struct task_struct *p) {}
static inline void hammer_v5_snapshot(u64 *p) {}
static inline void hammer_v5_install(const u64 *p) {}
#endif
#endif
