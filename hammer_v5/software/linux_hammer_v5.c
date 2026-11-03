/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/of.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/csr.h>
#include <asm/hammer_v5.h>
#include <asm/sbi.h>

bool hammer_v5_present;

void hammer_v5_snapshot(u64 *state)
{
	if (!hammer_v5_present)
		return;
	preempt_disable();
	hammer_vx_save(state);
	preempt_enable();
}

void hammer_v5_install(const u64 *state)
{
	if (!hammer_v5_present)
		return;
	preempt_disable();
	hammer_vx_restore(state);
	preempt_enable();
}

void hammer_v5_switch(struct task_struct *prev, struct task_struct *next)
{
	if (hammer_v5_present) {
		hammer_vx_save(prev->thread.hammer_v5);
		hammer_vx_restore(next->thread.hammer_v5);
	}
}

void hammer_v5_fork(struct task_struct *src)
{
	if (hammer_v5_present)
		hammer_v5_snapshot(src->thread.hammer_v5);
}

void hammer_v5_flush(void)
{
	u64 zero[8] = { 0 };

	if (hammer_v5_present) {
		preempt_disable();
		memset(current->thread.hammer_v5, 0,
		       sizeof(current->thread.hammer_v5));
		hammer_vx_restore(zero);
		preempt_enable();
	}
}

static long hammer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long selectors;
	struct sbiret result;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (arg)
		return -EINVAL;
	if (cmd == 0x4800)
		selectors = 1 | (2 << 3) | (3 << 6) | (4 << 9);
	else if (cmd == 0x4801)
		selectors = 1 | (2 << 3) | (3 << 6) | (5 << 9);
	else
		return -ENOTTY;
	result = sbi_ecall(HAMMER_V5_SBI_EXT, 0, selectors, 0, 0, 0, 0, 0);
	return result.error ? -EIO : 0;
}

static const struct file_operations hammer_fops = {
	.unlocked_ioctl = hammer_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice hammer_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hammer-v5",
	.fops = &hammer_fops,
	.mode = 0600,
};

static int __init hammer_init(void)
{
	struct sbiret result;
	int error;

	if (!of_machine_is_compatible("hammer,hammer-v5"))
		return -ENODEV;
	result = sbi_ecall(HAMMER_V5_SBI_EXT, 1, 0, 0, 0, 0, 0, 0);
	if (result.error || result.value != HAMMER_V5_MAGIC) {
		pr_err("HAMMER-V5: firmware context/counter ABI missing\n");
		return -ENODEV;
	}
	hammer_v5_present = true;
	hammer_v5_flush();
	csr_write(0x800, 1);
	csr_write(CSR_SCOUNTEREN, 0x7f);
	error = misc_register(&hammer_device);
	if (error) {
		csr_write(0x800, 0);
		hammer_v5_present = false;
		pr_err("HAMMER-V5: context device registration failed: %d\n", error);
		return error;
	}
	pr_info("HAMMER-V5: eager task/signal vector context, U custom-0, counters 0..6\n");
	return 0;
}
device_initcall(hammer_init);
