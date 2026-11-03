/* SPDX-License-Identifier: BSD-2-Clause */
#include <platform_override.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_error.h>
#include <sbi_utils/fdt/fdt_helper.h>

/* mvendorid is zero: OpenSBI registers vendor extension 0x09000000. */
static int hammer_final_init(bool cold_boot, const struct fdt_match *match)
{
	csr_write(CSR_MCOUNTEREN, 0x7f);
	csr_write(CSR_SCOUNTEREN, 0x7f);
	csr_write(CSR_MHPMEVENT3, 1);
	csr_write(CSR_MHPMEVENT4, 2);
	csr_write(CSR_MHPMEVENT5, 3);
	csr_write(CSR_MHPMEVENT6, 4);
	csr_write(CSR_MCOUNTINHIBIT, 0);
	return 0;
}

static int hammer_vendor(long funcid, struct sbi_trap_regs *regs,
			 struct sbi_ecall_return *out,
			 const struct fdt_match *match)
{
	unsigned long selectors = regs->a0;
	unsigned long old_inhibit;

	if (((regs->mstatus >> 11) & 3) != 1)
		return SBI_EDENIED;
	if (funcid == 1) {
		out->value = 0x48563501;
		return 0;
	}
	if (funcid != 0)
		return SBI_ENOTSUPP;
	if ((selectors >> 12) || (selectors & 7) > 5 ||
	    ((selectors >> 3) & 7) > 5 ||
	    ((selectors >> 6) & 7) > 5 ||
	    ((selectors >> 9) & 7) > 5)
		return SBI_EINVAL;

	old_inhibit = csr_read(CSR_MCOUNTINHIBIT);
	csr_write(CSR_MCOUNTINHIBIT, old_inhibit | 0x78);
	csr_write(CSR_MHPMEVENT3, selectors & 7);
	csr_write(CSR_MHPMEVENT4, (selectors >> 3) & 7);
	csr_write(CSR_MHPMEVENT5, (selectors >> 6) & 7);
	csr_write(CSR_MHPMEVENT6, (selectors >> 9) & 7);
	csr_write(CSR_MHPMCOUNTER3, 0);
	csr_write(CSR_MHPMCOUNTER4, 0);
	csr_write(CSR_MHPMCOUNTER5, 0);
	csr_write(CSR_MHPMCOUNTER6, 0);
	csr_write(CSR_MCOUNTINHIBIT, old_inhibit & ~0x78UL);
	out->value = 0;
	return 0;
}

static const struct fdt_match hammer_match[] = {
	{ .compatible = "hammer,hammer-v5" },
	{ }
};

const struct platform_override hammer_v5 = {
	.match_table = hammer_match,
	.final_init = hammer_final_init,
	.vendor_ext_provider = hammer_vendor,
};
