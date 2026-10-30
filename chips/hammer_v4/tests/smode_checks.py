#!/usr/bin/env python3
"""Host unit checks of the actual patched handler, not RTL/trap integration."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent

SHIM = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef EFAULT
#define EFAULT 14
#define EOPNOTSUPP 95
#endif
typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;
_Static_assert(sizeof(unsigned long) == 8, "RV64 host model");
#define SR_SUM 0x40000UL
#define SR_MXR 0x80000UL
#define CSR_STATUS 0
#define TASK_SIZE (1UL << 38)
#define __user
struct pt_regs { unsigned long epc, x[31], status, badaddr; };
static unsigned long csr, denied;
static unsigned reads, writes, preempt_depth, fault_depth, comparisons;
static unsigned saved_preempt_depth, saved_fault_depth;
static bool deny_write, execute_only;
static unsigned char code[8], data[8192];
static const unsigned long high = 0xffffffc000000000UL;
static unsigned long code_base, data_base;
static int access_byte(unsigned long a, bool wr, bool user, u8 *v)
{
    unsigned char *p;
    if (user != (a < TASK_SIZE)) return -EFAULT;
    if (a == denied && (!deny_write || wr)) return -EFAULT;
    if (a >= code_base && a - code_base < sizeof(code)) {
        if (wr || (execute_only && !(csr & SR_MXR))) return -EFAULT;
        p = code + a - code_base;
    } else if (a >= data_base && a - data_base < sizeof(data)) {
        p = data + a - data_base;
    } else return -EFAULT;
    if (wr) { *p = *v; ++writes; }
    else { *v = *p; ++reads; }
    return 0;
}
#define get_user(v,p) access_byte((unsigned long)(p), false, true, &(v))
#define put_user(v,p) write_byte((unsigned long)(p), true, (v))
#define get_kernel_nofault(v,p) access_byte((unsigned long)(p), false, false, &(v))
static int write_byte(unsigned long a, bool user, u8 v)
{ return access_byte(a, true, user, &v); }
static int copy_to_kernel_nofault(void *p, const void *v, size_t n)
{
    if (n != 1) abort();
    return write_byte((unsigned long)p, false, *(const u8 *)v);
}
static bool user_mode(struct pt_regs *r) { return !(r->status & 0x100); }
static unsigned long regs_get_register(struct pt_regs *r, unsigned n)
{ return *(unsigned long *)((char *)r + n); }
static unsigned long csr_read_set(unsigned c, unsigned long bits)
{ unsigned long old = csr; (void)c; csr |= bits; return old; }
static void csr_clear(unsigned c, unsigned long bits) { (void)c; csr &= ~bits; }
static void preempt_disable(void) { ++preempt_depth; }
static void preempt_enable(void) { --preempt_depth; }
static void pagefault_disable(void) { ++fault_depth; }
static void pagefault_enable(void) { --fault_depth; }
"""

HARNESS = r"""
static void check(bool ok, const char *why)
{
    ++comparisons;
    if (!ok) { fprintf(stderr, "MISMATCH %s\n", why); exit(1); }
}
static struct pt_regs setup(bool user, u32 insn, unsigned long offset)
{
    struct pt_regs r;
    memset(&r, 0, sizeof(r));
    for (unsigned i = 0; i < 31; ++i) r.x[i] = 0xabab0000 + i;
    code_base = (user ? 0 : high) + 0x1000;
    data_base = (user ? 0 : high) + 0x4000;
    r.epc = code_base;
    r.status = user ? 0 : 0x100;
    r.x[4] = data_base + offset;
    r.badaddr = r.x[4];
    for (unsigned i = 0; i < 4; ++i) code[i] = insn >> (8 * i);
    for (unsigned i = 0; i < sizeof(data); ++i) data[i] = (i * 73 + 0x81) & 255;
    csr = 0x102; denied = ~0UL; deny_write = false; execute_only = false;
    reads = writes = preempt_depth = fault_depth = 0;
    saved_preempt_depth = saved_fault_depth = 0;
    return r;
}
static u32 load_insn(unsigned f, unsigned rd, int imm)
{ return ((u32)imm & 4095) << 20 | 5 << 15 | f << 12 | rd << 7 | 3; }
static u32 store_insn(unsigned f, unsigned rs, int imm)
{
    u32 n = (u32)imm & 4095;
    return (n >> 5) << 25 | rs << 20 | 5 << 15 | f << 12 | (n & 31) << 7 | 0x23;
}
static void context(struct pt_regs *r, struct pt_regs *before, int rd, bool success)
{
    struct pt_regs expected = *before;
    if (success) {
        expected.epc += 4;
        if (rd > 0) expected.x[rd - 1] = r->x[rd - 1];
    }
    check(!memcmp(r, &expected, sizeof(*r)), "saved trap context/EPC");
    check(preempt_depth == saved_preempt_depth && fault_depth == saved_fault_depth,
          "balanced nested fault/preempt state");
    check(csr == 0x102 || csr == (0x102 | SR_MXR), "CSR restoration");
}
int main(void)
{
    unsigned cases = 0;
    for (unsigned user = 0; user < 2; ++user)
    for (unsigned f = 1; f <= 6; ++f) {
        if (f == 4) continue;
        unsigned size = 1U << (f & 3);
        for (unsigned boundary = 0; boundary < 2; ++boundary)
        for (unsigned rd_case = 0; rd_case < 3; ++rd_case)
        for (unsigned initial_mxr = 0; initial_mxr < 2; ++initial_mxr) {
            unsigned rd = rd_case == 0 ? 0 : (rd_case == 1 ? 5 : 10);
            struct pt_regs r = setup(user, load_insn(f, rd, -3),
                                     (boundary ? 4095 : 1) + 3);
            unsigned long addr = r.x[4] - 3, fault;
            r.badaddr = addr;
            execute_only = true;
            if (initial_mxr) csr |= SR_MXR;
            unsigned long saved_csr = csr, expected = 0;
            for (unsigned i = 0; i < size; ++i)
                expected |= (unsigned long)data[addr - data_base + i] << (8 * i);
            if (f < 4 && size < 8 && (expected & (1UL << (size * 8 - 1))))
                expected |= ~0UL << (size * 8);
            struct pt_regs before = r;
            check(!riscv_smode_emulate_misaligned(&r, false, &fault), "load success");
            if (rd) check(r.x[rd - 1] == expected, "load independent byte/sign result");
            check(reads == size + 4 && !writes, "x0 still accesses memory");
            check(csr == saved_csr, "MXR restored exactly");
            context(&r, &before, rd, true);
            ++cases;
        }
    }
    for (unsigned user = 0; user < 2; ++user)
    for (unsigned f = 1; f <= 3; ++f)
    for (unsigned zero = 0; zero < 2; ++zero) {
        struct pt_regs r = setup(user, store_insn(f, zero ? 0 : 10, -5), 4100);
        unsigned size = 1U << f;
        r.badaddr -= 5;
        r.x[9] = 0xfedcba9876543210UL;
        struct pt_regs before = r;
        unsigned char expected[sizeof(data)];
        memcpy(expected, data, sizeof(data));
        unsigned long value = zero ? 0 : r.x[9], fault;
        for (unsigned i = 0; i < size; ++i) expected[4095 + i] = value >> (8 * i);
        check(!riscv_smode_emulate_misaligned(&r, true, &fault), "store success");
        check(!memcmp(expected, data, sizeof(data)), "store data/byte footprint");
        check(writes == size, "store comparison length");
        context(&r, &before, -1, true);
        ++cases;
    }
    for (unsigned user = 0; user < 2; ++user)
    for (unsigned store = 0; store < 2; ++store)
    for (unsigned where = 0; where < 4; ++where) {
        struct pt_regs r = setup(user, store ? store_insn(3, 10, 0) :
                                  load_insn(3, 0, 0), 4095);
        unsigned long fault, expected_fault;
        if (where < 2) expected_fault = denied = code_base + where * 2;
        else expected_fault = denied = r.badaddr + (where == 2 ? 0 : 1);
        struct pt_regs before = r;
        check(riscv_smode_emulate_misaligned(&r, store, &fault) == -EFAULT,
              "instruction/data inaccessible byte rejection");
        check(fault == expected_fault, "precise failing byte address");
        context(&r, &before, -1, false);
        ++cases;
    }
    for (unsigned n = 0; n < 6; ++n) {
        u32 insn = n == 0 ? 0x0000302f : n == 1 ? 0x00000013 :
                   n == 2 ? load_insn(4, 10, 0) :
                   n == 3 ? store_insn(4, 10, 0) :
                   n == 4 ? 0x00000001 : 0x0000001f;
        struct pt_regs r = setup(false, insn, 1), before = r;
        unsigned long fault;
        check(riscv_smode_emulate_misaligned(&r, n == 0 || n == 3, &fault)
              == -EOPNOTSUPP, "unsupported/AMO remains unsupported");
        context(&r, &before, -1, false);
        ++cases;
    }
    for (unsigned sum = 0; sum < 2; ++sum) {
        struct pt_regs r = setup(false, load_insn(3, 10, 0), 1);
        data_base = 0x4000;
        r.x[4] = r.badaddr = data_base + 1;
        r.status |= sum ? SR_SUM : 0;
        struct pt_regs before = r;
        unsigned long fault;
        int result = riscv_smode_emulate_misaligned(&r, false, &fault);
        check(result == (sum ? 0 : -EFAULT), "saved SUM permission");
        context(&r, &before, sum ? 10 : -1, sum);
        ++cases;
    }
    for (unsigned failure = 0; failure < 2; ++failure) {
        struct pt_regs r = setup(false, load_insn(3, 10, 0), 1), before = r;
        saved_preempt_depth = preempt_depth = 2;
        saved_fault_depth = fault_depth = 3;
        if (failure) denied = r.badaddr + 2;
        unsigned long fault;
        check(riscv_smode_emulate_misaligned(&r, false, &fault) ==
              (failure ? -EFAULT : 0), "nested nofault context result");
        context(&r, &before, failure ? -1 : 10, !failure);
        ++cases;
    }
    for (unsigned bad_pc = 0; bad_pc < 2; ++bad_pc) {
        struct pt_regs r = setup(false, load_insn(3, 10, 0), 1);
        if (bad_pc) r.epc += 2;
        else r.x[4] = r.badaddr = data_base + 8;
        struct pt_regs before = r;
        unsigned long fault;
        check(riscv_smode_emulate_misaligned(&r, false, &fault) == -EOPNOTSUPP,
              "unaligned instruction PC/aligned data rejected");
        context(&r, &before, -1, false);
        ++cases;
    }
    printf("HOST_HANDLER_UNIT cases=%u comparisons=%u; not RTL/trap integration\n",
           cases, comparisons);
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--software", required=True, help="freshly rebuilt software directory")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    software = ROOT / args.software
    record = json.loads((software / "build-record.json").read_text())
    if record["status"] != "built":
        raise ValueError("Requires a completed real software build")
    patch = ROOT / "software/linux-6.6.1-smode-misaligned.patch"
    if hashlib.sha256(patch.read_bytes()).hexdigest() != record["sources"][
        "software/linux-6.6.1-smode-misaligned.patch"
    ]:
        raise ValueError("Handler patch differs from rebuilt inputs")
    source = software / "linux-6.6.1/arch/riscv/kernel/traps_misaligned_smode.c"
    out = ROOT / args.out
    if not out.resolve().is_relative_to(ROOT / "build"):
        parser.error("--out must be a fresh build/ subdirectory")
    out.mkdir(parents=True, exist_ok=False)
    include = out / "include"
    for name in ("linux/errno.h", "linux/preempt.h", "linux/uaccess.h",
                 "asm/csr.h", "asm/misaligned_smode.h", "asm/ptrace.h"):
        header = include / name
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text("")
    harness = out / "handler.c"
    harness.write_text(SHIM + "\n" + source.read_text() + "\n" + HARNESS)
    executable = out / "handler"
    commands = [
        ["gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
         "-I", str(include), str(harness), "-o", str(executable)],
        [str(executable)],
    ]
    identity = {"scope": __doc__, "handler_sha256": hashlib.sha256(
        source.read_bytes()).hexdigest(), "commands": commands, "results": []}
    try:
        for index, command in enumerate(commands):
            with (out / f"{index}.stdout.log").open("wb") as so, (
                out / f"{index}.stderr.log"
            ).open("wb") as se:
                result = subprocess.run(command, cwd=ROOT, stdout=so, stderr=se)
            identity["results"].append(result.returncode)
            if result.returncode:
                raise RuntimeError(f"Handler unit command {index} failed; see {args.out}")
    finally:
        (out / "unit.json").write_text(json.dumps(identity, indent=2) + "\n")
    print((out / "1.stdout.log").read_text(), end="")


if __name__ == "__main__":
    main()
