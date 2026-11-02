#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic source patch for the manifest-pinned dedicated boot build."""
from pathlib import Path


def replace(path, old, new):
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise ValueError(f"patch anchor in {path.name}: expected 1, found {count}")
    path.write_text(text.replace(old, new))


def apply(linux, opensbi, inputs):
    # Archive symbol hiding is unnecessary for this standalone firmware image.
    replace(opensbi / "Makefile",
            "ELFFLAGS\t+=\t-Wl,--exclude-libs,ALL\n", "")
    replace(opensbi / "firmware/fw_base.ldS",
            "\t. = ALIGN(1 << LOG2CEIL((SIZEOF(.rodata) + SIZEOF(.text)\n"
            "\t\t\t\t+ SIZEOF(.dynsym) + SIZEOF(.rela.dyn))));",
            "\t/* Include section padding; .dynsym need not exist without PIE. */\n"
            "\t. = ALIGN(1 << LOG2CEIL(. - FW_TEXT_START));")
    for entrypoint in ("defconfig.py", "genconfig.py"):
        replace(opensbi / "scripts/Kconfiglib" / entrypoint,
                "import kconfiglib",
                "from pathlib import Path\n"
                + ("import sys\n" if entrypoint == "defconfig.py" else "")
                + "\nsys.path.insert(0, str(Path(__file__).resolve().parent))\n"
                "\nimport kconfiglib")

    k = linux / "arch/riscv"
    replace(k / "Kconfig.socs", 'menu "SoC selection"',
            'menu "SoC selection"\n\nconfig SOC_HAMMER_V5\n'
            '\tbool "HAMMER-V5 custom-0 context support"\n'
            '\tdepends on 64BIT && MMU && RISCV_SBI && !SMP && !COMPAT\n'
            '\thelp\n\t  Eager custom vector task and extensible signal state.\n')
    replace(k / "include/asm/processor.h",
            "\tstruct __riscv_v_ext_state vstate;",
            "\tstruct __riscv_v_ext_state vstate;\n"
            "#ifdef CONFIG_SOC_HAMMER_V5\n\tu64 hammer_v5[8];\n#endif")
    replace(k / "include/asm/switch_to.h", "#include <asm/csr.h>",
            "#include <asm/csr.h>\n#include <asm/hammer_v5.h>")
    replace(k / "include/asm/switch_to.h",
            "\t((last) = __switch_to(__prev, __next));",
            "\thammer_v5_switch(__prev, __next);\t\t\\\n"
            "\t((last) = __switch_to(__prev, __next));")
    replace(k / "kernel/process.c", "#include <asm/vector.h>",
            "#include <asm/vector.h>\n#include <asm/hammer_v5.h>")
    replace(k / "kernel/process.c", "void flush_thread(void)\n{",
            "void flush_thread(void)\n{\n\thammer_v5_flush();")
    replace(k / "kernel/process.c", "\t*dst = *src;",
            "\thammer_v5_fork(src);\n\t*dst = *src;")
    replace(k / "kernel/process.c", "\t\t/* Kernel thread */",
            "\t\t/* Kernel thread */\n#ifdef CONFIG_SOC_HAMMER_V5\n"
            "\t\tmemset(p->thread.hammer_v5, 0, sizeof(p->thread.hammer_v5));\n"
            "#endif")
    replace(k / "kernel/Makefile", "obj-y\t+= signal.o",
            "obj-y\t+= signal.o\n"
            "obj-$(CONFIG_SOC_HAMMER_V5) += hammer_v5.o hammer_v5_context.o")
    (k / "include/asm/hammer_v5.h").write_bytes(
        (inputs / "linux_hammer_v5.h").read_bytes())
    (k / "kernel/hammer_v5.c").write_bytes(
        (inputs / "linux_hammer_v5.c").read_bytes())
    (k / "kernel/hammer_v5_context.S").write_bytes(
        (inputs / "hammer_v5_context.S").read_bytes())

    signal = k / "kernel/signal.c"
    replace(signal, "#include <asm/cacheflush.h>",
            "#include <asm/cacheflush.h>\n#include <asm/hammer_v5.h>")
    replace(signal, "\tstruct sigcontext __user *sc)\n{",
            "\tstruct sigcontext __user *sc, u64 *hammer_state,\n"
            "\tbool *hammer_seen)\n{")
    replace(signal, "\t\t\treturn 0;\n\t\tcase RISCV_V_MAGIC:",
            "\t\t\tif (hammer_v5_present && !*hammer_seen)\n"
            "\t\t\t\treturn -EINVAL;\n"
            "\t\t\treturn 0;\n"
            "\t\tcase HAMMER_V5_MAGIC:\n"
            "\t\t\tif (!hammer_v5_present || *hammer_seen ||\n"
            "\t\t\t    size != HAMMER_V5_SC_SIZE)\n"
            "\t\t\t\treturn -EINVAL;\n"
            "\t\t\terr = copy_from_user(hammer_state, sc_ext_ptr,\n"
            "\t\t\t\t\t     8 * sizeof(*hammer_state));\n"
            "\t\t\t*hammer_seen = true;\n"
            "\t\t\tbreak;\n\t\tcase RISCV_V_MAGIC:")
    replace(signal, "\tsigset_t set;\n",
            "\tsigset_t set;\n\tu64 hammer_state[8];\n"
            "\tbool hammer_seen = false;\n")
    replace(signal, "\tif (restore_sigcontext(regs, &frame->uc.uc_mcontext))",
            "\tif (restore_sigcontext(regs, &frame->uc.uc_mcontext,\n"
            "\t\t\t       hammer_state, &hammer_seen))")
    replace(signal, "\tif (restore_altstack(&frame->uc.uc_stack))\n"
            "\t\tgoto badframe;",
            "\tif (restore_altstack(&frame->uc.uc_stack))\n"
            "\t\tgoto badframe;\n"
            "\tif (hammer_seen)\n\t\thammer_v5_install(hammer_state);")
    replace(signal, "\tframe_size = sizeof(*frame);",
            "\tframe_size = sizeof(*frame);\n"
            "\tif (hammer_v5_present ||\n"
            "\t    (cal_all && IS_ENABLED(CONFIG_SOC_HAMMER_V5)))\n"
            "\t\ttotal_context_size += HAMMER_V5_SC_SIZE;")
    replace(signal, "\t/* Write zero to fp-reserved space",
            "\tif (hammer_v5_present) {\n"
            "\t\tu64 state[8];\n\n"
            "\t\thammer_v5_snapshot(state);\n"
            "\t\terr |= copy_to_user(sc_ext_ptr + 1, state, sizeof(state));\n"
            "\t\terr |= __put_user(HAMMER_V5_MAGIC, &sc_ext_ptr->magic);\n"
            "\t\terr |= __put_user(HAMMER_V5_SC_SIZE, &sc_ext_ptr->size);\n"
            "\t\tsc_ext_ptr = (void __user *)sc_ext_ptr + HAMMER_V5_SC_SIZE;\n"
            "\t}\n\t/* Write zero to fp-reserved space")

    o = opensbi / "platform/generic"
    (o / "hammer_v5.c").write_bytes(
        (inputs / "opensbi_hammer_v5.c").read_bytes())
    replace(o / "objects.mk", "platform-objs-y += platform.o",
            "platform-objs-y += platform.o\n"
            "platform-objs-y += hammer_v5.o\n"
            "carray-platform_override_modules-y += hammer_v5")
