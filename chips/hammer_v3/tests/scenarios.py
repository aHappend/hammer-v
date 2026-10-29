"""Architectural page-table stimuli, with expected results from the Python oracle."""

import random

from oracle import MASK64, sv39


def walker_cases(seed=17, count=1200):
    rng = random.Random(seed)
    classes = ("legal", "invalid-v", "write-only", "reserved-upper",
               "nonleaf-u", "nonleaf-a", "nonleaf-d", "access-root",
               "access-middle", "access-bottom", "misaligned-superpage",
               "accessed-clear", "dirty-clear", "noncanonical", "execute-only",
               "user-leaf", "supervisor-leaf")
    for number in range(count):
        kind = classes[number % len(classes)]
        level = number % 3
        # Cases requiring all three table levels deliberately use 4 KiB leaves.
        if kind in ("access-middle", "access-bottom"):
            level = 0
        if kind in ("nonleaf-u", "nonleaf-a", "nonleaf-d"):
            level = number % 2
        va = rng.getrandbits(39)
        if va & (1 << 38):
            va |= MASK64 ^ ((1 << 39) - 1)
        if kind == "noncanonical":
            va ^= 1 << 63
        access = (number // 3) % 4
        privilege = (number // 12) % 2
        sum_enable = bool(number & 1)
        mxr_enable = bool(number & 2)
        root = rng.getrandbits(44)
        asid = rng.getrandbits(16)
        tables = [rng.getrandbits(44), rng.getrandbits(44), root]
        physical_ppn = rng.getrandbits(44) & ~((1 << (9 * level)) - 1)
        flags = 0xCF  # V/R/W/X/A/D, supervisor leaf.
        if privilege == 0:
            flags |= 0x10
        if kind == "invalid-v":
            flags &= ~1
        elif kind == "write-only":
            flags = (flags | 4) & ~2
        elif kind == "accessed-clear":
            flags &= ~0x40
        elif kind == "dirty-clear":
            flags &= ~0x80
            access = 2 if number & 1 else 3
        elif kind == "execute-only":
            flags &= ~6
        elif kind == "user-leaf":
            flags |= 0x10
        elif kind == "supervisor-leaf":
            flags &= ~0x10
        elif kind == "misaligned-superpage":
            level = 1 + (number & 1)
            physical_ppn = (physical_ppn & ~((1 << (9 * level)) - 1)) | 1
        entries = {}
        errors = set()
        for walk_level in range(2, level - 1, -1):
            address = (tables[walk_level] << 12) + (
                ((va >> (12 + 9 * walk_level)) & 511) * 8)
            if walk_level == level:
                pte = (physical_ppn << 10) | flags
                if kind == "reserved-upper":
                    pte |= 1 << rng.randrange(54, 64)
            else:
                pte = (tables[walk_level - 1] << 10) | 1
                if number & 4:
                    pte |= 0x20
                if kind in ("nonleaf-u", "nonleaf-a", "nonleaf-d") and walk_level == 2:
                    pte |= {"nonleaf-u": 0x10, "nonleaf-a": 0x40, "nonleaf-d": 0x80}[kind]
            entries[address] = pte
            if (kind == "access-root" and walk_level == 2 or
                kind == "access-middle" and walk_level == 1 or
                    kind == "access-bottom" and walk_level == 0):
                errors.add(address)
        reads = []

        def read_pte(address):
            if address not in entries:
                raise AssertionError(f"scenario omitted PTE at {address:x}")
            reads.append((address, entries[address], int(address in errors)))
            if address in errors:
                raise OSError("deliberately injected physical read error")
            return entries[address]

        expected = sv39(va, access, privilege, (8 << 60) | root,
                        (int(sum_enable) << 18) | (int(mxr_enable) << 19), read_pte)
        yield {
            "class": kind, "va": va, "root": root, "asid": asid,
            "access": access, "priv": privilege, "sum": int(sum_enable),
            "mxr": int(mxr_enable), "expected_pa": expected.pa,
            "fault": {"": 0, "page": 1, "access": 2}[expected.fault],
            "level": max(0, expected.level), "global": int(expected.global_mapping),
            "reads": reads,
        }
