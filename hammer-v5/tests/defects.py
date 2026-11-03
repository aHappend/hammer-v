"""Disposable, compiled architectural/coherence/checker sensitivity tests."""
import hashlib
import re
import shutil

from evidence import ROOT, digest
from compressed import decode
from counters import scenarios


def remaining_mutations(ev):
    definitions = (
        ("compressed-length", "hammer_v5_fetch_path.sv",
         "bytes_q <= 2;", "bytes_q <= 4;", "top_tb", "top_tb.sv", ".", "top"),
        ("vector-squash", "hammer_v5_vector.sv",
         "if (commit && op_q == 0)",
         "if ((commit || (rst_n && abort_valid && can_dispose)) && op_q == 0)",
         "vector_tb", "vector_tb.sv", ".", "vector"),
        ("l2-way", "hammer_v5_l2.sv",
         "hits[0] ? 2'd0 : hits[1] ? 2'd1",
         "hits[0] ? 2'd1 : hits[1] ? 2'd1",
         "memory_tb", "sets-1/memory_tb.sv", "sets-1", "memory"),
        ("l2-mask", "hammer_v5_l2.sv",
         "ram_write_mask[lane]", "ram_write_mask[7-lane]",
         "memory_tb", "sets-1/memory_tb.sv", "sets-1", "memory"),
        ("counter-increment", "hammer_v5_csr.sv",
         "hpm_q[n] + {60'b0,increments[n]}",
         "hpm_q[n] + {60'b0,increments[n]} + 64'd1",
         "counter_tb", "counter_tb.sv", ".", "counter"),
    )
    originals = sorted((ROOT / "rtl").glob("*.sv"))
    identity = {p.name: digest(p) for p in originals}
    reports = []
    for name, filename, old, new, top, harness, run_dir, kind in definitions:
        text = (ROOT / "rtl" / filename).read_text()
        if text.count(old) != 1:
            raise AssertionError(f"{name}: mutation anchor not unique")
        modified = text.replace(old, new)
        destination = ev.directory / f"mutant-{name}-{hashlib.sha256(modified.encode()).hexdigest()[:16]}"
        destination.mkdir(exist_ok=False)
        mutant = destination / filename
        mutant.write_text(modified)
        sources = [mutant if path.name == filename else path for path in originals]
        objects = destination / "compile-obj"
        ev.record.setdefault("mutant_sources_sha256", {})[ev.relative(mutant)] = digest(mutant)
        ev.run(["verilator", "--binary", "--timing", "--top-module", top,
                "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "mutant-sim",
                ev.relative(ev.directory / harness), *map(ev.relative, sources)],
               name + "-compile")
        cwd = ev.directory / run_dir
        import os
        try:
            output = ev.run([os.path.relpath(objects / "mutant-sim", cwd)],
                            name + "-simulation", cwd=cwd, expected_exit=(-6, 1, 134))
            if kind == "top":
                match = re.search(
                    r"ARCH MISMATCH case=(\d+) pc=([0-9a-f]+) next=([0-9a-f]+) "
                    r"raw=([0-9a-f]+) rd=\s*(\d+) data=([0-9a-f]+)", output)
                if not match:
                    raise AssertionError("length mutant lacks architectural mismatch")
                case, pc, nxt, raw, rd, value = (int(match[i], 10 if i in (1, 5) else 16)
                                                for i in range(1, 7))
                expanded, illegal, _ = decode(raw)
                expected = [0, 2, 0x440D, 8, (expanded >> 20) & 4095]
                observed = [pc, nxt, raw, rd, value]
                if case != 0 or illegal or raw != 0x440D or nxt == expected[1]:
                    raise AssertionError("length mutant did not expose wrong first next PC")
            elif kind == "vector":
                match = re.search(
                    r"VECTOR MEMORY MISMATCH case=\s*(\d+).*"
                    r"expected_store=([0-9a-f]+) observed=([0-9a-f]+)", output)
                if not match:
                    raise AssertionError("squash mutant lacks observable stored-vector mismatch")
                case = int(match[1])
                row = (ev.directory / "vector.txt").read_text().splitlines()[case].split()
                expected, observed = int(match[2], 16), int(match[3], 16)
                if int(row[7], 16) != expected or observed == expected:
                    raise AssertionError("squash mutant did not fail unchanged vector oracle")
            elif kind == "memory":
                match = re.search(
                    r"MEMORY MISMATCH case=\s*(\d+).*expected=([0-9a-f]+)/\s*(\d+) "
                    r"observed=([0-9a-f]+)/([01])", output)
                if not match:
                    raise AssertionError("L2 mutant lacks public byte-memory mismatch")
                case = int(match[1])
                row = (cwd / "memory.txt").read_text().splitlines()[case].split()
                expected, observed = int(match[2], 16), int(match[4], 16)
                if int(row[4], 16) != expected or observed == expected:
                    raise AssertionError("L2 mutant did not fail unchanged byte-memory oracle")
            else:
                match = re.search(
                    r"CSR MISMATCH case=(\d+) addr=([0-9a-f]+) (before|after) "
                    r"expected=([0-9a-f]+)/.*observed=([0-9a-f]+)/", output)
                if not match:
                    raise AssertionError("counter mutant lacks observed CSR mismatch")
                case = int(match[1])
                rows, _ = scenarios()
                expected, observed = int(match[4], 16), int(match[5], 16)
                if (expected != rows[case][18 if match[3] == "before" else 19] or
                        expected == observed):
                    raise AssertionError("counter mutant did not fail independent CSR oracle")
            reports.append({"name": name, "source": ev.relative(mutant),
                            "case": case, "expected": expected, "observed": observed,
                            "compiled": True, "public_mismatch_checked": True})
        finally:
            if objects.is_dir():
                shutil.rmtree(objects)
        ev.record["additional_mutants"] = reports
        ev.save()
    if identity != {p.name: digest(p) for p in originals}:
        raise AssertionError("accepted RTL changed during disposable tests")
