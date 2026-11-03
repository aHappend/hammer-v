"""Disposable executable numerical mutants, checked through public responses."""
import re
import shutil

from evidence import ROOT, digest
from reference import int8_dot, rms, bf16_dot


def numerical_mutations(ev):
    mutations = (
        ("int8-sign", "hammer_v5_int8.sv",
         (("lane_a[n] * lane_b[n]", "$unsigned(lane_a[n]) * $unsigned(lane_b[n])"),),
         (0, 1)),
        ("bf16-order", "hammer_v5_bf16.sv",
         (("products[lane*2]", "products[lane == 0 ? 0 : 1]"),
          ("products[lane*2+1]", "products[lane == 0 ? 2 : 3]")), (2,)),
    )
    reports = []
    originals = {path.name: path for path in (ROOT / "rtl").glob("*.sv")}
    original_hashes = {name: digest(path) for name, path in originals.items()}
    for name, filename, edits, expected_ops in mutations:
        text = originals[filename].read_text()
        for old, new in edits:
            if text.count(old) != 1:
                raise AssertionError(f"{name}: unique mutation anchor missing")
            text = text.replace(old, new)
        import hashlib
        identity = hashlib.sha256(text.encode()).hexdigest()[:16]
        destination = ev.directory / f"mutant-{name}-{identity}"
        destination.mkdir(exist_ok=False)
        replacement = destination / filename
        replacement.write_text(text)
        sources = [replacement if source == filename else originals[source] for source in (
            "hammer_v5_int8.sv", "hammer_v5_bf16.sv", "hammer_v5_bf16_mul.sv",
            "hammer_v5_fp32_add.sv", "hammer_v5_fp32_round.sv")]
        ev.record.setdefault("mutant_sources_sha256", {})[ev.relative(replacement)] = digest(replacement)
        ev.run(["verilator", "--binary", "--timing", "--top-module", "probe_tb",
                "-Wno-fatal", "--Mdir", ev.relative(destination / "compile-obj"),
                "-o", "mutant-sim", ev.relative(ev.directory / "probe_tb.sv"),
                *map(ev.relative, sources)], f"{name}-compile")
        output = ev.run(["./" + (destination / "compile-obj/mutant-sim")
                        .relative_to(ev.directory).as_posix()],
                        f"{name}-simulation", cwd=ev.directory,
                        expected_exit=(-6, 1, 134))
        # The simulation consumes the same unmodified independent case table.
        # A rejected exit alone is not evidence: recompute its complete public mismatch.
        mismatch = re.search(
            r"NUMERICAL case=(\d+) op=(\d+) a=([0-9a-f]+) b=([0-9a-f]+) "
            r"seed=([0-9a-f]+) expected=([0-9a-f]+) observed=([0-9a-f]+)", output)
        if mismatch is None:
            raise AssertionError(f"{name}: no public numerical mismatch observed")
        case, op = int(mismatch[1]), int(mismatch[2])
        a, b, seed, expected, observed = (int(mismatch[i], 16) for i in range(3, 8))
        model = (int8_dot(a, b), rms(a, seed), bf16_dot(a, b))[op]
        record = (ev.directory / "cases.txt").read_text().splitlines()[case].split()
        if (op not in expected_ops or model != expected or observed == expected or
                list(map(lambda v: int(v, 16), record[1:5])) != [a, b, seed, expected]):
            raise AssertionError(f"{name}: mutant did not trigger its intended checked mismatch")
        reports.append({"mutant": name, "case": case, "operation": op,
                        "expected": f"{expected:016x}", "observed": f"{observed:016x}",
                        "compiled": True, "public_mismatch_checked": True,
                        "source": ev.relative(replacement)})
        shutil.rmtree(destination / "compile-obj")
    if original_hashes != {name: digest(path) for name, path in originals.items()}:
        raise AssertionError("accepted RTL changed during disposable mutation execution")
    ev.record["observed"]["numerical_mutants"] = reports
