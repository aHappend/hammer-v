"""Disposable synthetic parser fixtures; these are not RTL/boot measurements."""
import hashlib
import json
import shutil

from evidence import digest
from reference import bf16_dot
from userland import CASE_OPERANDS, compare_userland, expected, median
from boot_checks import boot_support_probe


def parser_probe(ev):
    boot_support_probe(ev)
    directory = ev.directory / "parser-fixture-8a6c1407"
    directory.mkdir()
    lines, counters = [], []
    clock, counter_time, cycle_value = 1, 1, 1000

    def emit(category, **record):
        nonlocal clock
        lines.append(f"{clock} HV5 {category} " +
                     " ".join(f"{key}={value}" for key, value in record.items()) + "\n")
        clock += 1

    def counter(address, value):
        nonlocal counter_time
        counters.append(f"{counter_time} {address:x} {value:x}\n")
        counter_time += 1

    def cycles(delta):
        nonlocal cycle_value
        counter(0xC00, cycle_value)
        cycle_value += delta
        counter(0xC00, cycle_value)
        cycle_value += 100

    def macs(delta):
        counter(0xC06, 0)
        counter(0xC06, delta)

    emit("USER", pid=1)
    fault_pc, handler_pc, fault_va, info, context = 0x10100, 0x10500, 0x3FFFFFE001, 0x20000, 0x21000
    emit("FAULTS", successful_vload=1, rejected=5, state_preserved=1,
         misaligned_pc=hex(fault_pc), misaligned_va=hex(fault_va))
    for task in (1, 2):
        emit("CONTEXT", task=task, yield_requests=64, signals=64, nested=64)
    for seed in (17, 43, 89):
        model = expected(seed)
        for index, (a, b) in enumerate(CASE_OPERANDS):
            value = bf16_dot(a, b)
            emit("CASE", seed=seed, kind="bf16", id=index, a=hex(a), b=hex(b),
                 result=hex(value), expected=hex(value))
        macs(256)
        emit("RMS", seed=seed, lanes=256, scalar_seed=hex(0xFFFFFFFFFFFFFF00),
             result=hex(model["rms"]))
        for precision in ("int8", "bf16"):
            scalar, vector = [], []
            for repeat in range(32):
                sc, vc = 1000 + 2 * repeat, 300 + 2 * repeat
                scalar.append(sc)
                vector.append(vc)
                for interval in ((sc, vc) if repeat % 2 == 0 else (vc, sc)):
                    cycles(interval)
            macs(8192)
            for repeat in range(32):
                emit("SAMPLE", seed=seed, kind=precision, repeat=repeat,
                     scalar_complete_cycles=scalar[repeat], vector_complete_cycles=vector[repeat])
            sc, vc = median(scalar), median(vector)
            emit("BENCH", seed=seed, kind=precision, reduction=256, repetitions=32,
                 scalar_complete_cycles=sc, vector_complete_cycles=vc,
                 speedup_numerator=sc, speedup_denominator=vc, macs=8192,
                 result=hex(model[precision]))
            cycles(200)
            emit("ARITH", seed=seed, kind=precision, excludes_loads=1,
                 vector_arithmetic_cycles=200)
        cycles(10000)
        macs(4608)
        hashes = {}
        for precision, matrix in model["matrices"].items():
            value = 14695981039346656037
            for (row, column), result in matrix.items():
                emit("RESULT", seed=seed, kind=precision, row=row, column=column,
                     result=hex(result))
                for byte in result.to_bytes(8, "little"):
                    value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
            hashes[precision] = hex(value)
        emit("TILE", seed=seed, committed_macs=4608, comparison_complete_cycles=10000,
             int8_hash=hashes["int8"], bf16_hash=hashes["bf16"])
        for address, delta in ((0xC03, 100), (0xC04, 80), (0xC05, 50), (0xC06, 30)):
            counter(address, 0)
            counter(address, delta)
        emit("CACHE", seed=seed, selectors="1,2,3,4", l1_lookups=100, l1_hits=80,
             l2_lookups=50, l2_hits=30)
    emit("DONE", seeds="17,43,89", numerical=1, context=1, faults=1, measured_speed=1)
    (directory / "uart-events.txt").write_text("".join(lines))
    (directory / "counter-reads.txt").write_text("".join(counters))
    (directory / "bf16-observed.txt").write_text("3f803f803f803f80 3f803f803f803f80 40800000\n")
    (directory / "user-pids.txt").write_text(
        "".join(f"{i} {pid}\n" for i, pid in enumerate((1, 2, 3, 2, 3, 1))))
    (directory / "user-ecalls.txt").write_text(
        "".join(f"{i} {number} 0\n" for i, number in
                enumerate([124] * 128 + [101] * 128 + [139] * 256)))
    (directory / "boot-observed.json").write_text(json.dumps({"u_custom": 1, "high_va_retired": 1}))
    (directory / "custom-fault-expectations.json").write_text(json.dumps({
        "symbols": {"hammer_try_misaligned_vload": fault_pc, "fault_handler": handler_pc},
        "linux_version": "6.6.1", "cause": 4, "signal": 7, "si_code": 1,
        "si_addr_is_epc": True, "ucontext_gpr_offset": 176}))
    (directory / "custom-faults.txt").write_text(
        f"MISALIGNED 10 {fault_pc:x} 4 {fault_va:x} {fault_va:x}\n"
        f"SIGBUS 20 {handler_pc:x} {info:x} {context:x}\n"
        f"SIGCODE 21 {info + 8:x} 1\n"
        f"SIGADDR 22 {info + 16:x} {fault_pc:x}\n"
        f"SIGPC 23 {context + 176:x} {fault_pc:x}\n"
        f"SIGA0 24 {context + 256:x} {fault_va:x}\n"
        "SIGRETURN 25\n")
    ev.record["scope"] = {"synthetic_parser_fixtures_only": True,
                         "no_RTL_or_Linux_execution": True}
    result = compare_userland(directory)
    reports = []
    mutations = (
        ("timing", "uart-events.txt", "scalar_complete_cycles=1000",
         "scalar_complete_cycles=1001", "printed timing sample"),
        ("cell", "uart-events.txt", "HV5 RESULT seed=17 kind=int8 row=0 column=0 result=",
         "HV5 RESULT seed=17 kind=int8 row=0 column=0 result=0x0#",
         "tensor cell"),
        ("bf16", "bf16-observed.txt", "40800000", "40800001", "exact rational"),
        ("context", "uart-events.txt", "HV5 CONTEXT task=2", "HV5 CONTEXT task=1",
         "context/signal"),
        ("trap-pc", "custom-faults.txt", f"{fault_pc:x} 4", f"{fault_pc+4:x} 4",
         "trap PC/cause/effective-address"),
        ("trap-cause", "custom-faults.txt", f"{fault_pc:x} 4", f"{fault_pc:x} 6",
         "trap PC/cause/effective-address"),
        ("trap-tval", "custom-faults.txt", f"4 {fault_va:x}", f"4 {fault_pc:x}",
         "trap PC/cause/effective-address"),
        ("sigbus-address", "custom-faults.txt", f"SIGADDR 22 {info+16:x} {fault_pc:x}",
         f"SIGADDR 22 {info+16:x} {fault_va:x}", "SIGADDR mismatch"),
        ("sigbus-code", "custom-faults.txt", f"SIGCODE 21 {info+8:x} 1",
         f"SIGCODE 21 {info+8:x} 2", "SIGCODE mismatch"),
        ("sigbus-saved-pc", "custom-faults.txt", f"SIGPC 23 {context+176:x} {fault_pc:x}",
         f"SIGPC 23 {context+176:x} {fault_pc+4:x}", "SIGPC mismatch"),
        ("sigbus-saved-address", "custom-faults.txt", f"SIGA0 24 {context+256:x} {fault_va:x}",
         f"SIGA0 24 {context+256:x} {fault_pc:x}", "SIGA0 mismatch"),
        ("missing-trap", "custom-faults.txt",
         f"MISALIGNED 10 {fault_pc:x} 4 {fault_va:x} {fault_va:x}\n", "",
         "missing independent"),
    )
    for name, filename, old, new, required in mutations:
        text = (directory / filename).read_text()
        if old not in text:
            raise AssertionError("parser fixture mutation anchor missing")
        if name == "cell":
            import re
            modified = re.sub(re.escape(old) + r"0x[0-9a-f]+", old + "0xdeadbeef", text, count=1)
        else:
            modified = text.replace(old, new, 1)
        identity = hashlib.sha256(modified.encode()).hexdigest()[:16]
        child = ev.directory / f"parser-{name}-{identity}"
        shutil.copytree(directory, child)
        (child / filename).write_text(modified)
        try:
            compare_userland(child)
        except AssertionError as error:
            if required not in str(error):
                raise AssertionError(f"{name}: wrong checker rejected fixture: {error}") from error
            reports.append({"fixture": name, "rejection": str(error)})
        else:
            raise AssertionError(f"{name}: malformed fixture was accepted")
    ev.record["generated_sha256"] = {
        ev.relative(path): digest(path)
        for path in ev.directory.glob("parser-*/*") if path.is_file()}
    ev.record["observed"] = {"synthetic_positive_fixture": result,
                             "synthetic_rejections": reports}
