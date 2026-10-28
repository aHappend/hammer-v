"""Analytical anchors for the independently authored instruction-set oracle."""

import sys
import struct
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from compiler import compile_benchmark, discover, load_elf
from cycle import equal
from encoding import i, r
from iss import MASK, arithmetic, decode
from portable import run_portable
from retention import ROOT, Evidence, ToolFailure


def portable_prerequisite_checks():
    campaign = Mock()
    failure = ToolFailure("PREREQUISITE_MISSING: synthetic unavailable compiler")
    with patch("compiler.discover", side_effect=failure), \
            patch("portable.fresh", return_value=ROOT / "fixture-tree") as create_tree, \
            patch("portable.sources", return_value={}) as enumerate_sources, \
            patch("portable.shutil.copyfile") as copy_source:
        try:
            run_portable(campaign)
        except ToolFailure as error:
            equal(error is failure, True, "portable preserves compiler prerequisite failure")
        else:
            equal(True, False, "portable cannot succeed without compilation prerequisite")
        create_tree.assert_not_called()
        enumerate_sources.assert_not_called()
        copy_source.assert_not_called()
        campaign.evidence.command.assert_not_called()
    tree = ROOT / "fixture-tree"
    with patch("compiler.discover", return_value=["/fixture/clang"]), \
            patch("portable.fresh", return_value=tree), \
            patch("portable.sources", return_value={}), \
            patch("portable.shutil.copyfile") as copy_source:
        result = run_portable(campaign)
    equal(result["source_tree"], "fixture-tree", "portable retains clean-tree output identity")
    equal(campaign.evidence.command.call_count, 3,
          "compiler preflight does not replace any clean-tree component")
    for invocation, component in zip(campaign.evidence.command.call_args_list,
                                     ("smoke", "sha256", "synthesis")):
        equal(invocation.args, (["python3", "tests/portable_child.py", component],),
              "portable component command unchanged")
        equal(invocation.kwargs, {"cwd": tree}, "components execute in clean source tree")
    copy_source.assert_not_called()
    print("PORTABLE_PREREQUISITE_FIXTURES compared=2; synthetic only; no compiler or RTL executed")


def interrupted_command_checks():
    for code in (-15, -9, 1, 0):
        with tempfile.TemporaryDirectory(prefix="hammer-interruption-fixture-") as directory:
            root = Path(directory)
            probe = Evidence.__new__(Evidence)
            probe.directory = root / "fixture"
            probe.directory.mkdir()
            probe.commands = []
            probe.hashes = {}
            argv = ["fixture-tool", "expected-rejection"]
            with patch("retention.ROOT", root), \
                    patch.object(probe, "version", return_value="synthetic fixture"), \
                    patch("retention.subprocess.run", return_value=Mock(returncode=code)):
                try:
                    folder, _ = probe.command(argv, cwd=root, expect_failure=True)
                except ToolFailure:
                    equal(code < 0, True, "completed command is not an interruption")
                    folder = (root / probe.commands[-1]).parent
                else:
                    equal(code >= 0, True,
                          "signal termination cannot count as expected-negative execution")
            receipt = json.loads((folder / "receipt.json").read_text())
            equal(receipt["argv"], argv, "interrupted command exact argv")
            equal(receipt["exit_code"], code, "original exit/signal status retained")
            equal(receipt["timed_out"], False, "signal termination is not a watchdog timeout")
            equal((root / receipt["stdout"]).exists(), True, "command stdout retained")
            equal((root / receipt["stderr"]).exists(), True, "command stderr retained")
    print("INTERRUPTION_FIXTURES compared=4; synthetic statuses; no tool interrupted")


def prerequisite_receipt_checks():
    with tempfile.TemporaryDirectory(prefix="hammer-receipt-fixture-") as directory:
        root = Path(directory)
        probe = Evidence.__new__(Evidence)
        probe.directory = root / "fixture"
        probe.directory.mkdir()
        probe.commands = []
        probe.hashes = {}
        argv = ["fixture-missing-compiler", "--target=rv64im"]
        with patch("retention.ROOT", root), \
                patch.object(probe, "version",
                             side_effect=ToolFailure("synthetic unavailable version query")), \
                patch("retention.subprocess.run",
                      side_effect=AssertionError("prerequisite failure must not launch command")):
            try:
                probe.command(argv, cwd=root, expect_failure=True)
            except ToolFailure as error:
                equal("tool prerequisite failed:" in str(error), True,
                      "version failure remains a prerequisite error")
            else:
                equal(True, False, "version failure cannot count as expected-negative execution")
        equal(len(probe.commands), 1, "attempted command retained on prerequisite failure")
        receipt = json.loads((root / probe.commands[0]).read_text())
        equal(receipt["argv"], argv, "unexecuted command exact argv")
        equal(receipt["exit_code"], None, "no invented child exit")
        equal(receipt["timed_out"], False, "version failure is not command timeout")
        equal(receipt["prerequisite_error"], "synthetic unavailable version query",
              "original prerequisite diagnostic retained")
        equal((root / receipt["stdout"]).read_bytes(), b"", "no invented child stdout")
        equal((root / receipt["stderr"]).read_text(),
              "synthetic unavailable version query\n", "retained prerequisite stderr")
        for field in ("cwd", "source_sha256", "start_time", "end_time", "timeout_s", "tool_version"):
            equal(field in receipt, True, f"prerequisite receipt includes {field}")
    print("PREREQUISITE_RECEIPT_FIXTURES compared=1; no compiler or RTL executed")


def compiler_selection_checks():
    cases = (
        ({}, {"clang": "/fixture/clang", "clang-23": "/fixture/clang",
              "clang-18": "/fixture/clang-18"},
         ["/fixture/clang", "/fixture/clang-18"]),
        ({"RISCV_CC": "selected"}, {"selected": "/fixture/selected",
                                   "clang": "/fixture/clang"},
         ["/fixture/selected"]),
        ({"RISCV_CC": "missing"}, {"clang": "/fixture/clang"}, None),
        ({"RISCV_CC": ""}, {"clang": "/fixture/clang"}, None),
        ({}, {}, None),
    )
    for environment, available, expected in cases:
        with patch.dict("os.environ", environment, clear=True), \
                patch("compiler.shutil.which", side_effect=available.get):
            try:
                actual = discover()
            except ToolFailure as error:
                if expected is not None:
                    raise
                equal(str(error).startswith("PREREQUISITE_MISSING:"), True,
                      "compiler selection failure diagnostic")
            else:
                equal(actual, expected, "compiler selection policy")
    print(f"COMPILER_SELECTION_FIXTURES compared={len(cases)}; no compiler executed")


def compiler_fallback_checks():
    with tempfile.TemporaryDirectory(prefix="hammer-compiler-fixture-") as directory:
        root = Path(directory)
        candidates = ["/fixture/clang", "/fixture/clang-18"]
        evidence = Mock(directory=root)
        evidence.command.side_effect = [
            (root / "first", {"exit_code": 1}),
            (root / "second", {"exit_code": 0}),
        ]
        loaded = object()
        with patch("compiler.ROOT", root), \
                patch("compiler.discover", return_value=candidates), \
                patch("compiler.load_elf", return_value=loaded) as loader:
            equal(compile_benchmark(evidence, 5) is loaded, True,
                  "fallback returns validated ELF rather than failed candidate")
        equal(evidence.command.call_count, 2, "failed compiler does not hide next candidate")
        for index, invocation in enumerate(evidence.command.call_args_list):
            argv = invocation.args[0]
            equal(argv[0], candidates[index], "compiler fallback order")
            for flag in ("--target=riscv64-unknown-elf", "-fuse-ld=lld",
                         "-march=rv64im", "-mabi=lp64", "-DBENCH=5"):
                equal(flag in argv, True, f"fallback preserves required flag {flag}")
            equal(invocation.kwargs, {"expect_failure": True},
                  "failed compilation retains its command result")
        first, second = [invocation.args[0][-1]
                         for invocation in evidence.command.call_args_list]
        equal(first != second, True, "fallback never reuses failed output namespace")
        loader.assert_called_once_with(root / second)

        evidence.command.reset_mock(side_effect=True)
        evidence.command.side_effect = [
            (root / "first", {"exit_code": 1}),
            (root / "second", {"exit_code": 1}),
        ]
        with patch("compiler.ROOT", root), \
                patch("compiler.discover", return_value=candidates), \
                patch("compiler.load_elf") as loader:
            try:
                compile_benchmark(evidence, 5)
            except ToolFailure as error:
                for receipt in ("first/receipt.json", "second/receipt.json"):
                    equal(receipt in str(error), True, "all compiler failures remain indexed")
            else:
                equal(True, False, "exhausted candidates cannot succeed")
            loader.assert_not_called()

        evidence.command.reset_mock(side_effect=True)
        evidence.command.return_value = (root / "invalid", {"exit_code": 0})
        with patch("compiler.ROOT", root), \
                patch("compiler.discover", return_value=candidates), \
                patch("compiler.load_elf", side_effect=ToolFailure("synthetic invalid ELF")):
            try:
                compile_benchmark(evidence, 5)
            except ToolFailure as error:
                equal(str(error), "synthetic invalid ELF", "invalid ELF diagnostic is not hidden")
            else:
                equal(True, False, "compiler exit zero does not establish a valid ELF")
        equal(evidence.command.call_count, 1, "invalid ELF is not silently replaced")
    print("COMPILER_FALLBACK_FIXTURES compared=3; synthetic only; no compiler or RTL executed")


def compiler_failure_propagation_checks():
    with tempfile.TemporaryDirectory(prefix="hammer-compiler-failure-fixture-") as directory:
        root = Path(directory)
        evidence = Mock(directory=root)
        missing = ToolFailure("PREREQUISITE_MISSING: synthetic unavailable compiler")
        with patch("compiler.discover", side_effect=missing), \
                patch("compiler.fresh") as create_output, \
                patch("compiler.load_elf") as loader:
            try:
                compile_benchmark(evidence, 5)
            except ToolFailure as error:
                equal(error is missing, True, "missing compiler preserves original failure")
            else:
                equal(True, False, "missing compiler cannot return a benchmark")
            evidence.command.assert_not_called()
            create_output.assert_not_called()
            loader.assert_not_called()

        for label in ("launch failure", "timeout"):
            failure = ToolFailure(f"synthetic compiler {label}; retained receipt")
            evidence.command.reset_mock(side_effect=True)
            evidence.command.side_effect = failure
            with patch("compiler.ROOT", root), \
                    patch("compiler.discover", return_value=[
                        "/fixture/clang", "/fixture/clang-18"]), \
                    patch("compiler.load_elf") as loader:
                try:
                    compile_benchmark(evidence, 5)
                except ToolFailure as error:
                    equal(error is failure, True, f"compiler {label} preserves original failure")
                else:
                    equal(True, False, f"compiler {label} cannot return a benchmark")
                equal(evidence.command.call_count, 1,
                      f"compiler {label} is not a completed negative compilation")
                loader.assert_not_called()
    print("COMPILER_FAILURE_FIXTURES compared=3; synthetic only; no compiler or RTL executed")


def compiler_elf_checks():
    image = bytearray(528)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0,
                     ident, 2, 243, 1, 0, 64, 192, 0, 64, 56, 2, 64, 3, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 512, 0, 0, 4, 4, 4)
    struct.pack_into("<IIQQQQQQ", image, 120,
                     1, 6, 520, 0x10000000, 0x10000000, 8, 16, 8)
    names = b"\0results\0_halt\0"
    image[400:400 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", image, 256,
                     0, 3, 0, 0, 400, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", image, 320,
                     0, 2, 0, 0, 432, 72, 1, 1, 8, 24)
    struct.pack_into("<IBBHQQ", image, 456, 1, 0x11, 0, 1, 0x10000000, 8)
    struct.pack_into("<IBBHQQ", image, 480, 9, 0x12, 0, 1, 0, 4)
    image[512:516] = b"\x13\x00\x00\x00"
    image[520:528] = (123).to_bytes(8, "little")
    path = Path("synthetic-abi-fixture.elf")
    with patch.object(Path, "read_bytes", return_value=bytes(image)):
        code, memory, symbols, actual_path = load_elf(path)
    equal(code[0], 0x13, "ELF fixture instruction segment")
    equal(memory[0], 123, "ELF fixture initialized data")
    equal(memory[1], 0, "ELF fixture zero-filled BSS")
    equal(symbols["results"], 0x10000000, "ELF fixture results symbol")
    equal(symbols["_halt"], 0, "ELF fixture halt symbol")
    equal(actual_path, path, "ELF fixture identity")
    invalid = []
    for label, offset, fmt, value in (
            ("missing executable segment", 64, "<I", 0),
            ("non-executable entry", 68, "<I", 4),
            ("relocatable image", 16, "<H", 1),
            ("bad ELF version", 20, "<I", 0),
            ("bad header size", 52, "<H", 0),
            ("bad program entry size", 54, "<H", 0),
            ("program table outside file", 32, "<Q", len(image)),
            ("bad section entry size", 58, "<H", 0),
            ("section table outside file", 40, "<Q", len(image)),
            ("segment payload outside file", 72, "<Q", len(image)),
            ("segment file larger than memory", 96, "<Q", 8),
            ("segment high-address alias", 80, "<Q", 1 << 32),
            ("invalid string-table index", 360, "<I", 3),
            ("bad symbol entry size", 376, "<Q", 0),
            ("string table outside file", 280, "<Q", len(image)),
            ("symbol table outside file", 344, "<Q", len(image)),
            ("symbol name outside strings", 456, "<I", len(names)),
            ("unaligned halt symbol", 488, "<Q", 2),
            ("unloaded results symbol", 464, "<Q", 0x10000010)):
        corrupted = bytearray(image)
        struct.pack_into(fmt, corrupted, offset, value)
        invalid.append((label, bytes(corrupted)))
    corrupted = bytearray(image)
    corrupted[400 + len(names) - 1] = ord("x")
    invalid += [("truncated header", bytes(image[:32])),
                ("unterminated symbol name", bytes(corrupted))]
    for flags in (1, 2, 4, 8, 16, 0x80000000):
        corrupted = bytearray(image)
        struct.pack_into("<I", corrupted, 48, flags)
        invalid.append((f"unsupported ABI flags={flags:#x}", bytes(corrupted)))
    for label, corrupted in invalid:
        with patch.object(Path, "read_bytes", return_value=corrupted):
            try:
                load_elf(path)
            except ToolFailure as error:
                equal(bool(str(error)), True, f"ELF rejection diagnostic: {label}")
            else:
                equal(True, False, f"ELF accepted {label}")
    print(f"COMPILER_ELF_FIXTURES valid=1 rejected={len(invalid)}; no compiler or RTL executed")


def main():
    portable_prerequisite_checks()
    interrupted_command_checks()
    prerequisite_receipt_checks()
    compiler_selection_checks()
    compiler_fallback_checks()
    compiler_failure_propagation_checks()
    compiler_elf_checks()
    cases = (
        ("ADD", MASK, 1, 0), ("SUB", 0, 1, MASK),
        ("ADDW", 0x7fffffff, 1, 0xffffffff80000000),
        ("SRAW", 0x80000000, 31, MASK),
        ("SRLW", 0x80000000, 31, 1),
        ("MULH", 1 << 63, 1 << 63, 1 << 62),
        ("MULHSU", MASK, MASK, MASK),
        ("MULHU", MASK, MASK, MASK - 1),
        ("DIV", MASK - 6, 3, MASK - 1), ("REM", MASK - 6, 3, MASK),
        ("DIV", 7, MASK - 2, MASK - 1), ("REM", 7, MASK - 2, 1),
        ("DIV", 1 << 63, MASK, 1 << 63), ("REM", 1 << 63, MASK, 0),
        ("DIVU", 17, 0, MASK), ("DIV", MASK - 6, 0, MASK),
        ("REM", MASK - 6, 0, MASK - 6),
        ("DIVW", 0x80000000, MASK, 0xffffffff80000000),
        ("REMW", 0x80000000, MASK, 0),
        ("DIVUW", 1 << 32, 1, 0), ("REMUW", 0x80000000, 0, 0xffffffff80000000),
    )
    for name, a, b, expected in cases:
        equal(arithmetic(name, a, b, 0, 0), expected, f"analytical anchor {name}")
    for name in ("ADD", "SUB", "SLL", "SLT", "SLTU", "XOR", "SRL", "SRA",
                 "OR", "AND", "MUL", "MULH", "MULHSU", "MULHU", "DIV",
                 "DIVU", "REM", "REMU", "ADDW", "SUBW", "SLLW", "SRLW",
                 "SRAW", "MULW", "DIVW", "DIVUW", "REMW", "REMUW"):
        equal(decode(r(name, 3, 1, 2)).name, name, "assembler/decoder mnemonic")
    equal(decode(i("SLLI", 1, 2, 32)).name, "SLLI", "RV64 shift bit five is legal")
    equal(decode(0x04001013).name, "ILLEGAL", "reserved RV64 shift upper bits")
    print(f"ORACLE_ANCHORS compared={len(cases)}")


if __name__ == "__main__":
    main()
