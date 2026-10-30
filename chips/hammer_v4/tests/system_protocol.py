#!/usr/bin/env python3
"""Freeze complete oracle outputs before DUT execution; compare without repair.

The producer is the independent scheduler, never a DUT capture. Missing bytes,
timing or coverage are errors, not opportunities to substitute a diagnostic.
"""

from collections import deque
import hashlib
import json

from system_oracle import BOUND, MASK, Scenario, canonical_json, digest, load_images


PANIC_END = (
    b"---[ end Kernel panic - not syncing: Attempted to kill init! "
    b"exitcode=0x00000000 ]---\r\n"
)
MAX_UART_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 1000000
MIN_COVERAGE = {
    "mret_handoff": 1, "fdt_reads": 1, "satp_sv39": 1, "sfence": 1,
    "sret_user": 1, "user_retired": 1, "demand_faults": 3,
    "demand_stores": 1536, "demand_loads": 1536, "syscall_write": 1,
    "syscall_uname": 1, "syscall_getpid": 1, "syscall_exit": 1,
    "supervisor_timers": 3, "timer_rearms": 4,
    "uart_plic_claims": 1, "uart_plic_completions": 1,
}


def natural(value, maximum=MASK):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"Expected an unsigned integer <= {maximum}: {value!r}")
    return value


def coverage_counts(value):
    if not isinstance(value, dict) or set(value) != set(MIN_COVERAGE):
        raise ValueError("Incomplete or unknown full-system coverage bins")
    for name, minimum in MIN_COVERAGE.items():
        if natural(value[name]) < minimum:
            raise AssertionError(f"Missing independently observed coverage: {name}")
    return value


def watches(value):
    if not isinstance(value, list) or not value:
        raise ValueError("The oracle must specify predicted memory observation ranges")
    names = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "start", "end"} or \
                type(item["name"]) is not str:
            raise ValueError("Invalid memory observation range")
        name = item["name"]
        if name not in ("fdt", "uart", "plic_m", "plic_s"):
            raise ValueError("Unknown observation range purpose")
        names.append(name)
        if natural(item["start"]) >= natural(item["end"]):
            raise ValueError("Empty/wrapped observation range")
        if name.startswith("plic_") and item["end"] - item["start"] != 4:
            raise ValueError("PLIC observations must name the exact claim/complete register")
    if not {"fdt", "uart"}.issubset(names) or not {"plic_m", "plic_s"}.intersection(names):
        raise ValueError("Missing predicted FDT, UART or PLIC observation range")
    for index, item in enumerate(value):
        if any(max(item["start"], other["start"]) < min(item["end"], other["end"])
               for other in value[:index]):
            raise ValueError("Overlapping observation ranges have ambiguous coverage")
    return value


def selected_retirement(ordinal, instruction, privilege, memory_address, memory_valid, ranges):
    return ordinal % 4096 == 0 or instruction & 127 in (0x0F, 0x73) or \
        privilege == 0 or memory_valid and any(
            item["start"] <= memory_address < item["end"] for item in ranges
        )


def event_line(kind, *values):
    """Canonical decimal wire format for independently predicted observations.

    R: edge, ordinal, pc, insn, next_pc, privilege, rd_we, rd, rd_data,
       mem_valid, mem_write, mem_addr, mask, mem_wdata, mem_rdata, a0,a1,a2,a7.
    T: edge, pc, cause, tval, target_privilege, interrupt, a0,a1,a7.
    R register snapshots are post-retirement; T snapshots are pre-trap.
    Inactive rd/memory fields are zero, as are load write-fields and store
    read-fields. Unqualified debug payload is not architectural state.
    """
    if kind not in ("R", "T") or len(values) != (19 if kind == "R" else 9):
        raise ValueError("Invalid architectural event shape")
    for value in values:
        natural(value)
    if values[0] >= BOUND:
        raise ValueError("Architectural event exceeds the continuous edge bound")
    if kind == "R":
        _, ordinal, pc, instruction, next_pc, privilege, rd_we, rd, result, valid, write, \
            address, mask, wdata, rdata, *_ = values
        if not ordinal or instruction > 0xFFFFFFFF or privilege not in (0, 1, 3) or \
                rd_we not in (0, 1) or rd > 31 or valid not in (0, 1) or \
                write not in (0, 1) or mask > 255 or pc & 3 or next_pc & 3:
            raise ValueError("Invalid retirement event fields")
        if not rd_we and (rd or result) or not valid and any(
            (write, address, mask, wdata, rdata)
        ) or valid and (write and rdata or not write and (mask or wdata)):
            raise ValueError("Inactive retirement payload is not canonical zero")
    elif values[4] not in (1, 3) or values[5] not in (0, 1) or values[1] & 3:
        raise ValueError("Invalid trap event fields")
    return kind + " " + " ".join(map(str, values)) + "\n"


def parse_event(line):
    if len(line) > 1024:
        raise ValueError("Oversized architectural event")
    fields = line.rstrip("\n").split(" ")
    if len(fields) not in (10, 20):
        raise ValueError("Invalid architectural event field count")
    try:
        values = tuple(int(token, 10) for token in fields[1:])
    except ValueError as error:
        raise ValueError("Non-integer architectural event") from error
    if event_line(fields[0], *values) != line:
        raise ValueError("Noncanonical architectural event encoding")
    return fields[0], values


def event_summary(path, start_edge, final_edge, ranges):
    if not 0 < path.stat().st_size <= MAX_EVENT_BYTES:
        raise ValueError("Missing or oversized expected architectural event stream")
    count, previous_edge, previous_retirement = 0, start_edge, 0
    last_kind_edge = {"R": -1, "T": -1}
    kinds = {"R": 0, "T": 0}
    with path.open("r", encoding="ascii", newline="") as stream:
        for line in stream:
            kind, values = parse_event(line)
            edge = values[0]
            if not previous_edge <= edge <= final_edge or edge <= last_kind_edge[kind]:
                raise ValueError("Architectural event order/final-edge mismatch")
            previous_edge = edge
            last_kind_edge[kind] = edge
            if kind == "R":
                ordinal, instruction, privilege, valid, address = \
                    values[1], values[3], values[5], values[9], values[11]
                if ordinal <= previous_retirement or not selected_retirement(
                    ordinal, instruction, privilege, address, valid, ranges
                ):
                    raise ValueError("Invalid retirement ordering or selection")
                previous_retirement = ordinal
            count += 1
            kinds[kind] += 1
            if count > MAX_EVENTS:
                raise ValueError("Architectural stream exceeds its storage bound")
    if not all(kinds.values()):
        raise ValueError("Expected stream lacks retirement or trap observations")
    return count, kinds


def local_artifact(directory, record, name):
    if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"} or \
            record["path"] != name:
        raise ValueError(f"Invalid expected artifact descriptor: {name}")
    path = directory / name
    if path.is_symlink() or not path.is_file() or path.resolve().parent != directory.resolve():
        raise ValueError(f"Expected artifact is not a local regular file: {name}")
    if natural(record["bytes"]) != path.stat().st_size or record["sha256"] != digest(path):
        raise AssertionError(f"Expected artifact changed: {name}")
    return path


def freeze_expectations(root, manifest_relative, scenario_path, directory):
    """Validate all producer outputs and create a non-replaceable launch seal."""
    manifest_path = root / manifest_relative
    _, images = load_images(root, manifest_relative)
    if scenario_path.is_symlink():
        raise ValueError("Frozen scenario may not be a symlink")
    scenario = Scenario.read(scenario_path)
    if scenario.image_hashes != tuple(
        (name, hashlib.sha256(data).hexdigest()) for name, _, data in images
    ):
        raise AssertionError("Scenario and actual loaded images differ")
    metadata_path = directory / "expectations.json"
    if metadata_path.is_symlink():
        raise ValueError("Expected metadata may not be a symlink")
    metadata = json.loads(metadata_path.read_text())
    fields = {
        "schema", "scope", "scenario_sha256", "manifest_sha256", "images", "seed",
        "bound", "final_edge", "coverage", "watches", "uart", "events", "event_count",
    }
    if set(metadata) != fields or metadata["schema"] != 1 or \
            metadata["scope"] != "independent-clocked-complete-linux" or \
            metadata["seed"] != scenario.seed or metadata["bound"] != BOUND:
        raise ValueError("Not a complete independently clocked system expectation")
    if metadata["scenario_sha256"] != digest(scenario_path) or \
            metadata["manifest_sha256"] != digest(manifest_path) or \
            metadata["images"] != dict(scenario.image_hashes):
        raise AssertionError("Oracle did not bind exactly the frozen workload")
    final_edge = natural(metadata["final_edge"], BOUND - 1)
    if final_edge < scenario.rx_first_edge + 2 * scenario.rx_spacing + 160:
        raise AssertionError("Oracle completion precedes the complete admitted UART input")
    coverage_counts(metadata["coverage"])
    ranges = watches(metadata["watches"])
    uart = local_artifact(directory, metadata["uart"], "expected-uart.bin")
    if not 0 < uart.stat().st_size <= MAX_UART_BYTES:
        raise ValueError("Missing or oversized complete expected UART")
    data = uart.read_bytes()
    if not data.endswith(PANIC_END) or b"HAMMER /init: FAIL" in data or \
            b"HAMMER firmware fatal" in data:
        raise AssertionError("Expected UART is not the successful full PID-1 exit workload")
    events = local_artifact(directory, metadata["events"], "expected-events.txt")
    count, kinds = event_summary(events, scenario.start_edge, final_edge, ranges)
    if natural(metadata["event_count"], MAX_EVENTS) != count:
        raise AssertionError("Expected architectural event count mismatch")
    control = [
        scenario.seed, scenario.start_edge, scenario.rx_first_edge,
        scenario.rx_spacing, final_edge, count, uart.stat().st_size, len(ranges),
    ]
    control_text = " ".join(map(str, control)) + "\n"
    for item in ranges:
        control_text += f"{item['name']} {item['start']} {item['end']}\n"
    with (directory / "control.txt").open("x", encoding="ascii") as stream:
        stream.write(control_text)
    sealed = {
        name: digest(directory / name) for name in (
            "expectations.json", "expected-uart.bin", "expected-events.txt", "control.txt"
        )
    }
    seal = {
        "schema": 1, "scenario_sha256": digest(scenario_path),
        "manifest_sha256": digest(manifest_path), "files": sealed,
        "event_kinds": kinds,
    }
    with (directory / "launch-seal.json").open("xb") as stream:
        stream.write(canonical_json(seal))
    return seal


def unchanged_expectations(directory, seal):
    if json.loads((directory / "launch-seal.json").read_text()) != seal:
        raise AssertionError("Launch seal changed after expectation freeze")
    if any((directory / name).is_symlink() or digest(directory / name) != old
           for name, old in seal["files"].items()):
        raise AssertionError("Frozen expectations changed after DUT launch")


def compare_uart(expected_path, actual_path):
    """Full streaming comparison; retain the first difference, never normalize."""
    offset, context = 0, deque(maxlen=32)
    with expected_path.open("rb") as expected, actual_path.open("rb") as actual:
        while True:
            want, got = expected.read(65536), actual.read(65536)
            if want != got:
                index = next((i for i, pair in enumerate(zip(want, got))
                              if pair[0] != pair[1]), min(len(want), len(got)))
                return {
                    "equal": False, "first_mismatch": offset + index,
                    "before_hex": (bytes(context) + want[:index])[-32:].hex(),
                    "expected_hex": want[index:index + 33].hex(),
                    "actual_hex": got[index:index + 33].hex(),
                }
            if not want:
                return {"equal": True, "bytes": offset}
            context.extend(want)
            offset += len(want)