#!/usr/bin/env python3
"""Analytical checks of system-oracle clock components, not Linux acceptance.

No RTL observations, retirement traces or captured UART are read. Full boot
execution and DUT equivalence are deliberately not claimed by these checks.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_oracle import (
    AxiRam, BOUND, CHANNELS, Clint, Clock, Counter, EdgeBoundExceeded,
    IMAGE_LAYOUT, MASK, Phase, Plic, SEEDS, Scenario, SerialReceiver,
    SerialTransmitter, canonical_json, digest, load_images, stall,
)


def rejected(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError(f"Expected {exception.__name__} rejection")


def clock_cases():
    clock, seen, state = Clock(), [], {"value": 0}
    for edge in (0, 3, 1000000000, BOUND - 1):
        clock.schedule(edge, Phase.SAMPLE, lambda e=edge: seen.append(
            ("sample", e, state["value"])
        ))
        clock.schedule(edge, Phase.UPDATE, lambda e=edge: state.update(value=e + 1))
        clock.schedule(edge, Phase.OBSERVE, lambda e=edge: seen.append(
            ("observe", e, state["value"])
        ))
    clock.run(BOUND - 1)
    if seen != [
        ("sample", 0, 0), ("observe", 0, 1),
        ("sample", 3, 1), ("observe", 3, 4),
        ("sample", 1000000000, 4), ("observe", 1000000000, 1000000001),
        ("sample", BOUND - 1, 1000000001), ("observe", BOUND - 1, BOUND),
    ] or clock.callbacks != 12:
        raise AssertionError("Clock phase ordering or event skipping mismatch")
    rejected(lambda: clock.schedule(0, Phase.SAMPLE, lambda: None), ValueError)
    rejected(lambda: clock.run(0), EdgeBoundExceeded)
    rejected(lambda: clock.schedule(BOUND, Phase.SAMPLE, lambda: None),
             EdgeBoundExceeded)
    rejected(lambda: clock.run(BOUND), EdgeBoundExceeded)
    second = Clock()
    second.run(0)
    if second.edge != 0:
        raise AssertionError("A new run did not receive its own c=0 bound")
    return {"phase_observations": len(seen), "callbacks": clock.callbacks,
            "last_edge": clock.edge, "separate_run_first_edge": second.edge,
            "past_or_bound_rejections": 4}


def counter_cases():
    counter = Counter()
    if counter.sample(0) != 0 or counter.sample(2000000000) != 2000000000:
        raise AssertionError("Clock counter depends on number of scheduled callbacks")
    counter.write(2000000000, MASK - 1)
    rejected(lambda: counter.sample(2000000000), ValueError)
    if [counter.sample(edge) for edge in range(2000000001, 2000000005)] != [
        MASK - 1, MASK, 0, 1,
    ]:
        raise AssertionError("Counter write override/wrap mismatch")
    counter.write(2000000004, 0x1234, 1)
    if counter.sample(2000000005) != 0x34:
        raise AssertionError("Counter byte strobe merged an unselected lane")
    counter.write(2000000005, MASK, 0)
    if counter.sample(2000000006) != 0x35:
        raise AssertionError("Zero strobe suppressed the ordinary counter increment")
    return {"sparse_elapsed_edges": 2000000000, "wrap_samples": 4,
            "byte_strobe_comparisons": 2, "post_write_resample_rejected": True}


def clint_cases():
    clock, snapshots = Clock(), []
    clint = Clint(clock)
    clint.request(10, 0x0200BFF8)
    for edge in (10, 11, 99):
        clock.schedule(edge, Phase.OBSERVE, lambda e=edge: snapshots.append(
            (e, clint.response.data, clint.response.error, clint.time.sample(e))
        ))
    clint.accept_response(100)
    clint.request(101, 0x02004000, write=True, data=105)
    clint.accept_response(102)
    interrupts = []
    for edge in (103, 104, 105, 106):
        clock.schedule(edge, Phase.SAMPLE,
                       lambda e=edge: interrupts.append((e, clint.pending(e))))
    clint.request(107, 0x0200BFF8, write=True, data=MASK, strobes=255)
    clint.accept_response(108)
    wrap = []
    for edge in (108, 109, 110):
        clock.schedule(edge, Phase.OBSERVE,
                       lambda e=edge: wrap.append(clint.time.sample(e)))
    clint.request(111, 0x0200BFF9, size=1)
    invalid = []
    clock.schedule(111, Phase.OBSERVE, lambda: invalid.append(clint.response))
    clock.run(111)
    if snapshots != [(10, 10, False, 10), (11, 10, False, 11), (99, 10, False, 99)]:
        raise AssertionError("CLINT snapshots changed under backpressure")
    if interrupts != [(103, False), (104, False), (105, True), (106, True)]:
        raise AssertionError("MTIP used a signed, post-edge or instruction clock")
    if wrap != [MASK, 0, 1]:
        raise AssertionError("CLINT mtime write/wrap mismatch")
    if len(invalid) != 1 or not invalid[0].error or invalid[0].data:
        raise AssertionError("CLINT accepted an invalid-width/alignment request")
    clock2 = Clock()
    failure = Clint(clock2)
    failure.request(0, 0x0200BFF8)
    failure.accept_response(0)
    rejected(lambda: clock2.run(0), AssertionError)
    return {"held_response_samples": len(snapshots),
            "unsigned_timer_boundary_samples": len(interrupts),
            "wrap_samples": len(wrap), "illegal_requests_rejected": 1,
            "same_edge_response_bypass_rejected": True}


def plic_cases():
    clock, observations = Clock(), []
    plic = Plic(clock)
    plic.configure(0, source=1, priority=3)
    plic.configure(1, source=2, priority=3)
    plic.configure(2, context=1, enable=6)
    rejected(lambda: plic.claim(2, 1), ValueError)
    plic.set_sources(2, 6)
    for edge in range(2, 6):
        clock.schedule(edge, Phase.OBSERVE, lambda e=edge: observations.append(
            (e, plic.meta, plic.sync, plic.pending, plic.irq)
        ))
    plic.claim(6, 1)
    plic.complete(7, 0, 1)  # Wrong context must not release the claimed source.
    clock.run(7)
    if observations != [
        (2, 6, 0, 0, (False, False)),
        (3, 6, 6, 0, (False, False)),
        (4, 6, 6, 6, (False, False)),
        (5, 6, 6, 6, (False, True)),
    ]:
        raise AssertionError("PLIC source synchronization/registered IRQ mismatch")
    if plic.claims != [(6, 1, 1)] or plic.service != {1: 1} or plic.completions:
        raise AssertionError("PLIC tie-breaking/claim/context ownership mismatch")
    plic.complete(8, 1, 1)
    clock.run(10)
    if plic.service or plic.completions != [(8, 1, 1)] or plic.pending != 6:
        raise AssertionError("Asserted source did not pend again after completion")
    plic.configure(11, context=1, threshold=3)
    clock.run(12)
    if plic.winner(1) or plic.irq[1]:
        raise AssertionError("PLIC threshold comparison was not strict")
    plic.set_sources(13, 0)
    clock.run(17)
    if plic.pending != 6:
        raise AssertionError("Deasserting a level source incorrectly cleared pending")
    return {"synchronizer_samples": len(observations), "lowest_id_tie_checked": True,
            "claims": plic.claims, "completions": plic.completions,
            "wrong_context_rejected": True, "level_repending_checked": True}


def serial_cases():
    clock, tx, received = Clock(), [], []
    serializer = SerialTransmitter(clock, lambda e, v: tx.append((e, v)))
    serializer.push(0, 0xA5)
    serializer.push(2, 0x5A)
    clock.run(322)
    first_bits = [0, 1, 0, 1, 0, 0, 1, 0, 1, 1]
    second_bits = [0, 0, 1, 0, 1, 1, 0, 1, 0, 1]
    expected = [(1 + index * 16, bit) for index, bit in enumerate(first_bits)] + [
        (162 + index * 16, bit) for index, bit in enumerate(second_bits)
    ]
    if tx != expected or serializer.completed != 2 or not serializer.temt:
        raise AssertionError("UART push/pop gap, frame timing or LSB-first serialization")
    rxclock = Clock()
    receiver = SerialReceiver(rxclock, lambda *args: received.append(args))
    previous = 1
    for edge, level in expected:
        if level != previous:
            receiver.transition(edge, level)
            previous = level
    rxclock.run(322)
    if received != [(156, 0xA5, False), (317, 0x5A, False)]:
        raise AssertionError(f"UART two-stage synchronization/framing: {received}")
    errors = []
    badclock = Clock()
    bad = SerialReceiver(badclock, lambda *args: errors.append(args))
    bad.transition(0, 0)  # Continuous low: zero byte with an invalid stop bit.
    badclock.run(155)
    if errors != [(155, 0, True)]:
        raise AssertionError("UART bad stop was hidden")
    fullclock = Clock()
    full = SerialTransmitter(fullclock, lambda *_: None)
    full.push(0, 1)
    full.push(1, 2)  # FIFO is full pre-edge, despite this edge's first TX pop.
    rejected(lambda: fullclock.run(1), AssertionError)
    return {"exact_tx_bits": len(tx), "decoded_frames": len(received),
            "rx_commit_edges": [entry[0] for entry in received],
            "bad_stop_checked": True, "full_preedge_push_rejected": True}


def scenario_cases(out, images):
    hashes = tuple((name, hashlib.sha256(data).hexdigest()) for name, _, data in images)
    summaries = []
    for seed in SEEDS:
        directory = out / f"seed-{seed}"
        directory.mkdir()
        scenario = Scenario(seed, 100000, 2000000 + seed, hashes)
        frozen = scenario.freeze(directory)
        if Scenario.read(directory / "scenario.json") != scenario:
            raise AssertionError("Scenario round trip changed frozen inputs")
        rejected(lambda: scenario.freeze(directory), FileExistsError)
        original = (directory / "scenario.json").read_bytes()
        if original != canonical_json(scenario.document()):
            raise AssertionError("Scenario encoding is not canonical")
        # A caller cannot silently remove required bounds, change baud or add
        # hidden stimulus fields while retaining a readable scenario.
        bad = scenario.document()
        bad["bound"] = BOUND + 1
        invalid = directory / "invalid-bound.json"
        invalid.write_bytes(canonical_json(bad))
        rejected(lambda: Scenario.read(invalid), ValueError)
        samples = {channel: [stall(seed, channel, ordinal) for ordinal in range(256)]
                   for channel in CHANNELS}
        if any(set(values) != set(range(8)) for values in samples.values()):
            raise AssertionError("AXI deterministic channel draws omit a stall endpoint")
        # Interleaved draws must be invariant to unrelated channel call counts.
        for channel in CHANNELS:
            for ordinal in range(256):
                stall(seed, "r", ordinal + 1000)
                if stall(seed, channel, ordinal) != samples[channel][ordinal]:
                    raise AssertionError("AXI draw depends on global RNG state")
        received, clock = [], Clock()
        receiver = SerialReceiver(clock, lambda *args: received.append(args))
        for edge, value in scenario.rx_transitions():
            receiver.transition(edge, value)
        clock.run(scenario.rx_first_edge + 20160)
        if received != [
            (scenario.rx_first_edge + index * 10000 + 155, value, False)
            for index, value in enumerate(b"v4\n")
        ]:
            raise AssertionError("Frozen RX transitions did not serialize exact workload")
        if digest(directory / "scenario.json") != frozen:
            raise AssertionError("Component execution rewrote the frozen scenario")
        summaries.append({"seed": seed, "scenario_sha256": frozen,
                          "rx_frames": len(received),
                          "channel_draws_checked": 2 * len(CHANNELS) * 256,
                          "all_stalls_0_through_7": True})
    if tuple(name for name, _, _ in images) != tuple(name for name, _, _ in IMAGE_LAYOUT):
        raise AssertionError("Source image set mismatch")
    return summaries


def axi_cases(images):
    results = []
    for seed in SEEDS:
        clock, read, writes = Clock(), [], []
        ram = AxiRam(clock, seed)
        ram.load(images)
        address = 0x87F00000
        ram.memory[address - 0x80000000:address - 0x80000000 + 8] = bytes(range(8))
        write = ram.write(address, 0, 16, 0xFEDCBA9876543210, 0x55,
                          lambda result: writes.append(result))
        expected_write = {
            "address": stall(seed, "aw", 0),
            "data": 16 + stall(seed, "w", 0),
        }
        expected_offer = max(expected_write.values()) + stall(seed, "b", 0)
        if (write.address_edge, write.data_edge, write.response_valid_after,
                write.response_edge) != (
            expected_write["address"], expected_write["data"],
            expected_offer, expected_offer + 1,
        ):
            raise AssertionError("AW/W independence or registered B delay mismatch")
        ram.read(address, 64, lambda record, data: read.append((record, data)))
        clock.run(100)
        expected_bytes = bytes((0x10, 1, 0x54, 3, 0x98, 5, 0xDC, 7))
        if writes != [write] or len(read) != 1 or \
                read[0][1] != int.from_bytes(expected_bytes, "little"):
            raise AssertionError("AXI byte-strobe write/read mismatch")
        if read[0][0].address_edge != 64 + stall(seed, "ar", 0) or \
                read[0][0].response_edge != \
                read[0][0].address_edge + stall(seed, "r", 0) + 1:
            raise AssertionError("AR/R delay or ordinal accounting mismatch")
        if ram.reads != 1 or ram.writes != 1:
            raise AssertionError("AXI transaction conservation mismatch")
        rejected(lambda: ram.read(address + 1, 101, lambda *_: None), ValueError)
        rejected(lambda: ram.read(0x88000000, 101, lambda *_: None), ValueError)
        rejected(lambda: ram.load(images), AssertionError)
        results.append({"seed": seed, "reads": ram.reads, "writes": ram.writes,
                        "independent_aw_w": True, "compared_write_strobes": 0x55,
                        "out_of_range_unaligned_and_reload_rejected": True})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest, images = load_images(ROOT, args.manifest)
    invocation = ["python3", "tests/system_oracle.py", "--manifest", args.manifest,
                  "--scenario", "not-generated.json", "--out", "not-generated"]
    result = subprocess.run(invocation, cwd=ROOT, capture_output=True, check=False)
    (out / "incomplete-cli.stdout.log").write_bytes(result.stdout)
    (out / "incomplete-cli.stderr.log").write_bytes(result.stderr)
    (out / "commands.json").write_text(json.dumps([{
        "argv": invocation, "cwd": ".", "exit_code": result.returncode,
        "scope": "incomplete CLI must reject, not manufacture an expectation",
    }], indent=2) + "\n")
    if result.returncode != 1 or b"No expected UART stream has been generated" \
            not in result.stderr:
        raise AssertionError("Unimplemented full-system CLI returned a success-shaped result")
    results = {
        "scope": "analytical clock/scenario/AXI/serial/peripheral component checks",
        "acceptance_evidence": False,
        "full_system_timed_oracle": False,
        "dut_execution": False,
        "manifest_sha256": digest(ROOT / args.manifest),
        "clock": clock_cases(),
        "counter": counter_cases(),
        "clint": clint_cases(),
        "plic": plic_cases(),
        "serial": serial_cases(),
        "scenarios": scenario_cases(out, images),
        "axi": axi_cases(images),
        "remaining": [
            "independent core fetch/pipeline/dependency/redirect/interrupt-boundary schedule",
            "cache/TLB/PTW/fabric/maintenance and MMIO timing integration",
            "clock-scheduled architectural execution of complete Linux images",
            "final pre-DUT UART expectation generation and immutability receipt",
            "compiled seeded DUT integration and clean full RTL reproduction",
        ],
    }
    (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print("COMPONENT_COMPARISONS_COMPLETE full_system_timed_oracle=false "
          "dut_execution=false seeds=11,29,47", flush=True)


if __name__ == "__main__":
    main()
