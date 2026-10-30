#!/usr/bin/env python3
"""Independent released-edge scheduling primitives for the system oracle.

Time here is not an instruction count. All inputs are frozen before execution,
samples precede updates, and clock counters continue during resource stalls.
These components are not yet a full-system execution engine: fetch/pipeline,
cache/PTW/fabric scheduling and the final expectation-generation CLI remain
unimplemented. Do not use this module's component checks as Linux acceptance.
"""

from collections import deque
from dataclasses import dataclass
from enum import IntEnum
import hashlib
import heapq
import json
from pathlib import Path


BOUND = 4294967296
MASK = (1 << 64) - 1
SEEDS = (11, 29, 47)
CHANNELS = ("aw", "w", "b", "ar", "r")
IMAGE_LAYOUT = (
    ("fw_jump.bin", 0x80000000, 0x80200000),
    ("Image", 0x80200000, 0x87E00000),
    ("hammer-v4.dtb", 0x87E00000, 0x88000000),
)


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def project_file(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or any(
        part in (".git", ".vulcan", ".tooling", "VULCAN") for part in path.parts
    ):
        raise ValueError(f"Not a deliverable-relative path: {relative}")
    resolved = (root / path).resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError(f"Input escapes project or is not a file: {relative}")
    return resolved


def load_images(root, manifest_path):
    """Bind immutable input bytes, never simulator outputs or old expectations."""
    manifest_path = project_file(root, manifest_path)
    manifest = json.loads(manifest_path.read_text())
    images = []
    for name, address, end in IMAGE_LAYOUT:
        record = manifest["images"][name]
        path = project_file(root, record["path"])
        data = path.read_bytes()
        if not data or len(data) != record["bytes"] or \
                hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise AssertionError(f"Changed software image: {name}")
        if address + len(data) > end:
            raise AssertionError(f"Overlapping/overflowing software image: {name}")
        images.append((name, address, data))
    expected_loads = {(address, manifest["images"][name]["path"])
                      for name, address, _ in IMAGE_LAYOUT}
    actual_loads = {(entry["address"], entry["path"])
                    for entry in manifest["memory_loads"]}
    if expected_loads != actual_loads or len(manifest["memory_loads"]) != 3:
        raise AssertionError("Manifest boot load addresses differ from admitted layout")
    return manifest, tuple(images)


def stall(seed, channel, ordinal, beat=0):
    """Channel-separated counter draw; calls on one channel affect no other."""
    if seed not in SEEDS or channel not in CHANNELS or \
            type(ordinal) is not int or ordinal < 0 or type(beat) is not int or beat < 0:
        raise ValueError("Invalid deterministic AXI draw key")
    key = f"HAMMER-V4/axi/v1/{seed}/{channel}/{ordinal}/{beat}\n".encode("ascii")
    return hashlib.sha256(key).digest()[0] & 7


@dataclass(frozen=True)
class Scenario:
    seed: int
    start_edge: int
    rx_first_edge: int
    image_hashes: tuple
    rx_data: bytes = b"v4\n"
    rx_spacing: int = 10000

    def __post_init__(self):
        if self.seed not in SEEDS or not 0 <= self.start_edge < self.rx_first_edge < BOUND:
            raise ValueError("Illegal seed or released-edge schedule")
        if self.rx_data != b"v4\n" or self.rx_spacing < 161:
            raise ValueError("The admitted boot RX workload must remain v4\\n at 8N1")
        if self.rx_first_edge + (len(self.rx_data) - 1) * self.rx_spacing + 160 >= BOUND:
            raise ValueError("RX waveform exceeds the continuous edge bound")
        expected_names = tuple(name for name, _, _ in IMAGE_LAYOUT)
        if tuple(name for name, _ in self.image_hashes) != expected_names or any(
            not isinstance(value, str) or len(value) != 64 or
            any(char not in "0123456789abcdef" for char in value)
            for _, value in self.image_hashes
        ):
            raise ValueError("Scenario must bind exactly the loaded image hashes")

    def document(self):
        return {
            "schema": 1, "seed": self.seed, "clock_period_ns": 10,
            "reset_edges": 4, "first_released_edge": 0, "bound": BOUND,
            "start_edge": self.start_edge,
            "images": dict(self.image_hashes),
            "rx": {"first_edge": self.rx_first_edge, "data_hex": self.rx_data.hex(),
                   "spacing_edges": self.rx_spacing, "bit_edges": 16,
                   "format": "8N1"},
            "external_irqs": [
                {"edge": self.rx_first_edge - 1, "plic_sources": 1},
                {"edge": self.rx_first_edge + 13 + self.seed, "plic_sources": 0},
            ],
            "axi": {"draw": "sha256-first-byte-low-3",
                    "key": "HAMMER-V4/axi/v1/{seed}/{channel}/{ordinal}/{beat}\\n",
                    "channels": list(CHANNELS), "max_stall_edges": 7},
        }

    def freeze(self, directory):
        """Create, never replace, the scenario used by an individual run."""
        path = directory / "scenario.json"
        with path.open("xb") as stream:
            stream.write(canonical_json(self.document()))
        return digest(path)

    @classmethod
    def read(cls, path):
        document = json.loads(Path(path).read_text())
        result = cls(
            document["seed"], document["start_edge"], document["rx"]["first_edge"],
            tuple((name, document["images"][name]) for name, _, _ in IMAGE_LAYOUT),
            bytes.fromhex(document["rx"]["data_hex"]), document["rx"]["spacing_edges"],
        )
        if document != result.document():
            raise ValueError("Unknown, modified or incomplete scenario contract")
        return result

    def rx_transitions(self):
        transitions, previous = [], 1
        for index, byte in enumerate(self.rx_data):
            first = self.rx_first_edge + index * self.rx_spacing
            bits = [0, *[(byte >> bit) & 1 for bit in range(8)], 1]
            for bit, level in enumerate(bits):
                if level != previous:
                    transitions.append((first + bit * 16, level))
                    previous = level
        return tuple(transitions)


class Phase(IntEnum):
    DRIVE = -1
    SAMPLE = 0
    UPDATE = 1
    OBSERVE = 2


class EdgeBoundExceeded(RuntimeError):
    pass


class Clock:
    """Discrete events with one continuous, immutable released-edge bound."""

    def __init__(self):
        self._events = []
        self._ordinal = 0
        self.edge = -1
        self.phase = Phase.OBSERVE
        self.callbacks = 0

    def schedule(self, edge, phase, callback):
        if type(edge) is not int or not 0 <= edge < BOUND:
            raise EdgeBoundExceeded(f"Released edge outside [0,{BOUND}): {edge}")
        phase = Phase(phase)
        if edge < self.edge or edge == self.edge and phase <= self.phase:
            raise ValueError("Cannot schedule into a sampled/published clock phase")
        if not callable(callback):
            raise TypeError("An event requires an executable callback")
        heapq.heappush(self._events, (edge, phase, self._ordinal, callback))
        self._ordinal += 1

    def run(self, through):
        if type(through) is not int or not self.edge <= through < BOUND:
            raise EdgeBoundExceeded("Invalid continuous run boundary")
        while self._events and self._events[0][0] <= through:
            edge, phase, _, callback = heapq.heappop(self._events)
            self.edge, self.phase = edge, phase
            callback()
            self.callbacks += 1
        self.edge, self.phase = through, Phase.OBSERVE


class Counter:
    """Counter samples are pre-edge; writes override that edge's increment."""

    def __init__(self):
        self._origin = 0
        self._value = 0
        self._last_sample = -1

    def sample(self, edge):
        if not self._origin <= edge < BOUND or edge < self._last_sample:
            raise ValueError("Counter sampled outside the continuous clock history")
        self._last_sample = edge
        return (self._value + edge - self._origin) & MASK

    def write(self, edge, value, strobes=255):
        if not 0 <= value <= MASK or not 0 <= strobes <= 255:
            raise ValueError("Counter data/strobes exceed bus width")
        before = self.sample(edge)
        if strobes:
            mask = sum(255 << (8 * lane) for lane in range(8) if strobes >> lane & 1)
            self._value = (before & ~mask) | (value & mask)
        else:
            self._value = (before + 1) & MASK
        self._origin = edge + 1


@dataclass(frozen=True)
class Response:
    edge: int
    data: int
    error: bool


class Clint:
    """CLINT acceptance snapshots and registered, backpressure-held responses."""

    def __init__(self, clock):
        self.clock = clock
        self.time = Counter()
        self.compare = MASK
        self.software = 0
        self.response = None
        self._requested = set()

    def pending(self, edge):
        return self.time.sample(edge) >= self.compare

    def request(self, edge, address, size=3, write=False, data=0, strobes=255):
        if edge in self._requested:
            raise ValueError("Multiple CLINT requests at the same edge")
        if type(size) is not int or not 0 <= size <= 3 or \
                not 0 <= data <= MASK or not 0 <= strobes <= 255:
            raise ValueError("CLINT request exceeds public bus width")
        self._requested.add(edge)

        def sample():
            self._requested.remove(edge)
            if self.response is not None:
                raise AssertionError("CLINT request before previous response acceptance")
            base, width = address & ~7, 1 << size
            extent = 4 if base == 0x02000000 else 8
            legal = base in (0x02000000, 0x02004000, 0x0200BFF8) and \
                address % width == 0 and address % 8 + width <= extent
            snapshots = {0x02000000: self.software, 0x02004000: self.compare,
                         0x0200BFF8: self.time.sample(edge)}
            value = snapshots.get(base, 0) if legal else 0

            def update():
                if legal and write:
                    mask = sum(255 << (8 * lane) for lane in range(8)
                               if strobes >> lane & 1)
                    if base == 0x0200BFF8:
                        self.time.write(edge, data, strobes)
                    elif base == 0x02004000:
                        self.compare = (value & ~mask) | (data & mask)
                    elif strobes & 1:
                        self.software = data & 1
                self.response = Response(edge, value, not legal)
            self.clock.schedule(edge, Phase.UPDATE, update)
        self.clock.schedule(edge, Phase.SAMPLE, sample)

    def accept_response(self, edge):
        def sample():
            if self.response is None or self.response.edge >= edge:
                raise AssertionError("CLINT response consumed before a registered edge")
            self.clock.schedule(edge, Phase.UPDATE, self._clear_response)
        self.clock.schedule(edge, Phase.SAMPLE, sample)

    def _clear_response(self):
        self.response = None


class Plic:
    """Independent level-source/synchronizer/claim model for the two contexts."""

    def __init__(self, clock):
        self.clock = clock
        self.priority = [0] * 33
        self.enable = [0, 0]
        self.threshold = [0, 0]
        self.sources = 0
        self.meta = 0
        self.sync = 0
        self.pending = 0
        self.service = {}
        self.irq = (False, False)
        self.claims = []
        self.completions = []
        self._scheduled = set()
        self._actions = {}

    def winner(self, context):
        if context not in (0, 1):
            raise ValueError("Illegal PLIC context")
        eligible = self.pending & self.enable[context]
        candidates = [source for source in range(1, 33)
                      if eligible >> source & 1 and source not in self.service and
                      self.priority[source] > self.threshold[context]]
        return max(candidates, key=lambda source: (self.priority[source], -source),
                   default=0)

    def set_sources(self, edge, mask):
        if not 0 <= mask < 1 << 33 or mask & 1:
            raise ValueError("PLIC sources must use IDs 1 through 32")

        def drive():
            self.sources = mask
            self._tick(edge)
        self.clock.schedule(edge, Phase.DRIVE, drive)

    def configure(self, edge, *, source=None, priority=None, context=None,
                  enable=None, threshold=None):
        if source is not None and (not 1 <= source <= 32 or
                                   type(priority) is not int or not 0 <= priority <= 7):
            raise ValueError("Illegal PLIC source/priority")
        if priority is not None and source is None:
            raise ValueError("Priority requires a source")
        if (enable is not None or threshold is not None) and context not in (0, 1):
            raise ValueError("PLIC configuration requires a context")
        if enable is not None and (not 0 <= enable < 1 << 33 or enable & 1):
            raise ValueError("Illegal PLIC enable mask")
        if threshold is not None and not 0 <= threshold <= 7:
            raise ValueError("Illegal PLIC threshold")
        self._action(edge, ("configure", source, priority, context, enable, threshold))

    def claim(self, edge, context):
        if context not in (0, 1):
            raise ValueError("Illegal PLIC claim context")
        self._action(edge, ("claim", context))

    def complete(self, edge, context, source):
        if context not in (0, 1) or not 0 <= source <= 32:
            raise ValueError("Illegal PLIC completion")
        self._action(edge, ("complete", context, source))

    def _action(self, edge, action):
        if edge in self._actions:
            raise ValueError("PLIC exposes one bus request per edge")
        self._actions[edge] = [action]
        self._tick(edge)

    def _tick(self, edge):
        if edge in self._scheduled:
            return
        self._scheduled.add(edge)

        def sample():
            self._scheduled.remove(edge)
            selected = (self.winner(0), self.winner(1))
            pending = self.pending
            for source in range(1, 33):
                if self.sync >> source & 1 and source not in self.service:
                    pending |= 1 << source
            service = dict(self.service)
            actions = self._actions.pop(edge, [])
            def update():
                self.meta, self.sync = self.sources, self.meta
                self.irq = tuple(bool(value) for value in selected)
                self.pending = pending
                self.service = service
                for action in actions:
                    if action[0] == "configure":
                        _, source, priority, context, enable, threshold = action
                        if source is not None:
                            self.priority[source] = priority
                        if enable is not None:
                            self.enable[context] = enable
                        if threshold is not None:
                            self.threshold[context] = threshold
                    elif action[0] == "claim":
                        context = action[1]
                        source = selected[context]
                        if source:
                            self.pending &= ~(1 << source)
                            self.service[source] = context
                        self.claims.append((edge, context, source))
                    else:
                        _, context, source = action
                        if self.service.get(source) == context:
                            del self.service[source]
                            self.completions.append((edge, context, source))
                stable = self.meta == self.sources and self.sync == self.meta and \
                    self.irq == (bool(self.winner(0)), bool(self.winner(1))) and all(
                        not (self.sync >> source & 1) or source in self.service or
                        self.pending >> source & 1 for source in range(1, 33)
                    )
                if not stable:
                    self._tick(edge + 1)
            self.clock.schedule(edge, Phase.UPDATE, update)
        self.clock.schedule(edge, Phase.SAMPLE, sample)


class SerialReceiver:
    """Pin-level 8N1 receiver with two synchronizers and a separate commit edge.

    The admitted console uses a 16-edge bit. This component intentionally has no
    direct byte-input API. Baud/format register scheduling belongs to the UART
    bus model, not to an instruction-stepped platform.
    """

    def __init__(self, clock, receive):
        self.clock = clock
        self.receive = receive
        self.line = 1
        self.meta = 1
        self.sync = 1
        self.active = False
        self._ticks = set()
        self._generation = 0
        self._byte = 0

    def transition(self, edge, level):
        if level not in (0, 1):
            raise ValueError("UART pin is not binary")

        def drive():
            self.line = level
            self._synchronize(edge)
        self.clock.schedule(edge, Phase.DRIVE, drive)

    def _synchronize(self, edge):
        if edge in self._ticks:
            return
        self._ticks.add(edge)

        def sample():
            self._ticks.remove(edge)
            old_meta, old_sync = self.meta, self.sync

            def update():
                self.meta, self.sync = self.line, old_meta
                if not self.active and not old_sync:
                    self.active = True
                    self._generation += 1
                    self._byte = 0
                    self._sample_bit(edge + 8, 0, self._generation)
                if self.meta != self.line or self.sync != self.meta or \
                        not self.active and not self.sync:
                    self._synchronize(edge + 1)
            self.clock.schedule(edge, Phase.UPDATE, update)
        self.clock.schedule(edge, Phase.SAMPLE, sample)

    def _sample_bit(self, edge, position, generation):
        def sample():
            level = self.sync

            def update():
                if generation != self._generation:
                    raise AssertionError("Stale RX frame scheduled after cancellation")
                if position == 0 and level:
                    self.active = False
                    self._synchronize(edge + 1)
                    return
                if 1 <= position <= 8:
                    self._byte |= level << (position - 1)
                if position == 9:
                    byte, error = self._byte, not level

                    def commit():
                        self.receive(edge + 1, byte, error)
                        self.active = False
                        self._synchronize(edge + 2)
                    self.clock.schedule(edge + 1, Phase.UPDATE, commit)
                else:
                    self._sample_bit(edge + 16, position + 1, generation)
            self.clock.schedule(edge, Phase.UPDATE, update)
        self.clock.schedule(edge, Phase.SAMPLE, sample)


class SerialTransmitter:
    """FIFO-to-pin 8N1 serializer; no immediate MMIO-to-output shortcut."""

    def __init__(self, clock, observe):
        self.clock = clock
        self.observe = observe
        self.capacity = 1
        self.queue = deque()
        self.active = False
        self.line = 1
        self._pops = set()
        self._pushes = set()
        self.completed = 0

    @property
    def thre(self):
        return not self.queue

    @property
    def temt(self):
        return not self.queue and not self.active

    def push(self, edge, byte):
        if not 0 <= byte <= 255 or edge in self._pushes:
            raise ValueError("Invalid or duplicate UART THR transaction")
        self._pushes.add(edge)

        def sample():
            self._pushes.remove(edge)
            # Capacity is pre-edge, even when a pop also occurs at this edge.
            if len(self.queue) >= self.capacity:
                raise AssertionError("UART THR request not ready: FIFO full")

            def update():
                self.queue.append(byte)
                if not self.active:
                    self._pop(edge + 1)
            self.clock.schedule(edge, Phase.UPDATE, update)
        self.clock.schedule(edge, Phase.SAMPLE, sample)

    def _pop(self, edge):
        if edge in self._pops:
            return
        self._pops.add(edge)

        def sample():
            self._pops.remove(edge)
            if self.active or not self.queue:
                return
            byte = self.queue[0]

            def update():
                if self.queue.popleft() != byte:
                    raise AssertionError("UART FIFO changed between sample and update")
                self.active = True
                bits = (0, *[(byte >> bit) & 1 for bit in range(8)], 1)
                for position, level in enumerate(bits):
                    if position == 0:
                        self._publish(edge, level)
                    else:
                        self.clock.schedule(
                            edge + position * 16, Phase.UPDATE,
                            lambda e=edge + position * 16, v=level: self._publish(e, v),
                        )

                def idle():
                    self.active = False
                    self.completed += 1
                    self._pop(edge + 161)
                self.clock.schedule(edge + 160, Phase.UPDATE, idle)
            self.clock.schedule(edge, Phase.UPDATE, update)
        self.clock.schedule(edge, Phase.SAMPLE, sample)

    def _publish(self, edge, level):
        self.line = level
        self.clock.schedule(edge, Phase.OBSERVE, lambda: self.observe(edge, level))


@dataclass(frozen=True)
class AxiSchedule:
    ordinal: int
    address: int
    address_edge: int
    data_edge: int | None
    response_valid_after: int
    response_edge: int


class AxiRam:
    """Single-beat external platform, not the core's cache/fabric timing model.

    Request edges designate the first pre-edge assertion of the corresponding
    master VALID. Independent channel draws delay acceptance. A response first
    offered after edge c can be sampled only at c+1. The caller predicts master
    readiness independently; it must not pass measured DUT timing here.
    """

    def __init__(self, clock, seed):
        if seed not in SEEDS:
            raise ValueError("Invalid system seed")
        self.clock, self.seed = clock, seed
        self.memory = bytearray(128 * 1024 * 1024)
        self.reads = self.writes = 0
        self._read_available = self._write_available = 0
        self.recent = deque(maxlen=32)

    def _index(self, address, width):
        if type(address) is not int or type(width) is not int or width <= 0 or \
                address < 0x80000000 or address + width > 0x88000000:
            raise ValueError("External RAM transaction outside admitted memory")
        return address - 0x80000000

    def load(self, images):
        if self.clock.edge != -1 or self.reads or self.writes:
            raise AssertionError("Images must be installed before the released clock")
        for _, address, data in images:
            offset = self._index(address, len(data))
            self.memory[offset:offset + len(data)] = data

    def read(self, address, request_edge, receive):
        if address & 7:
            raise ValueError("External AXI requires aligned 64-bit words")
        offset = self._index(address, 8)
        if request_edge < self._read_available:
            raise AssertionError("Independent master issued before read slot release")
        ordinal = self.reads
        accepted = request_edge + stall(self.seed, "ar", ordinal)
        offered = accepted + stall(self.seed, "r", ordinal)
        response_edge = offered + 1
        if response_edge >= BOUND:
            raise EdgeBoundExceeded("AXI read cannot finish within continuous bound")
        self.reads += 1
        self._read_available = response_edge + 1
        receipt = AxiSchedule(ordinal, address, accepted, None, offered, response_edge)
        self.recent.append(receipt)
        captured = []

        def capture():
            captured.append(int.from_bytes(self.memory[offset:offset + 8], "little"))
        self.clock.schedule(accepted, Phase.SAMPLE, capture)
        self.clock.schedule(response_edge, Phase.SAMPLE,
                            lambda: receive(receipt, captured[0]))
        return receipt

    def write(self, address, address_request_edge, data_request_edge, data, strobes, receive):
        if address & 7 or not 0 <= data <= MASK or not 0 <= strobes <= 255:
            raise ValueError("Invalid external AXI word/strobes")
        offset = self._index(address, 8)
        if min(address_request_edge, data_request_edge) < self._write_available:
            raise AssertionError("Independent master issued before write slot release")
        ordinal = self.writes
        accepted_aw = address_request_edge + stall(self.seed, "aw", ordinal)
        accepted_w = data_request_edge + stall(self.seed, "w", ordinal)
        transfer = max(accepted_aw, accepted_w)
        offered = transfer + stall(self.seed, "b", ordinal)
        response_edge = offered + 1
        if response_edge >= BOUND:
            raise EdgeBoundExceeded("AXI write cannot finish within continuous bound")
        self.writes += 1
        self._write_available = response_edge + 1
        receipt = AxiSchedule(
            ordinal, address, accepted_aw, accepted_w, offered, response_edge
        )
        self.recent.append(receipt)

        def update():
            for lane in range(8):
                if strobes >> lane & 1:
                    self.memory[offset + lane] = data >> (8 * lane) & 255
        self.clock.schedule(transfer, Phase.UPDATE, update)
        self.clock.schedule(response_edge, Phase.SAMPLE, lambda: receive(receipt))
        return receipt


if __name__ == "__main__":
    raise SystemExit(
        "Full-system expectation generation is not available yet. This module "
        "implements clock/scenario/platform components, not the required independent "
        "pipeline/cache/PTW scheduler. No expected UART stream has been generated."
    )
