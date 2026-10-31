#!/usr/bin/env python3
"""Released-edge memory execution for the independent system oracle.

The ordering rules are the registered interface contracts in ARCHITECTURE.md.
Values and permissions come from byte memory and the independent ISA rules,
not RTL state or DUT observations. This is not a core pipeline scheduler.
All response consumers in this module are continuously ready.
"""

from collections import deque
from dataclasses import dataclass, field

from architecture import PageFault, amo, canonical, leaf
from system_oracle import AxiRam, MASK, Phase


@dataclass(frozen=True)
class Word:
    address: int
    data: int = 0
    strobes: int = 0
    write: bool = False
    command: int = 0

    def __post_init__(self):
        if type(self.address) is not int or not 0 <= self.address <= MASK or \
                self.address & 7 or not 0 <= self.data <= MASK or \
                not 0 <= self.strobes <= 255 or type(self.write) is not bool:
            raise ValueError("Invalid aligned memory word transaction")
        if not self.write and (self.data or self.strobes):
            raise ValueError("A read cannot carry write payload")
        if self.command not in (0, 2, 3) or self.command and self.write:
            raise ValueError("Invalid cache maintenance command")


@dataclass(frozen=True)
class Reply:
    edge: int
    data: int = 0
    error: bool = False
    page_fault: bool = False


class Port:
    """Held requests and round-robin transaction ownership, not per-edge polling.

    A request is presented in DRIVE and sampled in SAMPLE. Ownership lasts
    through its registered response acceptance; the next request can accept
    only at the following edge. One owner cannot have two requests pending.
    """

    def __init__(self, clock, owners, serve):
        self.clock, self.owners, self.serve = clock, owners, serve
        self.waiting = {}
        self.live = set()
        self.prefer = 0
        self.busy = False
        self.ticks = set()
        self.accepted = 0
        self.completed = 0
        self.blocked_until = 0
        self.recent = deque(maxlen=32)

    def submit(self, owner, edge, request, receive):
        if owner not in range(self.owners) or owner in self.live or not callable(receive):
            raise ValueError("Invalid owner, duplicate request or missing consumer")
        self.live.add(owner)

        def drive():
            self.waiting[owner] = (request, receive)
            self._dispatch(edge)
        try:
            if edge == self.clock.edge and self.clock.phase == Phase.RESOLVE:
                drive()
            else:
                self.clock.schedule(edge, Phase.DRIVE, drive)
        except (ValueError, RuntimeError):
            self.live.remove(owner)
            raise

    def _dispatch(self, edge):
        edge = max(edge, self.blocked_until)
        if edge in self.ticks or self.busy:
            return
        self.ticks.add(edge)

        def sample():
            self.ticks.remove(edge)
            if self.busy or not self.waiting:
                return
            owner = 0 if self.owners == 1 else next(
                (self.prefer + offset) % self.owners
                for offset in range(self.owners)
                if (self.prefer + offset) % self.owners in self.waiting)
            request, receive = self.waiting.pop(owner)
            self.busy = True
            self.prefer = (owner + 1) % self.owners
            self.accepted += 1
            self.recent.append((edge, owner, request))
            delivered = False

            def finish(reply):
                nonlocal delivered
                if delivered or reply.edge <= edge:
                    raise AssertionError("Duplicate or combinational memory response")
                delivered = True

                def consume():
                    # The callback can publish its own registered result, but
                    # cannot reissue on this port before the next edge.
                    self.live.remove(owner)
                    self.completed += 1
                    receive(reply)

                    def release():
                        self.busy = False
                        if self.waiting:
                            self._dispatch(reply.edge + 1)
                    self.clock.schedule(reply.edge, Phase.UPDATE, release)
                self.clock.schedule(reply.edge, Phase.SAMPLE, consume)
            self.serve(owner, edge, request, finish)
        phase = Phase.ISSUE if edge == self.clock.edge and \
            self.clock.phase == Phase.RESOLVE else Phase.SAMPLE
        self.clock.schedule(edge, phase, sample)


def register_reply(reply, delay=1):
    return Reply(reply.edge + delay, reply.data, reply.error, reply.page_fault)


class RegisteredArbiter:
    def __init__(self, clock, downstream):
        self.downstream = downstream
        self.port = Port(clock, 3, self._serve)

    def _serve(self, owner, edge, request, finish):
        self.downstream.submit(0, edge + 1, request,
                               lambda reply: finish(register_reply(reply)))


class Backing:
    """Shared fabric, registered AXI master and deterministic external RAM."""

    def __init__(self, clock, seed, images=(), rom=b"", dmem_words=8192,
                 imem_words=16384):
        if not 1 <= dmem_words <= 8192 or not 1 <= imem_words <= 16384:
            raise ValueError("Invalid on-chip memory depths")
        if len(rom) > imem_words * 4:
            raise ValueError("Trampoline exceeds instruction memory")
        self.clock = clock
        self.ram = AxiRam(clock, seed)
        self.ram.load(images)
        self.rom = bytearray(imem_words * 4)
        self.rom[:len(rom)] = rom
        self.dmem = bytearray(dmem_words * 8)
        self.rom_known = len(rom)
        self.dmem_known = bytearray(len(self.dmem))
        self.master = Port(clock, 1, self._external)
        self.port = Port(clock, 3, self._fabric)

    def present(self, instruction, address):
        return (0 <= address < len(self.rom) if instruction else
                0x10000000 <= address < 0x10000000 + len(self.dmem)) or \
            0x80000000 <= address < 0x88000000

    def _fabric(self, owner, edge, request, finish):
        address = request.address
        instruction = owner == 0
        if not self.present(instruction, address) or instruction and request.write:
            finish(Reply(edge + 1, error=True))
        elif address >= 0x80000000:
            self.master.submit(0, edge + 1, request,
                               lambda reply: finish(register_reply(reply)))
        else:
            memory, offset = (self.rom, address) if instruction else \
                (self.dmem, address - 0x10000000)
            # The RAM request is accepted one edge after fabric capture.
            # Its synchronous read/pending stages precede the fabric capture.
            def sample():
                extent = min(8, len(memory) - offset)
                known = offset + extent <= self.rom_known if instruction else \
                    all(self.dmem_known[offset:offset + extent])
                if not request.write and not known:
                    raise NotImplementedError(
                        f"Uninitialized on-chip backing read at {address:#x}")
                data = int.from_bytes(memory[offset:offset + 8], "little")
                if request.write:
                    def update():
                        for lane in range(8):
                            if request.strobes >> lane & 1 and offset + lane < len(memory):
                                memory[offset + lane] = request.data >> (8 * lane) & 255
                                self.dmem_known[offset + lane] = 1
                    self.clock.schedule(edge + 1, Phase.UPDATE, update)
                finish(Reply(edge + 4, data))
            self.clock.schedule(edge + 1, Phase.SAMPLE, sample)

    def _external(self, owner, edge, request, finish):
        if request.write:
            self.ram.write(request.address, edge + 1, edge + 1,
                           request.data, request.strobes,
                           lambda receipt: finish(Reply(receipt.response_edge + 1)))
        else:
            self.ram.read(request.address, edge + 1,
                          lambda receipt, data: finish(Reply(receipt.response_edge + 1, data)))


@dataclass
class CacheLine:
    base: int = 0
    valid: bool = False
    dirty: bool = False
    data: bytearray = field(default_factory=lambda: bytearray(32))


class Cache:
    """Physical 32-byte direct-mapped storage with scheduled word transfers."""

    def __init__(self, clock, backing, instruction=False, lines=64):
        if lines not in (1, 4, 16, 64):
            raise ValueError("Invalid cache line count")
        self.clock, self.backing, self.instruction = clock, backing, instruction
        self.lines = [CacheLine() for _ in range(lines)]
        self.port = Port(clock, 1, self._serve)
        self.hits = self.misses = self.writebacks = 0

    def _serve(self, owner, edge, request, finish):
        if request.command:
            self._maintain(edge, request.command == 3, finish)
            return
        if not self.backing.present(self.instruction, request.address) or \
                self.instruction and request.write:
            finish(Reply(edge + 2, error=True))
            return
        base = request.address & ~31
        line = self.lines[(base // 32) % len(self.lines)]

        def lookup():
            if line.valid and line.base == base:
                self.hits += 1
                self._hit(line, request, edge + 1, finish)
                return
            self.misses += 1
            first = edge + 2
            if line.valid and line.dirty:
                self._writeback(line, first, lambda next_edge: refill(next_edge))
            else:
                self._invalidate(line, edge + 1)
                refill(first)

        def refill(first):
            def beat(index, issue_edge):
                address = base + 8 * index

                def received(reply):
                    if reply.error:
                        finish(register_reply(reply))
                        return
                    store_edge = reply.edge + 1

                    def store():
                        line.data[8 * index:8 * index + 8] = reply.data.to_bytes(8, "little")
                        if index == 3:
                            line.base, line.valid, line.dirty = base, True, False
                            # Re-read synchronous tag/data, then service the hit.
                            self.clock.schedule(store_edge + 2, Phase.SAMPLE,
                                                lambda: self._hit(
                                                    line, request, store_edge + 2, finish))
                        else:
                            beat(index + 1, store_edge + 1)
                    self.clock.schedule(store_edge, Phase.UPDATE, store)
                if self.backing.present(self.instruction, address):
                    self.backing.port.submit(int(not self.instruction), issue_edge,
                                             Word(address), received)
                else:
                    # A partial on-chip terminal line has zero absent words,
                    # with the same registered fill-store edge, not a wrap.
                    def absent():
                        received(Reply(issue_edge))
                    self.clock.schedule(issue_edge, Phase.SAMPLE, absent)
            beat(0, first)

        self.clock.schedule(edge + 1, Phase.SAMPLE, lookup)

    def _invalidate(self, line, edge):
        self.clock.schedule(edge, Phase.UPDATE,
                            lambda: self._clear(line))

    @staticmethod
    def _clear(line):
        line.valid = line.dirty = False

    def _writeback(self, line, first, complete, invalidate=True):
        def beat(index, issue_edge):
            address = line.base + 8 * index
            data = int.from_bytes(line.data[8 * index:8 * index + 8], "little")

            def received(reply):
                if reply.error:
                    raise AssertionError("Backing writeback failed in provisioned RAM")
                if index == 3:
                    def cleaned():
                        line.dirty = False
                        if invalidate:
                            line.valid = False
                    self.clock.schedule(reply.edge, Phase.UPDATE, cleaned)
                    complete(reply.edge + 1)
                else:
                    beat(index + 1, reply.edge + 1)
            # Each victim word needs a synchronous read edge before issue.
            self.writebacks += 1
            self.backing.port.submit(int(not self.instruction), issue_edge + 1,
                                     Word(address, data, 255, True), received)
        beat(0, first)

    def _maintain(self, edge, invalidate, finish):
        def scan(index, lookup_edge):
            def check():
                line = self.lines[index]

                def advance(next_edge):
                    def sample_next():
                        if index + 1 == len(self.lines):
                            finish(Reply(next_edge + 1))
                        else:
                            scan(index + 1, next_edge + 1)
                    self.clock.schedule(next_edge, Phase.SAMPLE, sample_next)

                if line.valid and line.dirty and not self.instruction:
                    self._writeback(line, lookup_edge + 2, advance, invalidate)
                else:
                    if invalidate:
                        self._invalidate(line, lookup_edge + 1)
                    advance(lookup_edge + 2)
            self.clock.schedule(lookup_edge + 1, Phase.SAMPLE, check)
        scan(0, edge + 1)

    def _hit(self, line, request, edge, finish):
        offset = request.address & 31
        data = int.from_bytes(line.data[offset:offset + 8], "little")
        if request.write:
            def update():
                for lane in range(8):
                    if request.strobes >> lane & 1:
                        line.data[offset + lane] = request.data >> (8 * lane) & 255
                line.dirty |= bool(request.strobes)
            self.clock.schedule(edge, Phase.UPDATE, update)
            data = 0
        finish(Reply(edge + 1, data))


@dataclass(frozen=True)
class Mapping:
    va: int
    ppn: int
    level: int
    flags: int
    asid: int

    def contains(self, va):
        size = 4096 * 512 ** self.level
        return va // size == self.va // size


@dataclass(frozen=True)
class TranslationRequest:
    address: int
    access: str
    satp: int
    status: int
    privilege: int

    def __post_init__(self):
        if self.access not in ("fetch", "load", "store", "atomic") or \
                self.privilege not in (0, 1, 3) or \
                any(type(value) is not int or not 0 <= value <= MASK
                    for value in (self.address, self.satp, self.status)):
            raise ValueError("Invalid architectural translation request")
        if self.satp >> 60 not in (0, 8):
            raise ValueError("Unsupported satp mode")

    @property
    def effective_privilege(self):
        if self.access != "fetch" and self.privilege == 3 and self.status & (1 << 17):
            return self.status >> 11 & 3
        return self.privilege


@dataclass(frozen=True)
class AtomicRequest:
    translation: TranslationRequest
    width: int
    value: int
    operation: int

    def __post_init__(self):
        access = "load" if self.operation == 2 else "store" if self.operation == 3 else "atomic"
        if self.operation not in (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28) or \
                self.width not in (4, 8) or self.translation.address % self.width or \
                self.translation.access != access or not 0 <= self.value <= MASK:
            raise ValueError("Invalid aligned architectural atomic request")


class Translation:
    """Separate port/TLB lookups and one shared, cached three-level walker.

    Permission evaluation is shared with architecture.py, not with the RTL.
    The walker sees dirty CPU page tables through the data-cache arbiter.
    Fences must be requested after both translation ports have drained.
    """

    def __init__(self, clock, data, entries=8):
        if entries not in (1, 4, 8, 16):
            raise ValueError("Invalid translation capacity")
        self.clock, self.data, self.entries = clock, data, entries
        self.tables = [[None] * entries for _ in range(2)]
        self.replacement = [0, 0]
        self.ports = [Port(clock, 1, lambda _, e, r, f, p=p: self._lookup(p, e, r, f))
                      for p in (0, 1)]
        self.walker = Port(clock, 2, self._walk)
        self.hits = self.walks = self.pte_reads = 0

    def _permission(self, request, mapping):
        try:
            return leaf(request.address, mapping.ppn, mapping.level, mapping.flags,
                        request.access, request.effective_privilege,
                        bool(request.status & (1 << 18)),
                        bool(request.status & (1 << 19))).physical, False
        except PageFault:
            return 0, True

    def _lookup(self, port, edge, request, finish):
        def lookup():
            if request.effective_privilege == 3 or request.satp >> 60 == 0:
                fault = bool(request.address >> 56)
                finish(Reply(edge + 3, 0 if fault else request.address, fault))
            elif not canonical(request.address):
                finish(Reply(edge + 3, page_fault=True))
            else:
                asid = request.satp >> 44 & 65535
                mapping = next((entry for entry in self.tables[port] if entry and
                                (entry.flags & 32 or entry.asid == asid) and
                                entry.contains(request.address)), None)
                if mapping:
                    self.hits += 1
                    physical, fault = self._permission(request, mapping)
                    finish(Reply(edge + 3, physical, page_fault=fault))
                else:
                    self.walker.submit(port, edge + 3, request,
                                       lambda reply: finish(register_reply(reply)))
        self.clock.schedule(edge + 2, Phase.SAMPLE, lookup)

    def _walk(self, port, edge, request, finish):
        self.walks += 1
        asid = request.satp >> 44 & 65535

        def level(table, depth, address_edge, global_mapping):
            address = table * 4096 + 8 * (request.address // (4096 * 512 ** depth) % 512)
            self.pte_reads += 1

            def received(reply):
                classify_edge = reply.edge + 1

                def classify():
                    pte = reply.data
                    flags = pte & 255
                    ppn = pte >> 10 & ((1 << 44) - 1)
                    if reply.error:
                        finish(Reply(classify_edge + 2, error=True))
                    elif pte >> 54 or not flags & 1 or flags & 4 and not flags & 2:
                        finish(Reply(classify_edge + 2, page_fault=True))
                    elif flags & 10:
                        mapping = Mapping(request.address, ppn, depth,
                                          flags | (32 if global_mapping else 0), asid)
                        physical, fault = self._permission(request, mapping)
                        if not fault:
                            # PTW response is consumed here; TLB refill and
                            # registered MMU response occur on this edge.
                            self.clock.schedule(classify_edge + 2, Phase.UPDATE,
                                                lambda: self._refill(port, mapping))
                        finish(Reply(classify_edge + 2, physical, page_fault=fault))
                    elif depth == 0 or flags & (16 | 64 | 128):
                        finish(Reply(classify_edge + 2, page_fault=True))
                    else:
                        level(ppn, depth - 1, classify_edge + 1,
                              global_mapping or bool(flags & 32))
                self.clock.schedule(classify_edge, Phase.SAMPLE, classify)
            self.data.port.submit(1, address_edge + 1, Word(address), received)
        level(request.satp & ((1 << 44) - 1), 2, edge + 1, False)

    def _refill(self, port, mapping):
        table = self.tables[port]
        slot = next((index for index, value in enumerate(table) if value is None),
                    self.replacement[port])
        for index, old in enumerate(table):
            if old and (old.flags & 32 or mapping.flags & 32 or old.asid == mapping.asid) and \
                    (old.contains(mapping.va) or mapping.contains(old.va)):
                table[index] = None
        table[slot] = mapping
        self.replacement[port] = (slot + 1) % self.entries

    def invalidate(self, edge, va=None, asid=None):
        if any(port.live for port in self.ports) or self.walker.live:
            raise AssertionError("Translation invalidation requires drained ports")

        def update():
            for port, table in enumerate(self.tables):
                for index, mapping in enumerate(table):
                    if mapping and (va is None or mapping.contains(va)) and (
                        asid is None or not mapping.flags & 32 and mapping.asid == asid
                    ):
                        table[index] = None
                self.replacement[port] = 0
        self.clock.schedule(edge, Phase.UPDATE, update)


class MemoryExecution:
    """Translated RAM, cache maintenance and serialized RV64A operations.

    Requests are virtual byte accesses; cache/fabric transfers remain aligned
    words. This layer preserves instruction word selection, shifted stores and
    fault causes without pretending that one interpreter step is one clock.
    The atomic port starts at atomic-translation acceptance and ends at DONE
    sampling, including the core's registered translation/start boundaries.
    It is not a prediction of fetch/decode/retirement or interrupt admission.
    """

    def __init__(self, clock, seed, images=(), rom=b"", cache_lines=64, mmio=None):
        self.clock = clock
        self.mmio = mmio
        self.backing = Backing(clock, seed, images, rom)
        self.icache = Cache(clock, self.backing, True, cache_lines)
        self.dcache = Cache(clock, self.backing, False, cache_lines)
        self.instruction = RegisteredArbiter(clock, self.icache.port)
        self.data = RegisteredArbiter(clock, self.dcache.port)
        self.translation = Translation(clock, self.data)
        self.ports = [Port(clock, 1, lambda _, e, r, f, p=p: self._serve(p, e, r, f))
                      for p in (0, 1)]
        self.maintenance = Port(clock, 1, self._maintain)
        self.atomic = Port(clock, 1, self._atomic)
        self.atomic_physical = Port(clock, 1, self._atomic_physical)
        self.reservation = None
        self.reservation_invalidations = set()
        self.data_translation = None

    def invalidate_reservation(self, edge):
        if edge in self.reservation_invalidations:
            return
        self.reservation_invalidations.add(edge)
        self.clock.schedule(edge, Phase.UPDATE, lambda: setattr(self, "reservation", None))
        self.clock.schedule(edge, Phase.OBSERVE,
                            lambda: self.reservation_invalidations.remove(edge))

    def _atomic(self, owner, edge, request, finish):
        if not isinstance(request, AtomicRequest):
            raise TypeError("Atomic port requires an AtomicRequest")

        def translated(reply):
            if reply.error or reply.page_fault:
                finish(register_reply(reply))
                return
            if not self.backing.present(False, reply.data):
                finish(Reply(reply.edge + 1, error=True))
                return
            physical = AtomicRequest(
                TranslationRequest(reply.data, request.translation.access, 0, 0, 3),
                request.width, request.value, request.operation,
            )
            self.clock.schedule(
                reply.edge + 2, Phase.SAMPLE,
                lambda: self._atomic_physical(0, reply.edge + 2, physical, finish))
        self.translation.ports[1].submit(0, edge + 1, request.translation, translated)

    def _atomic_physical(self, owner, edge, request, finish):
        if not isinstance(request, AtomicRequest) or \
                request.translation.satp or request.translation.privilege != 3:
            raise ValueError("Physical atomic port requires a Bare M-mode request")
        address, width, operation = request.translation.address, request.width, request.operation
        if not self.backing.present(False, address):
            finish(Reply(edge + 1, error=True))
            return

        def read(result):
            if result.error:
                finish(register_reply(result))
            elif operation == 2:
                def reserve():
                    if result.edge not in self.reservation_invalidations:
                        self.reservation = (address, width)
                self.clock.schedule(result.edge, Phase.UPDATE, reserve)
                finish(register_reply(result))
            else:
                write(result.edge + 2, amo(operation, result.data, request.value, width),
                      result.data)

        def write(issue_edge, value, old):
            def written(result):
                if not result.error:
                    self.clock.schedule(
                        result.edge, Phase.UPDATE,
                        lambda: setattr(self, "reservation", None))
                finish(Reply(result.edge + 1, 0 if result.error else old, result.error))
            self._physical(issue_edge, address, width, value, True, written)

        match = self.reservation == (address, width) and \
            edge not in self.reservation_invalidations
        if operation in (2, 3):
            self.clock.schedule(edge, Phase.UPDATE, lambda: setattr(self, "reservation", None))
        if operation == 3:
            if not match:
                finish(Reply(edge + 1, 1))
            else:
                write(edge + 1, request.value, 0)
        else:
            self._physical(edge + 1, address, width, 0, False, read)

    def _maintain(self, owner, edge, request, finish):
        instruction, invalidate = request
        if type(instruction) is not bool or type(invalidate) is not bool:
            raise ValueError("Maintenance requires instruction/invalidate selectors")
        word = Word(0, command=3 if invalidate else 2)
        if instruction:
            self.instruction.port.submit(
                0, edge + 1, word, lambda reply: finish(register_reply(reply)))
        else:
            self._route(edge + 1, word, lambda reply: finish(register_reply(reply)))

    def _serve(self, port, edge, access, finish):
        request, width, value = access
        if width not in (1, 2, 4, 8) or request.address % width:
            raise ValueError("Misalignment must trap before the memory request")
        if request.access == "fetch" and (port != 0 or width != 4) or \
                request.access != "fetch" and port != 1:
            raise ValueError("Wrong instruction/data port")
        if request.access == "atomic":
            raise ValueError("Read/modify/write requests must use the serialized atomic port")

        def translated(reply):
            if reply.error or reply.page_fault:
                finish(register_reply(reply))
                return
            if port == 1:
                self.data_translation = (reply.edge, request.address, reply.data,
                                         width, request.access)
            if not self.backing.present(port == 0, reply.data):
                if port == 0:
                    finish(Reply(reply.edge + 1, error=True))
                elif self.mmio is None:
                    raise NotImplementedError(f"MMIO scheduling not integrated: {reply.data:#x}")
                else:
                    self.mmio.submit(
                        0, reply.edge + 1,
                        (reply.data, width, request.access == "store", value),
                        lambda result: finish(register_reply(result)))
                return
            if port == 0:
                def fetched(result):
                    raw = result.data >> ((reply.data & 7) * 8) & ((1 << (width * 8)) - 1)
                    finish(Reply(result.edge + 1, raw, result.error, result.page_fault))
                word = Word(reply.data & ~7)
                self.instruction.port.submit(0, reply.edge + 1, word, fetched)
            else:
                self._physical(reply.edge, reply.data, width, value,
                               request.access == "store", finish)
        self.translation.ports[port].submit(0, edge + 1, request, translated)

    def _physical(self, edge, address, width, value, store, finish):
        lane = address & 7
        word = Word(address & ~7, (value << (8 * lane)) & MASK if store else 0,
                    ((1 << width) - 1) << lane if store else 0, store)

        def received(result):
            raw = result.data >> (lane * 8) & ((1 << (width * 8)) - 1)
            finish(Reply(result.edge + 1, 0 if store else raw,
                         result.error, result.page_fault))
        self._route(edge + 1, word, received)

    def _route(self, edge, word, receive):
        # A core data port has only one transaction, so this router cannot
        # contend with itself. PTW contention occurs at the shared arbiter.
        self.data.port.submit(0, edge + 1, word,
                              lambda reply: receive(register_reply(reply)))
