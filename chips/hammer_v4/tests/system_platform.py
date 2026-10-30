#!/usr/bin/env python3
"""Clocked peripheral register transactions for independent ISA execution.

The router captures a request, presents it to a peripheral on the next edge,
then registers the peripheral response. Values are sampled before side effects.
Unsupported console formats fail explicitly rather than fabricate wire bytes.
"""

from collections import deque

from rv64_reference import ReferencePlatform
from system_memory import Port, Reply
from system_oracle import BOUND, Clint, Counter, MASK, Phase, Plic, SerialReceiver, SerialTransmitter


class Platform:
    def __init__(self, clock, wire):
        self.clock = clock
        self.clint = Clint(clock)
        self.plic = Plic(clock)
        self.cycles = Counter()
        self.transmitter = SerialTransmitter(clock, wire)
        self.receiver = SerialReceiver(clock, self._received)
        self.rx = deque()
        self.ier = self.lcr = self.mcr = self.scr = 0
        self.divisor = 1
        self.fifo = False
        self.trigger = 1
        self.thre_pending = self.overrun = False
        self.external = 0
        self.changed = None
        self.port = Port(clock, 1, self._route)
        self.transactions = deque(maxlen=32)

    @property
    def mtime(self):
        return self.clint.time.sample(self.clock.edge)

    @property
    def mtimecmp(self):
        return self.clint.compare

    @property
    def msip(self):
        return self.clint.software

    def plic_source(self, context):
        return int(self.plic.irq[context])

    def _received(self, edge, byte, error):
        if len(self.rx) < self.transmitter.capacity:
            self.rx.append((byte, 4 if error else 0))
        else:
            self.overrun = True
        self._sources(edge + 1)

    def _sources(self, edge):
        def drive():
            self.plic.sources = self.external << 2 | int(not self.iir() & 1) << 1
            self.plic._tick(edge)
        self.clock.schedule(edge, Phase.DRIVE, drive)

    def set_external(self, edge, mask):
        if not 0 <= mask < 1 << 31:
            raise ValueError("External interrupt vector exceeds 31 sources")

        def drive():
            self.external = mask
            self.plic.sources = mask << 2 | int(not self.iir() & 1) << 1
            self.plic._tick(edge)
        self.clock.schedule(edge, Phase.DRIVE, drive)

    def _timer_changes(self, edge, next_time):
        if self.changed is None:
            return
        self.changed(edge + 1)
        if next_time < self.clint.compare:
            expiry = edge + 1 + self.clint.compare - next_time
            if expiry < BOUND:
                self.changed(expiry)
        wrap = edge + 1 + (1 << 64) - next_time
        if wrap < BOUND:
            self.changed(wrap)

    def iir(self):
        prefix = 0xC0 if self.fifo else 0
        if self.ier & 4 and (self.overrun or self.rx and self.rx[0][1]):
            return prefix | 6
        if self.ier & 1 and len(self.rx) >= self.trigger:
            return prefix | 4
        if self.ier & 2 and self.thre_pending:
            return prefix | 2
        return prefix | 1

    def _route(self, owner, edge, request, finish):
        address, width, store, value = request
        accepted = edge + 1

        def sample():
            self.transactions.append((accepted, address, width, store, value))
            if 0x10010000 <= address < 0x10010100:
                self._uart(accepted, address, width, store, value, finish)
            elif any(base <= address < base + extent for base, extent in (
                (0x02000000, 4), (0x02004000, 8), (0x0200BFF8, 8),
            )):
                self._clint(accepted, address, width, store, value, finish)
            elif 0x0C000000 <= address < 0x10000000:
                self._plic(accepted, address, width, store, value, finish)
            else:
                finish(Reply(accepted + 2, error=True))
        self.clock.schedule(accepted, Phase.SAMPLE, sample)

    def _uart(self, edge, address, width, store, value, finish):
        offset = address - 0x10010000
        if width != 1 or offset not in range(8):
            finish(Reply(edge + 2, error=True))
            return
        dlab = bool(self.lcr & 128)
        if store and offset == 0 and not dlab:
            if len(self.transmitter.queue) >= self.transmitter.capacity:
                self.clock.schedule(edge + 1, Phase.SAMPLE,
                                    lambda: self._uart(edge + 1, address, width,
                                                       store, value, finish))
                return
            if self.lcr != 3 or self.divisor not in (0, 1) or self.mcr & 16:
                raise NotImplementedError("Clocked console currently requires 8N1/divisor one")
            self.transmitter.accept(edge, value)
        read = 0
        if not store:
            if dlab and offset < 2:
                read = self.divisor >> (offset * 8) & 255
            elif offset == 0:
                read = self.rx[0][0] if self.rx else 0
            elif offset == 1:
                read = self.ier
            elif offset == 2:
                read = self.iir()
            elif offset == 3:
                read = self.lcr
            elif offset == 4:
                read = self.mcr
            elif offset == 5:
                read = int(bool(self.rx)) | int(self.overrun) << 1 | \
                    (self.rx[0][1] << 2 if self.rx else 0) | \
                    int(self.transmitter.thre) << 5 | int(self.transmitter.temt) << 6
            elif offset == 6:
                if self.mcr & 16:
                    raise NotImplementedError("Clocked loopback modem status not integrated")
            else:
                read = self.scr

        def update():
            if store:
                if dlab and offset < 2:
                    mask = 255 << (offset * 8)
                    self.divisor = self.divisor & ~mask | value << (offset * 8)
                elif offset == 0:
                    self.thre_pending = False
                elif offset == 1:
                    self.thre_pending = bool(value & 2 and (
                        self.thre_pending or not self.ier & 2 and self.transmitter.thre))
                    self.ier = value & 15
                elif offset == 2:
                    if value & 2 or bool(value & 1) != self.fifo:
                        self.rx.clear()
                        self.overrun = False
                    if value & 4 or bool(value & 1) != self.fifo:
                        self.transmitter.queue.clear()
                        self.thre_pending = bool(self.ier & 2)
                    self.fifo = bool(value & 1)
                    self.transmitter.capacity = 16 if self.fifo else 1
                    self.trigger = (1, 4, 8, 14)[value >> 6] if self.fifo else 1
                elif offset == 3:
                    self.lcr = value
                elif offset == 4:
                    self.mcr = value & 31
                elif offset == 7:
                    self.scr = value
            elif offset == 0 and not dlab and self.rx:
                self.rx.popleft()
            elif offset == 2 and read & 15 == 2:
                self.thre_pending = False
            elif offset == 5:
                self.overrun = False
            self._sources(edge + 1)
        self.clock.schedule(edge, Phase.UPDATE, update)
        finish(Reply(edge + 2, 0 if store else read))

    def _clint(self, edge, address, width, store, value, finish):
        base, lane = address & ~7, address & 7
        registers = {0x02000000: self.clint.software,
                     0x02004000: self.clint.compare,
                     0x0200BFF8: self.clint.time.sample(edge)}
        if base not in registers or lane + width > (4 if base == 0x02000000 else 8):
            finish(Reply(edge + 2, error=True))
            return
        old = registers[base]
        if store:
            mask = ((1 << (width * 8)) - 1) << (lane * 8)

            def update():
                changed = (old & ~mask) | value << (lane * 8)
                if base == 0x02000000:
                    self.clint.software = changed & 1
                elif base == 0x02004000:
                    self.clint.compare = changed
                else:
                    self.clint.time.write(edge, value << (lane * 8),
                                          ((1 << width) - 1) << lane)
                next_time = changed if base == 0x0200BFF8 else \
                    (self.clint.time.sample(edge) + 1) & MASK
                self._timer_changes(edge, next_time)
            self.clock.schedule(edge, Phase.UPDATE, update)
        finish(Reply(edge + 2, 0 if store else
                     old >> (lane * 8) & ((1 << (width * 8)) - 1)))

    def _plic(self, edge, address, width, store, value, finish):
        register = ReferencePlatform.plic_register(self, address)
        if address == 0x0C000000:
            register = ("zero", 0)
        if width != 4 or register is None or store and register[0] == "pending":
            finish(Reply(edge + 2, error=True))
            return
        kind, index = register
        plic, read = self.plic, 0
        if kind == "priority":
            read = plic.priority[index]
            if store:
                plic.configure(edge, source=index, priority=value & 7)
        elif kind == "enable":
            context, shift = index
            read = plic.enable[context] >> shift & 0xFFFFFFFF
            if store:
                mask = 0xFFFFFFFF << shift
                plic.configure(edge, context=context,
                               enable=(plic.enable[context] & ~mask | value << shift) &
                                      ((1 << 33) - 2))
        elif kind == "threshold":
            read = plic.threshold[index]
            if store:
                plic.configure(edge, context=index, threshold=value & 7)
        elif kind == "pending":
            read = plic.pending >> index & 0xFFFFFFFF
        elif kind == "claim":
            read = plic.winner(index)
            if store:
                plic.complete(edge, index, value) if value <= 32 else plic._tick(edge)
            else:
                plic.claim(edge, index)
        finish(Reply(edge + 2, 0 if store else read))
