#!/usr/bin/env python3
"""Suspend independent ISA execution at externally scheduled operations.

An instruction is evaluated from its immutable pre-instruction state after each
reply. Previously completed operations are replayed from a private journal,
never reissued. No register, CSR, trap or PC update becomes architectural until
the caller publishes at its independently predicted commit edge. In particular,
the caller must schedule CSR samples at writeback, not at instruction fetch.
"""

from dataclasses import dataclass

from rv64_reference import ArchitecturalTrap, Machine, MASK
from system_memory import TranslationRequest


@dataclass(frozen=True)
class Access:
    kind: str
    address: int | None
    width: int = 8
    value: int = 0
    asid: int | None = None


@dataclass(frozen=True)
class Fault:
    cause: int
    tval: int


class Suspended(Exception):
    def __init__(self, access):
        self.access = access
        super().__init__(str(access))


def architectural_state(machine):
    return {
        "registers": tuple(machine.registers),
        "pc": machine.pc, "privilege": machine.privilege,
        "reservation": machine.reservation, "sleeping": machine.sleeping,
        "commits": machine.commits, "csrs": dict(machine.csrs),
        "translations": {name: [dict(entry) for entry in entries]
                         for name, entries in machine.translations.items()},
    }


class Trial(Machine):
    def __init__(self, execution):
        super().__init__(execution.machine.platform)
        self.execution = execution
        state = execution.before
        self.registers = list(state["registers"])
        self.csrs = dict(state["csrs"])
        self.translations = {name: [dict(entry) for entry in entries]
                             for name, entries in state["translations"].items()}
        for name in ("pc", "privilege", "reservation", "sleeping", "commits"):
            setattr(self, name, state[name])
        self.cursor = 0
        self.csr_writes = []

    def access(self, request):
        index = self.cursor
        self.cursor += 1
        if index == len(self.execution.journal):
            raise Suspended(request)
        old, reply = self.execution.journal[index]
        if old != request:
            raise AssertionError(f"Architectural continuation diverged: {old} != {request}")
        if isinstance(reply, Fault):
            raise ArchitecturalTrap(reply.cause, reply.tval)
        return reply

    def read(self, address, width, access="load"):
        if address % width:
            raise ArchitecturalTrap(0 if access == "fetch" else 4, address)
        value = self.access(Access(access, address, width))
        if access == "fetch" and value & 127 == 0x2F:
            raise NotImplementedError("Atomic execution needs scheduled maintenance/reservations")
        return value

    def write(self, address, width, value):
        if address % width:
            raise ArchitecturalTrap(6, address)
        self.access(Access("store", address, width, value & ((1 << (width * 8)) - 1)))
        self.reservation = None

    def translate(self, address, access):
        raise NotImplementedError("Unscheduled physical translation is prohibited")

    def csr_read(self, address, instruction=0):
        # Validate privilege/CSR existence independently before requesting the
        # actual writeback-time sample from the scheduling caller.
        super().csr_read(address, instruction)
        return self.access(Access("csr", address))

    def csr_write(self, address, value, instruction):
        super().csr_write(address, value, instruction)
        self.csr_writes.append((address, value, instruction))

    def sfence(self, va, asid):
        self.access(Access("fence", va, asid=asid))
        super().sfence(va, asid)


class Instruction:
    """One in-order architectural continuation, independent of pipeline timing.

    advance() produces an Access, Fault or Commit. Replies must correspond to
    exactly the outstanding Access. publish() is a separate scheduling action;
    it never increments time or services interrupts implicitly.
    """

    def __init__(self, machine):
        self.machine = machine
        self.before = architectural_state(machine)
        self.journal = []
        self.pending = None
        self.trial = None
        self.result = None
        self.published = False

    def advance(self):
        if self.pending is not None or self.result is not None or self.published:
            raise AssertionError("Continuation requires its pending reply or is already complete")
        trial = Trial(self)
        try:
            result = trial.execute()
        except Suspended as suspension:
            if trial.cursor != len(self.journal) + 1:
                raise AssertionError("Incomplete continuation journal consumption")
            self.pending = suspension.access
            return self.pending
        except ArchitecturalTrap as error:
            self.result = Fault(error.cause, error.tval)
            return self.result
        if trial.cursor != len(self.journal):
            raise AssertionError("Architectural execution left unused completed operations")
        self.trial, self.result = trial, result
        return result

    def reply(self, value):
        if self.pending is None or self.result is not None:
            raise AssertionError("Reply without an outstanding architectural operation")
        if not isinstance(value, Fault):
            if type(value) is not int or not 0 <= value <= MASK:
                raise ValueError("Architectural reply must be unsigned XLEN or a precise fault")
            if self.pending.kind in ("store", "fence") and value:
                raise ValueError("Store/fence acknowledgment cannot contain read data")
            if self.pending.kind in ("fetch", "load") and value >= 1 << (8 * self.pending.width):
                raise ValueError("Read reply exceeds its access width")
        self.journal.append((self.pending, value))
        self.pending = None
        return self.advance()

    def translation_request(self):
        access = self.pending
        if access is None or access.kind not in ("fetch", "load", "store"):
            raise AssertionError("No outstanding architectural memory operation")
        return TranslationRequest(access.address, access.kind, self.before["csrs"][0x180],
                                  self.before["csrs"][0x300], self.before["privilege"])

    def publish(self):
        if self.pending is not None or self.result is None or self.published:
            raise AssertionError("Cannot publish incomplete or repeated architectural work")
        machine = self.machine
        for name in ("registers", "pc", "privilege", "reservation", "sleeping", "commits"):
            current = tuple(machine.registers) if name == "registers" else getattr(machine, name)
            if current != self.before[name]:
                raise AssertionError(f"Architectural state changed while instruction pending: {name}")
        # Clock/peripheral changes may update counters and pending interrupts,
        # but not software-owned CSRs behind this instruction's back.
        for address, old in self.before["csrs"].items():
            if address not in (0xB00, 0x344) and machine.csrs[address] != old:
                raise AssertionError(f"CSR changed while instruction pending: {address:#x}")
        self.published = True
        if isinstance(self.result, Fault):
            machine.trap(self.result.cause, self.result.tval)
            return self.result
        trial = self.trial
        machine.registers[:] = trial.registers
        for name in ("pc", "privilege", "reservation", "sleeping", "commits"):
            setattr(machine, name, getattr(trial, name))
        aliases = {0x100: 0x300, 0x104: 0x304, 0x144: 0x344}
        written = {aliases.get(address, address) for address, _, _ in trial.csr_writes}
        for address, value in trial.csrs.items():
            if address not in written and value != self.before["csrs"][address]:
                machine.csrs[address] = value
        # A write of the old value is still a write (notably counter overrides
        # and mip clears). Apply the ISA's ownership mask to current state.
        for address, value, instruction in trial.csr_writes:
            machine.csr_write(address, value, instruction)
        machine.translations = trial.translations
        return self.result
