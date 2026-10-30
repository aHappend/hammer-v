#!/usr/bin/env python3
"""Independent in-order scheduling from the documented stage/port contracts.

ISA values come exclusively from Instruction/Machine. The queue is a deque,
dependencies are register names, and a job owns each advancing stage. Lower
transactions cannot be canceled by a redirect. No DUT observations enter this
model. This engine is under integration; it is not Linux acceptance evidence.
"""

from collections import deque
from dataclasses import dataclass
from functools import cached_property
import struct

from architecture import branch_condition, signed
from rv64_reference import Commit, Machine
from system_execution import Access, Fault, Instruction
from system_memory import AtomicRequest, MemoryExecution, TranslationRequest
from system_oracle import MASK, Phase
from system_platform import Platform


@dataclass(frozen=True)
class Fetched:
    pc: int
    predicted: int
    word: int
    fault: Fault | None = None


@dataclass(frozen=True)
class MemoryObservation:
    valid: int = 0
    write: int = 0
    address: int = 0
    mask: int = 0
    wdata: int = 0
    rdata: int = 0


@dataclass
class Job:
    fetched: Fetched
    registers: list
    privilege: int
    execution: Instruction | None = None
    evaluated: bool = False
    operation: object = None
    result: object = None
    issued: bool = False
    ready_edge: int | None = None
    fence_edge: int | None = None

    @cached_property
    def word(self):
        return self.fetched.word

    @cached_property
    def opcode(self):
        return self.word & 127

    @cached_property
    def serial(self):
        return self.opcode in (0x0F, 0x2F) or self.opcode == 0x73 and (
            self.word >> 12 & 7 or self.word in (0x30200073, 0x10200073, 0x10500073) or
            self.word & 0xFE007FFF == 0x12000073)

    @cached_property
    def memory(self):
        return self.opcode in (3, 0x23)

    @cached_property
    def exclusive(self):
        return self.serial or self.memory

    @cached_property
    def muldiv(self):
        return self.opcode in (0x33, 0x3B) and self.word >> 25 == 1

    @cached_property
    def sources(self):
        if self.opcode in (0x37, 0x17, 0x6F, 0x0F):
            return ()
        if self.opcode == 0x73:
            if self.word >> 12 & 7:
                return () if self.word & (1 << 14) else (self.word >> 15 & 31,)
            if self.word & 0xFE007FFF != 0x12000073:
                return ()
        first = self.word >> 15 & 31
        return (first, self.word >> 20 & 31) if self.opcode in (
            0x23, 0x63, 0x33, 0x3B, 0x2F, 0x73) else (first,)

    @cached_property
    def destination(self):
        return self.word >> 7 & 31 if self.opcode in (
            0x37, 0x17, 0x6F, 0x67, 3, 0x13, 0x1B, 0x33, 0x3B, 0x2F, 0x73) else 0


class Predictor:
    def __init__(self, entries=16):
        self.entries = [None] * entries

    def predict(self, pc):
        entry = self.entries[pc // 4 % len(self.entries)]
        return entry[1] if entry and entry[0] == pc and (
            not entry[2] or entry[3] >= 2) else (pc + 4) & MASK

    def resolve(self, pc, target, taken, conditional):
        slot = pc // 4 % len(self.entries)
        old = self.entries[slot]
        hit = old is not None and old[0] == pc
        if hit or taken or not conditional:
            counter = max(0, min(3, old[3] + (1 if taken else -1))) if hit else \
                (2 if taken else 1)
            self.entries[slot] = (pc, target, conditional, counter)


class Core:
    def __init__(self, clock, seed, images, *, retirement, trap, wire, start_edge=100000):
        self.clock = clock
        self.platform = Platform(clock, wire)
        self.machine = Machine(self.platform)
        rom = struct.pack("<32I", 0x00000513, 0x043F05B7, 0x00559593,
                          0x00100293, 0x01F29293, 0x00028067, *([0x13] * 26))
        self.memory = MemoryExecution(clock, seed, images, rom, mmio=self.platform.port)
        self.retirement, self.trap_observation = retirement, trap
        self.predictor = Predictor()
        self.queue = deque()
        self.releasing = False
        self.decode = self.execute = self.mem = self.writeback = None
        self.platform.context = lambda: self.mem.fetched.pc if self.mem else self.machine.pc
        self.fetch_pc = 0
        self.fetching = self.killed = False
        self.fetched = None
        self.running = False
        self.stopped = False
        self.ticks = set()
        self.platform.changed = self.wake
        self.platform.plic.on_irq = lambda edge, _: self.wake(edge + 1)
        self.recent = deque(maxlen=32)
        self.wake(start_edge)

    def wake(self, edge):
        if edge in self.ticks:
            return
        self.ticks.add(edge)
        self.clock.schedule(edge, Phase.RESOLVE, lambda: self._tick(edge))

    def _copy_machine(self, pc, registers, privilege):
        state = Machine(self.platform)
        state.pc, state.registers, state.privilege = pc, list(registers), privilege
        state.csrs = dict(self.machine.csrs)
        state.commits = self.machine.commits
        return state

    def _evaluate(self, job):
        job.evaluated = True
        if job.opcode == 0x73 and (job.word >> 12 & 7 or
                                 job.word in (0x30200073, 0x10200073)):
            job.result = Commit(job.fetched.pc, job.word, (job.fetched.pc + 4) & MASK,
                                job.privilege, 0, 0, None)
            return
        state = self._copy_machine(job.fetched.pc, job.registers, job.privilege)
        job.execution = Instruction(state)
        job.execution.advance()
        job.operation = job.execution.reply(job.fetched.fault or job.word)
        if not isinstance(job.operation, Access):
            job.result = job.operation

    def _reply(self, job, reply):
        operation = job.operation
        if reply.error or reply.page_fault:
            access = "load" if operation.kind == "atomic" and operation.operation == 2 else \
                "store" if operation.kind == "atomic" else operation.kind
            value = Fault(({"fetch": 12, "load": 13, "store": 15} if reply.page_fault else
                           {"fetch": 1, "load": 5, "store": 7})[access], operation.address)
        else:
            value = reply.data
        job.operation = job.execution.reply(value)
        if isinstance(job.operation, Access):
            raise AssertionError(f"Unexpected second memory access in one instruction: {job.operation}")
        job.result = job.operation
        job.ready_edge = reply.edge
        self.wake(reply.edge)

    def _memory_issue(self, job, edge):
        operation = job.operation
        job.issued = True
        if isinstance(operation, Access) and operation.kind in ("load", "store", "atomic"):
            request = job.execution.translation_request()
            if operation.kind == "atomic":
                request = AtomicRequest(request, operation.width,
                                        operation.value, operation.operation)
                self.memory.atomic.submit(0, edge + 1, request,
                                          lambda reply: self._reply(job, reply))
            else:
                self.memory.ports[1].submit(
                    0, edge + 1, (request, operation.width, operation.value),
                    lambda reply: self._reply(job, reply))
        elif job.opcode == 0x0F:
            def cleaned(reply):
                if reply.error:
                    job.result = Fault(7, 0)
                    job.ready_edge = reply.edge
                    self.wake(reply.edge)
                elif job.word >> 12 & 7 == 1:
                    self.memory.maintenance.submit(
                        0, reply.edge + 1, (True, True), finished)
                else:
                    finished(reply)

            def finished(reply):
                if reply.error:
                    job.result = Fault(7, 0)
                job.ready_edge = reply.edge
                self.wake(reply.edge)
            self.memory.maintenance.submit(0, edge + 1, (False, False), cleaned)
        else:
            raise AssertionError(f"No scheduled memory operation: {operation}")

    def _csr_or_return(self, job, edge):
        # Serial instructions execute against current architectural state at WB;
        # no earlier Trial's stale counter/mip snapshot can become a CSR sample.
        execution = Instruction(self.machine)
        execution.advance()
        operation = execution.reply(job.word)
        if isinstance(operation, Access):
            if operation.kind != "csr":
                raise AssertionError("Unexpected writeback continuation")
            value = self.machine.csr_read(operation.address, job.word)
            operation = execution.reply(value)
        if isinstance(operation, Access):
            if operation.kind != "fence" or job.fence_edge is None or edge < job.fence_edge:
                raise AssertionError("Writeback did not finish its admitted fence")
            operation = execution.reply(0)
        old_satp = self.machine.csrs[0x180]
        result = execution.publish()
        if self.machine.csrs[0x180] != old_satp:
            for port in self.memory.translation.ports:
                port.blocked_until = edge + 5
            self.memory.translation.invalidate(edge + 3)
        address = job.word >> 20
        writes = job.word >> 12 & 3 == 1 or job.word >> 15 & 31
        if job.word & 127 == 0x73 and job.word >> 12 & 7 and writes and address == 0xB00:
            self.platform.cycles.write(edge, self.machine.csrs[0xB00])
        return result

    def _fence(self, job, edge):
        if job.fence_edge is not None or self.fetching:
            return
        if any(port.live for port in self.memory.translation.ports) or \
                self.memory.translation.walker.live:
            raise AssertionError("Serial fence reached an undrained translation")
        self.memory.translation.invalidate(edge + 2,
                                           job.operation.address
                                           if isinstance(job.operation, Access) and
                                           job.operation.kind == "fence" else None,
                                           job.operation.asid
                                           if isinstance(job.operation, Access) and
                                           job.operation.kind == "fence" else None)
        job.fence_edge = edge + 3
        self.memory.invalidate_reservation(job.fence_edge)
        self.wake(job.fence_edge)

    def _retire(self, job, edge):
        machine = self.machine
        if machine.pc != job.fetched.pc:
            raise AssertionError(f"Out-of-order publication: {machine.pc:#x} != {job.fetched.pc:#x}")
        if isinstance(job.result, Fault):
            result = job.result
            self._trap(edge, result.cause, result.tval)
            return True
        if job.opcode == 0x73 and job.serial and \
                job.word & 0xFE007FFF != 0x12000073:
            result = self._csr_or_return(job, edge)
            if isinstance(result, Fault):
                self.trap_observation(edge, self.machine.traps[-1], tuple(machine.registers))
                self.memory.invalidate_reservation(edge)
                return True
        else:
            result = job.result
            if not isinstance(result, Commit):
                raise AssertionError(f"Incomplete retirement: {result}")
            if result.rd:
                machine.registers[result.rd] = result.value
            machine.pc = result.next_pc
            machine.commits += 1
            machine.csrs[0xB02] = (machine.csrs[0xB02] + 1) & MASK
        if job.opcode == 0x73 and (job.word >> 12 & 7 or
                                  job.word in (0x30200073, 0x10200073)) or \
                result.memory and result.memory[0] in ("store", "atomic"):
            self.memory.invalidate_reservation(edge)
        observation = MemoryObservation()
        if result.memory or job.opcode == 0x2F:
            if result.memory:
                kind, address, width, value = result.memory
                store = kind in ("store", "atomic")
            else:
                access = next(request for request, _ in job.execution.journal
                              if request.kind == "atomic")
                address, width, value, store = access.address, access.width, 0, False
            operand = job.registers[job.word >> 20 & 31] if job.opcode == 0x23 else value
            observation = MemoryObservation(
                1, int(store), address,
                ((1 << width) - 1) << (address & 7) if store else 0,
                (operand << (8 * (address & 7))) & MASK if store else 0,
                value if not store else 0,
            )
        self.retirement(edge, machine.commits, result, tuple(machine.registers), observation)
        self.recent.append((edge, machine.commits, result.pc, result.instruction))
        return False

    def _trap(self, edge, cause, tval=0, interrupt=False):
        self.machine.trap(cause, tval, interrupt)
        self.trap_observation(edge, self.machine.traps[-1], tuple(self.machine.registers))
        self.memory.invalidate_reservation(edge)

    def _interrupt(self):
        machine = self.machine
        pending = machine.pending() & machine.csrs[0x304]
        for cause in (11, 3, 7, 9, 1, 5):
            if pending >> cause & 1:
                target = 1 if machine.csrs[0x303] >> cause & 1 else 3
                if machine.privilege < target or machine.privilege == target and \
                        machine.csrs[0x300] >> (1 if target == 1 else 3) & 1:
                    return cause
        return None

    def _fetch(self, edge):
        pc = self.fetch_pc
        request = TranslationRequest(pc, "fetch", self.machine.csrs[0x180],
                                     self.machine.csrs[0x300], self.machine.privilege)
        self.fetching = True

        def received(reply):
            fault = Fault(12 if reply.page_fault else 1, pc) if \
                reply.error or reply.page_fault else None
            self.fetched = (pc, reply.data, fault)
            self.wake(reply.edge)
        self.memory.ports[0].submit(0, edge, (request, 4, 0), received)

    def _tick(self, edge):
        self.ticks.remove(edge)
        if self.stopped:
            return
        machine = self.machine
        machine.csrs[0xB00] = self.platform.cycles.sample(edge)
        if not self.running:
            self.running = True
            self.wake(edge + 1)
            return
        d, x, m, w = self.decode, self.execute, self.mem, self.writeback
        serial = bool(d and d.serial) or any(
            job and job.exclusive for job in (x, m, w))
        interrupt = self._interrupt()
        pending_stop = interrupt is not None
        wake_sleep = machine.sleeping and bool(machine.pending() & machine.csrs[0x304])
        received = self.fetched
        predicted = self.predictor.predict(received[0]) if received else None
        m_complete = False
        if m:
            if m.ready_edge is not None:
                m_complete = m.ready_edge <= edge
            elif m.issued:
                m_complete = False
            elif isinstance(m.result, Fault):
                m_complete = True
            elif isinstance(m.operation, Access) and m.operation.kind == "fence":
                self._fence(m, edge)
                if m.fence_edge is not None and edge >= m.fence_edge:
                    m.operation = m.execution.reply(0)
                    m.result = m.operation
                    m_complete = True
            elif m.opcode in (3, 0x23, 0x2F, 0x0F):
                raise AssertionError("A memory-stage operation was not issued on entry")
            elif m.serial or m.memory:
                m_complete = not self.fetching
            else:
                m_complete = True
        m_fault = bool(m and isinstance(m.result, Fault))
        w_ready = True
        if w and w.opcode == 0x73 and w.word >> 20 == 0x180 and w.word >> 12 & 7 and (
            w.word >> 12 & 3 == 1 or w.word >> 15 & 31
        ):
            self._fence(w, edge)
            w_ready = w.fence_edge is not None and edge >= w.fence_edge
        w_fault = bool(w and isinstance(w.result, Fault))
        serial_commit = bool(w and w.exclusive and not w_fault and w_ready)

        if x:
            # Refresh operand snapshots using available older values only.
            changed = False
            for older in (w, m):
                if older is None or not isinstance(older.result, Commit):
                    continue
                if older is not w and (
                    older.opcode in (3, 0x2F) or older.opcode == 0x73 and older.serial
                ):
                    continue
                rd = older.result.rd
                if rd:
                    changed |= rd in x.sources and x.registers[rd] != older.result.value
                    x.registers[rd] = older.result.value
            if not x.evaluated or changed:
                self._evaluate(x)
        x_complete = bool(x and (not x.muldiv or isinstance(x.result, Fault) or
                                x.ready_edge is not None and x.ready_edge <= edge))
        if x and x.muldiv and x.ready_edge is None and not m and not w_fault:
            x.ready_edge = edge + 66
            self.wake(x.ready_edge)
        move_x = x_complete and (m is None or m_complete) and not (m_fault or w_fault) and \
            (not x.exclusive or m is None and w is None)
        redirect = None
        fault_transfer = bool(move_x and isinstance(x.result, Fault))
        if move_x and isinstance(x.result, Commit):
            if x.result.next_pc != x.fetched.predicted:
                redirect = x.result.next_pc
            if x.opcode in (0x63, 0x67, 0x6F):
                target = x.result.next_pc
                if x.opcode == 0x63:
                    word = x.word
                    displacement = (word >> 31) << 12 | (word >> 7 & 1) << 11 | \
                        (word >> 25 & 63) << 5 | (word >> 8 & 15) << 1
                    target = (x.fetched.pc + signed(displacement, 13)) & MASK
                self.predictor.resolve(x.fetched.pc, target,
                                       branch_condition(
                                           x.word >> 12 & 7,
                                           x.registers[x.word >> 15 & 31],
                                           x.registers[x.word >> 20 & 31])
                                       if x.opcode == 0x63 else True,
                                       x.opcode == 0x63)
        discard = self.killed or serial or pending_stop or m_fault or w_fault or \
            redirect is not None or fault_transfer or serial_commit
        pushed = Fetched(received[0], predicted, received[1], received[2]) if \
            received and not discard else None
        interlock = bool(d and any(
            older and older.destination and older.destination in d.sources and
            (older.opcode in (3, 0x2F) or older.opcode == 0x73 and older.serial)
            for older in (x, m)))
        move_d = bool(d and (x is None or move_x) and (m is None or m_complete) and
                      not interlock and not (m_fault or w_fault or fault_transfer) and
                      redirect is None and not (x and x.exclusive) and
                      not any(older and older.exclusive for older in (m, w)) and
                      (not d.serial or all(job is None for job in (x, m, w))))
        pop = bool(self.queue and (self.releasing or pending_stop) and
                   (d is None or move_d) and not serial and not discard)
        # Pending interrupts discard newly fetched responses, but must drain
        # previously accepted queue entries at the normal decode boundary.
        if pending_stop and self.queue and (d is None or move_d) and not serial and \
                not (m_fault or w_fault or redirect is not None or fault_transfer or serial_commit):
            pop = True
        commit_trap = False
        if w and w_ready:
            commit_trap = self._retire(w, edge)
        empty = not any((d, x, m, w, self.queue, self.fetching))
        if interrupt is not None and empty:
            self._trap(edge, interrupt, interrupt=True)
            commit_trap = True
        flush = commit_trap or serial_commit or redirect is not None or fault_transfer or m_fault
        launch = not self.fetching and len(self.queue) < 4 and not serial and \
            not pending_stop and not machine.sleeping and not flush
        if launch:
            self._fetch(edge)

        def update():
            if wake_sleep:
                machine.sleeping = False
            if received:
                self.fetched = None
                self.fetching = False
                self.killed = False
                if pushed:
                    self.fetch_pc = predicted
            self.writeback = m if m_complete else w if not w_ready else None
            self.mem = x if move_x else None if m_complete else m
            self.execute = d if move_d else None if move_x else x
            self.decode = None if move_d else d
            count = len(self.queue)
            if pop:
                item = self.queue.popleft()
                self.decode = Job(item, list(machine.registers), machine.privilege)
            if pushed:
                self.queue.append(pushed)
            if count == 4:
                self.releasing = True
            if count == 1 and pop and not pushed:
                self.releasing = False
            if move_d:
                d.registers = list(machine.registers)
                d.privilege = machine.privilege
            if flush:
                self.queue.clear()
                self.releasing = False
                self.decode = None
                if m_fault or commit_trap or serial_commit:
                    self.execute = None
                if commit_trap or serial_commit:
                    self.mem = self.writeback = None
                    self.fetch_pc = machine.pc
                elif redirect is not None:
                    self.fetch_pc = redirect
                if self.fetching:
                    self.killed = True
            if self.mem is x and x is not None and not x.issued and (
                x.opcode in (3, 0x23, 0x2F, 0x0F)
            ) and not isinstance(x.result, Fault):
                self._memory_issue(x, edge)
            active = move_d or move_x or m_complete or bool(w and w_ready) or pop
            active |= bool(self.queue and self.releasing and self.decode is None and not any(
                job and job.exclusive for job in (self.execute, self.mem, self.writeback)))
            if active or launch or flush or received or wake_sleep:
                self.wake(edge + 1)
        self.clock.schedule(edge, Phase.UPDATE, update)
