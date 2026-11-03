"""Public-pin pipeline schedule oracle; no DUT internals or observed stall inputs."""

from collections import Counter
from copy import deepcopy

from iss import DATA, MMIO, MASK, decode, evaluate


class ComparisonFailure(AssertionError):
    pass


def equal(actual, expected, context):
    if actual != expected:
        raise ComparisonFailure(f"{context}: observed={actual!r}, expected={expected!r}")


class CycleModel:
    def __init__(self, program, memory, config, response):
        self.program = program
        self.memory = bytearray(memory)
        self.mmio = bytearray(bytes.fromhex("aa81007ffe01ff80") * 8192)
        self.iw, self.dw, self.mode, self.entries = config
        self.response = response
        self.registers = [0] * 32
        self.stages = [None] * 4  # ID, EX, MEM, WB
        self.fetch = 0
        self.predictor = {}
        self.bus = None
        self.coverage = Counter()
        self.expected_trap = None
        self.retired = 0
        self.writes = []

    def read(self, address, width):
        base, data = (DATA, self.memory) if address < MMIO else (MMIO, self.mmio)
        start = address - base
        if start < 0 or start + width > len(data):
            raise ComparisonFailure(f"cycle oracle uninitialized read {address:#x}")
        return int.from_bytes(data[start:start + width], "little")

    def token(self, pc):
        word = self.program[pc // 4] if not pc & 3 and pc < len(self.program) * 4 else 0
        insn = decode(word)
        known_fault = (pc & 3) != 0 or pc >= 4 * self.iw or insn.name in ("ILLEGAL", "ECALL", "EBREAK")
        return {"pc": pc, "insn": insn, "known_fault": known_fault}

    def predict(self, token):
        pc, insn = token["pc"], token["insn"]
        if self.mode == 0:
            if insn.name == "JAL" or (insn.branch and insn.imm < 0):
                return (pc + insn.imm) & MASK
            return (pc + 4) & MASK
        item = self.predictor.get((pc // 4) % self.entries)
        if item and item[0] == pc and (not item[2] or item[3] >= 2):
            return item[1]
        return (pc + 4) & MASK

    def update_predictor(self, effect):
        if not effect.insn.control or effect.cause is not None:
            return
        pc = effect.pc
        if self.mode == 0:
            self.coverage["static_backward" if effect.insn.imm < 0 else "static_forward"] += 1
            return
        index = (pc // 4) % self.entries
        old = self.predictor.get(index)
        hit = old is not None and old[0] == pc
        if old is not None and not hit:
            self.coverage["btb_collision"] += 1
        if effect.insn.branch:
            counter = max(0, min(3, old[3] + (1 if effect.taken else -1))) if hit else (2 if effect.taken else 1)
            if effect.taken:
                self.predictor[index] = (pc, effect.next_pc, True, counter)
            elif hit:
                self.predictor[index] = (*old[:3], counter)
        else:
            self.predictor[index] = (pc, effect.next_pc, False, 1)

    def select(self, source, m, w):
        if source == 0:
            return 0
        if m and m["effect"].cause is None and not m["insn"].load and m["effect"].rd == source:
            if w and w["effect"].rd == source:
                self.coverage["youngest_priority"] += 1
            return 2
        if w and w["effect"].cause is None and w["effect"].rd == source:
            return 1
        return 0

    def check_bus(self, pre, cycle):
        # Channel signals are checked against independently scheduled request ownership.
        bus = self.bus
        valid = [0, 0, 0, 0, 0]
        if bus is not None:
            store = bus["token"]["insn"].store
            if bus["responded"] is None:
                valid = [int(store and not bus["aw"]), int(store and not bus["w"]),
                         int(store and bus["aw"] and bus["w"]),
                         int(not store and not bus["ar"]), int(not store and bus["ar"])]
        equal((pre["awvalid"], pre["wvalid"], pre["bready"], pre["arvalid"], pre["rready"]),
              tuple(valid), f"cycle {cycle} AXI channel ownership")
        equal((pre["awprot"], pre["arprot"]), (0, 0), f"cycle {cycle} AxPROT")
        if bus is None:
            return
        e = bus["token"]["effect"]
        if valid[0]:
            equal(pre["awaddr"], e.address & ~7, f"cycle {cycle} AW address")
        if valid[1]:
            equal((pre["wdata"], pre["wstrb"]), (e.data, e.mask), f"cycle {cycle} W payload")
        if valid[3]:
            equal(pre["araddr"], e.address & ~7, f"cycle {cycle} AR address")
        if pre["awvalid"] and pre["awready"]:
            bus["aw"] = True
            self.coverage["aw"] += 1
        if pre["wvalid"] and pre["wready"]:
            bus["w"] = True
            self.coverage["w"] += 1
        if pre["arvalid"] and pre["arready"]:
            bus["ar"] = True
            self.coverage["ar"] += 1
        if pre["bvalid"] and valid[2] or pre["rvalid"] and valid[4]:
            if not e.insn.store:
                equal(pre["rdata"], self.read(e.address & ~7, 8), f"cycle {cycle} R data")
            bus["responded"] = cycle + 1
            self.coverage["b" if e.insn.store else "r"] += 1

    def edge(self, pre, post, cycle):
        id_token, x, m, w = self.stages
        bus_before = deepcopy(self.bus)
        self.check_bus(pre, cycle)
        terminal = w is not None and w["effect"].cause is not None
        response_ready = bus_before is not None and bus_before["responded"] is not None and bus_before["responded"] <= cycle
        mem_fault = m is not None and (m["effect"].cause is not None or (
            m.get("mmio", False) and response_ready and self.response != 0))
        mem_advance = m is not None and not terminal and (
            m["effect"].cause is not None or not m.get("mmio", False) or response_ready)
        mem_ready = m is None or mem_advance
        older_fault = terminal or mem_fault
        regs = self.registers.copy()
        selectors = [0, 0]
        effect = None
        if x is not None:
            for idx, source in enumerate((x["insn"].rs1, x["insn"].rs2)):
                if idx < len(x["insn"].uses) and not x["known_fault"]:
                    selectors[idx] = self.select(source, m, w)
                    if selectors[idx]:
                        producer = m if selectors[idx] == 2 else w
                        regs[source] = producer["effect"].value
            # Faulting MMIO responses are applied at MEM, not speculated at EX.
            effect = evaluate(x["insn"], x["pc"], regs, self.read, self.iw, self.dw)
            if x["insn"].muldiv and effect.cause is None and not older_fault and "start" not in x:
                x["start"] = cycle
            complete = effect.cause is not None or not x["insn"].muldiv or cycle >= x.get("start", cycle) + 66
        else:
            complete = True
        ex_advance = x is not None and complete and mem_ready and not older_fault
        ex_ready = (x is None or ex_advance) and mem_ready
        redirect = ex_advance and effect.cause is None and effect.next_pc != x["pred"]
        fault_transfer = ex_advance and effect.cause is not None
        interlock = (x is not None and not x["known_fault"] and x["insn"].load and x["insn"].rd != 0
                     and id_token is not None and x["insn"].rd in id_token["insn"].uses)
        id_advance = id_token is not None and ex_ready and not interlock and not older_fault and not redirect and not fault_transfer
        fetch_accept = ((id_token is None or id_advance) and mem_ready and not older_fault and not redirect
                        and not fault_transfer and not (x is not None and x["known_fault"]))
        expected_observation = (
            int(x is not None and not older_fault), x["pc"] if x is not None and not older_fault else 0,
            selectors[0] if x is not None and not x["known_fault"] and not older_fault else 0,
            selectors[1] if x is not None and not x["known_fault"] and not older_fault else 0,
            selectors[1] if x is not None and x["insn"].store and not older_fault else 0,
            int(interlock and not older_fault and not redirect),
            int(m is not None and not mem_advance and not terminal),
            int(x is not None and x["insn"].muldiv and not complete and not older_fault),
            int(redirect), effect.next_pc if redirect else 0, 0,
        )
        observed = tuple(pre[key] for key in PRE_KEYS[:11])
        equal(observed, expected_observation, f"cycle {cycle} independent pipeline schedule")
        if interlock:
            self.coverage["load_use"] += 1
            if mem_ready and not older_fault:
                self.coverage["isolated_load_use"] += 1
        if x and x["insn"].load and id_token and not interlock:
            if x["insn"].rd == 0:
                self.coverage["x0_no_interlock"] += 1
            elif x["insn"].rd in (id_token["insn"].rs1, id_token["insn"].rs2):
                self.coverage["unused_no_interlock"] += 1
        if x is not None:
            for idx, source in enumerate(selectors):
                if source:
                    self.coverage[f"rs{idx + 1}_{source}"] += 1
            if x["insn"].store and selectors[1]:
                self.coverage["store_forward"] += 1
                self.coverage[f"store_{selectors[1]}"] += 1
            if x["insn"].branch and any(selectors):
                self.coverage["branch_forward"] += 1
            if x["insn"].name == "JALR" and selectors[0]:
                self.coverage["jalr_forward"] += 1
            if x["insn"].muldiv and complete and not mem_ready:
                self.coverage["m_complete_mem_hold"] += 1
        if redirect:
            self.coverage["redirect"] += 1
            if x.get("held", False):
                self.coverage["redirect_after_hold"] += 1
            if x["pred"] != (x["pc"] + 4) & MASK and effect.taken:
                self.coverage["target_correction"] += 1
            if id_token is not None:
                self.coverage["flush_" + id_token["insn"].name] += 1
                if id_token["insn"].store:
                    base = regs[id_token["insn"].rs1]
                    self.coverage["flush_mmio" if base >= MMIO else "flush_scratchpad"] += 1
        elif ex_advance and effect.insn.control and effect.cause is None:
            self.coverage["correct_prediction"] += 1
        # Architectural update occurs at the WB edge, independently of EX forwarding.
        expected_retire = w is not None and not terminal
        equal(post["retire"], int(expected_retire), f"cycle {cycle} retirement occupancy")
        equal(post["trap"], int(terminal), f"cycle {cycle} precise trap occupancy")
        equal(post["halted"], int(terminal), f"cycle {cycle} halted")
        if expected_retire:
            e = w["effect"]
            equal(tuple(post[key] for key in POST_KEYS[1:13]), e.trace(), f"cycle {cycle} pipeline retirement")
            if e.rd:
                self.registers[e.rd] = e.value
            self.retired += 1
        elif any(post[key] for key in POST_KEYS[1:13]):
            raise ComparisonFailure(f"cycle {cycle}: non-retirement trace fields not zero")
        if terminal:
            self.expected_trap = (w["effect"].pc, w["effect"].cause)
            equal((post["trap_pc"], post["cause"]), self.expected_trap, f"cycle {cycle} trap")
        else:
            equal((post["trap_pc"], post["cause"]), (0, 0), f"cycle {cycle} inactive trap")
        if post["retire"] or terminal:
            equal(post["registers"], self.registers, f"cycle {cycle} architectural registers")
        if terminal:
            self.stages = [None] * 4
            return
        next_w = None
        if mem_advance:
            next_w = deepcopy(m)
            e = next_w["effect"]
            if m.get("mmio", False) and self.response:
                e.cause = 7 if e.insn.store else 5
                e.rd = 0
            elif e.cause is None:
                if e.insn.load:
                    raw = self.read(e.address, e.insn.width)
                    from iss import sext
                    e.value = raw if e.insn.unsigned else sext(raw, e.insn.width * 8)
                    e.load_value = e.value
                elif e.insn.store:
                    base, data = (DATA, self.memory) if e.address < MMIO else (MMIO, self.mmio)
                    offset = e.address - base
                    raw = (e.data >> (8 * (e.address & 7))) & ((1 << (8 * e.insn.width)) - 1)
                    data[offset:offset + e.insn.width] = raw.to_bytes(e.insn.width, "little")
                    if base == DATA:
                        self.writes.append((cycle, e.address, e.data, e.mask))
            if m.get("mmio", False):
                self.bus = None
        if m is not None and m.get("mmio", False) and m["effect"].cause is None and self.bus is None and not mem_advance:
            self.bus = {"token": deepcopy(m), "aw": False, "w": False, "ar": False, "responded": None}
        next_m = None if mem_advance else m
        next_x = None if ex_advance else x
        if next_x is not None:
            next_x["held"] = True
        next_id = None if id_advance else id_token
        predicted = self.predict(id_token) if id_token is not None else self.fetch
        if ex_advance:
            next_m = deepcopy(x)
            next_m["effect"] = effect
            next_m["mmio"] = ((effect.insn.load or effect.insn.store) and MMIO <= effect.address < MMIO + 65536
                              and effect.cause is None)
            self.update_predictor(effect)
        if id_advance:
            next_x = deepcopy(id_token)
            next_x["pred"] = predicted
            if w and w["effect"].rd in id_token["insn"].uses:
                self.coverage["wb_id"] += 1
        if fetch_accept:
            next_id = self.token(predicted)
            self.fetch = (predicted + 4) & MASK
        if redirect:
            next_id, self.fetch = None, effect.next_pc
        if fault_transfer:
            next_id = None
        if mem_fault:
            next_id, next_x = None, None
        self.stages = [next_id, next_x, next_m, next_w]


PRE_KEYS = (
    "ex", "ex_pc", "sel1", "sel2", "store_sel", "load_stall", "mem_stall",
    "m_stall", "redirect", "redirect_pc", "host_ready", "awvalid", "awready",
    "awaddr", "awprot", "wvalid", "wready", "wdata", "wstrb", "bvalid",
    "bready", "bresp", "arvalid", "arready", "araddr", "arprot", "rvalid",
    "rready", "rdata", "edge_time",
)
POST_KEYS = (
    "retire", "pc", "next_pc", "insn", "rd_we", "rd", "rd_data",
    "mem", "write", "address", "mask", "data", "load_data", "trap", "trap_pc",
    "cause", "halted",
)
