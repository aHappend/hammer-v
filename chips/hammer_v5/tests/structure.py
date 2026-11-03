"""Real, memory-preserving Yosys checks of the delivered top hierarchy."""
import json

REQUIRED = {
    "hammer_v5_top": {"u_soc": "hammer_v5_soc", "u_boot_rom": "hammer_v4_boot_rom"},
    "hammer_v5_soc": {"u_core": "hammer_v5_core", "u_mmu": "hammer_v3_mmu",
                      "u_fetch_path": "hammer_v5_fetch_path", "u_l2": "hammer_v5_l2"},
    "hammer_v5_core": {"u_csr": "hammer_v5_csr", "u_vector": "hammer_v5_vector"},
    "hammer_v5_fetch_path": {"u_decompress": "hammer_v5_decompress"},
    "hammer_v5_vector": {"u_int8": "hammer_v5_int8", "u_bf16": "hammer_v5_bf16"},
}


def module_name(module, encoded):
    original = module.get("attributes", {}).get("hdlname", encoded)
    return original.split()[0].lstrip("\\")


def assert_fetch_storage(module):
    """Verify the repaired queue's actual netlist storage, not its source spelling."""
    entries = [module["netnames"].get(f"fetch_queue[{index}]") for index in range(4)]
    if any(entry is None or len(entry["bits"]) != 262 for entry in entries):
        raise AssertionError("fetch queue lost a 262-bit entry")
    bits = [bit for entry in entries for bit in entry["bits"]]
    if any(not isinstance(bit, int) for bit in bits) or len(set(bits)) != 1048:
        raise AssertionError("fetch queue storage collapsed or aliased")
    owners = {}
    resets = set()
    for cell in module["cells"].values():
        outputs = cell["connections"].get("Q", [])
        overlap = set(outputs) & set(bits)
        if not overlap:
            continue
        if cell["type"] not in ("$adff", "$adffe"):
            raise AssertionError("fetch queue requires constant asynchronous-reset flip-flops")
        parameters = cell["parameters"]
        if (int(parameters["ARST_VALUE"], 2) != 0 or
                int(parameters["ARST_POLARITY"], 2) != 0):
            raise AssertionError("fetch queue reset must be active-low constant zero")
        resets.add(tuple(cell["connections"]["ARST"]))
        for bit in overlap:
            owners[bit] = owners.get(bit, 0) + 1
    if len(owners) != 1048 or set(owners.values()) != {1} or len(resets) != 1:
        raise AssertionError("fetch queue lacks 1048 independent singly-driven resettable bits")
    if tuple(module["ports"]["rst_n"]["bits"]) not in resets:
        raise AssertionError("fetch queue asynchronous reset is not the core reset port")
    return {"entries": 4, "bits_per_entry": 262, "retained_bits": len(owners),
            "constant_zero_async_reset": True}


def assert_structure(path):
    netlist = json.loads(path.read_text())
    modules = netlist["modules"]
    visited = set()
    states = {}
    initializations = {}
    fetch_storage = []
    pending = ["hammer_v5_top"]
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        module = modules[name]
        human = module_name(module, name)
        if human == "hammer_v5_core":
            fetch_storage.append(assert_fetch_storage(module))
        attributes = module.get("attributes", {})
        for flag in ("blackbox", "whitebox"):
            if int(attributes.get(flag, "0"), 2):
                raise AssertionError(f"{name}: {flag} substitute")
        for signal, net in module.get("netnames", {}).items():
            initial = net.get("attributes", {}).get("init")
            if initial is not None:
                if any(bit not in "01" for bit in initial):
                    raise AssertionError(f"{name}.{signal}: undefined power-up state")
                if signal.endswith(".initialized") and any(bit != "0" for bit in initial):
                    raise AssertionError(f"{name}.{signal}: untouched RAM exposed at power-up")
                initializations[f"{name}.{signal}"] = initial
        cells = module.get("cells", {})
        for child, expected in REQUIRED.get(human, {}).items():
            matches = [cell for key, cell in cells.items()
                       if key == child or key.endswith("." + child)]
            if len(matches) != 1:
                raise AssertionError(f"{human}: required connected child {child} missing/ambiguous")
            implementation = matches[0]["type"]
            if implementation not in modules or \
                    module_name(modules[implementation], implementation) != expected:
                raise AssertionError(f"{human}.{child}: expected {expected}, got {implementation}")
            if not matches[0].get("connections"):
                raise AssertionError(f"{human}.{child}: disconnected")
        sequential_bits = 0
        memory_bits = 0
        for key, cell in cells.items():
            kind = cell["type"]
            if kind in modules:
                pending.append(kind)
            elif not kind.startswith("$"):
                raise AssertionError(f"{name}.{key}: unresolved cell {kind}")
            if "latch" in kind.lower() or kind in ("$div", "$mod", "$divfloor", "$modfloor"):
                raise AssertionError(f"{name}.{key}: forbidden {kind}")
            if kind in ("$aldff", "$aldffe"):
                raise AssertionError(
                    f"{name}.{key}: nonconstant asynchronous load {kind}; "
                    "the delivered sequential reset values must remain constant after lowering")
            if "dff" in kind.lower():
                sequential_bits += len(cell["connections"].get("Q", []))
            if kind in ("$mem", "$mem_v2"):
                parameters = cell["parameters"]
                memory_bits += int(parameters["WIDTH"], 2) * int(parameters["SIZE"], 2)
        states[human] = {
            "sequential_bits": states.get(human, {}).get("sequential_bits", 0) + sequential_bits,
            "memory_bits": states.get(human, {}).get("memory_bits", 0) + memory_bits,
        }
    for required in ("hammer_v5_core", "hammer_v5_csr", "hammer_v5_vector",
                     "hammer_v5_int8", "hammer_v5_bf16", "hammer_v5_l2"):
        if required not in states or states[required]["sequential_bits"] == 0:
            raise AssertionError(f"{required}: no substantive retained sequential state")
    if sum(row["memory_bits"] for row in states.values()) == 0:
        raise AssertionError("integrated hierarchy lost all RAM storage")
    return {"reachable_modules": len(visited), "retained_state": states,
            "constant_power_up_state": initializations, "fetch_queue_storage": fetch_storage}


def synthesis_probe(ev, sources, parameters):
    ev.version("yosys", ("-V",))
    output = ev.directory / "netlist.json"
    script = ev.directory / "synthesis.ys"
    # FPGA RAM-visibility bits have legal constant power-up initialization.
    # check -noinit rejects that attribute itself; assert_structure checks it.
    script.write_text(
        "read_verilog -sv " + " ".join(ev.relative(p) for p in sources) + "\n" +
        "hierarchy -check -top hammer_v5_top " +
        " ".join(f"-chparam {name} {value}" for name, value in parameters.items()) + "\n" +
        "proc\nopt_expr\nopt_clean\ncheck -assert\n"
        "memory -nomap\nopt_clean\ncheck -assert\n"
        "stat\nwrite_json " + ev.relative(output) + "\n")
    from evidence import digest
    ev.record["parameters"] = parameters
    ev.record["generated_sha256"] = {ev.relative(script): digest(script)}
    ev.run(["yosys", "-Q", "-T", "-s", ev.relative(script)], "yosys-structure",
           timeout_s=86400)
    result = assert_structure(output)
    ev.record["observed"] = result
    return result
