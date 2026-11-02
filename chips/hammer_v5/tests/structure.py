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


def assert_structure(path):
    netlist = json.loads(path.read_text())
    modules = netlist["modules"]
    visited = set()
    states = {}
    initializations = {}
    pending = ["hammer_v5_top"]
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        module = modules[name]
        human = module_name(module, name)
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
            "constant_power_up_state": initializations}


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
