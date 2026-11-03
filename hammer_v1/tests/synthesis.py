"""Memory-preserving real Yosys checks of hierarchy, state, RAM and forbidden cells."""

import json

from cycle import ComparisonFailure, equal
from retention import ROOT, fresh, require


def integer(value):
    return int(value, 2) if isinstance(value, str) else value


def check_multiplier(kind, parameters, path):
    if kind != "$mul":
        return
    widths = tuple(integer(parameters[key]) for key in ("A_WIDTH", "B_WIDTH"))
    if ".u_muldiv." in path or min(widths) >= 64:
        raise ComparisonFailure(
            f"forbidden combinational multiplier {path}: operand widths={widths}")


def run_synthesis(evidence, configurations=((16384, 8192, 1, 16), (1, 1, 0, 1), (769, 257, 1, 64))):
    require("yosys")
    results = []
    sources = " ".join(str(p.relative_to(ROOT)) for p in sorted(ROOT.glob("rtl/*.sv")))
    for config in configurations:
        directory = fresh(evidence.directory, "synthesis")
        output = directory / "netlist.json"
        script = directory / "synthesis.ys"
        parameters = " ".join(f"-chparam {name} {value}" for name, value in zip(
            ("IMEM_WORDS", "DMEM_WORDS", "PRED_MODE", "BTB_ENTRIES"), config))
        script.write_text(
            f"read_verilog -sv {sources}\n"
            f"hierarchy -check -top hammer_v1_top {parameters}\n"
            "proc\nopt_expr\nopt_clean\ncheck -assert\n"
            "memory -nomap\nopt_clean\ncheck -assert\nstat\n"
            f"write_json {output.relative_to(ROOT)}\n")
        evidence.command(["yosys", "-s", str(script.relative_to(ROOT))])
        netlist = json.loads(output.read_text())
        modules = netlist["modules"]
        top = modules["hammer_v1_top"]
        expected = {"u_core": "hammer_v1_core", "u_imem": "hammer_v1_imem",
                    "u_dmem": "hammer_v1_dmem", "u_axi": "hammer_v1_axi_lite"}

        def module_name(module):
            return modules[module].get("attributes", {}).get("hdlname", module).split()[0].lstrip("\\")

        def check_instances(parent, children):
            for instance, name in children.items():
                if instance not in parent["cells"]:
                    raise ComparisonFailure(f"missing literal instance {instance}")
                cell = parent["cells"][instance]
                equal(module_name(cell["type"]), name, f"instance {instance} module")
                if not any(isinstance(bit, int) for port in cell["connections"].values() for bit in port):
                    raise ComparisonFailure(f"constant/stub connectivity {instance}")
                if not modules[cell["type"]]["cells"]:
                    raise ComparisonFailure(f"empty/stub module {instance}")
                for port, description in modules[cell["type"]]["ports"].items():
                    equal(len(cell["connections"].get(port, [])), len(description["bits"]),
                          f"instance {instance} port {port} width/connectivity")
                for port in ("clk", "rst_n"):
                    if port in modules[cell["type"]]["ports"]:
                        equal(cell["connections"][port], parent["ports"][port]["bits"],
                              f"instance {instance} ungated common {port}")

        check_instances(top, expected)
        core = modules[top["cells"]["u_core"]["type"]]
        check_instances(core, {"u_" + name: "hammer_v1_" + name for name in (
            "regfile", "decode", "alu", "hazard", "predictor", "muldiv")})
        def direct_state_bits(module):
            return sum(integer(cell["parameters"]["WIDTH"])
                       for cell in module["cells"].values() if "dff" in cell["type"].lower())

        regfile = modules[core["cells"]["u_regfile"]["type"]]
        muldiv = modules[core["cells"]["u_muldiv"]["type"]]
        for name, actual, minimum in (("register file", direct_state_bits(regfile), 31 * 64),
                                     ("M engine", direct_state_bits(muldiv), 400),
                                     ("pipeline", direct_state_bits(core), 1500)):
            if actual < minimum:
                raise ComparisonFailure(f"insubstantial {name} state {actual} < {minimum} bits")
        counts = {"latches": 0, "divide_modulo": 0, "state_bits": 0, "memory_bits": 0}
        visited = []

        def visit(name, path):
            module = modules[name]
            if integer(module.get("attributes", {}).get("blackbox", 0)):
                raise ComparisonFailure(f"blackbox {path}")
            for instance, cell in module["cells"].items():
                kind = cell["type"]
                if kind in modules:
                    visit(kind, path + "." + instance)
                    continue
                if not kind.startswith("$"):
                    raise ComparisonFailure(f"unresolved module {kind}")
                check_multiplier(kind, cell["parameters"], path + "." + instance)
                lower = kind.lower()
                counts["latches"] += int("latch" in lower)
                counts["divide_modulo"] += int(lower in ("$div", "$mod", "$divfloor", "$modfloor"))
                if "dff" in lower:
                    counts["state_bits"] += integer(cell["parameters"]["WIDTH"])
                if kind in ("$mem", "$mem_v2"):
                    width, size = (integer(cell["parameters"][key]) for key in ("WIDTH", "SIZE"))
                    counts["memory_bits"] += width * size
                    visited.append((path, width, size))

        visit("hammer_v1_top", "hammer_v1_top")
        equal(counts["latches"], 0, "zero Yosys latches")
        equal(counts["divide_modulo"], 0, "zero Yosys combinational division/modulo")
        if counts["state_bits"] < 1000:
            raise ComparisonFailure(f"insubstantial architectural/pipeline/M state: {counts}")
        for path, width, size in (("hammer_v1_top.u_imem", 32, config[0]),
                                  ("hammer_v1_top.u_dmem", 64, config[1])):
            if not any(found_path == path and found_width == width and found_size == size
                       for found_path, found_width, found_size in visited):
                raise ComparisonFailure(f"missing retained SRAM {path} {width}x{size}: {visited}")
        results.append({"config": config, **counts, "netlist": str(output.relative_to(ROOT))})
    return results
