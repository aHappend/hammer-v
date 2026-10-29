#!/usr/bin/env python3
"""Portable L1 entry point. Missing coverage fails; preparation is never reused."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe as experiments
import system as integrated


ROOT = Path(__file__).resolve().parent.parent
SUITES = ("smoke-boundaries", "system", "defects", "synthesis", "portable")


class Suite:
    def __init__(self, name, preparation=False):
        self.name = name
        self.preparation = preparation
        self.run = experiments.Probe("l1-" + name, preparation=preparation)
        self.run.receipt["suite"] = name
        self.run.receipt["children"] = []

    def execute(self, name, function, *args, **kwargs):
        child = experiments.Probe("l1-" + self.name + "-" + name,
                                  preparation=self.preparation)
        error = None
        try:
            function(child, *args, **kwargs)
        except Exception as failure:
            error = f"{type(failure).__name__}: {failure}"
            raise
        finally:
            child.finish(error)
            self.run.receipt["children"].append({
                "name": name, "receipt": child.relative(child.folder / "receipt.json"),
                "exit_status": int(error is not None),
                "assertions": child.receipt["assertions"],
                "system_runs": child.receipt.get("system_runs", []),
            })
            self.run.persist()
        return child

    def smoke(self):
        self.execute("v3-bare", experiments.top_probe, False)
        self.execute("parent-bare", experiments.top_probe, True)
        self.execute("sv39-startup", experiments.top_probe, False, True)
        self.execute("sv39-console", experiments.console_probe)
        self.execute("coherence-compact", experiments.coherence_probe, "iverilog", 2)
        self.execute("parameter-elaboration-rejection", experiments.parameter_probe)
        self.execute("singleton-odd-behavior", experiments.boundary_probe)
        self.execute("outstanding-reset-abort", experiments.coherence_probe, "iverilog", 2, True)

    def system(self):
        self.execute("isa-v3", experiments.isa_probe)
        self.execute("isa-parent", experiments.isa_probe, True)
        self.execute("precise-faults", experiments.fault_probe)
        self.execute("software-context-switch", experiments.context_probe)
        self.execute("dirty-pte-shootdown", experiments.shootdown_probe)
        self.execute("coherent-data", experiments.coherence_probe)
        self.execute("plic", experiments.peripheral_probe, "plic")
        self.execute("uart", experiments.peripheral_probe, "uart")
        self.execute("walker", experiments.walker_probe)
        self.run.receipt["required_system_matrix"] = [
            {"configuration": list(configuration), "seed": seed,
             "required_translation_comparisons": 1000, "required_context_round_trips": 20,
             "required_coherent_exchanges": 100, "actual": None, "status": "not-executed"}
            for configuration in integrated.CONFIGURATIONS for seed in integrated.SEEDS
        ]
        self.run.persist()
        for index, configuration in enumerate(integrated.CONFIGURATIONS):
            try:
                self.execute(f"integrated-configuration-{index}", integrated.run_configuration,
                             configuration, accelerator=True)
            finally:
                for child in self.run.receipt["children"]:
                    for result in child["system_runs"]:
                        for row in self.run.receipt["required_system_matrix"]:
                            if (row["configuration"], row["seed"]) == (
                                    result["configuration"], result["seed"]):
                                row.update(result, receipt=child["receipt"])
                self.run.persist()
        rows = self.run.receipt["required_system_matrix"]
        self.require_complete(integrated.coverage_closure(rows))

    def defects(self):
        # A broken baseline cannot establish sensitivity of a semantic mutant.
        self.execute("baseline-walker", experiments.walker_probe)
        self.execute("baseline-shootdown", experiments.shootdown_probe)
        self.execute("baseline-faults", experiments.fault_probe)
        self.execute("baseline-plic", experiments.peripheral_probe, "plic")
        self.execute("baseline-uart", experiments.peripheral_probe, "uart")
        self.execute("baseline-coherence", experiments.coherence_probe)
        completed = []
        for mutant in experiments.WALKER_MUTANTS:
            self.execute("mutant-" + mutant, experiments.walker_probe, mutant)
            completed.append(mutant)
        for mutant in experiments.SYSTEM_MUTANTS:
            self.execute("mutant-" + mutant, experiments.system_mutant_probe, mutant)
            completed.append(mutant)
        if len(set(completed)) != 9:
            raise AssertionError(f"DEFECT_COVERAGE expected nine independent classes: {completed}")
        self.run.receipt["assertions"].append({
            "id": "nine-semantic-mutants", "passed": True, "classes": completed,
            "required": 9, "actual": len(completed)})

    def synthesis(self):
        for configuration in ("default", "min", "odd"):
            self.execute(configuration, experiments.synthesis_probe, configuration)

    def portable_worker(self):
        if (ROOT / "hammer_v2_reference").exists():
            raise AssertionError("PORTABILITY_INPUTS: worker must not have reference RTL")
        self.execute("sv39-console", experiments.console_probe)
        self.execute("coherence-compact", experiments.coherence_probe, "iverilog", 2)
        self.execute("real-structural-synthesis", experiments.synthesis_probe, "min")

    def portable(self):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        staging = self.run.folder / ("delivery-" + stamp)
        staging.mkdir()
        sources = sorted([*ROOT.glob("rtl/*.sv"), *ROOT.glob("design/*.md"),
                          *[p for p in ROOT.glob("tests/*") if p.is_file()]])
        inventory = []
        for source in sources:
            relative = source.relative_to(ROOT)
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            inventory.append({"path": str(relative), "sha256": experiments.digest(destination)})
        if not inventory:
            raise AssertionError("PORTABILITY_INPUTS: no declared deliverables")
        self.run.receipt["copied_inventory"] = inventory
        self.run.receipt["staging"] = self.run.relative(staging)
        self.run.persist()
        argv = ["python3", self.run.relative(staging / "tests/verify.py"), "--portable-worker"]
        if self.preparation:
            argv.append("--preparation")
        output = self.run.run("portable-worker", argv, timeout=3600)
        worker_path = Path(output.strip().splitlines()[-1])
        if worker_path.is_absolute() or ".." in worker_path.parts:
            raise AssertionError("PORTABILITY_RECEIPT: worker returned a nonrelative receipt")
        worker_receipt = staging / worker_path
        result = json.loads(worker_receipt.read_text())
        if result.get("exit_status") != 0 or len(result.get("children", [])) != 3:
            raise AssertionError("PORTABILITY_RECEIPT: compact behavior/synthesis did not complete")
        self.run.receipt["worker_receipt"] = self.run.relative(worker_receipt)
        self.run.receipt["assertions"].append({
            "id": "clean-deliverable-only-reproduction", "passed": True,
            "copied_files": len(inventory),
            "worker_receipt": self.run.relative(worker_receipt)})

    def require_complete(self, requirements):
        self.run.receipt["coverage_closure"] = requirements
        self.run.persist()
        missing = [requirement for requirement, passed in requirements.items() if not passed]
        if missing:
            raise AssertionError("INCOMPLETE_REQUIRED_COVERAGE: " + ", ".join(missing))

    def execute_suite(self, worker=False):
        error = None
        try:
            if worker:
                self.portable_worker()
            else:
                getattr(self, self.name.replace("-", "_"))()
        except Exception as failure:
            error = f"{type(failure).__name__}: {failure}"
            print(error, file=sys.stderr)
        self.run.finish(error)
        return int(error is not None)

    smoke_boundaries = smoke


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES)
    parser.add_argument("--preparation", action="store_true",
                        help="Retain an advisory run, never admitted acceptance")
    parser.add_argument("--portable-worker", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.portable_worker:
        return Suite("portable-worker", arguments.preparation).execute_suite(worker=True)
    outcomes = []
    for name in (arguments.suite,) if arguments.suite else SUITES:
        outcomes.append(Suite(name, arguments.preparation).execute_suite())
    return int(any(outcomes))


if __name__ == "__main__":
    sys.exit(main())
