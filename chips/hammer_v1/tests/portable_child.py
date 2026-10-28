"""Internal clean-tree components; these do not replace any admitted full suite."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from benchmarks import run_benchmarks
from retention import Evidence, ToolFailure
from synthesis import run_synthesis
from verify import Campaign
from cycle import ComparisonFailure


def main():
    evidence = Evidence("clean-" + sys.argv[1])
    campaign = Campaign(evidence)
    try:
        if sys.argv[1] == "smoke":
            campaign.hazard_probe()
        elif sys.argv[1] == "sha256":
            run_benchmarks(campaign, (5,))
        elif sys.argv[1] == "synthesis":
            campaign.records.extend(run_synthesis(evidence, ((3, 3, 1, 4),)))
        else:
            raise ValueError("unknown clean-tree component")
    except (ComparisonFailure, ToolFailure, OSError, ValueError) as error:
        print(evidence.finish("failed", error=str(error), **campaign.summary()))
        return 1
    print(evidence.finish("passed", **campaign.summary()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
