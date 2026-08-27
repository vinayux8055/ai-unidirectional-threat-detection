from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threatguard.service import service  # noqa: E402


def main() -> None:
    dataset = PROJECT_ROOT / "data" / "sample" / "demo_network_flows.csv"
    if not dataset.exists():
        raise SystemExit("Run scripts/generate_demo_data.py first.")
    result = service.train(
        dataset,
        profile_name="unidirectional",
        algorithms=["logistic_regression", "decision_tree", "random_forest"],
        actor="demo-script",
    )
    print(json.dumps({"model": result["model"], "dataset": result["dataset"]}, indent=2))


if __name__ == "__main__":
    main()

