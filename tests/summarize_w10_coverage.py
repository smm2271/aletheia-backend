"""Separate line/branch evidence from coverage.py JSON, locally and in CI."""
import json
import sys
from pathlib import Path

W10 = {"qr/dynamic_tokens.py", "qr/dynamic_state.py", "routes/qr_dynamic.py"}


def main():
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    groups = {"all-source": [], "W10": []}
    for name, data in report["files"].items():
        groups["all-source"].append(data["summary"])
        if name.replace("\\", "/") in W10:
            groups["W10"].append(data["summary"])
    assert len(groups["W10"]) == len(W10), "Missing W10 source coverage"
    for group, summaries in groups.items():
        covered = sum(s["covered_lines"] for s in summaries)
        lines = sum(s["num_statements"] for s in summaries)
        branches = sum(s["num_branches"] for s in summaries)
        hit = sum(s["covered_branches"] for s in summaries)
        print(f"{group}: lines {covered}/{lines} ({covered / lines:.2%}); branches {hit}/{branches} ({hit / branches:.2%})")
    for name, data in report["files"].items():
        if name.replace("\\", "/") in W10:
            print(f"{name}: missing lines={data['missing_lines']}; missing branches={data['missing_branches']}")


if __name__ == "__main__":
    main()
