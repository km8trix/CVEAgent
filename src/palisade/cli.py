"""`palisade scan <lockfile>` — print a ranked, cited vulnerability report as JSON."""

import argparse
import asyncio

from palisade.agents.graph import run_graph_path
from palisade.scanner import scan_path


def main() -> None:
    parser = argparse.ArgumentParser(prog="palisade")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="scan a lockfile")
    scan_cmd.add_argument(
        "path", help="path to a lockfile (requirements.txt, package-lock.json, ...)"
    )
    scan_cmd.add_argument(
        "--engine",
        choices=["scan", "graph"],
        default="scan",
        help="scan = M1 deterministic pipeline (default); graph = M2 agent graph with Verifier",
    )
    args = parser.parse_args()

    if args.command == "scan":
        run = run_graph_path if args.engine == "graph" else scan_path
        report = asyncio.run(run(args.path))
        print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
