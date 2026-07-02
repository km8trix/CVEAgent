"""`palisade scan <lockfile>` — print a ranked, cited vulnerability report as JSON."""

import argparse
import asyncio

from palisade.scanner import scan_path


def main() -> None:
    parser = argparse.ArgumentParser(prog="palisade")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="scan a lockfile")
    scan_cmd.add_argument(
        "path", help="path to a lockfile (requirements.txt, package-lock.json, ...)"
    )
    args = parser.parse_args()

    if args.command == "scan":
        report = asyncio.run(scan_path(args.path))
        print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
