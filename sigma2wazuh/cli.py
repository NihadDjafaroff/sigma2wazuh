"""Command-line entry point.

Usage:
    python -m sigma2wazuh convert RULE.yml [-o OUT.xml] [--start-id 100100] [--group-name NAME]
    python -m sigma2wazuh convert-dir RULES_DIR [-o OUT.xml] [--start-id 100100] [--group-name NAME]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .converter import DEFAULT_GROUP_NAME, convert_directory, convert_file
from .detection import ConversionError
from .sigma_parser import SigmaParseError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigma2wazuh", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-o", "--output", help="output XML file (default: stdout)")
    common.add_argument(
        "--start-id",
        type=int,
        default=100100,
        help="first Wazuh local rule ID to allocate (default: 100100)",
    )
    common.add_argument(
        "--group-name", default=DEFAULT_GROUP_NAME, help="Wazuh <group name=...> to wrap rules in"
    )

    p_file = sub.add_parser("convert", parents=[common], help="convert a single Sigma YAML file")
    p_file.add_argument("path", help="path to a Sigma rule .yml/.yaml file")

    p_dir = sub.add_parser(
        "convert-dir", parents=[common], help="convert every .yml/.yaml file in a directory"
    )
    p_dir.add_argument("path", help="directory containing Sigma rule files")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "convert":
            xml, warnings = convert_file(args.path, args.start_id, args.group_name)
            errors: list[tuple[Path, Exception]] = []
        else:
            xml, warnings, errors = convert_directory(args.path, args.start_id, args.group_name)
    except (SigmaParseError, ConversionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    for file_path, err in errors:
        print(f"error: {file_path}: {err}", file=sys.stderr)

    if args.output:
        Path(args.output).write_text(xml + "\n", encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(xml)

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
