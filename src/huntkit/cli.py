from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import attack, fieldmap
from .querygen import (
    DIALECTS,
    UnsupportedCondition,
    UnsupportedModifier,
    explain,
    render,
)
from .sigma import SigmaParseError, load


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="huntkit",
        description="Detection engineering helpers for Sigma rules.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    conv = sub.add_parser("convert", help="render a Sigma rule as a backend query")
    conv.add_argument("rule")
    conv.add_argument("--dialect", default="splunk", choices=list(DIALECTS))
    conv.add_argument("--explain", action="store_true", help="describe before rendering")

    cov = sub.add_parser("coverage", help="ATT&CK coverage across a rule directory")
    cov.add_argument("directory")
    cov.add_argument("--json", action="store_true")

    fmap = sub.add_parser("fields", help="inspect or extend the field map")
    fmap.add_argument("--overlay", help="JSON file merged into the built-in map")
    fmap.add_argument("--rule", help="report unmapped fields used by this rule")
    fmap.add_argument("--backend", default="splunk", choices=list(fieldmap.BACKENDS))

    args = parser.parse_args(argv)

    if args.command == "convert":
        return _convert(args)
    if args.command == "coverage":
        return _coverage(args)
    return _fields(args)


def _convert(args) -> int:
    try:
        rule = load(args.rule)
    except (SigmaParseError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.explain:
        print(explain(rule))

    try:
        print(render(rule, args.dialect))
    except (UnsupportedCondition, UnsupportedModifier) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if rule.unsupported:
        print(
            f"note: rule also uses untranslated {rule.unsupported}",
            file=sys.stderr,
        )
    return 0


def _coverage(args) -> int:
    if not Path(args.directory).is_dir():
        print(f"error: {args.directory} is not a directory", file=sys.stderr)
        return 1

    coverage = attack.load_directory(args.directory)

    if args.json:
        print(attack.export_json(coverage))
        return 0

    print(attack.report(coverage))

    if coverage.failed:
        print("\nrules that failed to parse")
        for path, error in coverage.failed:
            print(f"  {path}\n    {error}")

    if coverage.untagged:
        print("\nrules with no recognised attack.tXXXX tag")
        for entry in coverage.untagged:
            print(f"  {entry}")
    return 0


def _fields(args) -> int:
    if args.overlay:
        try:
            fieldmap.load_overrides(args.overlay)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.rule:
        try:
            rule = load(args.rule)
        except (SigmaParseError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        unmapped = fieldmap.unmapped_fields_in_rule(rule)
        used = []
        for block in list(rule.selections) + list(rule.filters):
            used.extend(block.fields)

        result = fieldmap.map_fields(sorted(set(used)), args.backend)
        print(f"{'canonical':22} -> {args.backend}")
        for canonical, target in sorted(result.fields.items()):
            print(f"  {canonical:22} {target}")
        if result.unmapped:
            print(f"\nno mapping for: {', '.join(result.unmapped)}")
        return 0

    print(fieldmap.coverage_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())