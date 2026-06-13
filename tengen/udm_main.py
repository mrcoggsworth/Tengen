"""CLI for the UDM parser, field registry, and model-update workflow.

Examples:
    # Parse a JSON alert (file or stdin) into UDM and record new fields
    cat alert.json | tengen-udm parse
    tengen-udm parse alert.json

    # Inspect the field registry
    tengen-udm fields --status new
    tengen-udm summary

    # Review actions
    tengen-udm approve 12
    tengen-udm ignore 7

    # Promote approved fields onto a new branch (no PR is opened automatically)
    tengen-udm propose            # preview the proposal table + scaffold
    tengen-udm branch             # create branch + commit the scaffold module
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from tengen.udm.field_registry import FieldRegistry, FieldStatus
from tengen.udm.model_updater import (
    create_update_branch,
    propose_from_registry,
    render_extension_module,
    render_proposal_table,
)
from tengen.udm.parser import UDMParser


def _load_input(path: str | None) -> dict[str, Any]:
    text = sys.stdin.read() if path in (None, "-") else open(path, encoding="utf-8").read()
    return json.loads(text)


def _cmd_parse(args: argparse.Namespace) -> int:
    registry = None if args.no_record else FieldRegistry()
    result = UDMParser(registry=registry).parse(_load_input(args.input))
    print(result.udm.model_dump_json(indent=2, exclude_none=True))
    if result.unmapped:
        print(f"\n# {len(result.unmapped)} unmapped field(s):", file=sys.stderr)
        for obs in result.unmapped:
            target = obs.suggested_udm_field or "(unmapped)"
            print(f"#   {obs.raw_path} -> {target}", file=sys.stderr)
    return 0


def _cmd_fields(args: argparse.Namespace) -> int:
    rows = FieldRegistry().list_fields(status=args.status, source_type=args.source)
    print(json.dumps(rows, indent=2, default=str))
    return 0


def _cmd_summary(_args: argparse.Namespace) -> int:
    print(json.dumps(FieldRegistry().summary(), indent=2))
    return 0


def _cmd_set_status(args: argparse.Namespace, status: FieldStatus) -> int:
    ok = FieldRegistry().set_status(args.field_id, status)
    print(f"field {args.field_id} -> {status.value}" if ok else f"field {args.field_id} not found")
    return 0 if ok else 1


def _cmd_propose(_args: argparse.Namespace) -> int:
    registry = FieldRegistry()
    proposals = propose_from_registry(registry)
    print(render_proposal_table(proposals))
    print("\n# --- scaffold (tengen/models/udm_proposed_fields.py) ---\n")
    print(render_extension_module(proposals))
    return 0


def _cmd_branch(args: argparse.Namespace) -> int:
    result = create_update_branch(
        FieldRegistry(), branch=args.branch, commit=not args.no_commit,
        mark_promoted=not args.no_promote,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "proposals"}, indent=2))
    return 0 if result["created"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tengen-udm", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse", help="parse an alert into UDM")
    p_parse.add_argument("input", nargs="?", default="-", help="JSON file path or '-' for stdin")
    p_parse.add_argument("--no-record", action="store_true", help="do not write new fields to the registry")
    p_parse.set_defaults(func=_cmd_parse)

    p_fields = sub.add_parser("fields", help="list field-registry candidates")
    p_fields.add_argument("--status", default=None, help="filter by status")
    p_fields.add_argument("--source", default=None, help="filter by source type")
    p_fields.set_defaults(func=_cmd_fields)

    sub.add_parser("summary", help="registry summary counts").set_defaults(func=_cmd_summary)

    p_approve = sub.add_parser("approve", help="approve a field candidate")
    p_approve.add_argument("field_id", type=int)
    p_approve.set_defaults(func=lambda a: _cmd_set_status(a, FieldStatus.APPROVED))

    p_ignore = sub.add_parser("ignore", help="ignore a field candidate")
    p_ignore.add_argument("field_id", type=int)
    p_ignore.set_defaults(func=lambda a: _cmd_set_status(a, FieldStatus.IGNORED))

    sub.add_parser("propose", help="preview proposed model fields").set_defaults(func=_cmd_propose)

    p_branch = sub.add_parser("branch", help="create a branch with proposed model fields")
    p_branch.add_argument("--branch", default=None, help="branch name (default: udm/field-additions-<ts>)")
    p_branch.add_argument("--no-commit", action="store_true")
    p_branch.add_argument("--no-promote", action="store_true", help="do not mark fields promoted")
    p_branch.set_defaults(func=_cmd_branch)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
