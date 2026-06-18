"""Model updater — promotes approved registry fields into the UDM model.

Workflow:
    1. The parser discovers new fields → :class:`FieldRegistry`.
    2. An analyst reviews them in the dashboard and marks some ``approved``.
    3. This module turns approved rows into proposed Pydantic fields, renders a
       reviewable scaffold module + PR body, and (via the CLI) creates a branch
       and commits the scaffold so a pull request can be opened.

The generated scaffold is intentionally a *separate* module
(``tengen/models/udm_proposed_fields.py``) of ``*Additions`` classes rather than
an in-place edit of ``udm.py`` — the live model is never mutated automatically;
a human folds the approved fields in during PR review.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tengen.models import udm as udm_models
from tengen.udm.field_registry import FieldRegistry, FieldStatus

# Maps a UDM sub-model name to its Pydantic class (for existing-field checks).
_MODEL_REGISTRY: dict[str, type] = {
    "Metadata": udm_models.Metadata,
    "Noun": udm_models.Noun,
    "User": udm_models.User,
    "Process": udm_models.Process,
    "File": udm_models.File,
    "RegistryEntry": udm_models.RegistryEntry,
    "Resource": udm_models.Resource,
    "CloudContext": udm_models.CloudContext,
    "Location": udm_models.Location,
    "Network": udm_models.Network,
    "NetworkHttp": udm_models.NetworkHttp,
    "SecurityResult": udm_models.SecurityResult,
}

_PROPOSED_MODULE = "tengen/models/udm_proposed_fields.py"


def _target_model(suggested_udm_field: str) -> str:
    s = suggested_udm_field
    if s.startswith("metadata."):
        return "Metadata"
    if s.startswith("network.http."):
        return "NetworkHttp"
    if s.startswith("network."):
        return "Network"
    if s.startswith("security_result."):
        return "SecurityResult"
    if ".user." in s:
        return "User"
    if ".process." in s:
        return "Process"
    if ".file." in s:
        return "File"
    if ".registry." in s:
        return "RegistryEntry"
    if ".cloud." in s:
        return "CloudContext"
    if ".resource." in s:
        return "Resource"
    if ".location." in s:
        return "Location"
    return "Noun"


def _identifier(text: str) -> str:
    # Split camelCase / PascalCase / acronym boundaries into snake_case.
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    name = re.sub(r"[^0-9a-zA-Z]+", "_", text).strip("_").lower()
    name = re.sub(r"_+", "_", name)
    if not name:
        name = "field"
    if name[0].isdigit():
        name = f"f_{name}"
    return name


def _field_name(suggested_udm_field: str, raw_path: str) -> str:
    if suggested_udm_field:
        leaf = suggested_udm_field.split(".")[-1]
    else:
        leaf = raw_path.split(".")[-1].replace("[]", "")
    return _identifier(leaf)


def _py_field(name: str, value_type: str) -> str:
    return {
        "str": f'{name}: str = ""',
        "int": f"{name}: int | None = None",
        "float": f"{name}: float | None = None",
        "bool": f"{name}: bool = False",
        "list": f"{name}: list[Any] = Field(default_factory=list)",
        "dict": f"{name}: dict[str, Any] = Field(default_factory=dict)",
    }.get(value_type, f'{name}: str = ""')


@dataclass
class FieldProposal:
    """A proposed addition to (or confirmation of) a UDM model field."""

    field_id: int
    source_type: str
    raw_path: str
    suggested_udm_field: str
    value_type: str
    sample_value: str
    occurrence_count: int
    target_model: str
    field_name: str
    is_new: bool  # False when the suggested field already exists on the model

    def py_field(self) -> str:
        return _py_field(self.field_name, self.value_type)


def propose_from_registry(
    registry: FieldRegistry,
    statuses: tuple[FieldStatus | str, ...] = (FieldStatus.APPROVED,),
) -> list[FieldProposal]:
    """Build field proposals from registry rows in the given statuses."""
    status_values = {s.value if isinstance(s, FieldStatus) else str(s) for s in statuses}
    proposals: list[FieldProposal] = []
    seen: set[tuple[str, str]] = set()
    for row in registry.list_fields(limit=10_000):
        if row["status"] not in status_values:
            continue
        target = _target_model(row["suggested_udm_field"])
        name = _field_name(row["suggested_udm_field"], row["raw_path"])
        key = (target, name)
        existing = name in set(_MODEL_REGISTRY[target].model_fields)
        proposals.append(
            FieldProposal(
                field_id=row["id"],
                source_type=row["source_type"],
                raw_path=row["raw_path"],
                suggested_udm_field=row["suggested_udm_field"],
                value_type=row["value_type"],
                sample_value=row["sample_value"],
                occurrence_count=row["occurrence_count"],
                target_model=target,
                field_name=name,
                is_new=not existing and key not in seen,
            )
        )
        if not existing:
            seen.add(key)
    return proposals


def render_proposal_table(proposals: list[FieldProposal]) -> str:
    """Render a Markdown review table of proposals."""
    if not proposals:
        return "_No field proposals._"
    lines = [
        "| Source | Raw path | → UDM model.field | Type | New? | Seen |",
        "|--------|----------|-------------------|------|------|------|",
    ]
    for p in proposals:
        lines.append(
            f"| {p.source_type} | `{p.raw_path}` | "
            f"`{p.target_model}.{p.field_name}` | {p.value_type} | "
            f"{'yes' if p.is_new else 'exists'} | {p.occurrence_count} |"
        )
    return "\n".join(lines)


def render_extension_module(proposals: list[FieldProposal]) -> str:
    """Render a Python scaffold of ``*Additions`` classes for the new fields."""
    new = [p for p in proposals if p.is_new]
    by_model: dict[str, list[FieldProposal]] = {}
    for p in new:
        by_model.setdefault(p.target_model, []).append(p)

    header = (
        '"""AUTO-GENERATED proposed UDM field additions — DO NOT import in prod.\n\n'
        "Generated by tengen.udm.model_updater from approved field-registry rows.\n"
        "Each class lists fields proposed for the matching model in\n"
        "``tengen/models/udm.py``. Review, then fold the fields into the real\n"
        f"models and delete this file. Generated at {datetime.now(tz=timezone.utc).isoformat()}.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "from typing import Any\n\n"
        "from pydantic import BaseModel, Field\n"
    )
    if not by_model:
        return header + "\n# No new fields to propose.\n"

    blocks: list[str] = [header]
    for model_name in sorted(by_model):
        blocks.append(f"\n\nclass {model_name}Additions(BaseModel):")
        blocks.append(f'    """Proposed additions to {model_name}."""\n')
        emitted: set[str] = set()
        for p in by_model[model_name]:
            if p.field_name in emitted:
                continue
            emitted.add(p.field_name)
            blocks.append(
                f"    # from {p.source_type} `{p.raw_path}` "
                f"(seen {p.occurrence_count}x, e.g. {p.sample_value!r})"
            )
            blocks.append(f"    {p.py_field()}")
    return "\n".join(blocks) + "\n"


def render_pr_body(proposals: list[FieldProposal]) -> str:
    new_count = sum(1 for p in proposals if p.is_new)
    return (
        "## Proposed UDM model field additions\n\n"
        f"This PR was generated from {len(proposals)} approved field-registry "
        f"candidate(s); {new_count} introduce new model fields.\n\n"
        f"{render_proposal_table(proposals)}\n\n"
        "Review the scaffold in `tengen/models/udm_proposed_fields.py`, fold the "
        "fields into `tengen/models/udm.py`, then delete the scaffold.\n"
    )


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )


def create_update_branch(
    registry: FieldRegistry,
    repo_root: Path | str | None = None,
    branch: str | None = None,
    module_path: str = _PROPOSED_MODULE,
    commit: bool = True,
    mark_promoted: bool = True,
) -> dict[str, Any]:
    """Create a branch with the generated scaffold for approved fields.

    Returns a result dict. Does NOT open a pull request — that is left to the
    caller (e.g. the GitHub MCP tools / ``gh``) after review.
    """
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    proposals = propose_from_registry(registry)
    new_proposals = [p for p in proposals if p.is_new]

    result: dict[str, Any] = {
        "created": False,
        "branch": branch,
        "module_path": module_path,
        "proposals": [p.__dict__ for p in proposals],
        "new_field_count": len(new_proposals),
        "pr_body": render_pr_body(proposals),
        "error": None,
    }

    if not new_proposals:
        result["error"] = "no approved new fields to promote"
        return result

    branch = branch or f"udm/field-additions-{datetime.now(tz=timezone.utc):%Y%m%d-%H%M%S}"
    result["branch"] = branch
    target = root / module_path

    try:
        _run_git(["checkout", "-b", branch], root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_extension_module(proposals))
        if commit:
            _run_git(["add", str(target)], root)
            _run_git(
                ["commit", "-m", f"feat(udm): propose {len(new_proposals)} new model field(s)"],
                root,
            )
        result["created"] = True
    except subprocess.CalledProcessError as exc:  # pragma: no cover - git env dependent
        result["error"] = exc.stderr or str(exc)
        return result

    if mark_promoted:
        for p in proposals:
            registry.set_status(p.field_id, FieldStatus.PROMOTED, notes=f"branch={branch}")

    return result
