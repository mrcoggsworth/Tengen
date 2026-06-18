"""Model updater: proposal generation + scaffold rendering."""
from __future__ import annotations

import subprocess

from tengen.udm.field_registry import FieldRegistry, FieldStatus
from tengen.udm.model_updater import (
    create_update_branch,
    propose_from_registry,
    render_extension_module,
    render_proposal_table,
    render_pr_body,
)


def _seed(registry: FieldRegistry) -> None:
    # Genuinely new field (no existing model field "mfa_authenticated").
    registry.observe("aws", "additionalEventData.MFAAuthenticated", "true", "")
    # Maps onto an existing Noun field (hostname already exists).
    registry.observe("crowdstrike", "DeviceName", "WS-1", "principal.hostname")
    # New numeric field on Network.
    registry.observe("firewall", "packet_count", 99, "network.packet_count")
    for row in registry.list_fields():
        registry.set_status(row["id"], FieldStatus.APPROVED)


def test_propose_marks_new_vs_existing(tmp_path):
    registry = FieldRegistry(db_path=str(tmp_path / "f.db"))
    _seed(registry)
    proposals = {p.field_name: p for p in propose_from_registry(registry)}

    assert proposals["mfa_authenticated"].target_model == "Noun"
    assert proposals["mfa_authenticated"].is_new is True

    assert proposals["hostname"].target_model == "Noun"
    assert proposals["hostname"].is_new is False  # already on Noun

    assert proposals["packet_count"].target_model == "Network"
    assert proposals["packet_count"].is_new is True
    assert proposals["packet_count"].value_type == "int"
    registry.close()


def test_only_approved_are_proposed(tmp_path):
    registry = FieldRegistry(db_path=str(tmp_path / "f.db"))
    registry.observe("aws", "newThing", "x", "")
    # status defaults to NEW → not proposed
    assert propose_from_registry(registry) == []
    registry.close()


def test_render_extension_module_is_valid_python(tmp_path):
    registry = FieldRegistry(db_path=str(tmp_path / "f.db"))
    _seed(registry)
    proposals = propose_from_registry(registry)
    source = render_extension_module(proposals)

    # Must compile and define Additions classes only for NEW fields.
    compile(source, "udm_proposed_fields.py", "exec")
    assert "class NounAdditions(BaseModel):" in source
    assert "class NetworkAdditions(BaseModel):" in source
    assert "mfa_authenticated: str" in source
    assert "packet_count: int | None = None" in source
    # Existing fields are not re-declared.
    assert "hostname:" not in source
    registry.close()


def test_render_proposal_table_and_pr_body(tmp_path):
    registry = FieldRegistry(db_path=str(tmp_path / "f.db"))
    _seed(registry)
    proposals = propose_from_registry(registry)
    table = render_proposal_table(proposals)
    body = render_pr_body(proposals)
    assert "Raw path" in table
    assert "`Network.packet_count`" in table
    assert "Proposed UDM model field additions" in body
    registry.close()


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_create_update_branch_in_temp_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-b", "main"], repo)
    _git(["config", "user.email", "t@t.io"], repo)
    _git(["config", "user.name", "Test"], repo)
    _git(["config", "commit.gpgsign", "false"], repo)
    (repo / "README.md").write_text("seed\n")
    _git(["add", "."], repo)
    _git(["commit", "-m", "init"], repo)

    registry = FieldRegistry(db_path=str(tmp_path / "f.db"))
    _seed(registry)

    result = create_update_branch(registry, repo_root=repo, branch="udm/test-fields")
    assert result["created"] is True
    assert result["branch"] == "udm/test-fields"
    assert result["new_field_count"] >= 2

    # The branch exists and the scaffold module was committed.
    branches = subprocess.run(
        ["git", "branch", "--list", "udm/test-fields"], cwd=repo, capture_output=True, text=True
    ).stdout
    assert "udm/test-fields" in branches
    assert (repo / "tengen/models/udm_proposed_fields.py").exists()

    # Approved fields are marked promoted afterwards.
    assert registry.summary()["promoted"] >= 2
    registry.close()
