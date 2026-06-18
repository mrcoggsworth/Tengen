"""Field registry: upsert, status transitions, summary."""
from __future__ import annotations

import pytest

from tengen.udm.field_registry import FieldRegistry, FieldStatus


@pytest.fixture()
def registry(tmp_path):
    reg = FieldRegistry(db_path=str(tmp_path / "fields.db"))
    yield reg
    reg.close()


def test_observe_inserts_then_upserts(registry):
    registry.observe("aws", "requestParameters.userName", "bob", "principal.user.userid")
    registry.observe("aws", "requestParameters.userName", "carol", "principal.user.userid")
    rows = registry.list_fields(source_type="aws")
    assert len(rows) == 1
    row = rows[0]
    assert row["occurrence_count"] == 2
    assert row["sample_value"] == "carol"
    assert row["status"] == FieldStatus.NEW.value


def test_value_type_inference(registry):
    registry.observe("firewall", "packets", 42)
    registry.observe("firewall", "blocked", True)
    types = {r["raw_path"]: r["value_type"] for r in registry.list_fields()}
    assert types["packets"] == "int"
    assert types["blocked"] == "bool"


def test_status_and_suggested_field_updates(registry):
    registry.observe("gcp", "protoPayload.request.policy", {"k": "v"})
    field_id = registry.list_fields()[0]["id"]

    assert registry.set_status(field_id, FieldStatus.APPROVED, notes="looks useful")
    assert registry.set_suggested_field(field_id, "target.resource.attribute_labels")

    row = registry.get(field_id)
    assert row["status"] == "approved"
    assert row["notes"] == "looks useful"
    assert row["suggested_udm_field"] == "target.resource.attribute_labels"
    assert registry.set_status(999999, FieldStatus.IGNORED) is False


def test_summary_counts(registry):
    registry.observe("aws", "a", "1")
    registry.observe("aws", "b", "2")
    registry.observe("gcp", "c", "3")
    registry.set_status(registry.list_fields(source_type="aws")[0]["id"], FieldStatus.APPROVED)

    summary = registry.summary()
    assert summary["total"] == 3
    assert summary["approved"] == 1
    assert summary["new"] == 2
    assert summary["by_source"]["aws"] == 2
    assert summary["by_source"]["gcp"] == 1
