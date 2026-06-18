"""Dashboard UDM field-registry API (front-end monitoring access)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tengen.dashboard import app as app_module
from tengen.udm.field_registry import FieldRegistry


@pytest.fixture()
def client(tmp_path, monkeypatch):
    registry = FieldRegistry(db_path=str(tmp_path / "fields.db"))
    monkeypatch.setattr(app_module, "_registry", registry)
    # No `with`: lifespan (and the RabbitMQ consumer threads) stays off.
    yield TestClient(app_module.app), registry
    registry.close()


def test_list_fields_empty(client):
    c, _ = client
    assert c.get("/api/udm/fields").json() == []


def test_list_and_filter_fields(client):
    c, registry = client
    registry.observe("aws", "foo.bar", "baz", "principal.user.userid")
    registry.observe("gcp", "x.y", "z", "")
    assert len(c.get("/api/udm/fields").json()) == 2
    aws = c.get("/api/udm/fields", params={"source_type": "aws"}).json()
    assert len(aws) == 1 and aws[0]["source_type"] == "aws"


def test_patch_approve_and_remap(client):
    c, registry = client
    registry.observe("aws", "foo.bar", "baz", "")
    fid = c.get("/api/udm/fields").json()[0]["id"]

    r = c.patch(f"/api/udm/fields/{fid}", json={"status": "approved", "suggested_udm_field": "principal.hostname"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "approved"
    assert body["suggested_udm_field"] == "principal.hostname"


def test_patch_invalid_status_and_missing(client):
    c, registry = client
    registry.observe("aws", "foo.bar", "baz")
    fid = c.get("/api/udm/fields").json()[0]["id"]
    assert c.patch(f"/api/udm/fields/{fid}", json={"status": "bogus"}).status_code == 422
    assert c.patch("/api/udm/fields/424242", json={"status": "ignored"}).status_code == 404


def test_summary_endpoint(client):
    c, registry = client
    registry.observe("aws", "a", "1")
    registry.observe("aws", "b", "2")
    summary = c.get("/api/udm/fields/summary").json()
    assert summary["total"] == 2
    assert summary["new"] == 2
