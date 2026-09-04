"""
Tests for the FastAPI control plane (api/app.py).
Uses FastAPI's TestClient — no real network or running server required.
"""

import pytest
from fastapi.testclient import TestClient

from entropica_audit_engine.api.app import app
from entropica_audit_engine.api.store import store


@pytest.fixture(autouse=True)
def clear_store():
    store.clear()
    yield
    store.clear()


@pytest.fixture
def client():
    return TestClient(app)


class TestHealthAndRules:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_list_rules_includes_all_five(self, client):
        r = client.get("/rules")
        assert r.status_code == 200
        rule_ids = {rule["rule_id"] for rule in r.json()}
        assert rule_ids == {
            "API1:2023", "API3:2023", "API4:2023", "API6:2023", "API7:2023",
        }


class TestBolaEndpoint:
    def test_sequential_ids_returns_finding_and_persists(self, client):
        payload = {
            "target_url": "https://api.example.com/orders",
            "sample_ids": [str(i) for i in range(3001, 3015)],
        }
        r = client.post("/findings/bola", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body is not None
        assert body["rule_id"] == "API1:2023"

        r2 = client.get("/findings")
        assert len(r2.json()) == 1

    def test_random_uuids_returns_null(self, client):
        import uuid

        payload = {
            "target_url": "https://api.example.com/sessions",
            "sample_ids": [str(uuid.uuid4()) for _ in range(6)],
        }
        r = client.post("/findings/bola", json=payload)
        assert r.status_code == 200
        assert r.json() is None


class TestResourceConsumptionEndpoint:
    def test_overload_flagged(self, client):
        payload = {
            "target_url": "https://api.example.com/x",
            "rate_samples": [[float(t), 100.0] for t in range(10)],
        }
        r = client.post("/findings/resource-consumption", json=payload)
        assert r.status_code == 200
        assert r.json() is not None


class TestMassAssignmentEndpoint:
    def test_write_only_field_flagged(self, client):
        payload = {
            "target_url": "https://api.example.com/users",
            "read_fields": ["id", "name"],
            "write_fields": ["id", "name", "role"],
        }
        r = client.post("/findings/mass-assignment", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body is not None
        assert "role" in body["evidence"]["write_only_fields"]


class TestScanEndpoint:
    def test_empty_urls_rejected(self, client):
        r = client.post("/scans", json={"urls": []})
        assert r.status_code == 400
