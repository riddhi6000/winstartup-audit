import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api

TOKEN = "test-token"
HEADERS = {"X-WinAudit-Token": TOKEN}


@pytest.fixture
def client(monkeypatch):
    saved = []
    monkeypatch.setattr(api, "API_TOKEN", TOKEN)
    monkeypatch.setattr(api, "perform_scan", lambda: [])
    monkeypatch.setattr(api, "load_baseline", lambda path: None)
    monkeypatch.setattr(api, "save_baseline", lambda entries, path: saved.append(path))

    test_client = TestClient(api.app, base_url="http://127.0.0.1:8000")
    test_client.saved = saved
    return test_client


def test_scan_requires_token(client):
    assert client.get("/api/scan").status_code == 403
    assert client.get("/api/scan", headers={"X-WinAudit-Token": "wrong"}).status_code == 403


def test_scan_accepts_valid_token(client):
    response = client.get("/api/scan", headers=HEADERS)

    assert response.status_code == 200
    assert response.json()["total_entries"] == 0


def test_baseline_save_requires_token(client):
    response = client.post("/api/baseline/save")

    assert response.status_code == 403
    assert client.saved == []


def test_baseline_save_with_token_saves(client):
    response = client.post("/api/baseline/save", headers=HEADERS)

    assert response.status_code == 200
    assert len(client.saved) == 1


def test_cross_origin_request_rejected_even_with_token(client):
    response = client.get(
        "/api/scan",
        headers={**HEADERS, "Origin": "https://evil.example"},
    )

    assert response.status_code == 403


def test_unknown_host_header_rejected(client):
    evil = TestClient(api.app, base_url="http://evil.example")

    assert evil.get("/").status_code == 400


def test_no_cors_headers_are_sent(client):
    response = client.options(
        "/api/scan",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-winaudit-token",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_interactive_docs_are_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_second_scan_is_rejected_while_one_is_running(client):
    assert api._scan_lock.acquire(blocking=False)
    try:
        response = client.get("/api/scan", headers=HEADERS)
    finally:
        api._scan_lock.release()

    assert response.status_code == 409


def test_lock_is_released_after_a_scan(client):
    assert client.get("/api/scan", headers=HEADERS).status_code == 200
    assert client.get("/api/scan", headers=HEADERS).status_code == 200


def test_scan_failure_returns_generic_error(client, monkeypatch):
    def boom():
        raise RuntimeError(r"secret detail C:\Users\someone")

    monkeypatch.setattr(api, "perform_scan", boom)

    response = client.get("/api/scan", headers=HEADERS)

    assert response.status_code == 500
    assert "secret" not in response.text
    assert "someone" not in response.text
    assert client.get("/api/scan", headers=HEADERS).status_code == 500  # lock released


def test_corrupt_baseline_does_not_block_scan(client, monkeypatch):
    def bad_baseline(path):
        raise ValueError("Baseline file contains invalid JSON.")

    monkeypatch.setattr(api, "load_baseline", bad_baseline)

    response = client.get("/api/scan", headers=HEADERS)
    body = response.json()

    assert response.status_code == 200
    assert body["baseline_error"] == "Baseline file contains invalid JSON."
    assert body["baseline_saved_at"] is None
    assert body["diff"] is None


def test_dashboard_injects_token_and_matching_csp_nonce(client):
    response = client.get("/")

    assert response.status_code == 200
    assert TOKEN in response.text
    assert "__WINAUDIT_TOKEN__" not in response.text
    assert "__CSP_NONCE__" not in response.text

    csp = response.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"' in response.text
    assert response.headers["cache-control"] == "no-store"