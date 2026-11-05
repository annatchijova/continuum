"""
tests/test_security_r8.py
==========================
Red-team round R8: the Studio HTTP boundary (browser -> local server -> core
-> optional narration provider). Two findings, both reproduced against a live
server and fixed:

R8-001 (High) - cross-origin requests to the local API. The handler checked
neither `Host`, `Origin`, nor `Content-Type`. Any web page the owner visited
while Studio was unlocked could:
  * send a CORS "simple" request (`Content-Type: text/plain`, no preflight) to
    `/api/ask` with `allow_narration: true`, sending vault excerpts to the
    configured third-party provider without the owner's per-request consent;
  * plant records via `/api/capture` (poisoning what heirs later see);
  * lock the session or switch it to the demo workspace (`/api/lock`,
    `/api/demo`);
  * with DNS rebinding (attacker hostname resolving to 127.0.0.1), read every
    API response, including `/api/dashboard` and `/api/ask` excerpts, and
    brute-force `/api/unlock` with readable results.
Fix: every request must carry a loopback `Host` for the bound port; a present
`Origin` must match it; `Sec-Fetch-Site` must not be cross-site/same-site; and
POST bodies must be `application/json`, which forces a CORS preflight that the
server never approves.

R8-002 (Medium) - the global session mutex was held while reading the request
body. One connection announcing a body and never sending it froze every API
call (including `/api/lock`) indefinitely. Fix: read and parse the body before
taking the mutex, and give every connection a socket timeout.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from continuum_web import narrator, server


PASSPHRASE = "a-long-test-passphrase"


@pytest.fixture()
def live(tmp_path, monkeypatch):
    """A real Studio server on an ephemeral loopback port with an open vault."""
    studio = server.Studio(tmp_path / "ws")
    studio.create("owner@example.test", PASSPHRASE)
    studio.capture("Bank", "Account at Banco Sur 1234-5678; PIN hint is the dog.", [])
    handler = type("TestHandler", (server.Handler,), {"studio": studio})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_port, studio
    finally:
        httpd.shutdown()
        httpd.server_close()
        if studio.agent is not None:
            studio.lock()


def _request(port, method, path, body=None, headers=None, timeout=5.0):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def _same_origin(port):
    return {
        "Content-Type": "application/json",
        "Origin": f"http://127.0.0.1:{port}",
        "Sec-Fetch-Site": "same-origin",
    }


# --- R8-001: cross-origin requests --------------------------------------------


def test_r8_001_cross_site_simple_request_cannot_force_narration(live, monkeypatch):
    """The original exploit: a text/plain POST from another site triggered
    provider egress. It must be refused before the core is queried."""
    port, _studio = live
    egress = []
    monkeypatch.setattr(narrator, "enabled", lambda *, opted_in: opted_in)
    monkeypatch.setattr(
        narrator, "narrate", lambda *args: egress.append(args) or "narrated"
    )
    status, _ = _request(
        port,
        "POST",
        "/api/ask",
        json.dumps({"question": "bank account", "allow_narration": True}),
        {"Content-Type": "text/plain", "Origin": "https://evil.example"},
    )
    assert status == 403
    assert egress == []


@pytest.mark.parametrize(
    "path, payload",
    [
        ("/api/capture", {"title": "Will", "body": "Everything to Mallory.", "tags": []}),
        ("/api/lock", {}),
        ("/api/demo", {}),
        ("/api/ask", {"question": "bank"}),
        ("/api/unlock", {"owner_email": "owner@example.test", "passphrase": "guess-guess"}),
    ],
)
def test_r8_001_foreign_origin_is_refused_on_every_post_route(live, path, payload):
    """Variant sweep: the check is route-independent, not a per-route patch."""
    port, studio = live
    before = studio.snapshot()["total_artifacts"]
    headers = {**_same_origin(port), "Origin": "https://evil.example"}
    status, _ = _request(port, "POST", path, json.dumps(payload), headers)
    assert status == 403
    assert studio.agent is not None, "a refused request must not lock the session"
    assert studio.snapshot()["total_artifacts"] == before
    assert studio.snapshot()["workspace_mode"] == "private"


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_r8_001_fetch_metadata_cross_site_is_refused(live, site):
    port, _studio = live
    headers = {"Content-Type": "application/json", "Sec-Fetch-Site": site}
    status, _ = _request(port, "POST", "/api/ask", json.dumps({"question": "bank"}), headers)
    assert status == 403


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", None])
def test_r8_001_post_requires_json_content_type(live, content_type):
    """Without an Origin header (older clients), a non-JSON media type is
    still refused, so a CORS-simple request never reaches the core."""
    port, studio = live
    headers = {} if content_type is None else {"Content-Type": content_type}
    status, _ = _request(port, "POST", "/api/lock", "{}", headers)
    assert status == 415
    assert studio.agent is not None


@pytest.mark.parametrize("path", ["/api/dashboard", "/api/health", "/index.html"])
def test_r8_001_dns_rebinding_host_is_refused(live, path):
    """A rebinding attacker reaches 127.0.0.1 under its own hostname; the
    response must not be served to that origin."""
    port, _studio = live
    status, body = _request(port, "GET", path, headers={"Host": f"rebind.evil.example:{port}"})
    assert status == 403
    assert "owner@example.test" not in body


def test_r8_001_host_on_another_port_is_refused(live):
    port, _studio = live
    status, _ = _request(port, "GET", "/api/dashboard", headers={"Host": f"127.0.0.1:{port + 1}"})
    assert status == 403


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_r8_001_same_origin_browser_flow_still_works(live, host):
    """Negative control: the real UI (same-origin fetch with JSON) is unaffected,
    for both loopback spellings."""
    port, _studio = live
    origin = f"http://{host}:{port}"
    headers = {
        "Host": f"{host}:{port}",
        "Origin": origin,
        "Content-Type": "application/json; charset=utf-8",
        "Sec-Fetch-Site": "same-origin",
    }
    status, body = _request(port, "POST", "/api/ask", json.dumps({"question": "bank"}), headers)
    assert status == 200, body
    assert json.loads(body)["agent_flow"]["retrieval"] == "completed"
    status, body = _request(port, "GET", "/api/dashboard", headers={"Host": f"{host}:{port}"})
    assert status == 200
    assert json.loads(body)["open"] is True


def test_r8_001_cli_client_without_origin_still_works(live):
    """A local non-browser client sends no Origin; JSON + loopback Host is enough."""
    port, _studio = live
    status, _ = _request(
        port, "POST", "/api/integrity", "{}", {"Content-Type": "application/json"}
    )
    assert status == 200


# --- R8-002: slow body must not hold the session mutex ------------------------


def test_r8_002_slow_body_does_not_block_other_requests(live):
    port, _studio = live
    stalled = socket.create_connection(("127.0.0.1", port))
    try:
        stalled.sendall(
            b"POST /api/lock HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
            b"Content-Type: application/json\r\nContent-Length: 50\r\n\r\n{" % port
        )
        time.sleep(0.2)
        started = time.monotonic()
        status, _ = _request(port, "GET", "/api/dashboard", timeout=3.0)
        assert status == 200
        assert time.monotonic() - started < 1.0
    finally:
        stalled.close()


def test_r8_002_stalled_connection_is_dropped_by_socket_timeout(live, monkeypatch):
    """A connection that never completes its body is closed by the server."""
    assert 0 < server.Handler.timeout == server.REQUEST_TIMEOUT_SECONDS <= 30
    # Shorten the configured timeout only to observe the drop quickly.
    monkeypatch.setattr(server.Handler, "timeout", 0.5)
    port, studio = live
    stalled = socket.create_connection(("127.0.0.1", port))
    stalled.settimeout(5.0)
    try:
        stalled.sendall(
            b"POST /api/lock HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
            b"Content-Type: application/json\r\nContent-Length: 50\r\n\r\n{" % port
        )
        data = stalled.recv(4096)
        # Closed (b"") or answered with an error; never a successful lock.
        assert b"200 OK" not in data
    finally:
        stalled.close()
    assert studio.agent is not None
