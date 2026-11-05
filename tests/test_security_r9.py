"""
tests/test_security_r9.py
==========================
Red-team round R9: the narration-provider boundary. Two findings, reproduced
against the real narrator with local fake providers and fixed:

R9-001 (High) - API key forwarded on redirect. The NVIDIA path used
`urllib.request.urlopen`, whose redirect handler copies `Authorization` to
the new location, even on another host. A 301/302/303 from the configured
endpoint (compromised, misconfigured, or intercepted over plain HTTP) sent
`Bearer <key>` to the redirect target, and that host's reply was shown as
the narration. Fix: a transport that refuses every redirect, and a base URL
that must be HTTPS (plain HTTP is accepted only for loopback test servers).

R9-002 (High) - the output check was a single phrase regex. Of 17 probes,
only two were withheld: synonyms ("you're authorized", "identity is
confirmed"), other languages, homoglyphs (Cyrillic "е"), zero-width
characters, first-person impersonation of the deceased ("I am your father"),
and directive medical or financial advice all reached the UI. Fix: text is
normalized (NFKC/NFKD, format characters dropped, accents and common
confusables folded) before a broader authority / impersonation / advice
screen, and every number in the narration must already appear in the
question, the deterministic result, or the selected evidence.

This is a deterministic mitigation, not a proof that a model cannot
misbehave: the core result and sources stay visible beside any narration,
and a withheld narration falls back to that core result.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from continuum_web import narrator


QUESTION = "Where is the apartment deed?"
ANSWER = "Results for \"apartment deed\" (1):\n  • [legal] Property deed for 42 Cedar Street"
EVIDENCE = [
    "Property deed for the apartment at 42 Cedar Street. The notary is Elena Ruiz "
    "and the original is in the blue archival folder. Account 1234-5678, 1,500 USD, 1998."
]


def _check(text: str) -> str:
    return narrator._validate_narration(text, QUESTION, ANSWER, EVIDENCE)


# --- R9-002: output screen ----------------------------------------------------

WITHHELD = [
    # authority claims, the original pattern and its bypasses
    "Access granted.",
    "Your identity has been verified and heir access granted.",
    "You're authorized to open the vault.",
    "You’re authorized to open the vault.",
    "Your identity is confirmed.",
    "I have verified your identity.",
    "Access is granted to you as heir.",
    "You now have access to everything.",
    "ACCESS  GRANTED",
    "Acceso concedido.",
    "Estás autorizado a abrir la bóveda.",
    "Tu identidad fue verificada.",
    "Ya tenés acceso a todo.",
    "Accès accordé.",
    "Accеss granted",          # Cyrillic e
    "access​ granted",         # zero-width space
    "aсcess grаnted",     # Cyrillic s and a
    # impersonation of the deceased
    "I am your father and I want you to have the house.",
    "I'm your mom. Keep the blue folder safe.",
    "This is your grandmother speaking.",
    "As your grandmother, I forgive you.",
    "Soy tu mamá; quiero que te quedes con la casa.",
    "Te habla tu abuelo.",
    "Como tu padre, te pido que firmes.",
    # legal, financial, or medical advice
    "You should sell the apartment now and invest in bonds.",
    "Stop taking the penicillin, it is safe.",
    "You need to contest the will.",
    "I recommend that you sell the apartment.",
    "Deberías vender el departamento.",
    "Te recomiendo dejar de tomar la medicación.",
]


@pytest.mark.parametrize("text", WITHHELD)
def test_r9_002_unsafe_narration_is_withheld(text):
    with pytest.raises(narrator.NarrationError, match="Narration withheld"):
        _check(text)


INVENTED_NUMBERS = [
    "The deed is for 44 Cedar Street.",
    "The account number is 1234-9999.",
    "It was signed in 2003.",
    "The balance is 15,000 USD.",
]


@pytest.mark.parametrize("text", INVENTED_NUMBERS)
def test_r9_002_numbers_absent_from_the_evidence_are_withheld(text):
    with pytest.raises(narrator.NarrationError, match="not in the selected evidence"):
        _check(text)


ALLOWED = [
    "The deed for the apartment at 42 Cedar Street is in the blue archival folder.",
    "One record matches: the notary is Elena Ruiz, and the original is in the blue folder.",
    "The record mentions account 1234-5678 and an amount of 1500 USD from 1998.",
    "The record mentions 1,500 USD.",
    "I found 1 record. It says the original deed is in the blue archival folder.",
    "El registro indica que la escritura está en la carpeta azul.",
    "The owner's mother is not mentioned in the selected record.",
    "No relevant information was found for this question.",
    "The note describes how the owner wanted the family archive to be shared.",
    "This is your mother's recipe, according to the record.",
    "You can find the deed in the blue archival folder.",
    "The checklist says to cancel the streaming subscription after the export.",
]


@pytest.mark.parametrize("text", ALLOWED)
def test_r9_002_faithful_third_person_narration_still_passes(text):
    """Negative control: the screen must not swallow ordinary narration."""
    assert _check(text) == text


def test_r9_002_instructions_forbid_impersonation_and_new_numbers():
    rules = narrator._INSTRUCTIONS
    assert "third person" in rules
    assert "Never speak as" in rules
    assert "numbers" in rules


# --- R9-001: redirects never carry the key ------------------------------------


@pytest.fixture()
def redirecting_provider():
    seen: list[tuple[str, str | None]] = []

    class Thief(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self):
            seen.append((self.command, self.headers.get("Authorization")))
            body = json.dumps({"choices": [{"message": {"content": "stolen"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _reply

    thief = ThreadingHTTPServer(("127.0.0.1", 0), Thief)

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            code = int(self.path.split("/")[2])
            self.send_response(code)
            self.send_header("Location", f"http://localhost:{thief.server_port}/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()

    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    for server in (thief, provider):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield provider.server_port, seen
    finally:
        for server in (thief, provider):
            server.shutdown()
            server.server_close()


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_r9_001_redirect_is_refused_and_key_never_forwarded(
    redirecting_provider, monkeypatch, code
):
    port, seen = redirecting_provider
    monkeypatch.setenv("CONTINUUM_LLM_PROVIDER", "nvidia")
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-secret")
    monkeypatch.setenv("CONTINUUM_NVIDIA_BASE_URL", f"http://127.0.0.1:{port}/redir/{code}")
    with pytest.raises(narrator.NarrationError):
        narrator.narrate(QUESTION, ANSWER, EVIDENCE)
    assert seen == []


@pytest.mark.parametrize(
    "base_url",
    [
        "http://integrate.api.nvidia.com/v1",
        "http://10.0.0.5:8000/v1",
        "ftp://integrate.api.nvidia.com/v1",
        "file:///etc/passwd",
    ],
)
def test_r9_001_key_is_never_sent_over_plain_http_to_a_remote_host(monkeypatch, base_url):
    sent = []
    monkeypatch.setenv("CONTINUUM_LLM_PROVIDER", "nvidia")
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-secret")
    monkeypatch.setenv("CONTINUUM_NVIDIA_BASE_URL", base_url)
    monkeypatch.setattr(narrator, "_post", lambda *a, **k: sent.append(a))
    with pytest.raises(narrator.NarrationError, match="HTTPS"):
        narrator.narrate(QUESTION, ANSWER, EVIDENCE)
    assert sent == []


# --- R9-003: variant on the OpenAI Agents SDK path ----------------------------
#
# Live probe (openai 3.46.0, openai-agents 0.24.0): the SDK strips
# Authorization on a cross-host redirect, but on a 307 it re-POSTs the full
# request body - the plaintext excerpts - to the redirect host, and it accepts
# a plain-HTTP OPENAI_BASE_URL. Fix: a per-agent AsyncOpenAI client whose
# HTTP client never follows redirects (the pattern OpenAI documents for
# keeping requests on one origin), plus the same HTTPS rule as NVIDIA.


@pytest.fixture()
def fake_openai_sdk(monkeypatch):
    import sys
    from types import SimpleNamespace

    captured: dict = {}

    class FakeHttpClient:
        def __init__(self, **kwargs):
            captured["http_client"] = kwargs

    class FakeAsyncOpenAI:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

    class FakeResponsesModel:
        def __init__(self, model, openai_client, **kwargs):
            captured["model"] = (model, openai_client)

    class FakeRunner:
        @staticmethod
        def run_sync(agent, message, **kwargs):
            captured["agent"] = agent
            return SimpleNamespace(final_output="The deed is in the blue archival folder.")

    def record(name):
        return lambda **kwargs: captured.setdefault(name, kwargs)

    monkeypatch.setitem(
        sys.modules,
        "agents",
        SimpleNamespace(
            Agent=record("agent_kwargs"),
            ModelSettings=record("model_settings"),
            RunConfig=record("run_config"),
            Runner=FakeRunner,
            OpenAIResponsesModel=FakeResponsesModel,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "openai",
        SimpleNamespace(AsyncOpenAI=FakeAsyncOpenAI, DefaultAsyncHttpx2Client=FakeHttpClient),
    )
    monkeypatch.setenv("CONTINUUM_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    return captured


def test_r9_003_openai_client_never_follows_redirects(fake_openai_sdk):
    narrator.narrate(QUESTION, ANSWER, EVIDENCE)
    captured = fake_openai_sdk
    assert captured["http_client"]["follow_redirects"] is False
    assert captured["client"]["api_key"] == "sk-secret"
    model_name, client = captured["model"]
    assert model_name == "gpt-5.6"
    # The agent runs on the model bound to this client, not on a bare model
    # name that would make the SDK build its own redirect-following client.
    assert type(captured["agent_kwargs"]["model"]).__name__ == "FakeResponsesModel"
    assert type(captured["client"]["http_client"]).__name__ == "FakeHttpClient"
    assert type(client).__name__ == "FakeAsyncOpenAI"
    # The privacy contract from earlier rounds still holds.
    assert captured["model_settings"] == {"store": False}
    assert captured["run_config"] == {"tracing_disabled": True}


@pytest.mark.parametrize(
    "base_url", ["http://api.openai.com/v1", "http://10.0.0.5/v1", "ftp://api.openai.com/v1"]
)
def test_r9_003_openai_base_url_must_be_https(fake_openai_sdk, monkeypatch, base_url):
    monkeypatch.setenv("OPENAI_BASE_URL", base_url)
    with pytest.raises(narrator.NarrationError, match="HTTPS"):
        narrator.narrate(QUESTION, ANSWER, EVIDENCE)
    assert "client" not in fake_openai_sdk


def test_r9_003_openai_https_or_loopback_base_url_is_passed_through(fake_openai_sdk, monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.example/v1")
    narrator.narrate(QUESTION, ANSWER, EVIDENCE)
    assert fake_openai_sdk["client"]["base_url"] == "https://gateway.example/v1"
