"""Dependency-free local web server for Continuum Studio.

The browser is a presentation layer.  The vault, classification, access policy,
and audit trail stay in the existing deterministic core.  This deliberately
keeps model output outside of every authorization and storage decision.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from legacy.agent.memory_agent import LegacyAgent
from legacy.agent.query_engine import QueryEngine
from continuum_web import narrator


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DEFAULT_WORKSPACE = Path(os.environ.get("CONTINUUM_DATA_DIR", ".continuum"))


class Studio:
    """Small session coordinator; no passphrase is persisted by the UI."""

    def __init__(self, workspace: Path) -> None:
        self.root = workspace.resolve()
        self.workspace = self.root
        self.agent: LegacyAgent | None = None
        self.owner_id = "owner"
        self.passphrase: str | None = None
        self.role = "owner"

    def _new_agent(self, owner_id: str) -> LegacyAgent:
        self.owner_id = owner_id.strip() or "owner"
        return LegacyAgent(self.workspace, self.owner_id)

    def create(self, owner_id: str, passphrase: str) -> dict[str, Any]:
        if len(passphrase) < 10:
            raise ValueError("Use a passphrase with at least 10 characters.")
        agent = self._new_agent(owner_id)
        if agent._vault.exists():
            raise ValueError("A vault already exists here. Unlock it instead.")
        agent.initialize(passphrase)
        self.agent, self.passphrase = agent, passphrase
        self.role = "owner"
        return self.snapshot()

    def unlock(self, owner_id: str, passphrase: str) -> dict[str, Any]:
        agent = self._new_agent(owner_id)
        agent.open_owner(passphrase)
        self.agent, self.passphrase = agent, passphrase
        self.role = "owner"
        return self.snapshot()

    def unlock_heir(
        self, heir_id: str, passphrase: str, heir_key: str | None = None
    ) -> dict[str, Any]:
        heir_id = heir_id.strip()
        if not heir_id:
            raise ValueError("Enter the heir identifier provided by the owner.")
        agent = self._new_agent(heir_id)
        if not agent.open_heir(heir_id, passphrase, heir_key=heir_key or None):
            raise ValueError("Heir access was not granted by the vault policy.")
        self.agent, self.passphrase, self.role = agent, passphrase, "heir"
        return self.snapshot()

    def lock(self) -> None:
        if self.agent is not None and self.passphrase is not None:
            self.agent.lock(self.passphrase)
        self.agent, self.passphrase = None, None

    def require_open(self) -> LegacyAgent:
        if self.agent is None:
            raise ValueError("Unlock a Continuum workspace first.")
        return self.agent

    def capture(
        self, title: str, body: str, tags: list[str], *, filename: str | None = None
    ) -> dict[str, Any]:
        agent = self.require_open()
        if self.role != "owner":
            raise ValueError("Heir view is read-only.")
        title = title.strip() or "Untitled memory"
        body = body.strip()
        if not body:
            raise ValueError("Add a memory before saving it.")
        inbox = self.workspace / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        # Randomized filename prevents a later capture from replacing prior evidence.
        path = inbox / _capture_filename(title, filename)
        path.write_text(body, encoding="utf-8")
        record = agent.ingest(path, notes="Captured in Continuum Studio", tags=tags)
        return {"record": record.to_dict(), "dashboard": self.snapshot()}

    def ask(self, question: str, *, allow_narration: bool = False) -> dict[str, Any]:
        agent = self.require_open()
        question = question.strip()
        if not question:
            raise ValueError("Ask Continuum a question.")
        response = QueryEngine(agent._memory).query(question, top_k=6)
        agent._audit.append("STUDIO_QUERY", actor=self.owner_id, detail=question[:80])
        sources = [
            {
                "artifact": item.artifact,
                "category": item.category.value,
                "excerpt": item.content[:180].replace("\n", " "),
            }
            for item in response.results
        ]
        narration = None
        narration_error = None
        if narrator.enabled(opted_in=allow_narration) and sources:
            try:
                narration = narrator.narrate(
                    question, response.answer, [item["excerpt"] for item in sources]
                )
            except narrator.NarrationError as exc:
                narration_error = str(exc)
        return {
            "answer": response.answer,
            "intent": response.intent.value,
            "category": response.category_filter.value if response.category_filter else None,
            "sources": sources,
            "narration": narration,
            "narration_error": narration_error,
            "mode": "GPT-5.6 narration + deterministic retrieval" if narration else "deterministic retrieval",
        }

    def heir_guide(self) -> dict[str, str]:
        """Return the core-generated guide without any model transformation."""
        agent = self.require_open()
        return {"guide": agent.heir_guide(actor=self.owner_id)}

    def integrity_report(self) -> dict[str, Any]:
        """Combine both independent checks exposed by the deterministic core."""
        agent = self.require_open()
        audit = agent.verify_audit()
        memory = agent.verify_memory_integrity()
        return {"valid": audit["valid"] and memory["ok"], "audit": audit, "memory": memory}

    def snapshot(self) -> dict[str, Any]:
        agent = self.require_open()
        summary = agent.summary(self.owner_id)
        integrity = self.integrity_report()
        return {
            "owner_id": summary["owner_id"],
            "created_at": summary["created_at"],
            "total_artifacts": summary["total_artifacts"],
            "by_category": summary["by_category"],
            "heirs": summary["heirs"],
            "audit_events": summary["audit_trail_length"],
            "integrity": integrity["valid"],
            "hmac_checked": integrity["audit"]["hmac_checked"],
            "role": self.role,
            "open": True,
        }

    def demo(self) -> dict[str, Any]:
        self.lock()
        # Never replace a user's selected workspace. Demo data is confined to
        # this predictable child directory and is the only directory reset.
        self.workspace = self.root / "safe-demo"
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
        self.workspace.mkdir(parents=True)
        self.create("Alex Morgan", "continuum-demo")
        memories = [
            ("Apartment deed", "Property deed for the apartment at 42 Cedar Street. The notary is Elena Ruiz and the original is in the blue archival folder.", ["home", "urgent"]),
            ("Emergency care plan", "Medical history: allergy to penicillin. Primary physician: Dr. Lee. Keep the current medication list with this note.", ["health"]),
            ("Family archive", "Photos from the 1998 coastal trip are labeled COAST-98 and stored in the family archive drive.", ["family"]),
            ("Subscription checklist", "Cancel the streaming subscription and cloud photo plan after confirming the family archive has been exported.", ["accounts"]),
        ]
        for title, body, tags in memories:
            self.capture(title, body, tags)
        return self.snapshot()


def _safe_filename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")
    return (cleaned or "memory")[:56]


def _capture_filename(title: str, filename: str | None) -> str:
    """Build a contained filename for a browser-provided text file."""
    source = Path(filename or "")
    suffix = source.suffix.lower()
    if suffix not in {".txt", ".md", ".csv", ".json"}:
        suffix = ".txt"
    stem = source.stem if source.stem else title
    return f"{secrets.token_hex(8)}-{_safe_filename(stem)}{suffix}"


class Handler(SimpleHTTPRequestHandler):
    studio: Studio

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep a local demo quiet; errors still become API responses.
        return

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/health":
            self._json({"ok": True, "product": "Continuum Studio"})
            return
        if urlparse(self.path).path == "/api/dashboard":
            self._run(lambda _: self.studio.snapshot())
            return
        super().do_GET()

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        routes = {
            "/api/create": lambda body: self.studio.create(body.get("owner_id", "owner"), body.get("passphrase", "")),
            "/api/unlock": lambda body: self.studio.unlock(body.get("owner_id", "owner"), body.get("passphrase", "")),
            "/api/unlock-heir": lambda body: self.studio.unlock_heir(
                body.get("heir_id", ""),
                body.get("passphrase", ""),
                body.get("heir_key"),
            ),
            "/api/lock": lambda body: self._locked(),
            "/api/capture": lambda body: self.studio.capture(
                body.get("title", ""), body.get("body", ""), body.get("tags", []),
                filename=body.get("filename"),
            ),
            "/api/ask": lambda body: self.studio.ask(
                body.get("question", ""),
                allow_narration=body.get("allow_narration") is True,
            ),
            "/api/heir-guide": lambda body: self.studio.heir_guide(),
            "/api/integrity": lambda body: self.studio.integrity_report(),
            "/api/demo": lambda body: self.studio.demo(),
        }
        action = routes.get(route)
        if action is None:
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        self._run(action)

    def _locked(self) -> dict[str, bool]:
        self.studio.lock()
        return {"locked": True}

    def _read_json(self) -> dict[str, Any]:
        size = int(self.headers.get("Content-Length", "0"))
        if size > 1_000_000:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(size) or b"{}")

    def _run(self, action) -> None:
        try:
            self._json(action(self._read_json() if self.command == "POST" else {}))
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # The response avoids exposing paths or vault details.
            self._json({"error": f"The protected operation could not complete: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _json(self, body: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the Continuum Studio local app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args(argv)
    Handler.studio = Studio(args.workspace)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Continuum Studio is running at http://{args.host}:{args.port}")
    print(f"Protected workspace: {args.workspace.resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        Handler.studio.lock()
        server.server_close()


if __name__ == "__main__":
    main()
