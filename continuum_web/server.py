"""Dependency-free local web server for Continuum Studio.

The browser is a presentation layer.  The vault, classification, access policy,
and audit trail stay in the existing deterministic core.  This deliberately
keeps model output outside of every authorization and storage decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import threading
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from legacy.agent.memory_agent import LegacyAgent
from legacy.agent.query_engine import QueryEngine
from legacy.core.lockfile import AgentLock
from legacy.vault.conditions import AccessPolicy, InactivityCondition
from continuum_web import narrator


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DEFAULT_WORKSPACE = Path(os.environ.get("CONTINUUM_DATA_DIR", ".continuum"))
MAX_JSON_BODY_BYTES = 1_000_000
# Keep the Studio transport aligned with MemoryField's indexed-content limit.
# Larger documents need a chunked importer rather than silent truncation.
MAX_CAPTURE_BYTES = 256 * 1024
RECOVERY_SHARE_COUNT = 5
RECOVERY_THRESHOLD = 3
_MANAGED_WORKSPACE_FILES = (
    "legacy.vault",
    "audit.db",
    "audit.db-shm",
    "audit.db-wal",
    "memory.db",
    "memory.db-shm",
    "memory.db-wal",
    "knowledge.db",
    "knowledge.db-shm",
    "knowledge.db-wal",
    "agent.lock",
)
_MANAGED_WORKSPACE_DIRECTORIES = ("artifacts", "inbox")
_EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)


def _decode_json_object(raw: bytes) -> dict[str, Any]:
    """Accept only a JSON object as an API request body."""
    value = json.loads(raw or b"{}")
    if not isinstance(value, dict):
        raise ValueError("Request body must be a JSON object.")
    return value


def _normalize_email(value: str) -> str:
    """Return the canonical local-product email identity or reject it."""
    if not isinstance(value, str):
        raise ValueError("Enter the owner's email address.")
    email = value.strip().casefold()
    if len(email) > 254 or not _EMAIL_PATTERN.fullmatch(email):
        raise ValueError("Enter a valid email address.")
    return email


def _owner_principal(email: str) -> str:
    """Keep the email out of audit actors while binding it in the vault."""
    return "owner-" + hashlib.sha256(email.encode("utf-8")).hexdigest()[:24]


def _studio_identity(value: str) -> str:
    """Keep direct Python callers compatible; HTTP routes require an email."""
    try:
        return _normalize_email(value)
    except ValueError:
        if isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", value):
            return value
        raise


class Studio:
    """Small session coordinator; no passphrase is persisted by the UI."""

    def __init__(self, workspace: Path) -> None:
        self.root = workspace.resolve()
        self.workspace = self.root
        self.agent: LegacyAgent | None = None
        self.owner_id = "owner"
        self.passphrase: str | None = None
        self.role = "owner"
        self._demo_active = False
        self._mutex = threading.RLock()
        self._workspace_lock: AgentLock | None = None

    def _new_agent(self, owner_email: str) -> LegacyAgent:
        self.owner_id = _owner_principal(owner_email)
        return LegacyAgent(self.workspace, self.owner_id)

    def _acquire_workspace(self) -> None:
        if self._workspace_lock is None:
            self._workspace_lock = AgentLock(self.workspace).acquire()

    def _release_workspace(self) -> None:
        if self._workspace_lock is not None:
            self._workspace_lock.release()
            self._workspace_lock = None

    def _require_no_open_session(self) -> None:
        if self.agent is not None:
            raise ValueError("A workspace is already open. Lock it before opening another.")

    def create(
        self,
        owner_email: str,
        passphrase: str,
        *,
        inactivity_days: int | None = None,
        inactivity_last_activity: datetime | None = None,
        setup_recovery: bool = False,
    ) -> dict[str, Any]:
        if len(passphrase) < 10:
            raise ValueError("Use a passphrase with at least 10 characters.")
        if inactivity_days is not None and (
            isinstance(inactivity_days, bool)
            or not isinstance(inactivity_days, int)
            or not 1 <= inactivity_days <= 36_500
        ):
            raise ValueError("Inactivity protection must be between 1 and 36,500 days.")
        if inactivity_last_activity is not None and inactivity_days is None:
            raise ValueError("An inactivity timestamp requires an inactivity policy.")
        owner_email = _studio_identity(owner_email)
        self._require_no_open_session()
        self._acquire_workspace()
        try:
            agent = self._new_agent(owner_email)
            if agent._vault.exists():
                raise ValueError("A vault already exists here. Unlock it instead.")
            policy = None
            if inactivity_days is not None:
                policy = AccessPolicy(
                    [
                        InactivityCondition(
                            days=inactivity_days,
                            last_activity_iso=(
                                inactivity_last_activity or datetime.now(timezone.utc)
                            ).isoformat(),
                        )
                    ]
                )
            agent.initialize(passphrase, policy=policy, owner_email=owner_email)
            # Studio workspaces opt into the core's database-at-rest encryption
            # before accepting their first captured memory.
            agent.encrypt_database(passphrase)
            self.agent, self.passphrase = agent, passphrase
            self.role = "owner"
            recovery_shares = None
            if setup_recovery:
                recovery_shares = agent.setup_custody(
                    passphrase,
                    shares=RECOVERY_SHARE_COUNT,
                    threshold=RECOVERY_THRESHOLD,
                )
            result = self.snapshot()
            if recovery_shares is not None:
                result["recovery_shares"] = recovery_shares
            return result
        except Exception:
            self._release_workspace()
            raise

    def unlock(self, owner_email: str, passphrase: str) -> dict[str, Any]:
        owner_email = _studio_identity(owner_email)
        self._require_no_open_session()
        self._acquire_workspace()
        try:
            agent = self._new_agent(owner_email)
            agent.open_owner(passphrase, expected_owner_email=owner_email)
            self.agent, self.passphrase = agent, passphrase
            self.role = "owner"
            return self.snapshot()
        except Exception:
            self._release_workspace()
            raise

    def reset_passphrase(
        self, owner_email: str, shares: list[str], new_passphrase: str
    ) -> dict[str, Any]:
        """Use K-of-N custody shares to reset a lost owner passphrase."""
        owner_email = _studio_identity(owner_email)
        if len(new_passphrase) < 10:
            raise ValueError("Use a passphrase with at least 10 characters.")
        if (
            not isinstance(shares, list)
            or not 2 <= len(shares) <= RECOVERY_SHARE_COUNT
            or not all(isinstance(share, str) and share.strip() for share in shares)
        ):
            raise ValueError("Enter the recovery shares, one per line.")
        self._require_no_open_session()
        self._acquire_workspace()
        try:
            agent = self._new_agent(owner_email)
            agent.set_passphrase_from_recovery(
                [share.strip() for share in shares],
                new_passphrase,
                actor=self.owner_id,
                expected_owner_email=owner_email,
            )
            self.agent, self.passphrase, self.role = agent, new_passphrase, "owner"
            return self.snapshot()
        except Exception:
            self._release_workspace()
            raise

    def unlock_heir(
        self, heir_id: str, passphrase: str, heir_key: str | None = None
    ) -> dict[str, Any]:
        heir_id = heir_id.strip()
        if not heir_id:
            raise ValueError("Enter the heir identifier provided by the owner.")
        self._require_no_open_session()
        self._acquire_workspace()
        try:
            agent = self._new_agent(heir_id)
            if not agent.open_heir(heir_id, passphrase, heir_key=heir_key or None):
                raise ValueError("Heir access was not granted by the vault policy.")
            self.agent, self.passphrase, self.role = agent, passphrase, "heir"
            return self.snapshot()
        except Exception:
            self._release_workspace()
            raise

    def lock(self) -> None:
        if self.agent is not None and self.passphrase is not None:
            self.agent.lock(self.passphrase)
        self.agent, self.passphrase = None, None
        self._release_workspace()
        if self._demo_active:
            self.workspace = self.root
            self._demo_active = False

    def require_open(self) -> LegacyAgent:
        if self.agent is None:
            raise ValueError("Unlock a Continuum workspace first.")
        return self.agent

    def capture(
        self,
        title: str,
        body: str,
        tags: list[str],
        *,
        filename: str | None = None,
        include_dashboard: bool = True,
    ) -> dict[str, Any]:
        agent = self.require_open()
        if self.role != "owner":
            raise ValueError("Heir view is read-only.")
        if not isinstance(title, str) or not isinstance(body, str):
            raise ValueError("Memory title and content must be text.")
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise ValueError("Tags must be a list of text values.")
        title = title.strip() or "Untitled memory"
        body = body.strip()
        tags = [tag.strip() for tag in tags if tag.strip()]
        if not body:
            raise ValueError("Add a memory before saving it.")
        if len(body.encode("utf-8")) > MAX_CAPTURE_BYTES:
            raise ValueError("Captured text must be 256 KiB or smaller.")
        if self.passphrase is None:
            raise RuntimeError("The open workspace has no session passphrase.")
        inbox = self.workspace / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        # Randomized filename prevents a later capture from replacing prior evidence.
        path = inbox / _capture_filename(title, filename)
        path.write_text(body, encoding="utf-8")
        try:
            record = agent.ingest(
                path, notes="Captured in Continuum Studio", tags=tags
            )
            agent.archive_artifact(path, self.passphrase)
        finally:
            path.unlink(missing_ok=True)
        result = {"record": record.to_dict()}
        if include_dashboard:
            result["dashboard"] = self.snapshot()
        return result

    def delete_workspace(
        self, owner_email: str, passphrase: str
    ) -> dict[str, bool]:
        """Permanently remove only Continuum-managed data for an open owner vault."""
        agent = self.require_open()
        if self.role != "owner":
            raise ValueError("Heir access is read-only and cannot delete a workspace.")
        expected_email = agent._index.owner_email if agent._index else ""
        if not expected_email or not secrets.compare_digest(
            owner_email.strip().casefold(), expected_email
        ):
            raise ValueError("Enter the owner email that is bound to this workspace.")
        if self.passphrase is None or not secrets.compare_digest(passphrase, self.passphrase):
            raise ValueError("Re-enter the current vault passphrase to delete the workspace.")

        target = self.workspace.resolve()
        agent._audit.append(
            "WORKSPACE_DELETION_REQUESTED",
            actor=self.owner_id,
            detail="owner confirmed permanent deletion of Continuum-managed data",
        )
        self.lock()
        for name in _MANAGED_WORKSPACE_DIRECTORIES:
            shutil.rmtree(target / name, ignore_errors=True)
        for name in _MANAGED_WORKSPACE_FILES:
            (target / name).unlink(missing_ok=True)
        try:
            target.rmdir()
        except OSError:
            # Deliberately preserve any unrelated owner files in a custom workspace.
            pass
        return {"deleted": True}

    def ask(self, question: str, *, allow_narration: bool = False) -> dict[str, Any]:
        agent = self.require_open()
        question = question.strip()
        if not question:
            raise ValueError("Ask Continuum a question.")
        response = QueryEngine(agent._memory).query(question, top_k=6)
        sources = [
            {
                "artifact": item.artifact,
                "category": item.category.value,
                "excerpt": item.content[:180].replace("\n", " "),
            }
            for item in response.results
        ]
        # The audit proves the workflow happened without recording a potentially
        # sensitive natural-language question or any plaintext evidence.
        agent._audit.append(
            "STUDIO_QUERY",
            actor=self.owner_id,
            detail=(
                f"intent={response.intent.value} selected_sources={len(sources)}"
            ),
        )
        narration = None
        narration_error = None
        narration_status = "not_requested"
        narration_available = narrator.enabled(opted_in=allow_narration)
        if allow_narration and not sources:
            narration_status = "skipped_no_evidence"
            agent._audit.append(
                "STUDIO_NARRATION_SKIPPED",
                actor=self.owner_id,
                detail="reason=no_evidence selected_sources=0",
            )
        elif allow_narration and not narration_available:
            narration_status = "skipped_not_configured"
            agent._audit.append(
                "STUDIO_NARRATION_SKIPPED",
                actor=self.owner_id,
                detail=f"reason=not_configured selected_sources={len(sources)}",
            )
        elif narration_available and sources:
            agent._audit.append(
                "STUDIO_NARRATION_REQUESTED",
                actor=self.owner_id,
                detail=f"consent=true selected_sources={len(sources)}",
            )
            try:
                narration = narrator.narrate(
                    question, response.answer, [item["excerpt"] for item in sources]
                )
                narration_status = "completed"
                agent._audit.append(
                    "STUDIO_NARRATION_COMPLETED",
                    actor=self.owner_id,
                    detail=f"selected_sources={len(sources)}",
                )
            except narrator.NarrationError as exc:
                narration_error = str(exc)
                narration_status = "failed"
                agent._audit.append(
                    "STUDIO_NARRATION_FAILED",
                    actor=self.owner_id,
                    detail=f"selected_sources={len(sources)}",
                )
        return {
            "answer": response.answer,
            "intent": response.intent.value,
            "category": response.category_filter.value if response.category_filter else None,
            "sources": sources,
            "narration": narration,
            "narration_error": narration_error,
            "agent_flow": {
                "retrieval": "completed",
                "selected_sources": len(sources),
                "narration": narration_status,
            },
            "mode": (
                f"{narrator._provider().title()} narration + deterministic retrieval"
                if narration
                else "deterministic retrieval"
            ),
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
            "owner_email": agent._index.owner_email if agent._index else "",
            "created_at": summary["created_at"],
            "total_artifacts": summary["total_artifacts"],
            "by_category": summary["by_category"],
            "heirs": summary["heirs"],
            "audit_events": summary["audit_trail_length"],
            "integrity": integrity["valid"],
            "hmac_checked": integrity["audit"]["hmac_checked"],
            "database_encrypted": bool(agent._index and agent._index.db_key_hex),
            "heir_policy_configured": bool(agent._index and agent._index.policy),
            "role": self.role,
            "workspace_mode": "safe_demo" if self._demo_active else "private",
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
        # The fictional demo needs a policy that is visibly satisfied so its
        # documented heir-view walkthrough remains possible without changing
        # the protection assigned to any real Studio workspace.
        self.create(
            "alex.morgan@example.test",
            "continuum-demo",
            inactivity_days=90,
            inactivity_last_activity=datetime.now(timezone.utc) - timedelta(days=90),
        )
        self._demo_active = True
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

    def end_headers(self) -> None:
        """Constrain the local browser surface as a defense in depth layer."""
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; img-src 'self'; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

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
            "/api/create": lambda body: self.studio.create(
                _normalize_email(body.get("owner_email", "")),
                body.get("passphrase", ""),
                inactivity_days=body.get("inactivity_days"),
                setup_recovery=body.get("setup_recovery") is True,
            ),
            "/api/unlock": lambda body: self.studio.unlock(
                _normalize_email(body.get("owner_email", "")), body.get("passphrase", "")
            ),
            "/api/reset-passphrase": lambda body: self.studio.reset_passphrase(
                _normalize_email(body.get("owner_email", "")),
                body.get("shares", []),
                body.get("new_passphrase", ""),
            ),
            "/api/unlock-heir": lambda body: self.studio.unlock_heir(
                body.get("heir_id", ""),
                body.get("passphrase", ""),
                body.get("heir_key"),
            ),
            "/api/lock": lambda body: self._locked(),
            "/api/capture": lambda body: self.studio.capture(
                body.get("title", ""), body.get("body", ""), body.get("tags", []),
                filename=body.get("filename"),
                include_dashboard=body.get("include_dashboard") is not False,
            ),
            "/api/delete-workspace": lambda body: self.studio.delete_workspace(
                _normalize_email(body.get("owner_email", "")),
                body.get("passphrase", ""),
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
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Content-Length must be a number.") from exc
        if not 0 <= size <= MAX_JSON_BODY_BYTES:
            raise ValueError("Request is too large.")
        return _decode_json_object(self.rfile.read(size))

    def _run(self, action) -> None:
        try:
            with self.studio._mutex:
                self._json(action(self._read_json() if self.command == "POST" else {}))
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception:
            self._json(
                {"error": "The protected operation could not complete."},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def _json(self, body: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the Continuum Studio local app")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        choices=["127.0.0.1"],
        help="Continuum Studio is intentionally limited to local loopback.",
    )
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
