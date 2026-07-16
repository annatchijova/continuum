"""
legacy/agent/doctor.py
=======================
Comprehensive legacy health check with a single verdict.

Integrity checks were previously scattered: `verify_audit()` checks the hash
chain, `verify_memory_integrity()` compares the vault with memory.db, and the
ArtifactStore verifies artifacts while reading them. KL-008b documents that
these checks are mutually blind: a valid audit trail can coexist with a
corrupt memory.db. The doctor runs all checks and adds policy sanity checks
that no module covered (last_activity in the future? unreadable unlock date?).

Checks:
  files               vault / audit.db / memory.db presentes
  audit_chain         hash chain integro (HMAC if hay key)
  memory_integrity    vault index  memory.db (incluye ghost memories)
  artifact_store      each artifact archivado decrypts and su hash matches
                       (only if is provee passphrase)
  policy_sanity       parseable and temporally coherent conditions

The doctor repairs nothing: it diagnoses and records the result in the audit
trail (DOCTOR_RUN event). Repair is the owner's decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from legacy.vault.conditions import (
    AccessPolicy,
    DateCondition,
    HeirKeyCondition,
    InactivityCondition,
)

# Clock skew tolerated when checking timestamps.
_CLOCK_SKEW = timedelta(minutes=5)

# Minimum acceptable PBKDF2 iteration count for heir keys.
_MIN_KEY_ITERATIONS = 100_000


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class DoctorReport:
    ok: bool
    checks: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [c.to_dict() for c in self.checks],
            "failed": [c.name for c in self.checks if not c.ok],
        }


def _check_policy(policy_dict: Optional[Dict[str, Any]]) -> CheckResult:
    """Check that the policy is parseable and temporally coherent."""
    if not policy_dict:
        return CheckResult(
            "policy_sanity", True, "no policy; open access (intentional?)"
        )
    try:
        policy = AccessPolicy.from_dict(policy_dict)
    except (ValueError, KeyError, TypeError) as exc:
        return CheckResult("policy_sanity", False, f"policy is not parseable: {exc}")

    now = datetime.now(timezone.utc)
    problems: List[str] = []
    for cond in policy.conditions:
        if isinstance(cond, InactivityCondition):
            try:
                last = datetime.fromisoformat(cond.last_activity_iso)
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last - now > _CLOCK_SKEW:
                    problems.append(
                        f"last_activity_iso is in the future ({cond.last_activity_iso}) "
                        f"— the inactivity condition would never be met"
                    )
                if cond.days <= 0:
                    problems.append(f"inactivity days={cond.days} — always satisfied")
            except ValueError:
                problems.append(
                    f"last_activity_iso is unreadable: {cond.last_activity_iso!r}"
                )
        elif isinstance(cond, DateCondition):
            try:
                datetime.fromisoformat(cond.unlock_after_iso)
            except ValueError:
                problems.append(
                    f"unlock_after_iso is unreadable: {cond.unlock_after_iso!r} "
                    f"— the vault would never activate by date"
                )
        elif isinstance(cond, HeirKeyCondition):
            if cond.iterations < _MIN_KEY_ITERATIONS:
                problems.append(
                    f"heir_key iterations={cond.iterations} — minimum {_MIN_KEY_ITERATIONS}"
                )
            try:
                bytes.fromhex(cond.salt_hex)
                bytes.fromhex(cond.key_hash)
            except ValueError:
                problems.append(f"heir_key for {cond.heir_id}: salt/hash is not hexadecimal")

    if problems:
        return CheckResult("policy_sanity", False, "; ".join(problems))
    n = len(policy.conditions)
    return CheckResult(
        "policy_sanity", True, f"{n} coherent condition(s), operator {policy.operator.value}"
    )


def run_doctor(agent, passphrase: Optional[str] = None) -> DoctorReport:
    """
    Run all checks on an agent with the vault unlocked.

    agent      : LegacyAgent unlocked by a previous open_owner call.
    passphrase : required only to verify the ArtifactStore; when None, that
                 check is skipped and reported as successful.
    """
    if not agent._unlocked or agent._index is None:
        raise RuntimeError("Vault is locked. The doctor requires an unlocked vault.")

    checks: List[CheckResult] = []

    # Check required files.
    missing = [
        name for name, p in [
            ("legacy.vault", agent._data_dir / "legacy.vault"),
            ("audit.db", agent._data_dir / "audit.db"),
            ("memory.db", agent._data_dir / "memory.db"),
        ] if not p.exists()
    ]
    checks.append(CheckResult(
        "files",
        not missing,
        "all files present" if not missing
        else f"missing: {', '.join(missing)}",
    ))

    # Check the audit hash chain.
    audit = agent.verify_audit()
    checks.append(CheckResult(
        "audit_chain",
        bool(audit["valid"]),
        (f"{audit['length']} eventos, "
         f"{'HMAC verified' if audit['hmac_checked'] else 'hash-only (no HMAC key)'}")
        if audit["valid"]
        else f"invalid chain from seq={audit['first_invalid_seq']}: "
             f"{audit['summary']}",
    ))

    # Check vault-to-memory integrity.
    mem = agent.verify_memory_integrity()
    checks.append(CheckResult(
        "memory_integrity",
        bool(mem["ok"]),
        f"{mem['checked']} artifact(s) cross-checked with no divergence" if mem["ok"]
        else "; ".join(mem["errors"][:5]),
    ))

    # Check archived artifact integrity.
    hashes = agent._store.list_hashes()
    if not hashes:
        checks.append(CheckResult(
            "artifact_store", True, "store is empty; nothing to verify"
        ))
    else:
        bad = [
            h for h in hashes if not agent.verify_artifact(h, passphrase)
        ]
        checks.append(CheckResult(
            "artifact_store",
            not bad,
            f"{len(hashes)} artifact(s) decrypted and intact" if not bad
            else f"{len(bad)}/{len(hashes)} corrupt, tampered, or without "
                 f"an available secret: "
                 + ", ".join(h[:16] + "..." for h in bad[:3]),
        ))

    # Check policy consistency.
    checks.append(_check_policy(agent._index.policy))

    # Check custody metadata and v2 artifact compatibility.
    info = agent._vault.info()
    version = info.get("version")
    slots = info.get("keyslots", [])
    if version == "2":
        has_recovery = "recovery" in slots
        v2_artifacts = [
            h for h in hashes if agent._store.envelope_version(h) == "2"
        ]
        # A v2 artifact without a vault store key cannot be recovered.
        orphan_v2 = bool(v2_artifacts) and not agent._index.store_key_hex
        checks.append(CheckResult(
            "custody",
            not orphan_v2,
            (f"vault v2, slots={slots}"
             + (", custody configured" if has_recovery
                else ", no custody (shares do not exist)"))
            if not orphan_v2
            else f"{len(v2_artifacts)} artifact(s) are v2 but the vault has no "
                 f"store key — unrecoverable",
        ))
    else:
        checks.append(CheckResult(
            "custody", True,
            f"vault v{version} (original format) — no keyslots; "
            f"migrates to v2 on the next re-seal",
        ))

    # Check database encryption status.
    has_key = bool(agent._index.db_key_hex)

    def _eval_db(label: str, enc: Dict[str, int]) -> tuple:
        if enc["total"] == 0:
            return True, f"{label} is empty"
        if enc["plaintext"] == 0 and has_key:
            return True, f"{label}: {enc['encrypted']} encrypted at rest"
        if not has_key and enc["encrypted"] == 0:
            return True, (f"{label}: {enc['plaintext']} in plaintext (opt-in; "
                          f"enable with `encrypt-db`)")
        # Mixed encryption states require an explicit repair.
        return False, (f"{label}: mixed — {enc['encrypted']} encrypted, "
                       f"{enc['plaintext']} in plaintext, db_key="
                       f"{'yes' if has_key else 'no'}; re-run `encrypt-db`")

    try:
        parts = [_eval_db("memory.db", agent._memory.encryption_status())]
        if (agent._data_dir / "knowledge.db").exists():
            parts.append(_eval_db("knowledge.db",
                                   agent.knowledge.encryption_status()))
        ok_enc = all(p[0] for p in parts)
        checks.append(CheckResult(
            "db_encryption", ok_enc, "  ".join(p[1] for p in parts)
        ))
    except Exception as exc:
        checks.append(CheckResult("db_encryption", False, f"not evaluable: {exc}"))

    ok = all(c.ok for c in checks)
    agent._audit.append(
        "DOCTOR_RUN",
        actor=agent._owner_id,
        detail=f"ok={ok} checks={len(checks)} "
               f"failed={[c.name for c in checks if not c.ok]}",
    )
    return DoctorReport(ok=ok, checks=checks)
