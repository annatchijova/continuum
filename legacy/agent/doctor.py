"""
legacy/agent/doctor.py
=======================
Chequeo integral of salud of the legado  a only veredicto.

the verificaciones of integridad estaban dispersas: `verify_audit()` mira
the hash chain, `verify_memory_integrity()` cruza vault vs memory.db, and the
ArtifactStore verifica to the leer. KL-008b documenta that are mutuamente
ciegas: a audit trail valid convive with a memory.db corrupta. the
doctor the ejecuta all and adds sanity checks of the politica that no
module cubria (last_activity in the futuro? fecha of unlock unreadable?).

Checks:
  files               vault / audit.db / memory.db presentes
  audit_chain         hash chain integro (HMAC if hay key)
  memory_integrity    vault index  memory.db (incluye ghost memories)
  artifact_store      each artifact archivado decrypts and su hash matches
                       (only if is provee passphrase)
  policy_sanity       conditions parseables and temporalmente coherentes

the doctor NO repara nada: diagnostica and registra the result in the
audit trail (evento DOCTOR_RUN). Reparar is decision of the owner.
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

# Implementation note.
_CLOCK_SKEW = timedelta(minutes=5)

# Implementation note.
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
    """Sanity of the politica: parseable and temporalmente coherente."""
    if not policy_dict:
        return CheckResult(
            "policy_sanity", True, "without politica  acceso abierto (intencional?)"
        )
    try:
        policy = AccessPolicy.from_dict(policy_dict)
    except (ValueError, KeyError, TypeError) as exc:
        return CheckResult("policy_sanity", False, f"política no parseable: {exc}")

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
                        f"last_activity_iso en el futuro ({cond.last_activity_iso}) "
                        f"— la condición de inactividad nunca se cumpliría"
                    )
                if cond.days <= 0:
                    problems.append(f"inactivity days={cond.days} — se cumple siempre")
            except ValueError:
                problems.append(
                    f"last_activity_iso ilegible: {cond.last_activity_iso!r}"
                )
        elif isinstance(cond, DateCondition):
            try:
                datetime.fromisoformat(cond.unlock_after_iso)
            except ValueError:
                problems.append(
                    f"unlock_after_iso ilegible: {cond.unlock_after_iso!r} "
                    f"— el vault jamás se activaría por fecha"
                )
        elif isinstance(cond, HeirKeyCondition):
            if cond.iterations < _MIN_KEY_ITERATIONS:
                problems.append(
                    f"heir_key iterations={cond.iterations} — piso {_MIN_KEY_ITERATIONS}"
                )
            try:
                bytes.fromhex(cond.salt_hex)
                bytes.fromhex(cond.key_hash)
            except ValueError:
                problems.append(f"heir_key de {cond.heir_id}: salt/hash no hex")

    if problems:
        return CheckResult("policy_sanity", False, "; ".join(problems))
    n = len(policy.conditions)
    return CheckResult(
        "policy_sanity", True, f"{n} condición(es) coherente(s), operador {policy.operator.value}"
    )


def run_doctor(agent, passphrase: Optional[str] = None) -> DoctorReport:
    """
    Ejecuta all the chequeos over a agente with the vault ABIERTO.

    agent      : LegacyAgent desbloqueado (open_owner previo).
    passphrase : necesaria only for verificar the ArtifactStore; if is
                 None ese check is omite (is reporta as skipped-ok).
    """
    if not agent._unlocked or agent._index is None:
        raise RuntimeError("Vault cerrado. the doctor needs the vault abierto.")

    checks: List[CheckResult] = []

    # Implementation note.
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
        "all the files presentes" if not missing
        else f"faltan: {', '.join(missing)}",
    ))

    # Implementation note.
    audit = agent.verify_audit()
    checks.append(CheckResult(
        "audit_chain",
        bool(audit["valid"]),
        (f"{audit['length']} eventos, "
         f"{'HMAC verificado' if audit['hmac_checked'] else 'hash-only (without a key HMAC)'}")
        if audit["valid"]
        else f"cadena inválida desde seq={audit['first_invalid_seq']}: "
             f"{audit['summary']}",
    ))

    # Implementation note.
    mem = agent.verify_memory_integrity()
    checks.append(CheckResult(
        "memory_integrity",
        bool(mem["ok"]),
        f"{mem['checked']} artifact(s) cruzados sin divergencia" if mem["ok"]
        else "; ".join(mem["errors"][:5]),
    ))

    # Implementation note.
    # Implementation note.
    # Implementation note.
    hashes = agent._store.list_hashes()
    if not hashes:
        checks.append(CheckResult(
            "artifact_store", True, "store empty  nada that verificar"
        ))
    else:
        bad = [
            h for h in hashes if not agent.verify_artifact(h, passphrase)
        ]
        checks.append(CheckResult(
            "artifact_store",
            not bad,
            f"{len(hashes)} artifact(s) decrypted and intact" if not bad
            else f"{len(bad)}/{len(hashes)} corruptos, manipulados o sin "
                 f"secreto disponible: "
                 + ", ".join(h[:16] + "..." for h in bad[:3]),
        ))

    # Implementation note.
    checks.append(_check_policy(agent._index.policy))

    # Implementation note.
    info = agent._vault.info()
    version = info.get("version")
    slots = info.get("keyslots", [])
    if version == "2":
        has_recovery = "recovery" in slots
        v2_artifacts = [
            h for h in hashes if agent._store.envelope_version(h) == "2"
        ]
        # Implementation note.
        orphan_v2 = bool(v2_artifacts) and not agent._index.store_key_hex
        checks.append(CheckResult(
            "custody",
            not orphan_v2,
            (f"vault v2, slots={slots}"
             + (", custodia configurada" if has_recovery
                else ", without custodia (the shares no existen)"))
            if not orphan_v2
            else f"{len(v2_artifacts)} artifact(s) v2 pero el vault no "
                 f"tiene store key — irrecuperables",
        ))
    else:
        checks.append(CheckResult(
            "custody", True,
            f"vault v{version} (formato original) — sin keyslots; "
            f"se migra a v2 en el próximo re-sellado",
        ))

    # Implementation note.
    has_key = bool(agent._index.db_key_hex)

    def _eval_db(label: str, enc: Dict[str, int]) -> tuple:
        if enc["total"] == 0:
            return True, f"{label} vacío"
        if enc["plaintext"] == 0 and has_key:
            return True, f"{label}: {enc['encrypted']} encrypted at rest"
        if not has_key and enc["encrypted"] == 0:
            return True, (f"{label}: {enc['plaintext']} in plaintext (opt-in; "
                          f"enable with `encrypt-db`)")
        # Implementation note.
        return False, (f"{label}: mixed — {enc['encrypted']} encrypted, "
                       f"{enc['plaintext']} in plaintext, db_key="
                       f"{'si' if has_key else 'no'}; re-corré `encrypt-db`")

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
        checks.append(CheckResult("db_encryption", False, f"no evaluable: {exc}"))

    ok = all(c.ok for c in checks)
    agent._audit.append(
        "DOCTOR_RUN",
        actor=agent._owner_id,
        detail=f"ok={ok} checks={len(checks)} "
               f"failed={[c.name for c in checks if not c.ok]}",
    )
    return DoctorReport(ok=ok, checks=checks)
