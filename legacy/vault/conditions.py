"""
legacy/vault/conditions.py
===========================
conditions of activacion of the vault.

the usuario define what must ocurrir for that the heirs
puedan desbloquear the legado. the conditions are AND by default
(all deben cumplirse). is can configurar OR explicito.

Tipos of condition:
  InactivityCondition   N dias without actividad of the owner
  DateCondition         fecha/hora UTC especifica
  HeirKeyCondition      heir presenta key secreta pre-registrada
  ManualCondition       owner marca manualmente "activar"

all the conditions are serializables a JSON for persistencia encrypted.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


class ConditionType(str, Enum):
    INACTIVITY = "inactivity"
    DATE       = "date"
    HEIR_KEY   = "heir_key"
    MANUAL     = "manual"


class ConditionOperator(str, Enum):
    AND = "and"
    OR  = "or"


@dataclass
class InactivityCondition:
    """Vault is activa if the owner no registra actividad in N dias."""
    days: int
    last_activity_iso: str  # ISO 8601 UTC  is updates in each actividad

    type: str = ConditionType.INACTIVITY

    def is_met(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        last = datetime.fromisoformat(self.last_activity_iso)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (now - last) >= timedelta(days=self.days)

    def touch(self) -> None:
        self.last_activity_iso = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "days": self.days,
                "last_activity_iso": self.last_activity_iso}


@dataclass
class DateCondition:
    """Vault is activa in o after of a fecha UTC especifica."""
    unlock_after_iso: str   # ISO 8601 UTC

    type: str = ConditionType.DATE

    def is_met(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        unlock = datetime.fromisoformat(self.unlock_after_iso)
        if unlock.tzinfo is None:
            unlock = unlock.replace(tzinfo=timezone.utc)
        return now >= unlock

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "unlock_after_iso": self.unlock_after_iso}


@dataclass
class HeirKeyCondition:
    """
    Vault is activa when a heir presenta the key secreta pre-registrada.
    the key nunca is almacena in plaintext  only su hash PBKDF2.
    """
    key_hash: str       # PBKDF2-SHA256 hex of the key
    salt_hex: str       # hex  required for verificar
    heir_id: str        # identificador of the heir autorizado
    iterations: int = 260_000

    type: str = ConditionType.HEIR_KEY

    def is_met(self, presented_key: str) -> bool:
        salt = bytes.fromhex(self.salt_hex)
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            presented_key.encode("utf-8"),
            salt,
            self.iterations,
        ).hex()
        # Implementation note.
        return secrets.compare_digest(candidate, self.key_hash)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "key_hash": self.key_hash,
            "salt_hex": self.salt_hex,
            "heir_id": self.heir_id,
            "iterations": self.iterations,
        }

    @staticmethod
    def create(heir_id: str, secret_key: str, iterations: int = 260_000) -> "HeirKeyCondition":
        """generates the condition a partir of the key in plaintext (only to the record)."""
        salt = secrets.token_bytes(32)
        key_hash = hashlib.pbkdf2_hmac(
            "sha256",
            secret_key.encode("utf-8"),
            salt,
            iterations,
        ).hex()
        return HeirKeyCondition(
            key_hash=key_hash,
            salt_hex=salt.hex(),
            heir_id=heir_id,
            iterations=iterations,
        )


@dataclass
class ManualCondition:
    """the owner activa the vault manualmente (testing, pre-mortem)."""
    activated: bool = False

    type: str = ConditionType.MANUAL

    def is_met(self, **_) -> bool:
        return self.activated

    def activate(self) -> None:
        self.activated = True

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "activated": self.activated}


AnyCondition = InactivityCondition | DateCondition | HeirKeyCondition | ManualCondition


def condition_from_dict(d: Dict[str, Any]) -> AnyCondition:
    t = d.get("type")
    if t == ConditionType.INACTIVITY:
        return InactivityCondition(days=d["days"], last_activity_iso=d["last_activity_iso"])
    if t == ConditionType.DATE:
        return DateCondition(unlock_after_iso=d["unlock_after_iso"])
    if t == ConditionType.HEIR_KEY:
        return HeirKeyCondition(
            key_hash=d["key_hash"], salt_hex=d["salt_hex"],
            heir_id=d["heir_id"], iterations=d.get("iterations", 260_000),
        )
    if t == ConditionType.MANUAL:
        return ManualCondition(activated=d.get("activated", False))
    raise ValueError(f"Tipo de condición desconocido: {t!r}")


@dataclass
class AccessPolicy:
    """
    Politica of acceso: lista of conditions + operador AND/OR.

    evaluate() returns True when the politica is satisface.
    for HeirKeyCondition, pasar heir_key=<key presentada>.
    """
    conditions: List[AnyCondition]
    operator: ConditionOperator = ConditionOperator.AND

    def evaluate(
        self,
        *,
        now: Optional[datetime] = None,
        heir_key: Optional[str] = None,
    ) -> bool:
        results = []
        for cond in self.conditions:
            if isinstance(cond, HeirKeyCondition):
                results.append(cond.is_met(heir_key or ""))
            elif isinstance(cond, (InactivityCondition, DateCondition)):
                results.append(cond.is_met(now))
            elif isinstance(cond, ManualCondition):
                results.append(cond.is_met())
            else:
                results.append(False)

        if not results:
            return False
        if self.operator == ConditionOperator.AND:
            return all(results)
        return any(results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operator": self.operator,
            "conditions": [c.to_dict() for c in self.conditions],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AccessPolicy":
        return AccessPolicy(
            conditions=[condition_from_dict(c) for c in d.get("conditions", [])],
            operator=ConditionOperator(d.get("operator", ConditionOperator.AND)),
        )
