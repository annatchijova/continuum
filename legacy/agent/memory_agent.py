"""
legacy/agent/memory_agent.py
=============================
Orquestador principal of the legado digital.

Ciclo of vida:
  1. owner ingiere artifacts (documents, fotos, notas).
  2. Clasificador asigna categoria determinista.
  3. field of memory almacena content + embedding.
  4. Vault encrypts the index with the passphrase of the owner.
  5. Audit trail registra each operation with hash chain.

  to the activarse the acceso (condition cumplida):
  6. heir provee key  vault is opens.
  7. Query engine responde questions over the legado.

the agente opera in dos modos:
  OWNER   owner ingiere and gestiona.
  HEIR    heir (only lectura post-activacion).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import closing
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from legacy.core.audit_trail import AuditTrail
from legacy.core.shamir import Share, combine_shares, split_secret
from legacy.ingestion.classifier import DocumentClassifier, ClassificationResult
from legacy.ingestion.doc_types import DocCategory
from legacy.memory.field import MemoryField, MemoryState, RecallResult
from legacy.memory.consolidator import ConsolidationReport, Consolidator
from legacy.vault.locker import (
    Vault,
    VaultAuthError,
    VaultCorruptError,
    VaultNotFoundError,
)
from legacy.vault.artifact_store import ArtifactStore
from legacy.vault.conditions import AccessPolicy, HeirKeyCondition, InactivityCondition


# Implementation note.
# Implementation note.
# Implementation note.

@dataclass
class ArtifactRecord:
    artifact_id: str
    path: str
    filename: str
    category: str
    content_hash: str
    classification_confidence: str
    memory_id: str
    ingested_at: str
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ArtifactRecord":
        return ArtifactRecord(**d)


@dataclass
class LegacyIndex:
    owner_id: str
    created_at: str
    last_updated: str
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    heirs: List[Dict[str, Any]] = field(default_factory=list)
    policy: Optional[Dict[str, Any]] = None
    notes: str = ""
    # Implementation note.
    # Implementation note.
    # Implementation note.
    store_key_hex: str = ""
    # Implementation note.
    # Implementation note.
    db_key_hex: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "LegacyIndex":
        return LegacyIndex(**d)


# Implementation note.
# Implementation note.
# Implementation note.

class LegacyAgent:
    """
    Agente principal of legado digital.

    data_dir   : directory of trabajo of the agente (audit_trail, memory, vault).
    owner_id   : identificador of the owner (does not have that be PII  can
                 be a hash o a alias).
    hmac_key   : bytes for the HMAC of the audit trail. None  variable of entorno.
    """

    def __init__(
        self,
        data_dir: Path,
        owner_id: str,
        hmac_key: Optional[bytes] = None,
    ) -> None:
        self._data_dir = data_dir
        self._owner_id = owner_id
        data_dir.mkdir(parents=True, exist_ok=True)

        self._audit = AuditTrail(
            db_path=data_dir / "audit.db",
            hmac_key=hmac_key,
        )
        self._memory = MemoryField(db_path=data_dir / "memory.db")
        self._vault = Vault(vault_path=data_dir / "legacy.vault")
        self._store = ArtifactStore(store_dir=data_dir / "artifacts")
        self._classifier = DocumentClassifier()
        self._index: Optional[LegacyIndex] = None
        self._unlocked: bool = False
        self._knowledge = None   # lazy  knowledge.db only is crea if is usa

    @property
    def knowledge(self):
        """KnowledgeBase of the legado (is crea to the primer uso)."""
        if self._knowledge is None:
            from legacy.knowledge.extractor import KnowledgeBase
            self._knowledge = KnowledgeBase(
                self._data_dir / "knowledge.db", db_key=self._store_key_none_safe_db_key()
            )
        return self._knowledge

    def _store_key_none_safe_db_key(self) -> Optional[bytes]:
        """db_key of the index if the vault is abierto and the tiene; if no, None."""
        if self._index and self._index.db_key_hex:
            return bytes.fromhex(self._index.db_key_hex)
        return None

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def initialize(self, passphrase: str, policy: Optional[AccessPolicy] = None) -> None:
        """
        Crea the vault initial. only is llama once by owner.
        if already exists, lanza ValueError.
        """
        if self._vault.exists():
            raise ValueError("the vault already exists. Usa open_owner() for abrirlo.")

        now = datetime.now(timezone.utc).isoformat()
        self._index = LegacyIndex(
            owner_id=self._owner_id,
            created_at=now,
            last_updated=now,
            policy=policy.to_dict() if policy else None,
        )
        self._vault.seal(self._index.to_dict(), passphrase)
        self._unlocked = True
        self._apply_db_key()

        self._audit.append(
            "VAULT_CREATED",
            actor=self._owner_id,
            detail=f"vault inicializado, policy={'set' if policy else 'none'}",
        )

    def open_owner(self, passphrase: str) -> None:
        """opens the vault as owner."""
        raw = self._vault.open(passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "VAULT_UNLOCKED",
            actor=self._owner_id,
            detail="acceso owner",
        )

    def lock(self, passphrase: str) -> None:
        """Re-encrypts the vault with the state actual."""
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault no is abierto.")
        self._index.last_updated = datetime.now(timezone.utc).isoformat()
        self._vault.seal(self._index.to_dict(), passphrase)
        self._unlocked = False
        self._audit.append("VAULT_LOCKED", actor=self._owner_id)

    def rekey(self, old_passphrase: str, new_passphrase: str) -> Dict[str, Any]:
        """
        Rota the passphrase. Complemento of revoke_heir  revocar a alguien
        that already conoce the passphrase no sirve without poder cambiarla (KL-011).

        with the vault v2 (keyslots) the rotation is a rewrap of the slot of
        passphrase: the payload no is re-encrypts and the slot of recovery
        (custodia) SOBREVIVE  the shares repartidos siguen siendo validos.

        Tres pasos, each uno re-ejecutable tras a crash:
          1. Garantizar the store key sellada in the vault (with the old).
          2. Convertir artifacts v1 (passphrase)  v2 (store key). A partir
             of aca the artifacts are independientes of the passphrase.
          3. Rewrap of the keyslot of passphrase (old  new).
        if the proceso muere in 1-2, the vault opens with the old and re-correr
        rekey(old, new) complete the trabajo (the already convertidos is are skipped).
        if muere after of 3, the rotation already is complete.

        to the finish, the agente remains desbloqueado with the index fresco.
        """
        if not new_passphrase:
            raise ValueError("the passphrase new no can be empty.")

        # Implementation note.
        raw = self._vault.open(old_passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()

        # Implementation note.
        # Implementation note.
        key = self._ensure_store_key(old_passphrase)

        # Implementation note.
        stats = self._store.convert_to_key(old_passphrase, key)

        # Implementation note.
        self._vault.rewrap_passphrase(old_passphrase, new_passphrase)

        self._audit.append(
            "PASSPHRASE_ROTATED",
            actor=self._owner_id,
            detail=f"artifacts_converted={stats['converted']} "
                   f"artifacts_skipped={stats['skipped']} "
                   f"custody_preserved={self._vault.has_recovery_slot()}",
        )
        return stats

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def setup_custody(
        self, passphrase: str, *, shares: int, threshold: int
    ) -> List[str]:
        """
        Configura the recovery by custodios:
          1. generates a recovery key aleatoria of 32 bytes.
          2. the adds as keyslot of the vault (envuelve the data key).
          3. the parte in `shares` fragmentos with umbral `threshold`
             (Shamir over GF(2^8)) and the DESCARTA.

        returns the shares serializados  ESTA is the UNICA VEZ that EXISTEN:
        ni the recovery key ni the shares is persisten in no lado.
        any subconjunto of `threshold` custodios reconstruye the
        key; less that eso no obtiene informacion some.

        Re-configurar replaces the slot: the shares previous remain
        inservibles (revocacion of custodios of facto).
        """
        if threshold < 2:
            raise ValueError(
                "threshold must be >= 2  with umbral 1 each custodio "
                "can open the legado by si only."
            )
        if shares < threshold:
            raise ValueError(f"shares ({shares}) debe ser >= threshold ({threshold}).")

        # Implementation note.
        # Implementation note.
        raw = self._vault.open(passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        key = self._ensure_store_key(passphrase)
        self._store.convert_to_key(passphrase, key)

        recovery_key = secrets.token_bytes(32)
        self._vault.add_recovery_slot(passphrase, recovery_key)
        share_objs = split_secret(recovery_key, shares=shares, threshold=threshold)

        self._audit.append(
            "CUSTODY_CONFIGURED",
            actor=self._owner_id,
            detail=f"shares={shares} threshold={threshold} "
                   f"(la clave y los shares no se persisten)",
        )
        return [s.serialize() for s in share_objs]

    def remove_custody(self, passphrase: str) -> bool:
        """removes the slot of recovery. the shares remain inservibles."""
        removed = self._vault.remove_recovery_slot(passphrase)
        self._audit.append(
            "CUSTODY_REMOVED",
            actor=self._owner_id,
            detail=f"removed={removed}",
        )
        return removed

    # Implementation note.

    def add_timelock(
        self, passphrase: str, squarings: int, *, modulus_bits: int = 2048
    ) -> None:
        """
        adds a camino of recovery by time-lock puzzle: the data key
        remains recuperable resolviendo `squarings` cuadraturas secuenciales
        (offline, without custodios). Piso of trabajo, NO reloj of pared 
        ver legacy/core/timelock.py. is ADICIONAL a passphrase and custodia.
        """
        self._vault.add_timelock_slot(passphrase, squarings, modulus_bits=modulus_bits)
        self._audit.append(
            "TIMELOCK_CONFIGURED",
            actor=self._owner_id,
            detail=f"squarings={squarings} modulus_bits={modulus_bits}",
        )

    def remove_timelock(self, passphrase: str) -> bool:
        removed = self._vault.remove_timelock_slot(passphrase)
        self._audit.append(
            "TIMELOCK_REMOVED", actor=self._owner_id, detail=f"removed={removed}",
        )
        return removed

    def recover_with_timelock(self, *, actor: str, progress=None) -> None:
        """
        opens the vault resolviendo the time-lock puzzle (slow by design).
        Deja the agente desbloqueado.
        """
        raw = self._vault.open_with_timelock(progress=progress)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "VAULT_RECOVERED_TIMELOCK",
            actor=actor,
            detail="recovery by time-lock puzzle resuelto",
        )

    def set_passphrase_from_timelock(
        self, new_passphrase: str, *, actor: str, progress=None
    ) -> None:
        """Resuelve the puzzle once, fija passphrase new and opens the vault."""
        if not new_passphrase:
            raise ValueError("the passphrase new no can be empty.")
        self._vault.set_passphrase_with_timelock(new_passphrase, progress=progress)
        raw = self._vault.open(new_passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "PASSPHRASE_RESET_BY_TIMELOCK",
            actor=actor,
            detail="passphrase restablecida tras resolver the time-lock",
        )

    def recover_with_shares(self, shares: List[str], *, actor: str) -> None:
        """
        opens the vault reconstruyendo the recovery key from the shares of
        the custodios  without a passphrase. the agente remains desbloqueado.
        """
        recovery_key = combine_shares(shares)
        raw = self._vault.open_with_recovery(recovery_key)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "VAULT_RECOVERED",
            actor=actor,
            detail=f"recuperación por custodios con {len(shares)} share(s)",
        )

    def set_passphrase_from_recovery(
        self, shares: List[str], new_passphrase: str, *, actor: str
    ) -> None:
        """
        Restablece the passphrase of the vault usando the shares  the camino
        complete of the heirs: reconstruyen the key with the
        custodios, fijan su propia passphrase and operan normalmente.
        """
        if not new_passphrase:
            raise ValueError("the passphrase new no can be empty.")
        recovery_key = combine_shares(shares)
        self._vault.set_passphrase_with_recovery(recovery_key, new_passphrase)
        raw = self._vault.open(new_passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "PASSPHRASE_RESET_BY_RECOVERY",
            actor=actor,
            detail=f"passphrase restablecida con {len(shares)} share(s)",
        )

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def ingest(
        self,
        path: Path,
        *,
        notes: str = "",
        tags: Optional[List[str]] = None,
        force_category: Optional[DocCategory] = None,
        extract_knowledge: bool = False,
    ) -> ArtifactRecord:
        """
        Ingiere a artifact in the legado.
        classifies, almacena in memory, registra in index.

        FIX F-001 (TOCTOU): the file is reads a SOLA VEZ aqui.
        the content leido is pasa directamente to the clasificador.
        the content_hash is of the content real that va a the memory.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault no is abierto. Llama a open_owner() first.")

        # Implementation note.
        try:
            raw = path.read_bytes()[:65_536]
        except OSError:
            raw = b""

        is_binary = b"\x00" in raw[:512]
        if is_binary:
            text_content = ""
        else:
            text_content = raw.decode("utf-8", errors="replace")

        # Implementation note.
        result: ClassificationResult = self._classifier.classify(
            text_content, filename=path.name
        )
        category = force_category or result.category

        # Implementation note.
        if is_binary:
            content = f"[{category.value}] {path.name}"
        else:
            content = text_content or f"[{category.value}] {path.name}"

        # Implementation note.
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        for existing in self._index.artifacts:
            if existing.get("content_hash") == content_hash:
                self._audit.append(
                    "ARTIFACT_SKIPPED_DUPLICATE",
                    actor=self._owner_id,
                    artifact=str(path),
                    detail=(
                        f"duplicate of artifact_id={existing['artifact_id'][:8]} "
                        f"hash={content_hash[:16]}"
                    ),
                )
                return ArtifactRecord.from_dict(existing)

        # Implementation note.
        memory_id = self._memory.store(
            content=content,
            category=category,
            artifact=str(path),
            tags=tags or [],
        )

        artifact_id = str(uuid.uuid4())         # FIX F-008: import in module
        record = ArtifactRecord(
            artifact_id=artifact_id,
            path=str(path),
            filename=path.name,
            category=category.value,
            content_hash=content_hash,          # hash of the content real
            classification_confidence=result.confidence,
            memory_id=memory_id,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            tags=tags or [],
            notes=notes,
        )
        self._index.artifacts.append(record.to_dict())

        self._audit.append(
            "ARTIFACT_INGESTED",
            actor=self._owner_id,
            artifact=str(path),
            detail=f"category={category.value} confidence={result.confidence} "
                   f"hash={content_hash[:16]}",
        )

        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        if extract_knowledge and not is_binary and text_content:
            entry = self.knowledge.extract_and_store(
                text_content, source_path=str(path)
            )
            if entry is not None:
                self._audit.append(
                    "KNOWLEDGE_EXTRACTED",
                    actor=self._owner_id,
                    artifact=str(path),
                    detail=f"entry_id={entry.entry_id[:8]} "
                           f"domain={entry.domain.value} "
                           f"confidence={entry.confidence}",
                )
        return record

    def ingest_directory(
        self,
        directory: Path,
        *,
        recursive: bool = True,
        extensions: Optional[List[str]] = None,
        extract_knowledge: bool = False,
    ) -> List[ArtifactRecord]:
        """
        Ingiere all the files in a directory.

        FIX F-002 (symlink traversal): valida that the path resuelto
        este dentro of the directory solicitado before of procesar.
        Symlinks that apunten fuera are ignorados and registrados in
        the audit trail.
        """
        glob_pat = "**/*" if recursive else "*"
        base = directory.resolve()
        records = []
        for p in directory.glob(glob_pat):
            if not p.is_file():
                continue
            # Implementation note.
            try:
                resolved = p.resolve()
                resolved.relative_to(base)  # lanza ValueError if is fuera
            except ValueError:
                self._audit.append(
                    "INGEST_SKIPPED",
                    actor=self._owner_id,
                    artifact=str(p),
                    detail=f"symlink traversal bloqueado: {p} → {resolved}",
                )
                continue
            if extensions and p.suffix.lower() not in extensions:
                continue
            try:
                record = self.ingest(p, extract_knowledge=extract_knowledge)
                records.append(record)
            except Exception as exc:
                self._audit.append(
                    "INGEST_ERROR",
                    actor=self._owner_id,
                    artifact=str(p),
                    detail=str(exc)[:120],
                )
        return records

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def open_heir(
        self,
        heir_id: str,
        passphrase: str,
        *,
        heir_key: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> bool:
        """
        Intenta open the vault as heir.
        Evalua the politica of acceso before of decrypt.
        returns True if the acceso fue concedido.
        """
        # Implementation note.
        try:
            raw = self._vault.open(passphrase)
        except VaultAuthError:
            self._audit.append(
                "ACCESS_DENIED",
                actor=heir_id,
                detail="passphrase incorrect",
            )
            return False

        index = LegacyIndex.from_dict(raw)

        # Implementation note.
        # Implementation note.
        # Implementation note.
        if any(
            h.get("heir_id") == heir_id and h.get("revoked_at")
            for h in index.heirs
        ):
            self._audit.append(
                "ACCESS_DENIED",
                actor=heir_id,
                detail="heir revocado",
            )
            return False

        policy_dict = index.policy

        if policy_dict:
            policy = AccessPolicy.from_dict(policy_dict)
            granted = policy.evaluate(now=now, heir_key=heir_key)
        else:
            granted = True  # without politica  acceso abierto

        # Implementation note.
        # Implementation note.
        # Implementation note.
        now_tag = f" now_override={now.isoformat()}" if now is not None else ""
        self._audit.append(
            "CONDITION_CHECK",
            actor=heir_id,
            detail=f"policy_result={'GRANTED' if granted else 'DENIED'}{now_tag}",
        )

        if granted:
            self._index = index
            self._unlocked = True
            self._apply_db_key()
            self._audit.append("VAULT_UNLOCKED", actor=heir_id, detail="acceso heir")

        return granted

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def query(
        self,
        question: str,
        actor: str,
        *,
        category: Optional[DocCategory] = None,
        top_k: int = 5,
    ) -> List[RecallResult]:
        """
        Responde a question over the legado.
        Registra in audit trail.
        """
        if not self._unlocked:
            raise RuntimeError("Vault cerrado.")

        results = self._memory.recall(question, category=category, top_k=top_k)
        self._audit.append(
            "QUERY",
            actor=actor,
            detail=f"q={question[:80]!r} results={len(results)}",
        )
        return results

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def add_heir(self, heir_id: str, display_name: str, email: str = "") -> None:
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault no is abierto.")
        self._index.heirs.append({
            "heir_id": heir_id,
            "display_name": display_name,
            "email": email,
            "added_at": datetime.now(timezone.utc).isoformat(),
        })
        self._audit.append(
            "HEIR_ADDED",
            actor=self._owner_id,
            detail=f"heir_id={heir_id} display_name={display_name}",
        )

    def register_heir_key(self, heir_id: str) -> str:
        """
        generates a key secreta for the heir and adds the
        HeirKeyCondition correspondiente a the politica of acceso.

        returns the key in plaintext  este is the unico momento in that exists
        fuera of the cabeza of the owner: only su hash PBKDF2 is persiste.
        Entregarla to the heir by a canal seguro (ver KL-011).

        Semantica with politica existente: the condition is adds with the
        operador vigente. with AND (default), the heir needs the key
        and the demas conditions (defensa in profundidad); with OR, the key
        alcanza by si sola.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault no is abierto.")

        secret = secrets.token_urlsafe(32)
        cond = HeirKeyCondition.create(heir_id, secret)

        if self._index.policy:
            policy = AccessPolicy.from_dict(self._index.policy)
            policy.conditions.append(cond)
        else:
            policy = AccessPolicy([cond])
        self._index.policy = policy.to_dict()

        self._audit.append(
            "HEIR_KEY_REGISTERED",
            actor=self._owner_id,
            detail=f"heir_id={heir_id} iterations={cond.iterations} "
                   f"policy_conditions={len(policy.conditions)}",
        )
        return secret

    def revoke_heir(self, heir_id: str) -> bool:
        """
        Revoca a heir: marca su entry with revoked_at (no is borra 
        the historial remains) and removes sus HeirKeyCondition of the politica.
        open_heir() denegara a a heir revocado aunque the politica
        general este satisfecha.

        Nota fail-closed: if the politica remains without conditions tras quitar
        the key, evaluate() returns False for all the heirs until
        that the owner configure a condition new.

        returns True if algo cambio (heir found o key quitada).
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault no is abierto.")

        found = False
        for h in self._index.heirs:
            if h.get("heir_id") == heir_id and not h.get("revoked_at"):
                h["revoked_at"] = datetime.now(timezone.utc).isoformat()
                found = True

        removed_keys = 0
        if self._index.policy:
            policy = AccessPolicy.from_dict(self._index.policy)
            kept = [
                c for c in policy.conditions
                if not (isinstance(c, HeirKeyCondition) and c.heir_id == heir_id)
            ]
            removed_keys = len(policy.conditions) - len(kept)
            if removed_keys:
                policy.conditions = kept
                self._index.policy = policy.to_dict()

        self._audit.append(
            "HEIR_REVOKED",
            actor=self._owner_id,
            detail=f"heir_id={heir_id} found={found} keys_removed={removed_keys}",
        )
        return found or removed_keys > 0

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def reinforce_memory(self, memory_id: str) -> None:
        """
        Eleva a memory a REINFORCED and it registra in the audit trail.

        FIX R2-002: the call directa a MemoryField.reinforce() era silenciosa
         any code with vault abierto podia reforzar memories falsas without
        dejar rastro. Este metodo is the unico punto autorizado of acceso.
        """
        if not self._unlocked:
            raise RuntimeError("Vault cerrado.")
        self._memory.reinforce(memory_id)
        self._audit.append(
            "MEMORY_REINFORCED",
            actor=self._owner_id,
            detail=f"memory_id={memory_id}",
        )

    def forget_memory(self, memory_id: str) -> None:
        """
        Marca a memory as FORGOTTEN and it registra in the audit trail.

        FIX R2-002: idem. Hacer olvidar a memory verdadera era indetectable.
        """
        if not self._unlocked:
            raise RuntimeError("Vault cerrado.")
        self._memory.forget(memory_id)
        self._audit.append(
            "MEMORY_FORGOTTEN",
            actor=self._owner_id,
            detail=f"memory_id={memory_id}",
        )

    def consolidate(
        self,
        *,
        similarity_threshold: float = 0.85,
        reinforce_threshold: int = 5,
        forget_after_days: float = 90.0,
        score_decay: float = 0.98,
    ) -> ConsolidationReport:
        """
        Ejecuta the consolidacion of the field of memory and the registra in the
        audit trail. before the Consolidator only era invocable a mano and
        corria without dejar rastro  mutaba estados (FORGOTTEN, REINFORCED)
        of forma indetectable, the same problema that FIX R2-002 cerro
        for reinforce()/forget().
        """
        if not self._unlocked:
            raise RuntimeError("Vault cerrado.")
        report = Consolidator(
            self._memory,
            similarity_threshold=similarity_threshold,
            reinforce_threshold=reinforce_threshold,
            forget_after_days=forget_after_days,
            score_decay=score_decay,
        ).run()
        self._audit.append(
            "MEMORY_CONSOLIDATED",
            actor=self._owner_id,
            detail=(
                f"merged={report.duplicates_merged} "
                f"pruned={report.synapses_pruned} "
                f"promoted={report.promoted_to_reinforced} "
                f"forgotten={report.degraded_to_forgotten} "
                f"errors={len(report.errors)}"
            ),
        )
        return report

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def _store_key(self) -> Optional[bytes]:
        """Store key of the index, if exists (vault abierto)."""
        if self._index and self._index.store_key_hex:
            return bytes.fromhex(self._index.store_key_hex)
        return None

    def _apply_db_key(self) -> None:
        """
        Propaga the db_key of the index to the MemoryField tras open the vault.
        must llamarse after of each asignacion of self._index proveniente
        of a vault decrypted (open_owner/open_heir/recover/initialize).
        without esto, memory.db encrypted seria unreadable aunque the vault este
        abierto  the composition break clasico between dos modulos correctos.
        """
        if self._index is None:
            return
        key = bytes.fromhex(self._index.db_key_hex) if self._index.db_key_hex else None
        self._memory.set_db_key(key)
        if self._knowledge is not None:
            self._knowledge.set_db_key(key)

    def encrypt_database(self, passphrase: str) -> Dict[str, Any]:
        """
        encrypts at rest memory.db (KL-001): generates a db_key, the seals in
        the vault, and migra the rows in plaintext a ciphertext.

        Orden crash-safe (as _ensure_store_key): the db_key is PERSISTE in
        the vault before of encrypt the primera row. if the proceso muere a
        mitad of the migracion, the database remains mixta (plaintext+ciphertext),
        perfectamente legible with the db_key already sellada, and re-correr
        encrypt_database the complete.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault cerrado.")

        if not self._index.db_key_hex:
            db_key = secrets.token_bytes(32)
            self._index.db_key_hex = db_key.hex()
            self._vault.seal(self._index.to_dict(), passphrase)
            self._audit.append(
                "DB_KEY_CREATED",
                actor=self._owner_id,
                detail="key of encrypted of memory.db sellada in the vault",
            )
        self._apply_db_key()
        stats = self._memory.migrate_encryption()

        # Implementation note.
        # Implementation note.
        # Implementation note.
        kb_stats = {"migrated": 0, "skipped": 0}
        if (self._data_dir / "knowledge.db").exists():
            kb_stats = self.knowledge.migrate_encryption()

        self._audit.append(
            "DB_ENCRYPTED",
            actor=self._owner_id,
            detail=(f"memory migrated={stats['migrated']} skipped={stats['skipped']}; "
                    f"knowledge migrated={kb_stats['migrated']} "
                    f"skipped={kb_stats['skipped']}"),
        )
        return {"memory": stats, "knowledge": kb_stats}

    def _ensure_store_key(self, passphrase: str) -> bytes:
        """
        Garantiza that the index tiene store key, PERSISTIENDOLA in the
        vault before of return. the orden importa: if a artifact is
        cifrara with a key that only vive in memory and the proceso
        muriera before of the proximo seal(), the artifact quedaria
        indescifrable for siempre.
        """
        assert self._index is not None
        key = self._store_key()
        if key is not None:
            return key
        key = secrets.token_bytes(32)
        self._index.store_key_hex = key.hex()
        self._vault.seal(self._index.to_dict(), passphrase)
        self._audit.append(
            "STORE_KEY_CREATED",
            actor=self._owner_id,
            detail="key of the artifact store generada and sellada in the vault",
        )
        return key

    def _artifact_secret(self, artifact_hash: str, passphrase: Optional[str]):
        """Secreto correcto for the envelope: store key (v2) o passphrase (v1)."""
        if self._store.envelope_version(artifact_hash) == "2":
            key = self._store_key()
            if key is None:
                raise VaultAuthError(
                    f"El artifact {artifact_hash[:16]}… es v2 pero el vault "
                    f"no tiene store key — vault y store desincronizados."
                )
            return key
        if passphrase is None:
            raise VaultAuthError(
                f"El artifact {artifact_hash[:16]}… es v1 — se necesita la "
                f"passphrase para descifrarlo."
            )
        return passphrase

    def archive_artifact(self, path: Path, passphrase: str) -> str:
        """
        encrypts and guarda the file crudo in the ArtifactStore (envelope v2,
        with the store key of the vault). returns the content_hash (id).

        A diferencia of ingest()  that only indexa rutas and hashes  esto
        preserves the bytes: a testamento archivado sobrevive aunque the
        original is borre of the filesystem.
        """
        if not self._unlocked:
            raise RuntimeError("Vault cerrado.")
        key = self._ensure_store_key(passphrase)
        artifact_hash = self._store.put(path, key)
        self._audit.append(
            "ARTIFACT_ARCHIVED",
            actor=self._owner_id,
            artifact=str(path),
            detail=f"hash={artifact_hash[:16]} store=artifacts/ envelope=v2",
        )
        return artifact_hash

    def restore_artifact(
        self, artifact_hash: str, dest: Path, passphrase: Optional[str] = None,
        *, actor: str,
    ) -> Path:
        """
        Recupera a artifact archivado and it writes in `dest`.
        Envelopes v2 is descifran with the store key of the vault (no require
        passphrase  funciona also tras a recovery by custodios);
        envelopes v1 heredados require the passphrase.
        the integridad is verifica dos veces (tag GCM + SHA-256 vs id).
        """
        if not self._unlocked:
            raise RuntimeError("Vault cerrado.")
        secret = self._artifact_secret(artifact_hash, passphrase)
        out = self._store.restore(artifact_hash, dest, secret)
        self._audit.append(
            "ARTIFACT_RESTORED",
            actor=actor,
            artifact=str(dest),
            detail=f"hash={artifact_hash[:16]}",
        )
        return out

    def verify_artifact(
        self, artifact_hash: str, passphrase: Optional[str] = None
    ) -> bool:
        """True if the artifact archivado decrypts e integro (v1 o v2)."""
        try:
            secret = self._artifact_secret(artifact_hash, passphrase)
        except (VaultAuthError, VaultCorruptError, VaultNotFoundError):
            return False
        return self._store.verify(artifact_hash, secret)

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def heartbeat(self, passphrase: str) -> None:
        """
        Registra actividad of the owner.
        updates InactivityCondition.last_activity_iso if exists.

        FIX: the refresco of actividad is persiste with seal() before of return.
        without esto, tocar the condition only mutaba the index in memory and the new
        last_activity_iso is perdia a less that the caller llamara a lock() after
         a heartbeat perdido can disparar InactivityCondition and conceder
        acceso a the heirs mientras the owner sigue activo.
        """
        self.open_owner(passphrase)
        assert self._index is not None
        if self._index.policy:
            policy = AccessPolicy.from_dict(self._index.policy)
            for cond in policy.conditions:
                if hasattr(cond, "touch"):
                    cond.touch()
            self._index.policy = policy.to_dict()
            self._index.last_updated = datetime.now(timezone.utc).isoformat()
            self._vault.seal(self._index.to_dict(), passphrase)
        self._audit.append("HEARTBEAT", actor=self._owner_id)

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def summary(self, actor: str) -> Dict[str, Any]:
        """summary of the legado: categorias, conteos, artifacts prioritarios."""
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault cerrado.")

        by_category: Dict[str, List[Dict]] = {}
        for a in self._index.artifacts:
            cat = a.get("category", "unknown")
            by_category.setdefault(cat, []).append(a)

        self._audit.append("QUERY", actor=actor, detail="summary requested")

        return {
            "owner_id": self._index.owner_id,
            "created_at": self._index.created_at,
            "total_artifacts": len(self._index.artifacts),
            "heirs": [
                h.get("display_name") for h in self._index.heirs
                if not h.get("revoked_at")
            ],
            "by_category": {
                cat: len(items) for cat, items in by_category.items()
            },
            "memory_stats": self._memory.stats(),
            "audit_trail_length": self._audit.length,
        }

    def heir_guide(self, actor: str) -> str:
        """
        generates the Guia of the heir (markdown determinista) and registra
        the evento in the audit trail.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault cerrado.")
        from legacy.agent.heir_guide import build_guide

        guide = build_guide(
            self._index,
            memory_stats=self._memory.stats(),
            audit_length=self._audit.length,
            archived_hashes=self._store.list_hashes(),
        )
        self._audit.append(
            "GUIDE_GENERATED",
            actor=actor,
            detail=f"artifacts={len(self._index.artifacts)}",
        )
        return guide

    # Implementation note.
    # Implementation note.
    # Implementation note.

    def verify_audit(self, hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
        """Verifica the integridad of the audit trail."""
        result = self._audit.verify(hmac_key=hmac_key)
        return result.to_dict()

    def verify_memory_integrity(self) -> Dict[str, Any]:
        """
        FIX R3-001: cross-referencia the index encrypted of the vault with
        the content real of memory.db.

        the vault protege the index (artifact_id, memory_id, content_hash).
        memory.db no is encrypted  a attacker with acceso to the filesystem can
        modificar su content without break the audit trail.
        Este metodo detects esa divergencia comparando the content_hash of the index
        (dentro of the vault decrypted) with the content_hash almacenado in memory.db.

        returns: {ok, checked, errors: [str]}
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault cerrado.")

        errors: List[str] = []
        checked = 0
        db_path = self._data_dir / "memory.db"

        if not db_path.exists():
            errors.append("memory.db no found")
        else:
            # Implementation note.
            # Implementation note.
            with closing(sqlite3.connect(db_path)) as conn:
                conn.row_factory = sqlite3.Row

                # Implementation note.
                # Implementation note.
                # Implementation note.
                vault_memory_ids: set = set()
                for artifact in self._index.artifacts:
                    memory_id = artifact.get("memory_id", "")
                    expected_hash = artifact.get("content_hash", "")
                    if not memory_id or not expected_hash:
                        continue
                    vault_memory_ids.add(memory_id)
                    checked += 1
                    row = conn.execute(
                        "SELECT content FROM memories WHERE memory_id=?",
                        (memory_id,),
                    ).fetchone()
                    if row is None:
                        errors.append(
                            f"memory_id={memory_id[:8]}… ausente de memory.db"
                        )
                    else:
                        # Implementation note.
                        # Implementation note.
                        # Implementation note.
                        # Implementation note.
                        content = self._memory._dec(
                            memory_id, "content", row["content"]
                        )
                        if content is None:
                            errors.append(
                                f"memory_id={memory_id[:8]}… encrypted content "
                                f"unreadable (missing db_key or tampered data)"
                            )
                        else:
                            # Implementation note.
                            # Implementation note.
                            # Implementation note.
                            # Implementation note.
                            # Implementation note.
                            actual_hash = hashlib.sha256(
                                content.encode("utf-8")
                            ).hexdigest()
                            if actual_hash != expected_hash:
                                errors.append(
                                    f"memory_id={memory_id[:8]}… altered content: "
                                    f"vault={expected_hash[:16]} "
                                    f"actual={actual_hash[:16]}"
                                )

                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
                # Implementation note.
                orphan_rows = conn.execute(
                    "SELECT memory_id FROM memories WHERE state != 'FORGOTTEN'"
                ).fetchall()
                for row in orphan_rows:
                    mid = row["memory_id"]
                    if mid not in vault_memory_ids:
                        errors.append(
                            f"memory_id={mid[:8]}… en memory.db sin artifact "
                            f"en vault index (ghost memory)"
                        )

        ok = len(errors) == 0
        self._audit.append(
            "INTEGRITY_CHECK",
            actor=self._owner_id,
            detail=f"memory_integrity ok={ok} checked={checked} errors={len(errors)}",
        )
        return {"ok": ok, "checked": checked, "errors": errors}
