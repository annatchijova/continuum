"""
legacy/agent/memory_agent.py
=============================
Main digital-legacy orchestrator.

Lifecycle:
  1. Owner ingests artifacts (documents, photos, notes).
  2. The classifier assigns a deterministic category.
  3. The memory field stores content and embeddings.
  4. The vault encrypts the index with the owner's passphrase.
  5. The audit trail records every operation in a hash chain.

When access activates (the condition is met):
  6. The heir provides a key and the vault opens.
  7. The query engine answers questions about the legacy.

The agent operates in two modes:
  OWNER   owner ingests and manages.
  HEIR    heir (read-only after activation).
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


# Artifact and legacy-index data models.

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
    # Store encryption key, sealed inside the vault.
    store_key_hex: str = ""
    # Database encryption key, sealed inside the vault.
    db_key_hex: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "LegacyIndex":
        return LegacyIndex(**d)


# Legacy agent.

class LegacyAgent:
    """
    Main digital-legacy agent.

    data_dir   : agent working directory (audit trail, memory, vault).
    owner_id   : owner identifier (does not need to be PII; may be a hash or alias).
    hmac_key   : audit-trail HMAC bytes. None means use the environment variable.
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
        self._knowledge = None   # lazy; knowledge.db is created only when used

    @property
    def knowledge(self):
        """KnowledgeBase for the legacy (created on first use)."""
        if self._knowledge is None:
            from legacy.knowledge.extractor import KnowledgeBase
            self._knowledge = KnowledgeBase(
                self._data_dir / "knowledge.db", db_key=self._store_key_none_safe_db_key()
            )
        return self._knowledge

    def _store_key_none_safe_db_key(self) -> Optional[bytes]:
        """Return the index db_key when the unlocked index has one; otherwise None."""
        if self._index and self._index.db_key_hex:
            return bytes.fromhex(self._index.db_key_hex)
        return None

    # Vault lifecycle.

    def initialize(self, passphrase: str, policy: Optional[AccessPolicy] = None) -> None:
        """
        Create the initial vault. Call once by the owner.
        Raise ValueError if it already exists.
        """
        if self._vault.exists():
            raise ValueError("The vault already exists. Use open_owner() to open it.")

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
            detail=f"vault initialized, policy={'set' if policy else 'none'}",
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
            detail="owner access",
        )

    def lock(self, passphrase: str) -> None:
        """Re-encrypt the vault with its current state."""
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is not open.")
        self._index.last_updated = datetime.now(timezone.utc).isoformat()
        self._vault.seal(self._index.to_dict(), passphrase)
        self._unlocked = False
        self._audit.append("VAULT_LOCKED", actor=self._owner_id)

    def rekey(self, old_passphrase: str, new_passphrase: str) -> Dict[str, Any]:
        """
        Rotate the passphrase. Revoking an heir is insufficient when someone
        already knows the passphrase; it must be changed (KL-011).

        With the v2 keyslot vault, rotation rewraps only the passphrase slot:
        the payload is not re-encrypted and the recovery slot survives.

        Three steps, each safe to rerun after a crash:
          1. Ensure the store key is sealed in the vault using the old passphrase.
          2. Convert v1 artifacts (passphrase) to v2 (store key). Artifacts are
             then independent of the passphrase.
          3. Rewrap the passphrase keyslot (old to new).
        If the process stops during steps 1–2, the vault opens with the old
        passphrase and rerunning rekey(old, new) completes the work. Converted
        artifacts are skipped. After step 3, rotation is complete.

        At the end, the agent remains unlocked with the refreshed index.
        """
        if not new_passphrase:
            raise ValueError("The new passphrase cannot be empty.")

        # Open and apply the old key before changing anything.
        raw = self._vault.open(old_passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()

        # Ensure the store key exists and convert legacy artifacts.
        key = self._ensure_store_key(old_passphrase)

        # Rewrap the vault passphrase slot.
        stats = self._store.convert_to_key(old_passphrase, key)

        # Record the completed rotation.
        self._vault.rewrap_passphrase(old_passphrase, new_passphrase)

        self._audit.append(
            "PASSPHRASE_ROTATED",
            actor=self._owner_id,
            detail=f"artifacts_converted={stats['converted']} "
                   f"artifacts_skipped={stats['skipped']} "
                   f"custody_preserved={self._vault.has_recovery_slot()}",
        )
        return stats

    # Custody and recovery.

    def setup_custody(
        self, passphrase: str, *, shares: int, threshold: int
    ) -> List[str]:
        """
        Configure custodian recovery:
          1. Generate a random 32-byte recovery key.
          2. Add it as a vault keyslot (wrapping the data key).
          3. Split it into `shares` fragments with `threshold`
             (Shamir over GF(2^8)), then discard the key.

        Return serialized shares. This is the only time they exist:
        neither the recovery key nor the shares are persisted anywhere.
        Any subset of `threshold` custodians reconstructs the key; fewer
        shares reveal no information.

        Reconfiguring replaces the slot; previous shares become unusable,
        effectively revoking the custodians.
        """
        if threshold < 2:
            raise ValueError(
                "threshold must be >= 2; with threshold 1, each custodian "
                "could open the legacy alone."
            )
        if shares < threshold:
            raise ValueError(f"shares ({shares}) must be >= threshold ({threshold}).")

        # Open the vault and convert legacy artifacts before adding custody.
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
                   f"(the key and shares are not persisted)",
        )
        return [s.serialize() for s in share_objs]

    def remove_custody(self, passphrase: str) -> bool:
        """Remove the recovery slot; existing shares become unusable."""
        removed = self._vault.remove_recovery_slot(passphrase)
        self._audit.append(
            "CUSTODY_REMOVED",
            actor=self._owner_id,
            detail=f"removed={removed}",
        )
        return removed

    # Time-lock recovery.

    def add_timelock(
        self, passphrase: str, squarings: int, *, modulus_bits: int = 2048
    ) -> None:
        """
        Add a recovery path through a time-lock puzzle: the data key remains
        recoverable by solving `squarings` sequential squarings offline,
        without custodians. This is a work floor, not a wall clock; see
        legacy/core/timelock.py. It is additional to passphrase and custody.
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
        Open the vault by solving the time-lock puzzle (slow by design).
        Leave the agent unlocked.
        """
        raw = self._vault.open_with_timelock(progress=progress)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "VAULT_RECOVERED_TIMELOCK",
            actor=actor,
            detail="recovery by solved time-lock puzzle",
        )

    def set_passphrase_from_timelock(
        self, new_passphrase: str, *, actor: str, progress=None
    ) -> None:
        """Solve the puzzle once, set the new passphrase, and open the vault."""
        if not new_passphrase:
            raise ValueError("The new passphrase cannot be empty.")
        self._vault.set_passphrase_with_timelock(new_passphrase, progress=progress)
        raw = self._vault.open(new_passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "PASSPHRASE_RESET_BY_TIMELOCK",
            actor=actor,
            detail="passphrase reset after solving the time-lock",
        )

    def recover_with_shares(self, shares: List[str], *, actor: str) -> None:
        """
        Open the vault by reconstructing the recovery key from custodian
        shares without a passphrase. The agent remains unlocked.
        """
        recovery_key = combine_shares(shares)
        raw = self._vault.open_with_recovery(recovery_key)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "VAULT_RECOVERED",
            actor=actor,
            detail=f"custodian recovery with {len(shares)} share(s)",
        )

    def set_passphrase_from_recovery(
        self, shares: List[str], new_passphrase: str, *, actor: str
    ) -> None:
        """
        Reset the vault passphrase using shares: the complete heir path
        reconstructs the key with custodians, sets a new passphrase, and
        resumes normal operation.
        """
        if not new_passphrase:
            raise ValueError("The new passphrase cannot be empty.")
        recovery_key = combine_shares(shares)
        self._vault.set_passphrase_with_recovery(recovery_key, new_passphrase)
        raw = self._vault.open(new_passphrase)
        self._index = LegacyIndex.from_dict(raw)
        self._unlocked = True
        self._apply_db_key()
        self._audit.append(
            "PASSPHRASE_RESET_BY_RECOVERY",
            actor=actor,
            detail=f"passphrase reset with {len(shares)} share(s)",
        )

    # Artifact ingestion.

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
        Ingest an artifact into the legacy.
        Classify it, store it in memory, and record it in the index.

        FIX F-001 (TOCTOU): the file is reads a SOLA VEZ aqui.
        The content read is passed directly to the classifier.
        content_hash is computed from the exact content stored in memory.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is not open. Call open_owner() first.")

        # Read the file once to avoid TOCTOU inconsistencies.
        try:
            raw = path.read_bytes()[:65_536]
        except OSError:
            raw = b""

        is_binary = b"\x00" in raw[:512]
        if is_binary:
            text_content = ""
        else:
            text_content = raw.decode("utf-8", errors="replace")

        # Classify the exact content that was read.
        result: ClassificationResult = self._classifier.classify(
            text_content, filename=path.name
        )
        category = force_category or result.category

        # Use a stable placeholder for binary files.
        if is_binary:
            content = f"[{category.value}] {path.name}"
        else:
            content = text_content or f"[{category.value}] {path.name}"

        # Hash the exact content stored in memory.
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Idempotency: do not ingest the same content twice.
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

        # Store the content in the adaptive memory field.
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
            content_hash=content_hash,          # hash of the actual content
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

        # Optionally extract professional knowledge from text content.
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
        Ingest all files in a directory.

        FIX F-002 (symlink traversal): verify that the resolved path remains
        inside the requested directory before processing. Symlinks pointing
        outside are ignored and recorded in the audit trail.
        """
        glob_pat = "**/*" if recursive else "*"
        base = directory.resolve()
        records = []
        for p in directory.glob(glob_pat):
            if not p.is_file():
                continue
            # Resolve and contain-check every candidate path.
            try:
                resolved = p.resolve()
                resolved.relative_to(base)  # raises ValueError when outside
            except ValueError:
                self._audit.append(
                    "INGEST_SKIPPED",
                    actor=self._owner_id,
                    artifact=str(p),
                    detail=f"symlink traversal blocked: {p} → {resolved}",
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

    # Heir access.

    def open_heir(
        self,
        heir_id: str,
        passphrase: str,
        *,
        heir_key: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> bool:
        """
        Try to open the vault as an heir.
        Evaluate the access policy before decrypting.
        Return True if access is granted.
        """
        # Authenticate the passphrase before evaluating policy.
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

        # Revoked heirs are denied even with a valid passphrase.
        if any(
            h.get("heir_id") == heir_id and h.get("revoked_at")
            for h in index.heirs
        ):
            self._audit.append(
                "ACCESS_DENIED",
                actor=heir_id,
                detail="heir revoked",
            )
            return False

        policy_dict = index.policy

        if policy_dict:
            policy = AccessPolicy.from_dict(policy_dict)
            granted = policy.evaluate(now=now, heir_key=heir_key)
        else:
            granted = True  # no policy means open access

        # Record the policy decision before unlocking.
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
            self._audit.append("VAULT_UNLOCKED", actor=heir_id, detail="heir access")

        return granted

    # Queries and heir management.

    def query(
        self,
        question: str,
        actor: str,
        *,
        category: Optional[DocCategory] = None,
        top_k: int = 5,
    ) -> List[RecallResult]:
        """
        Answer a question about the legacy.
        Record the query in the audit trail.
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked.")

        results = self._memory.recall(question, category=category, top_k=top_k)
        self._audit.append(
            "QUERY",
            actor=actor,
            detail=f"q={question[:80]!r} results={len(results)}",
        )
        return results

    # Heir registration and revocation.

    def add_heir(self, heir_id: str, display_name: str, email: str = "") -> None:
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is not open.")
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
        Generate a secret key for the heir and add the corresponding
        HeirKeyCondition to the access policy.

        Return the key in plaintext. This is the only moment it exists outside
        the owner's control; only its PBKDF2 hash is persisted. Deliver it to
        the heir through a secure channel (see KL-011).

        With an existing policy, add the condition using its current operator.
        With AND (default), the heir needs this key and every other condition;
        with OR, the key is sufficient by itself.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is not open.")

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
        Revoke an heir: mark its entry with revoked_at (history is retained)
        and remove its HeirKeyCondition from the policy. open_heir() denies a
        revoked heir even when the general policy is satisfied.

        Fail-closed note: if removing the key leaves the policy without
        conditions, evaluate() returns False for every heir until the owner
        configures a new condition.

        Return True if anything changed (heir found or key removed).
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is not open.")

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

    # Memory lifecycle operations.

    def reinforce_memory(self, memory_id: str) -> None:
        """
        Promote a memory to REINFORCED and record it in the audit trail.

        FIX R2-002: a direct call to MemoryField.reinforce() was silent; any
        code with an open vault could reinforce false memories without a trace.
        This method is the only authorized access point.
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked.")
        self._memory.reinforce(memory_id)
        self._audit.append(
            "MEMORY_REINFORCED",
            actor=self._owner_id,
            detail=f"memory_id={memory_id}",
        )

    def forget_memory(self, memory_id: str) -> None:
        """
        Mark a memory as FORGOTTEN and record it in the audit trail.

        FIX R2-002: likewise, forgetting a genuine memory was undetectable.
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked.")
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
        Run memory-field consolidation and record it in the audit trail. Before
        this wrapper, Consolidator was manually invoked without a trace and
        mutated FORGOTTEN and REINFORCED states undetectably, the same issue
        closed by FIX R2-002 for reinforce() and forget().
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked.")
        report = Consolidator(
            self._memory,
            similarity_threshold=similarity_threshold,
            reinforce_threshold=reinforce_threshold,
            forget_after_days=forget_after_days,
            score_decay=score_decay,
        ).run()
        # FIX R7-002: record each memory this consolidation run marked
        # FORGOTTEN, by memory_id, in the SAME format as forget_memory().
        # This lets verify_memory_integrity distinguish a legitimate
        # suppression (audit-attributable) from a state flip to FORGOTTEN
        # injected into memory.db by an attacker (no audit event -> tampering).
        for mid in report.forgotten_ids:
            self._audit.append(
                "MEMORY_FORGOTTEN",
                actor=self._owner_id,
                detail=f"memory_id={mid} reason=consolidation",
            )
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

    # Encryption and artifact-store helpers.

    def _store_key(self) -> Optional[bytes]:
        """Return the index store key when present."""
        if self._index and self._index.store_key_hex:
            return bytes.fromhex(self._index.store_key_hex)
        return None

    def _apply_db_key(self) -> None:
        """
        Propagate the index db_key to MemoryField after opening the vault.
        Call this after every assignment to self._index from a decrypted vault
        (open_owner, open_heir, recovery, or initialization). Without it,
        encrypted memory.db would be unreadable even with an open vault.
        """
        if self._index is None:
            return
        key = bytes.fromhex(self._index.db_key_hex) if self._index.db_key_hex else None
        self._memory.set_db_key(key)
        if self._knowledge is not None:
            self._knowledge.set_db_key(key)

    def encrypt_database(self, passphrase: str) -> Dict[str, Any]:
        """
        Encrypt memory.db at rest (KL-001): generate a db_key, seal it in the
        vault, and migrate plaintext rows to ciphertext.

        Crash-safe ordering (like _ensure_store_key): persist the db_key in the
        vault before encrypting the first row. If the process stops midway,
        the database remains mixed but readable with the sealed key; rerunning
        encrypt_database completes the migration.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is locked.")

        if not self._index.db_key_hex:
            db_key = secrets.token_bytes(32)
            self._index.db_key_hex = db_key.hex()
            self._vault.seal(self._index.to_dict(), passphrase)
            self._audit.append(
                "DB_KEY_CREATED",
                actor=self._owner_id,
                detail="memory.db encryption key sealed in the vault",
            )
        self._apply_db_key()
        stats = self._memory.migrate_encryption()

        # Knowledge encryption uses the same database key.
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
        Ensure that the index has a store key, persisting it in the vault
        before returning. Ordering matters: if an artifact were encrypted with
        a key that existed only in memory and the process stopped before the
        next seal(), the artifact would be permanently unreadable.
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
            detail="artifact-store key generated and sealed in the vault",
        )
        return key

    def _artifact_secret(self, artifact_hash: str, passphrase: Optional[str]):
        """Return the correct envelope secret: store key (v2) or passphrase (v1)."""
        if self._store.envelope_version(artifact_hash) == "2":
            key = self._store_key()
            if key is None:
                raise VaultAuthError(
                    f"Artifact {artifact_hash[:16]}… is v2, but the vault "
                    f"has no store key — vault and store are out of sync."
                )
            return key
        if passphrase is None:
            raise VaultAuthError(
                f"Artifact {artifact_hash[:16]}… is v1 — the passphrase is "
                f"required to decrypt it."
            )
        return passphrase

    def archive_artifact(self, path: Path, passphrase: str) -> str:
        """
        encrypts and guarda the file crudo in the ArtifactStore (envelope v2,
        with the store key of the vault). returns the content_hash (id).

        Unlike ingest(), which only indexes paths and hashes, this preserves
        the bytes: an archived will survives even if the original is deleted
        from the filesystem.
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked.")
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
        Restore an archived artifact to `dest`.
        V2 envelopes decrypt with the vault store key and do not require a
        passphrase, including after custodian recovery; legacy v1 envelopes
        require the passphrase. Integrity is checked twice (GCM tag and
        SHA-256 against the artifact id).
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked.")
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
        """Return True if the archived artifact decrypts and is intact (v1 or v2)."""
        try:
            secret = self._artifact_secret(artifact_hash, passphrase)
        except (VaultAuthError, VaultCorruptError, VaultNotFoundError):
            return False
        return self._store.verify(artifact_hash, secret)

    # Owner activity and reporting.

    def heartbeat(self, passphrase: str) -> None:
        """
        Record owner activity.
        Update InactivityCondition.last_activity_iso when present.

        FIX: the activity refresh is persisted with seal() before returning.
        Without this, touching the condition would mutate only the in-memory
        index, and a lost heartbeat could trigger InactivityCondition and grant
        heirs access while the owner remains active.
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

    # Summary and heir guide.

    def summary(self, actor: str) -> Dict[str, Any]:
        """Return a legacy summary: categories, counts, and active heirs."""
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is locked.")

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
        Generate the heir guide (deterministic markdown) and record the event
        in the audit trail.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is locked.")
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

    # Integrity checks.

    def verify_audit(self, hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
        """Verify audit-trail integrity."""
        result = self._audit.verify(hmac_key=hmac_key)
        return result.to_dict()

    def verify_memory_integrity(self) -> Dict[str, Any]:
        """
        FIX R3-001: cross-reference the vault's encrypted index with the
        actual content in memory.db.

        The vault protects artifact_id, memory_id, and content_hash. An attacker
        with filesystem access could modify unencrypted memory.db without
        breaking the audit trail. This method detects divergence by comparing
        the decrypted index hashes with the content stored in memory.db.

        Return {ok, checked, errors: [str]}.
        """
        if not self._unlocked or self._index is None:
            raise RuntimeError("Vault is locked.")

        errors: List[str] = []
        checked = 0
        db_path = self._data_dir / "memory.db"

        # FIX R7-002: memories legitimately forgotten are attributable to a
        # MEMORY_FORGOTTEN audit event (manual forget_memory() or
        # consolidation). An indexed memory that shows up FORGOTTEN in
        # memory.db WITHOUT this backing was suppressed out of band (a
        # state flip injected at the filesystem level): invisible to the
        # heir, and until now invisible to this check too. `state` governs
        # recall visibility but lives outside the encryption perimeter and
        # unauthenticated - the archetype "critical state outside the
        # perimeter". Audit attribution is as strong as the hash chain:
        # with LEGACY_HMAC_KEY, forging a covering event requires the key
        # (KL-009); without HMAC an attacker could already rewrite everything.
        audited_forgotten: set = set()
        for ev in self._audit.events(event_type="MEMORY_FORGOTTEN"):
            for tok in (ev.get("detail") or "").split():
                if tok.startswith("memory_id="):
                    audited_forgotten.add(tok[len("memory_id="):])

        if not db_path.exists():
            errors.append("memory.db not found")
        else:
            # Compare every indexed memory entry with the database.
            with closing(sqlite3.connect(db_path)) as conn:
                conn.row_factory = sqlite3.Row

                # Track indexed IDs to detect ghost memories.
                vault_memory_ids: set = set()
                for artifact in self._index.artifacts:
                    memory_id = artifact.get("memory_id", "")
                    expected_hash = artifact.get("content_hash", "")
                    if not memory_id or not expected_hash:
                        continue
                    vault_memory_ids.add(memory_id)
                    checked += 1
                    row = conn.execute(
                        "SELECT content, state FROM memories WHERE memory_id=?",
                        (memory_id,),
                    ).fetchone()
                    if row is None:
                        errors.append(
                            f"memory_id={memory_id[:8]}… missing from memory.db"
                        )
                    else:
                        # Suppression: an indexed memory marked FORGOTTEN with
                        # no audit-trail backing = an injected state flip
                        # (FIX R7-002). Content may still be intact (hash OK)
                        # but the heir no longer sees it.
                        if (
                            row["state"] == "FORGOTTEN"
                            and memory_id not in audited_forgotten
                        ):
                            errors.append(
                                f"memory_id={memory_id[:8]}… indexed but "
                                f"FORGOTTEN with no audit event (out-of-band "
                                f"suppression: invisible to the heir)"
                            )
                        # Decrypt the stored content using the active database key.
                        content = self._memory._dec(
                            memory_id, "content", row["content"]
                        )
                        if content is None:
                            errors.append(
                                f"memory_id={memory_id[:8]}… encrypted content "
                                f"unreadable (missing db_key or tampered data)"
                            )
                        else:
                            # Compare its actual hash with the sealed index hash.
                            actual_hash = hashlib.sha256(
                                content.encode("utf-8")
                            ).hexdigest()
                            if actual_hash != expected_hash:
                                errors.append(
                                    f"memory_id={memory_id[:8]}… altered content: "
                                    f"vault={expected_hash[:16]} "
                                    f"actual={actual_hash[:16]}"
                                )

                # Find non-forgotten database rows absent from the vault index.
                orphan_rows = conn.execute(
                    "SELECT memory_id FROM memories WHERE state != 'FORGOTTEN'"
                ).fetchall()
                for row in orphan_rows:
                    mid = row["memory_id"]
                    if mid not in vault_memory_ids:
                        errors.append(
                            f"memory_id={mid[:8]}… in memory.db without an artifact "
                            f"in the vault index (ghost memory)"
                        )

        ok = len(errors) == 0
        self._audit.append(
            "INTEGRITY_CHECK",
            actor=self._owner_id,
            detail=f"memory_integrity ok={ok} checked={checked} errors={len(errors)}",
        )
        return {"ok": ok, "checked": checked, "errors": errors}
