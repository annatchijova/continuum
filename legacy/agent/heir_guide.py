"""
legacy/agent/heir_guide.py
===========================
Heir Guide Generator.

The product's central deliverable: when the vault activates, the heir does
not receive a database — they receive a readable document explaining WHAT
exists, WHERE to begin, and HOW to verify that nothing was manipulated.

Propiedades:
  - Deterministic: the same index and timestamp produce the same markdown,
    byte for byte. No LLM. Ordering follows CATEGORY_PROFILES priority
    (1 = urgent administrative matters), then the filename within each
    category. Reproducible for auditing.
  - Self-contained: the document includes verification instructions
    (verify_legacy.py), so the heir does not need this software to trust the
    audit trail.
  - No secrets: the guide lists paths, hashes, and metadata — never
    credential contents or the passphrase.

Uso:
    from legacy.agent.heir_guide import build_guide
    md = build_guide(index)                        # dict or LegacyIndex
    md = agent.heir_guide(actor="heir_1")          # with an audit event
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from legacy.ingestion.doc_types import CATEGORY_PROFILES, DocCategory

# Unknown categories or categories without a profile go last.
_FALLBACK_PRIORITY = 99

# What each category means to an heir without technical context.
_CATEGORY_GUIDANCE: Dict[str, str] = {
    DocCategory.LEGAL.value:
        "Legal documents — wills, powers of attorney, and contracts. "
        "Take them to a notary or lawyer BEFORE making decisions.",
    DocCategory.FINANCIAL.value:
        "Accounts, investments, and insurance. Banks often freeze accounts "
        "after notification: review everything before notifying them.",
    DocCategory.IDENTITY.value:
        "Identity documents. Required for almost every administrative matter.",
    DocCategory.MEDICAL.value:
        "Medical history. Relevant to life insurance and pending matters.",
    DocCategory.REAL_ESTATE.value:
        "Property and mortgages. Check for outstanding debts and fees.",
    DocCategory.SUBSCRIPTION.value:
        "Recurring-billing services. Cancel them promptly to stop charges.",
    DocCategory.CREDENTIAL.value:
        "Clues about accounts and access (no passwords). A list of services "
        "where accounts may need to be closed or claims filed.",
    DocCategory.PROFESSIONAL.value:
        "Degrees, projects, and professional history.",
    DocCategory.PERSONAL.value:
        "Letters, journals, and personal memories.",
    DocCategory.MEDIA.value:
        "Photos, videos, and audio.",
    DocCategory.UNKNOWN.value:
        "Unclassified — review manually.",
}


def _category_priority(cat_value: str) -> int:
    try:
        profile = CATEGORY_PROFILES.get(DocCategory(cat_value))
    except ValueError:
        return _FALLBACK_PRIORITY
    return profile.priority if profile else _FALLBACK_PRIORITY


def _group_artifacts(
    artifacts: List[Dict[str, Any]],
) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Group by category and sort by (priority, category, filename)."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for a in artifacts:
        groups.setdefault(a.get("category", "unknown"), []).append(a)
    for items in groups.values():
        items.sort(key=lambda a: (a.get("filename", ""), a.get("artifact_id", "")))
    return sorted(
        groups.items(), key=lambda kv: (_category_priority(kv[0]), kv[0])
    )


def build_guide(
    index: Any,
    *,
    memory_stats: Optional[Dict[str, Any]] = None,
    audit_length: Optional[int] = None,
    archived_hashes: Optional[List[str]] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    Generate the guide in markdown from the vault index.

    index           : LegacyIndex or its dictionary representation.
    memory_stats    : MemoryField.stats() — optional.
    audit_length    : number of audit-trail events — optional.
    archived_hashes : content hashes present in the encrypted ArtifactStore.
    generated_at    : ISO 8601; injectable for fully reproducible output.
    """
    d: Dict[str, Any] = index if isinstance(index, dict) else index.to_dict()
    artifacts: List[Dict[str, Any]] = d.get("artifacts", [])
    heirs: List[Dict[str, Any]] = [
        h for h in d.get("heirs", []) if not h.get("revoked_at")
    ]
    ts = generated_at or datetime.now(timezone.utc).isoformat()
    archived = set(archived_hashes or [])

    lines: List[str] = []
    w = lines.append

    w("# Heir Guide — Digital Legacy")
    w("")
    w(f"**Owner:** {d.get('owner_id', '?')}  ")
    w(f"**Legacy created:** {d.get('created_at', '?')}  ")
    w(f"**Last updated:** {d.get('last_updated', '?')}  ")
    w(f"**Guide generated:** {ts}")
    w("")
    w("This document was generated deterministically from the encrypted legacy")
    w("index. It contains no credential secrets or sensitive content — only a map of")
    w("what exists, where it is, and how to verify it.")
    w("")

    # ── Resumen ───────────────────────────────────────────────────────────
    w("## Summary")
    w("")
    w(f"- Indexed artifacts: **{len(artifacts)}**")
    if archived:
        w(f"- Artifacts with an encrypted copy in storage: **{len(archived)}**")
    if memory_stats:
        w(f"- Queryable memories: **{memory_stats.get('total', 0)}**")
    if audit_length is not None:
        w(f"- Audit-trail events: **{audit_length}**")
    if heirs:
        names = ", ".join(
            h.get("display_name") or h.get("heir_id", "?") for h in heirs
        )
        w(f"- Registered heirs: {names}")
    w("")

    # ── Where to start ────────────────────────────────────────────────────
    w("## Where to start")
    w("")
    w("Categories are ordered by urgency (1 = address first).")
    w("")

    if not artifacts:
        w("*The index contains no artifacts.*")
        w("")
    else:
        for cat, items in _group_artifacts(artifacts):
            prio = _category_priority(cat)
            w(f"### [{prio}] {cat} ({len(items)})")
            w("")
            guidance = _CATEGORY_GUIDANCE.get(cat)
            if guidance:
                w(f"> {guidance}")
                w("")
            for a in items:
                fname = a.get("filename") or "(unnamed)"
                path = a.get("path", "?")
                chash = (a.get("content_hash") or "")[:16]
                notes = a.get("notes") or ""
                tags = a.get("tags") or []
                mark = " 🔒" if a.get("content_hash") in archived else ""
                w(f"- **{fname}**{mark}")
                w(f"  - Path: `{path}`")
                w(f"  - Hash: `{chash}…` — ingested {a.get('ingested_at', '?')}")
                if tags:
                    w(f"  - Tags: {', '.join(tags)}")
                if notes:
                    w(f"  - Owner note: {notes}")
            w("")
        if archived:
            w("The 🔒 symbol indicates that an encrypted copy of the file exists in")
            w("`<data_dir>/artifacts/` and can be restored with `legacy restore <hash>`.")
            w("")

    # ── Verification ──────────────────────────────────────────────────────
    w("## How to verify that nothing was manipulated")
    w("")
    w("1. The audit trail records every access to the legacy in a hash chain.")
    w("   Verify it with the self-contained script (requires only Python):")
    w("")
    w("   ```")
    w("   python3 verify_legacy.py <data_dir>/audit.db")
    w("   ```")
    w("")
    w("2. If the owner gave you an HMAC key, use it — without one, verification")
    w("   detects accidents but not an attacker who rewrites the entire chain:")
    w("")
    w("   ```")
    w("   python3 verify_legacy.py <data_dir>/audit.db --hmac-key-hex <key>")
    w("   ```")
    w("")
    w("3. The hash listed next to each artifact is the SHA-256 of its content")
    w("   at ingestion time. Recompute it for the current file to detect later")
    w("   modifications.")
    w("")
    w("---")
    w(f"*Generated by Digital Legacy — {ts}*")
    w("")

    return "\n".join(lines)
