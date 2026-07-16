"""
legacy/agent/heir_guide.py
===========================
Generador de la Guía del Heredero.

El entregable central del producto: cuando el vault se activa, el heredero
no recibe una base de datos — recibe un documento legible que le dice QUÉ
hay, POR DÓNDE empezar y CÓMO verificar que nada fue manipulado.

Propiedades:
  - Determinista : mismo índice + mismo instante → mismo markdown, byte a
    byte. Sin LLM. El orden viene de la prioridad de CATEGORY_PROFILES
    (1 = urgente para trámites) y, dentro de cada categoría, del nombre
    de archivo. Reproducible para auditoría.
  - Autónomo     : el documento incluye las instrucciones de verificación
    (verify_legacy.py) para que el heredero no dependa de este software
    para confiar en el audit trail.
  - Sin secretos : la guía lista rutas, hashes y metadatos — nunca
    contenido de credenciales ni la passphrase.

Uso:
    from legacy.agent.heir_guide import build_guide
    md = build_guide(index)                        # dict o LegacyIndex
    md = agent.heir_guide(actor="heir_1")          # con evento de audit
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from legacy.ingestion.doc_types import CATEGORY_PROFILES, DocCategory

# Prioridad de categorías desconocidas / sin perfil: al final.
_FALLBACK_PRIORITY = 99

# Qué significa cada categoría para un heredero sin contexto técnico.
_CATEGORY_GUIDANCE: Dict[str, str] = {
    DocCategory.LEGAL.value:
        "Documentos legales — testamentos, poderes, contratos. "
        "Llevalos a un escribano o abogado ANTES de tomar decisiones.",
    DocCategory.FINANCIAL.value:
        "Cuentas, inversiones y seguros. Los bancos suelen congelar cuentas "
        "al ser notificados: relevá todo antes de avisar.",
    DocCategory.IDENTITY.value:
        "Documentos de identidad. Necesarios para casi todos los trámites.",
    DocCategory.MEDICAL.value:
        "Historial médico. Relevante para seguros de vida y causas pendientes.",
    DocCategory.REAL_ESTATE.value:
        "Propiedades e hipotecas. Verificá deudas y expensas pendientes.",
    DocCategory.SUBSCRIPTION.value:
        "Servicios con cobro recurrente. Cancelalos pronto para frenar débitos.",
    DocCategory.CREDENTIAL.value:
        "Indicios de cuentas y accesos (sin contraseñas). Lista de servicios "
        "donde existir dados de baja o reclamar.",
    DocCategory.PROFESSIONAL.value:
        "Títulos, proyectos y trayectoria profesional.",
    DocCategory.PERSONAL.value:
        "Cartas, diarios y memorias personales.",
    DocCategory.MEDIA.value:
        "Fotos, videos y audio.",
    DocCategory.UNKNOWN.value:
        "Sin clasificar — revisá manualmente.",
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
    """Agrupa por categoría y ordena por (prioridad, categoría, filename)."""
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
    Genera la guía en markdown a partir del índice del vault.

    index           : LegacyIndex o su dict (como sale del vault).
    memory_stats    : MemoryField.stats() — opcional.
    audit_length    : cantidad de eventos del audit trail — opcional.
    archived_hashes : content_hashes presentes en el ArtifactStore cifrado.
    generated_at    : ISO 8601; inyectable para salida 100% reproducible.
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

    w("# Guía del Heredero — Legado Digital")
    w("")
    w(f"**Propietario:** {d.get('owner_id', '?')}  ")
    w(f"**Legado creado:** {d.get('created_at', '?')}  ")
    w(f"**Última actualización:** {d.get('last_updated', '?')}  ")
    w(f"**Guía generada:** {ts}")
    w("")
    w("Este documento fue generado de forma determinista a partir del índice")
    w("cifrado del legado. No contiene contraseñas ni contenido sensible —")
    w("solo el mapa de qué existe, dónde está y cómo verificarlo.")
    w("")

    # ── Resumen ───────────────────────────────────────────────────────────
    w("## Resumen")
    w("")
    w(f"- Artifacts indexados: **{len(artifacts)}**")
    if archived:
        w(f"- Artifacts with an encrypted copy in storage: **{len(archived)}**")
    if memory_stats:
        w(f"- Memorias consultables: **{memory_stats.get('total', 0)}**")
    if audit_length is not None:
        w(f"- Eventos en el audit trail: **{audit_length}**")
    if heirs:
        names = ", ".join(
            h.get("display_name") or h.get("heir_id", "?") for h in heirs
        )
        w(f"- Herederos registrados: {names}")
    w("")

    # ── Por dónde empezar ─────────────────────────────────────────────────
    w("## Por dónde empezar")
    w("")
    w("Las categorías están ordenadas por urgencia (1 = atender primero).")
    w("")

    if not artifacts:
        w("*El índice no contiene artifacts.*")
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
                fname = a.get("filename") or "(sin nombre)"
                path = a.get("path", "?")
                chash = (a.get("content_hash") or "")[:16]
                notes = a.get("notes") or ""
                tags = a.get("tags") or []
                mark = " 🔒" if a.get("content_hash") in archived else ""
                w(f"- **{fname}**{mark}")
                w(f"  - Ruta: `{path}`")
                w(f"  - Hash: `{chash}…` — ingresado {a.get('ingested_at', '?')}")
                if tags:
                    w(f"  - Tags: {', '.join(tags)}")
                if notes:
                    w(f"  - Nota del propietario: {notes}")
            w("")
        if archived:
            w("The 🔒 symbol indicates that an encrypted copy of the file exists in")
            w("`<data_dir>/artifacts/` recuperable con `legacy restore <hash>`.")
            w("")

    # ── Verificación ──────────────────────────────────────────────────────
    w("## Cómo verificar que nada fue manipulado")
    w("")
    w("1. El audit trail registra cada acceso al legado con una cadena de")
    w("   hashes. Verificalo con el script autónomo (solo requiere Python):")
    w("")
    w("   ```")
    w("   python3 verify_legacy.py <data_dir>/audit.db")
    w("   ```")
    w("")
    w("2. Si el propietario te entregó una clave HMAC, usala — sin ella la")
    w("   verificación detecta accidentes pero no a un atacante que reescriba")
    w("   la cadena completa:")
    w("")
    w("   ```")
    w("   python3 verify_legacy.py <data_dir>/audit.db --hmac-key-hex <clave>")
    w("   ```")
    w("")
    w("3. El hash listado junto a cada artifact es el SHA-256 de su contenido")
    w("   al momento de la ingestión. Podés recomputarlo sobre el archivo")
    w("   actual para detectar modificaciones posteriores.")
    w("")
    w("---")
    w(f"*Generado por Digital Legacy — {ts}*")
    w("")

    return "\n".join(lines)
