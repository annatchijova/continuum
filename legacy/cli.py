# Implementation note.
"""
legacy/cli.py
==============
Interfaz of linea of comandos for Digital Legacy.

Instalable as console script: `pip install .` deja the comando `legacy`
disponible. `cli/legacy_cli.py` remains as shim of compatibilidad.

Comandos:
  init        inicializa a vault new
  ingest      ingiere a file o directory
  query       query the legado in lenguaje natural
  summary     summary of the legado (categorias, conteos)
  heir        opens the vault as heir
  verify      verifica the integridad of the audit trail
  heartbeat   registra actividad of the owner
  knowledge   gestiona the database of conocimiento
  status      state of the vault and audit trail

Uso:
    python3 cli/legacy_cli.py init --data-dir ~/.legacy --owner-id mi_alias
    python3 cli/legacy_cli.py ingest ~/documents/contract.pdf
    python3 cli/legacy_cli.py query "where is the contract of the casa?"
    python3 cli/legacy_cli.py summary
    python3 cli/legacy_cli.py verify
"""
from __future__ import annotations

import argparse
import getpass
import hmac as _hmac
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# Implementation note.
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from legacy.agent.memory_agent import LegacyAgent
from legacy.agent.query_engine import QueryEngine
from legacy.core.lockfile import AgentLock, LockHeldError
from legacy.ingestion.doc_types import DocCategory
from legacy.knowledge.extractor import KnowledgeBase, KnowledgeDomain
from legacy.vault.conditions import (
    AccessPolicy,
    ConditionOperator,
    DateCondition,
    HeirKeyCondition,
    InactivityCondition,
    ManualCondition,
)


# Implementation note.
# Implementation note.
# Implementation note.

def _default_data_dir() -> Path:
    return Path(os.environ.get("LEGACY_DATA_DIR", Path.home() / ".legacy"))


def _get_agent(data_dir: Path, owner_id: str) -> LegacyAgent:
    return LegacyAgent(data_dir=data_dir, owner_id=owner_id)


def _ask_passphrase(prompt: str = "Passphrase of the vault: ") -> str:
    return getpass.getpass(prompt)


def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _print_separator() -> None:
    print("" * 60)


# Implementation note.
# Implementation note.
# Implementation note.

def cmd_init(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    if agent._vault.exists():
        print(f"ERROR: ya existe un vault en {data_dir}")
        print("for reiniciar, elimina the directory manualmente.")
        return 1

    # Implementation note.
    conditions = []
    if args.inactivity_days:
        conditions.append(
            InactivityCondition(
                days=args.inactivity_days,
                last_activity_iso=datetime.now(timezone.utc).isoformat(),
            )
        )
    if args.unlock_date:
        conditions.append(DateCondition(unlock_after_iso=args.unlock_date))
    if args.manual:
        conditions.append(ManualCondition(activated=False))

    policy = AccessPolicy(conditions) if conditions else None

    passphrase = _ask_passphrase("Crea tu passphrase of the vault: ")
    confirm = _ask_passphrase("Confirma the passphrase: ")
    # Implementation note.
    if not _hmac.compare_digest(passphrase, confirm):
        print("ERROR: the passphrases no coinciden.")
        return 1

    agent.initialize(passphrase, policy=policy)
    agent.lock(passphrase)

    print(f"✓ Vault inicializado en {data_dir}")
    if policy:
        print(f"  Política: {len(conditions)} condición(es) configurada(s)")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR abriendo vault: {exc}")
        return 1

    path = Path(args.path)
    tags = args.tags.split(",") if args.tags else []

    if path.is_file():
        try:
            record = agent.ingest(
                path, notes=args.notes or "", tags=tags,
                extract_knowledge=args.knowledge,
            )
            print(f"✓ {path.name}")
            print(f"  Categoría   : {record.category}")
            print(f"  Confianza   : {record.classification_confidence}")
            print(f"  Hash        : {record.content_hash[:16]}…")
        except Exception as exc:
            print(f"ERROR: {exc}")
            agent.lock(passphrase)
            return 1
    elif path.is_dir():
        ext_list = None
        if args.extensions:
            ext_list = [e if e.startswith(".") else f".{e}"
                        for e in args.extensions.split(",")]
        records = agent.ingest_directory(
            path, recursive=not args.no_recursive, extensions=ext_list,
            extract_knowledge=args.knowledge,
        )
        print(f"✓ {len(records)} archivo(s) ingerido(s) de {path}")
        by_cat: dict = {}
        for r in records:
            by_cat[r.category] = by_cat.get(r.category, 0) + 1
        for cat, count in sorted(by_cat.items()):
            print(f"  {cat:<20} {count}")
    else:
        print(f"ERROR: {path} no existe.")
        agent.lock(passphrase)
        return 1

    agent.lock(passphrase)
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    engine = QueryEngine(agent._memory)
    response = engine.query(args.question, top_k=args.top_k)

    _print_separator()
    print(f"CONSULTA: {response.query}")
    print(f"Intención detectada: {response.intent.value}")
    if response.category_filter:
        print(f"Categoría: {response.category_filter.value}")
    _print_separator()
    print(response.answer)

    agent._audit.append("QUERY", actor=args.owner_id, detail=args.question[:80])
    agent.lock(passphrase)
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    summary = agent.summary(args.owner_id)
    _print_separator()
    print("summary of the LEGADO DIGITAL")
    _print_separator()
    print(f"Propietario      : {summary['owner_id']}")
    print(f"Creado           : {summary['created_at']}")
    print(f"Total artifacts  : {summary['total_artifacts']}")
    print(f"Herederos        : {', '.join(summary['heirs']) or 'ninguno'}")
    print(f"Audit trail      : {summary['audit_trail_length']} eventos")
    print()
    print("by categoria:")
    for cat, count in sorted(summary["by_category"].items()):
        print(f"  {cat:<20} {count}")
    print()
    mem_stats = summary.get("memory_stats", {})
    print(f"Memorias en campo: {mem_stats.get('total', 0)}")
    print(f"Vocabulario      : {mem_stats.get('vocab_size', 0)} términos")

    agent.lock(passphrase)
    return 0


def cmd_heir(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase(f"Passphrase del vault [{args.heir_id}]: ")
    heir_key = None
    if args.heir_key:
        heir_key = args.heir_key

    granted = agent.open_heir(
        heir_id=args.heir_id,
        passphrase=passphrase,
        heir_key=heir_key,
    )

    if not granted:
        print("ACCESO DENEGADO  the politica of acceso no is satisfecha.")
        print("Verifica that is cumplan the conditions configuradas by the owner.")
        return 1

    print(f"✓ Acceso concedido para heredero: {args.heir_id}")
    _print_separator()

    if args.query:
        engine = QueryEngine(agent._memory)
        response = engine.query(args.query, top_k=5)
        print(f"CONSULTA: {response.query}")
        _print_separator()
        print(response.answer)
    else:
        summary = agent.summary(args.heir_id)
        print(f"Total artifacts : {summary['total_artifacts']}")
        print("by categoria:")
        for cat, count in sorted(summary["by_category"].items()):
            print(f"  {cat:<20} {count}")
        print()
        print("Usa --query for hacer questions over the legado.")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    result = agent.verify_audit()
    _print_separator()
    print("VERIFICACION of the AUDIT TRAIL")
    _print_separator()
    print(f"Eventos   : {result['length']}")
    print(f"HMAC      : {'verificado' if result['hmac_checked'] else 'hash-only'}")
    print()

    if result["valid"]:
        print(" AUDIT TRAIL INTEGRO")
    else:
        print(f"✗ AUDIT TRAIL COMPROMETIDO")
        print(f"  Primer eslabón inválido: seq={result['first_invalid_seq']}")
        summary = result.get("summary", {})
        for kind, count in summary.items():
            if count > 0:
                print(f"  {kind}: {count} error(es)")
    return 0 if result["valid"] else 1


def cmd_heartbeat(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)
    passphrase = _ask_passphrase()
    try:
        agent.heartbeat(passphrase)
        agent.lock(passphrase)
        print(f"✓ Actividad registrada: {datetime.now(timezone.utc).isoformat()}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1


def cmd_guide(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    guide = agent.heir_guide(actor=args.owner_id)
    agent.lock(passphrase)

    if args.output:
        out = Path(args.output)
        out.write_text(guide, encoding="utf-8")
        print(f"✓ Guía del heredero escrita en {out}")
    else:
        print(guide)
    return 0


def cmd_archive(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    path = Path(args.path)
    if not path.is_file():
        print(f"ERROR: {path} no existe o no es un archivo.")
        return 1

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    artifact_hash = agent.archive_artifact(path, passphrase)
    agent.lock(passphrase)
    print(f"✓ {path.name} archivado cifrado")
    print(f"  Hash (id de recuperación): {artifact_hash}")
    print(f"  Recuperar con: legacy restore {artifact_hash[:16]}… --output <destino>")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    # Implementation note.
    matches = [h for h in agent._store.list_hashes() if h.startswith(args.hash)]
    if not matches:
        print(f"ERROR: ningún artifact archivado empieza con '{args.hash}'.")
        agent.lock(passphrase)
        return 1
    if len(matches) > 1:
        print(f"ERROR: prefijo ambiguo — {len(matches)} coincidencias.")
        agent.lock(passphrase)
        return 1

    try:
        dest = agent.restore_artifact(
            matches[0], Path(args.output), passphrase, actor=args.owner_id
        )
    except Exception as exc:
        print(f"ERROR restaurando: {exc}")
        agent.lock(passphrase)
        return 1

    agent.lock(passphrase)
    print(f"✓ Artifact restaurado en {dest} (integridad verificada)")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from legacy.agent.export_bundle import export_bundle

    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    try:
        manifest = export_bundle(
            agent, Path(args.dest), actor=args.owner_id, passphrase=passphrase
        )
    except ValueError as exc:
        print(f"ERROR: {exc}")
        agent.lock(passphrase)
        return 1

    agent.lock(passphrase)
    _print_separator()
    print(f"✓ Bundle exportado en {args.dest}")
    print(f"  Archivos           : {len(manifest['files'])}")
    print(f"  Artifacts cifrados : {manifest['artifacts_included']} "
          f"({'verificados' if manifest['artifacts_verified'] else 'without verificar'})")
    print(f"  Audit trail        : {manifest['audit']['length']} eventos, "
          f"tip {manifest['audit']['tip_hash'][:16]}…")
    print(f"  Verificador incluido: {'si' if manifest['verify_script_included'] else 'no'}")
    return 0


def cmd_heir_revoke(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    changed = agent.revoke_heir(args.heir_id)
    agent.lock(passphrase)

    if changed:
        print(f"✓ Heredero revocado: {args.heir_id}")
        print("  Sus keys fueron eliminadas of the politica of acceso.")
        print("  important: if the heir conoce the passphrase of the vault,")
        print("  the revocacion no it detiene (KL-011)  cambia the passphrase.")
    else:
        print(f"No se encontró un heredero activo con id '{args.heir_id}'.")
    return 0 if changed else 1


def cmd_custody(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    if args.custody_cmd == "status":
        info = agent._vault.info()
        _print_separator()
        print("CUSTODIA of the LEGADO")
        _print_separator()
        if not info.get("exists"):
            print("No hay vault in este data_dir.")
            return 1
        print(f"Vault      : v{info.get('version')}")
        print(f"Keyslots   : {', '.join(info.get('keyslots', []))}")
        if "recovery" in info.get("keyslots", []):
            print("Custodia   :  configurada  a umbral of custodios can")
            print("             recover the legado without the passphrase.")
        else:
            print("Custodia   :  no configurada  if the passphrase is pierde,")
            print("             the legado is irrecuperable. Usa `custody setup`.")
        return 0

    if args.custody_cmd == "setup":
        passphrase = _ask_passphrase()
        try:
            shares = agent.setup_custody(
                passphrase, shares=args.shares, threshold=args.threshold
            )
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        agent.lock(passphrase)

        _print_separator()
        print(f"CUSTODIA CONFIGURADA — {args.threshold} de {args.shares}")
        _print_separator()
        print()
        print("Entrega a share a each custodio, by canales separados.")
        print("is muestran a SOLA VEZ  ni the key ni the shares remain")
        print("guardados in no lado. any grupo of "
              f"{args.threshold} custodios")
        print("can recover the legado; less that eso no obtiene nada.")
        print()
        for i, s in enumerate(shares, 1):
            print(f"── Custodio {i} " + "" * 45)
            print(s)
            print()
        print("Sugerencia: imprimir each share and sellarlo in a over with")
        print("the nombre of the custodio. if re-ejecutas `custody setup`, estos")
        print("shares remain INSERVIBLES (revocacion of custodios).")
        return 0

    if args.custody_cmd == "remove":
        passphrase = _ask_passphrase()
        try:
            removed = agent.remove_custody(passphrase)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        if removed:
            print(" Custodia eliminada  the shares repartidos already no sirven.")
            return 0
        print("No habia custodia configurada.")
        return 1

    # Implementation note.

    if args.custody_cmd == "calibrate":
        from legacy.core.timelock import calibrate, estimate_squarings
        print("Midiendo the velocidad of cuadratura of ESTA maquina...")
        rate = calibrate(seconds=1.5, modulus_bits=args.modulus_bits)
        print(f"  ≈ {rate:,} cuadraturas/segundo (módulo {args.modulus_bits} bits)")
        if args.days:
            t = estimate_squarings(args.days, rate)
            print(f"  para ≈ {args.days} día(s) a ESTE ritmo: --squarings {t}")
        print()
        print("ADVERTENCIA: is a piso of TRABAJO, no a fecha. Hardware more")
        print("fast resuelve before  elegi --squarings asumiendo the hardware")
        print("of the adversario, no the tuyo. Ver KL-011.")
        return 0

    if args.custody_cmd == "timelock-setup":
        passphrase = _ask_passphrase()
        try:
            agent.add_timelock(passphrase, args.squarings,
                               modulus_bits=args.modulus_bits)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        # Implementation note.
        # Implementation note.
        print(f"✓ Time-lock configurado: {args.squarings:,} cuadraturas "
              f"secuenciales (módulo {args.modulus_bits} bits).")
        print("  Camino ADICIONAL of recovery: resolver the puzzle opens the")
        print("  vault without a passphrase ni custodios. Piso of TRABAJO, no fecha")
        print("  (KL-011). Re-ejecutar replaces the puzzle.")
        return 0

    if args.custody_cmd == "timelock-remove":
        passphrase = _ask_passphrase()
        try:
            removed = agent.remove_timelock(passphrase)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        print(" Time-lock eliminado." if removed else "No habia time-lock configurado.")
        return 0 if removed else 1

    if args.custody_cmd == "timelock-recover":
        info = agent._vault.timelock_info()
        if not info:
            print("ERROR: the vault does not have a slot time-lock.")
            return 1
        print(f"Resolviendo el time-lock: {info['squarings']:,} cuadraturas "
              f"secuenciales. Esto ES lento por diseño.")

        def _progress(done, total):
            print(f"  … {done:,}/{total:,} ({100*done//total}%)", flush=True)

        try:
            if args.set_passphrase:
                new = _ask_passphrase("Passphrase new for the vault: ")
                confirm = _ask_passphrase("Confirma the passphrase new: ")
                if not _hmac.compare_digest(new, confirm) or not new:
                    print("ERROR: the passphrases no coinciden o are vacias.")
                    return 1
                agent.set_passphrase_from_timelock(
                    new, actor=args.actor or "recovery", progress=_progress)
                print(" LEGADO RECUPERADO  passphrase new establecida.")
            else:
                agent.recover_with_timelock(
                    actor=args.actor or "recovery", progress=_progress)
                print(" LEGADO RECUPERADO (only lectura of esta session).")
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1

        summary = agent.summary(args.actor or "recovery")
        print(f"\nPropietario     : {summary['owner_id']}")
        print(f"Total artifacts : {summary['total_artifacts']}")
        return 0

    if args.custody_cmd == "recover":
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        # Implementation note.
        shares: list = list(args.share or [])
        if args.share:
            print("AVISO: pasar shares by --share the deja visibles in the "
                  "table of procesos and the historial of the shell.")
            print("       Preferi the entry interactiva (without --share) o "
                  "--shares-file.")
        if args.shares_file:
            p = Path(args.shares_file)
            if not p.is_file():
                print(f"ERROR: {p} no existe.")
                return 1
            shares += [
                line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        if not shares:
            # Implementation note.
            print("Ingresa the shares of the custodios (uno by linea; "
                  "linea empty for finish):")
            while True:
                s = _ask_passphrase(f"  share #{len(shares) + 1}: ").strip()
                if not s:
                    break
                shares.append(s)
        if not shares:
            print("ERROR: no is ingreso no share.")
            return 1

        try:
            if args.set_passphrase:
                new = _ask_passphrase("Passphrase new for the vault: ")
                confirm = _ask_passphrase("Confirma the passphrase new: ")
                if not _hmac.compare_digest(new, confirm) or not new:
                    print("ERROR: the passphrases no coinciden o are vacias.")
                    return 1
                agent.set_passphrase_from_recovery(
                    shares, new, actor=args.actor or "recovery"
                )
                print(" LEGADO RECUPERADO  passphrase new establecida.")
                print("  A partir of now the vault opens with the passphrase new.")
            else:
                agent.recover_with_shares(shares, actor=args.actor or "recovery")
                print(" LEGADO RECUPERADO (only lectura of esta session).")
                print("  for fijar a passphrase new: "
                      "custody recover --set-passphrase")
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1

        summary = agent.summary(args.actor or "recovery")
        print()
        print(f"Propietario     : {summary['owner_id']}")
        print(f"Total artifacts : {summary['total_artifacts']}")
        for cat, count in sorted(summary["by_category"].items()):
            print(f"  {cat:<20} {count}")
        return 0

    return 1


def cmd_encrypt_db(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    try:
        stats = agent.encrypt_database(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        agent.lock(passphrase)
        return 1
    agent.lock(passphrase)

    mem, kb = stats["memory"], stats["knowledge"]
    print(" Bases encrypted at rest (KL-001).")
    print(f"  memory.db    : {mem['migrated']} cifradas (ya cifradas: {mem['skipped']})")
    print(f"  knowledge.db : {kb['migrated']} cifradas (ya cifradas: {kb['skipped']})")
    print("  the key vive dentro of the vault: is opens with the passphrase o by")
    print("  recovery of custodios. without the vault, the bases are ilegibles.")
    return 0


def cmd_rekey(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    old = _ask_passphrase("Passphrase ACTUAL of the vault: ")
    new = _ask_passphrase("Passphrase new: ")
    confirm = _ask_passphrase("Confirma the passphrase new: ")
    if not _hmac.compare_digest(new, confirm):
        print("ERROR: the passphrases nuevas no coinciden.")
        return 1
    if not new:
        print("ERROR: the passphrase new no can be empty.")
        return 1

    try:
        stats = agent.rekey(old, new)
    except Exception as exc:
        print(f"ERROR: {exc}")
        print("Nada fue modificado if the passphrase actual era incorrect.")
        print("if the error ocurrio a mitad of rotation, volve a correr")
        print("`legacy rekey` with the same passphrases for completarla.")
        return 1

    agent.lock(new)
    print(" Passphrase rotada (rewrap of the keyslot  payload intacto).")
    print(f"  Artifacts migrados a store key: {stats['converted']} "
          f"(ya migrados: {stats['skipped']})")
    if agent._vault.has_recovery_slot():
        print("  Custodia: the shares repartidos SIGUEN siendo validos.")
    print()
    print("RECORDATORIO: if entregaste the passphrase old in a over")
    print("sellado, reemplazala  the old already no opens nada.")
    return 0


def cmd_bundle_verify(args: argparse.Namespace) -> int:
    from legacy.agent.export_bundle import check_manifest
    from legacy.core.audit_trail import AuditTrail

    bundle = Path(args.bundle_dir)
    if not bundle.is_dir():
        print(f"ERROR: {bundle} no existe o no es un directorio.")
        return 1

    _print_separator()
    print(f"VERIFICACIÓN DE BUNDLE — {bundle}")
    _print_separator()

    ok = True
    problems = check_manifest(bundle)
    if problems:
        ok = False
        print(f"✗ manifest         {len(problems)} problema(s):")
        for p in problems:
            print(f"    - {p}")
    else:
        print(" manifest         all the hashes coinciden")

    audit_db = bundle / "audit.db"
    if audit_db.is_file():
        result = AuditTrail(db_path=audit_db, hmac_key=b"").verify(hmac_key=b"")
        if result.valid:
            print(f"✓ audit_chain      {result.length} eventos, cadena íntegra "
                  f"(hash-only)")
        else:
            ok = False
            print(f"✗ audit_chain      inválida desde seq={result.first_invalid_seq}")
    else:
        ok = False
        print(" audit_chain      audit.db ausente")

    print()
    print(" BUNDLE INTEGRO" if ok else " BUNDLE altered  request a copy new")
    return 0 if ok else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    from legacy.agent.doctor import run_doctor

    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    report = run_doctor(agent, passphrase=passphrase)
    agent.lock(passphrase)

    _print_separator()
    print("DOCTOR  SALUD of the LEGADO")
    _print_separator()
    for c in report.checks:
        mark = "" if c.ok else ""
        print(f"{mark} {c.name:<18} {c.detail}")
    print()
    print(" TODO in ORDEN" if report.ok
          else " HAY PROBLEMAS  revisa the checks marcados with ")
    return 0 if report.ok else 1


def cmd_heir_add(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    agent.add_heir(
        heir_id=args.heir_id,
        display_name=args.name or args.heir_id,
        email=args.email or "",
    )
    secret = None
    if args.with_key:
        secret = agent.register_heir_key(args.heir_id)

    agent.lock(passphrase)

    print(f"✓ Heredero registrado: {args.heir_id}")
    if secret:
        _print_separator()
        print("key SECRETA of the heir  is sample a SOLA VEZ:")
        print(f"\n    {secret}\n")
        print("only su hash remains in the vault; if is pierde, genera another.")
        print("Entregala by a canal seguro (over sellado, escribano).")
        print("the heir the usara with: legacy heir <id> --heir-key <key>")
        _print_separator()
    return 0


def cmd_consolidate(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    report = agent.consolidate(forget_after_days=args.forget_after_days)
    agent.lock(passphrase)

    _print_separator()
    print("CONSOLIDACION of the field of memory")
    _print_separator()
    print(f"Duplicados fusionados : {report.duplicates_merged}")
    print(f"Sinapsis podadas      : {report.synapses_pruned}")
    print(f"Promovidas (frecuencia): {report.promoted_to_reinforced}")
    print(f"Olvidadas (inactividad): {report.degraded_to_forgotten}")
    print(f"Scores actualizados   : {report.scores_updated}")
    if report.errors:
        print(f"Errores               : {report.errors}")
    return 0 if not report.errors else 1


def cmd_knowledge(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    kb = KnowledgeBase(data_dir / "knowledge.db")

    if args.knowledge_cmd == "add":
        path = Path(args.file)
        if not path.is_file():
            print(f"ERROR: {path} no existe.")
            return 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"ERROR: {exc}")
            return 1
        entries = kb.extract_chunks(text, source_path=str(path))
        print(f"✓ {len(entries)} entrada(s) extraída(s) de {path.name}")
        for e in entries[:3]:
            print(f"  [{e.domain.value}] {e.title} ({e.confidence})")

    elif args.knowledge_cmd == "search":
        results = kb.search(args.query, top_k=args.top_k)
        _print_separator()
        print(f"BASE DE CONOCIMIENTO — '{args.query}' ({len(results)} resultado(s))")
        _print_separator()
        for r in results:
            print(f"\n[{r.domain.value}] {r.title} ({r.confidence})")
            print(f"  {r.summary[:200]}")
            if r.source_path:
                print(f"  Fuente: {r.source_path}")

    elif args.knowledge_cmd == "stats":
        stats = kb.stats()
        print(f"Total entradas: {stats['total']}")
        for domain, count in sorted(stats["by_domain"].items()):
            print(f"  {domain:<20} {count}")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    vault_path = data_dir / "legacy.vault"
    audit_path = data_dir / "audit.db"
    memory_path = data_dir / "memory.db"
    kb_path = data_dir / "knowledge.db"

    _print_separator()
    print("state of the VAULT")
    _print_separator()
    print(f"Directorio : {data_dir}")
    print(f"Vault      : {' exists' if vault_path.exists() else ' does not exist'}")
    print(f"Audit trail: {' exists' if audit_path.exists() else ' does not exist'}")
    print(f"Memoria    : {' exists' if memory_path.exists() else ' does not exist'}")
    print(f"Conocimiento: {' exists' if kb_path.exists() else ' does not exist'}")

    if audit_path.exists():
        import sqlite3 as _sq
        try:
            conn = _sq.connect(audit_path)
            count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            last = conn.execute(
                "SELECT timestamp, event_type FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            conn.close()
            print(f"\nAudit trail: {count} evento(s)")
            if last:
                print(f"Último evento: [{last[1]}] {last[0]}")
        except Exception:
            pass
    return 0


# Implementation note.
# Implementation note.
# Implementation note.

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="legacy",
        description="Digital Legacy  Memory Agent for legado digital",
    )
    parser.add_argument(
        "--data-dir",
        default=str(_default_data_dir()),
        help=f"Directorio de datos (default: {_default_data_dir()})",
    )
    parser.add_argument(
        "--owner-id",
        default=os.environ.get("LEGACY_OWNER_ID", "owner"),
        help="Identificador of the owner",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # Implementation note.
    p_init = sub.add_parser("init", help="Inicializa a vault new")
    p_init.add_argument("--inactivity-days", type=int,
                        help="Activar after of N dias of inactividad")
    p_init.add_argument("--unlock-date",
                        help="Activar in fecha ISO 8601 (ej: 2030-01-01T00:00:00+00:00)")
    p_init.add_argument("--manual", action="store_true",
                        help="Activacion manual (for testing)")

    # Implementation note.
    p_ingest = sub.add_parser("ingest", help="Ingiere file(s)")
    p_ingest.add_argument("path", help="file o directory")
    p_ingest.add_argument("--tags", help="Tags separados by coma")
    p_ingest.add_argument("--notes", help="Notas over the artifact")
    p_ingest.add_argument("--extensions", help="Extensiones a procesar (ej: .pdf,.txt)")
    p_ingest.add_argument("--no-recursive", action="store_true",
                          help="No procesar subdirectorios")
    p_ingest.add_argument("--knowledge", action="store_true",
                          help="Extraer also a the database of conocimiento")

    # Implementation note.
    p_query = sub.add_parser("query", help="query the legado")
    p_query.add_argument("question", help="question in lenguaje natural")
    p_query.add_argument("--top-k", type=int, default=8,
                         help="Maximo of resultados (default: 8)")

    # Implementation note.
    sub.add_parser("summary", help="summary of the legado")

    # Implementation note.
    p_heir = sub.add_parser("heir", help="Acceso as heir")
    p_heir.add_argument("heir_id", help="ID of the heir")
    p_heir.add_argument("--heir-key", help="key secreta of the heir")
    p_heir.add_argument("--query", help="query inmediata tras the acceso")

    # Implementation note.
    p_guide = sub.add_parser("guide", help="generates the Guia of the heir (markdown)")
    p_guide.add_argument("--output", help="file destination (default: stdout)")

    # Implementation note.
    p_arch = sub.add_parser("archive", help="Guarda a copy encrypted of the file")
    p_arch.add_argument("path", help="file a archivar")

    # Implementation note.
    p_rest = sub.add_parser("restore", help="Recupera a artifact archivado")
    p_rest.add_argument("hash", help="Hash (o prefijo unico) of the artifact")
    p_rest.add_argument("--output", required=True, help="Ruta destination")

    # Implementation note.
    p_exp = sub.add_parser("export",
                           help="Exporta a bundle portable for heirs")
    p_exp.add_argument("dest", help="directory destination (new o empty)")

    # Implementation note.
    p_hrev = sub.add_parser("heir-revoke", help="Revoca a heir")
    p_hrev.add_argument("heir_id", help="Identificador of the heir a revocar")

    # Implementation note.
    p_cust = sub.add_parser(
        "custody",
        help="recovery by umbral of custodios (Shamir)",
    )
    cust_sub = p_cust.add_subparsers(dest="custody_cmd", required=True)
    p_cs = cust_sub.add_parser("setup", help="Reparte the key of recovery")
    p_cs.add_argument("--shares", type=int, required=True,
                      help="Cantidad of custodios (N)")
    p_cs.add_argument("--threshold", type=int, required=True,
                      help="Cuantos hacen missing for recover (K)")
    p_cr = cust_sub.add_parser(
        "recover",
        help="Recupera the legado with K shares (interactive by default)",
    )
    p_cr.add_argument("--share", action="append",
                      help="a share by argumento (INSEGURO: visible in `ps` and "
                           "the historial; preferi the entry interactiva)")
    p_cr.add_argument("--shares-file",
                      help="file with a share by linea (for automatizacion)")
    p_cr.add_argument("--set-passphrase", action="store_true",
                      help="Fijar a passphrase new tras recover")
    p_cr.add_argument("--actor", help="who recupera (for the audit trail)")
    cust_sub.add_parser("status", help="state of the custodia (without a passphrase)")
    cust_sub.add_parser("remove", help="removes the custodia (invalida shares)")

    # Implementation note.
    p_cal = cust_sub.add_parser(
        "calibrate", help="Mide cuadraturas/seg and sugiere --squarings")
    p_cal.add_argument("--days", type=float, help="Traducir N dias a --squarings")
    p_cal.add_argument("--modulus-bits", type=int, default=2048)
    p_tls = cust_sub.add_parser(
        "timelock-setup", help="adds a camino of recovery by time-lock puzzle")
    p_tls.add_argument("--squarings", type=int, required=True,
                       help="Cuadraturas secuenciales (piso of trabajo; ver calibrate)")
    p_tls.add_argument("--modulus-bits", type=int, default=2048)
    p_tlr = cust_sub.add_parser(
        "timelock-recover", help="Recupera resolviendo the puzzle (slow by design)")
    p_tlr.add_argument("--set-passphrase", action="store_true",
                       help="Fijar a passphrase new tras recover")
    p_tlr.add_argument("--actor", help="who recupera (for the audit trail)")
    cust_sub.add_parser("timelock-remove", help="removes the slot time-lock")

    # Implementation note.
    sub.add_parser("encrypt-db",
                   help="encrypts at rest memory.db (KL-001)")

    # Implementation note.
    sub.add_parser("rekey", help="Rota the passphrase of the vault and the artifacts")

    # Implementation note.
    p_bv = sub.add_parser("bundle-verify",
                          help="Verifica the integridad of a bundle exportado")
    p_bv.add_argument("bundle_dir", help="directory of the bundle")

    # Implementation note.
    sub.add_parser("doctor", help="Chequeo integral of salud of the legado")

    # Implementation note.
    p_hadd = sub.add_parser("heir-add", help="Registra a heir")
    p_hadd.add_argument("heir_id", help="Identificador of the heir")
    p_hadd.add_argument("--name", help="Nombre for mostrar")
    p_hadd.add_argument("--email", help="Email of contacto")
    p_hadd.add_argument("--with-key", action="store_true",
                        help="generates a key secreta and adds HeirKeyCondition")

    # Implementation note.
    p_cons = sub.add_parser("consolidate",
                            help="Consolida the memory (dedup, poda, decay)")
    p_cons.add_argument("--forget-after-days", type=float, default=90.0,
                        help="Dias without acceso for degradar a FORGOTTEN (default: 90)")

    # Implementation note.
    sub.add_parser("verify", help="Verifica the audit trail")

    # Implementation note.
    sub.add_parser("heartbeat", help="Registra actividad of the owner")

    # Implementation note.
    p_kn = sub.add_parser("knowledge", help="database of conocimiento profesional")
    kn_sub = p_kn.add_subparsers(dest="knowledge_cmd", required=True)
    p_kn_add = kn_sub.add_parser("add", help="Agregar document")
    p_kn_add.add_argument("file", help="file of text o markdown")
    p_kn_search = kn_sub.add_parser("search", help="search in the conocimiento")
    p_kn_search.add_argument("query")
    p_kn_search.add_argument("--top-k", type=int, default=5)
    kn_sub.add_parser("stats", help="Estadisticas of the database of conocimiento")

    # Implementation note.
    sub.add_parser("status", help="state of the vault and files of data")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "init":      cmd_init,
        "ingest":    cmd_ingest,
        "query":     cmd_query,
        "summary":   cmd_summary,
        "heir":      cmd_heir,
        "guide":     cmd_guide,
        "archive":   cmd_archive,
        "restore":   cmd_restore,
        "doctor":    cmd_doctor,
        "heir-add":  cmd_heir_add,
        "heir-revoke": cmd_heir_revoke,
        "export":    cmd_export,
        "custody":   cmd_custody,
        "encrypt-db": cmd_encrypt_db,
        "rekey":     cmd_rekey,
        "bundle-verify": cmd_bundle_verify,
        "consolidate": cmd_consolidate,
        "verify":    cmd_verify,
        "heartbeat": cmd_heartbeat,
        "knowledge": cmd_knowledge,
        "status":    cmd_status,
    }

    # Implementation note.
    # Implementation note.
    # Implementation note.
    # Implementation note.
    mutating = {
        "init", "ingest", "heartbeat", "guide", "archive", "restore",
        "query", "summary", "doctor", "heir-add", "heir-revoke",
        "export", "custody", "rekey", "encrypt-db", "consolidate",
    }

    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        sys.exit(1)

    if args.command in mutating:
        try:
            with AgentLock(Path(args.data_dir)):
                sys.exit(fn(args))
        except LockHeldError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)
    else:
        sys.exit(fn(args))


if __name__ == "__main__":
    main()
