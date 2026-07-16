# Command-line interface for Digital Legacy.
"""
legacy/cli.py
==============
Command-line interface for Digital Legacy.

Installable as a console script: `pip install .` makes the `legacy` command
available. `cli/legacy_cli.py` remains as a compatibility shim.

Commands:
  init        initialize a new vault
  ingest      ingest a file or directory
  query       query the legacy in natural language
  summary     summarize the legacy (categories, counts)
  heir        open the vault as an heir
  verify      verify audit-trail integrity
  heartbeat   record owner activity
  knowledge   manage the knowledge database
  status      show vault and audit-trail status

Uso:
    python3 cli/legacy_cli.py init --data-dir ~/.legacy --owner-id mi_alias
    python3 cli/legacy_cli.py ingest ~/documents/contract.pdf
    python3 cli/legacy_cli.py query "where is the contract for the house?"
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

# Import project modules from the repository root when run directly.
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


# CLI helpers.

def _default_data_dir() -> Path:
    return Path(os.environ.get("LEGACY_DATA_DIR", Path.home() / ".legacy"))


def _get_agent(data_dir: Path, owner_id: str) -> LegacyAgent:
    return LegacyAgent(data_dir=data_dir, owner_id=owner_id)


def _ask_passphrase(prompt: str = "Vault passphrase: ") -> str:
    return getpass.getpass(prompt)


def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _print_separator() -> None:
    print("" * 60)


# Commands.

def cmd_init(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    if agent._vault.exists():
        print(f"ERROR: a vault already exists in {data_dir}")
        print("To restart, remove the directory manually.")
        return 1

    # Build the optional access policy.
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

    passphrase = _ask_passphrase("Create the vault passphrase: ")
    confirm = _ask_passphrase("Confirm the passphrase: ")
    if not _hmac.compare_digest(passphrase, confirm):
        print("ERROR: the passphrases do not match.")
        return 1

    agent.initialize(passphrase, policy=policy)
    agent.lock(passphrase)

    print(f"✓ Vault initialized in {data_dir}")
    if policy:
        print(f"  Policy: {len(conditions)} condition(s) configured")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR opening vault: {exc}")
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
            print(f"  Category    : {record.category}")
            print(f"  Confidence  : {record.classification_confidence}")
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
        print(f"✓ Ingested {len(records)} file(s) from {path}")
        by_cat: dict = {}
        for r in records:
            by_cat[r.category] = by_cat.get(r.category, 0) + 1
        for cat, count in sorted(by_cat.items()):
            print(f"  {cat:<20} {count}")
    else:
        print(f"ERROR: {path} does not exist.")
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
    print(f"QUERY: {response.query}")
    print(f"Detected intent: {response.intent.value}")
    if response.category_filter:
        print(f"Category: {response.category_filter.value}")
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
    print("DIGITAL LEGACY SUMMARY")
    _print_separator()
    print(f"Owner            : {summary['owner_id']}")
    print(f"Created          : {summary['created_at']}")
    print(f"Total artifacts  : {summary['total_artifacts']}")
    print(f"Heirs            : {', '.join(summary['heirs']) or 'none'}")
    print(f"Audit trail      : {summary['audit_trail_length']} events")
    print()
    print("By category:")
    for cat, count in sorted(summary["by_category"].items()):
        print(f"  {cat:<20} {count}")
    print()
    mem_stats = summary.get("memory_stats", {})
    print(f"Memories         : {mem_stats.get('total', 0)}")
    print(f"Vocabulary       : {mem_stats.get('vocab_size', 0)} terms")

    agent.lock(passphrase)
    return 0


def cmd_heir(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    passphrase = _ask_passphrase(f"Vault passphrase [{args.heir_id}]: ")
    heir_key = None
    if args.heir_key:
        heir_key = args.heir_key

    granted = agent.open_heir(
        heir_id=args.heir_id,
        passphrase=passphrase,
        heir_key=heir_key,
    )

    if not granted:
        print("ACCESS DENIED: the access policy is not satisfied.")
        print("Verify that the owner's configured conditions are met.")
        return 1

    print(f"✓ Access granted to heir: {args.heir_id}")
    _print_separator()

    if args.query:
        engine = QueryEngine(agent._memory)
        response = engine.query(args.query, top_k=5)
        print(f"QUERY: {response.query}")
        _print_separator()
        print(response.answer)
    else:
        summary = agent.summary(args.heir_id)
        print(f"Total artifacts : {summary['total_artifacts']}")
        print("By category:")
        for cat, count in sorted(summary["by_category"].items()):
            print(f"  {cat:<20} {count}")
        print()
        print("Use --query to ask questions about the legacy.")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    result = agent.verify_audit()
    _print_separator()
    print("AUDIT TRAIL VERIFICATION")
    _print_separator()
    print(f"Events    : {result['length']}")
    print(f"HMAC      : {'verified' if result['hmac_checked'] else 'hash-only'}")
    print()

    if result["valid"]:
        print("✓ AUDIT TRAIL INTACT")
    else:
        print("✗ AUDIT TRAIL COMPROMISED")
        print(f"  First invalid link: seq={result['first_invalid_seq']}")
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
        print(f"✓ Activity recorded: {datetime.now(timezone.utc).isoformat()}")
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
        print(f"✓ Heir guide written to {out}")
    else:
        print(guide)
    return 0


def cmd_archive(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    path = Path(args.path)
    if not path.is_file():
        print(f"ERROR: {path} does not exist or is not a file.")
        return 1

    passphrase = _ask_passphrase()
    try:
        agent.open_owner(passphrase)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    artifact_hash = agent.archive_artifact(path, passphrase)
    agent.lock(passphrase)
    print(f"✓ {path.name} archived encrypted")
    print(f"  Hash (recovery id): {artifact_hash}")
    print(f"  Restore with: legacy restore {artifact_hash[:16]}… --output <destination>")
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

    # Resolve the hash prefix.
    matches = [h for h in agent._store.list_hashes() if h.startswith(args.hash)]
    if not matches:
        print(f"ERROR: no archived artifact starts with '{args.hash}'.")
        agent.lock(passphrase)
        return 1
    if len(matches) > 1:
        print(f"ERROR: ambiguous prefix — {len(matches)} matches.")
        agent.lock(passphrase)
        return 1

    try:
        dest = agent.restore_artifact(
            matches[0], Path(args.output), passphrase, actor=args.owner_id
        )
    except Exception as exc:
        print(f"ERROR restoring artifact: {exc}")
        agent.lock(passphrase)
        return 1

    agent.lock(passphrase)
    print(f"✓ Artifact restored to {dest} (integrity verified)")
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
    print(f"✓ Bundle exported to {args.dest}")
    print(f"  Files              : {len(manifest['files'])}")
    print(f"  Encrypted artifacts: {manifest['artifacts_included']} "
          f"({'verified' if manifest['artifacts_verified'] else 'not verified'})")
    print(f"  Audit trail        : {manifest['audit']['length']} events, "
          f"tip {manifest['audit']['tip_hash'][:16]}…")
    print(f"  Verifier included  : {'yes' if manifest['verify_script_included'] else 'no'}")
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
        print(f"✓ Heir revoked: {args.heir_id}")
        print("  The heir's keys were removed from the access policy.")
        print("  Important: if the heir knows the vault passphrase,")
        print("  revocation cannot stop access (KL-011); change the passphrase.")
    else:
        print(f"No active heir found with id '{args.heir_id}'.")
    return 0 if changed else 1


def cmd_custody(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    if args.custody_cmd == "status":
        info = agent._vault.info()
        _print_separator()
        print("LEGACY CUSTODY")
        _print_separator()
        if not info.get("exists"):
            print("No vault exists in this data directory.")
            return 1
        print(f"Vault      : v{info.get('version')}")
        print(f"Keyslots   : {', '.join(info.get('keyslots', []))}")
        if "recovery" in info.get("keyslots", []):
            print("Custody    :  configured; the custodian threshold can")
            print("             recover the legacy without the passphrase.")
        else:
            print("Custody    :  not configured; if the passphrase is lost,")
            print("             the legacy is unrecoverable. Use `custody setup`.")
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
        print(f"CUSTODY CONFIGURED — {args.threshold} of {args.shares}")
        _print_separator()
        print()
        print("Give one share to each custodian through separate channels.")
        print("They are shown ONCE ONLY; neither the key nor shares remain")
        print("stored anywhere. Any group of "
              f"{args.threshold} custodians")
        print("can recover the legacy; fewer shares reveal nothing.")
        print()
        for i, s in enumerate(shares, 1):
            print(f"── Custodian {i} " + "" * 45)
            print(s)
            print()
        print("Suggestion: print each share and seal it in an envelope with")
        print("the custodian's name. If you rerun `custody setup`, these")
        print("shares become UNUSABLE (custodians are revoked).")
        return 0

    if args.custody_cmd == "remove":
        passphrase = _ask_passphrase()
        try:
            removed = agent.remove_custody(passphrase)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        if removed:
            print(" Custody removed; distributed shares are no longer valid.")
            return 0
        print("No custody was configured.")
        return 1

    # Time-lock calibration and recovery commands.

    if args.custody_cmd == "calibrate":
        from legacy.core.timelock import calibrate, estimate_squarings
        print("Measuring squaring speed on THIS machine...")
        rate = calibrate(seconds=1.5, modulus_bits=args.modulus_bits)
        print(f"  ≈ {rate:,} squarings/second ({args.modulus_bits}-bit modulus)")
        if args.days:
            t = estimate_squarings(args.days, rate)
            print(f"  for ≈ {args.days} day(s) at THIS rate: --squarings {t}")
        print()
        print("WARNING: this is a WORK floor, not a date. Faster hardware")
        print("solves it sooner; choose --squarings based on the adversary's")
        print("hardware, not yours. See KL-011.")
        return 0

    if args.custody_cmd == "timelock-setup":
        passphrase = _ask_passphrase()
        try:
            agent.add_timelock(passphrase, args.squarings,
                               modulus_bits=args.modulus_bits)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        print(f"✓ Time-lock configured: {args.squarings:,} sequential squarings "
              f"({args.modulus_bits}-bit modulus).")
        print("  ADDITIONAL recovery path: solving the puzzle opens the")
        print("  vault without a passphrase or custodians. WORK floor, not a date")
        print("  (KL-011). Rerunning replaces the puzzle.")
        return 0

    if args.custody_cmd == "timelock-remove":
        passphrase = _ask_passphrase()
        try:
            removed = agent.remove_timelock(passphrase)
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1
        print(" Time-lock removed." if removed else "No time-lock was configured.")
        return 0 if removed else 1

    if args.custody_cmd == "timelock-recover":
        info = agent._vault.timelock_info()
        if not info:
            print("ERROR: the vault has no time-lock slot.")
            return 1
        print(f"Solving the time-lock: {info['squarings']:,} sequential "
              f"squarings. This IS slow by design.")

        def _progress(done, total):
            print(f"  … {done:,}/{total:,} ({100*done//total}%)", flush=True)

        try:
            if args.set_passphrase:
                new = _ask_passphrase("New vault passphrase: ")
                confirm = _ask_passphrase("Confirm the new passphrase: ")
                if not _hmac.compare_digest(new, confirm) or not new:
                    print("ERROR: the passphrases do not match or are empty.")
                    return 1
                agent.set_passphrase_from_timelock(
                    new, actor=args.actor or "recovery", progress=_progress)
                print(" LEGACY RECOVERED; new passphrase set.")
            else:
                agent.recover_with_timelock(
                    actor=args.actor or "recovery", progress=_progress)
                print(" LEGACY RECOVERED (read-only for this session).")
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1

        summary = agent.summary(args.actor or "recovery")
        print(f"\nPropietario     : {summary['owner_id']}")
        print(f"Total artifacts : {summary['total_artifacts']}")
        return 0

    if args.custody_cmd == "recover":
        # Collect shares from explicit arguments, a file, or secure prompts.
        shares: list = list(args.share or [])
        if args.share:
            print("WARNING: passing shares with --share exposes them in the "
                  "process table and shell history.")
            print("         Prefer interactive entry (without --share) or "
                  "--shares-file.")
        if args.shares_file:
            p = Path(args.shares_file)
            if not p.is_file():
                print(f"ERROR: {p} does not exist.")
                return 1
            shares += [
                line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        if not shares:
            print("Enter custodian shares (one per line; empty line to finish):")
            while True:
                s = _ask_passphrase(f"  share #{len(shares) + 1}: ").strip()
                if not s:
                    break
                shares.append(s)
        if not shares:
            print("ERROR: no shares were entered.")
            return 1

        try:
            if args.set_passphrase:
                new = _ask_passphrase("New vault passphrase: ")
                confirm = _ask_passphrase("Confirm the new passphrase: ")
                if not _hmac.compare_digest(new, confirm) or not new:
                    print("ERROR: the passphrases do not match or are empty.")
                    return 1
                agent.set_passphrase_from_recovery(
                    shares, new, actor=args.actor or "recovery"
                )
                print(" LEGACY RECOVERED; new passphrase set.")
                print("  The vault now opens with the new passphrase.")
            else:
                agent.recover_with_shares(shares, actor=args.actor or "recovery")
                print(" LEGACY RECOVERED (read-only for this session).")
                print("  To set a new passphrase: "
                      "custody recover --set-passphrase")
        except Exception as exc:
            print(f"ERROR: {exc}")
            return 1

        summary = agent.summary(args.actor or "recovery")
        print()
        print(f"Owner           : {summary['owner_id']}")
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
    print(" Databases encrypted at rest (KL-001).")
    print(f"  memory.db    : {mem['migrated']} encrypted (already encrypted: {mem['skipped']})")
    print(f"  knowledge.db : {kb['migrated']} encrypted (already encrypted: {kb['skipped']})")
    print("  The key is stored inside the vault: open with the passphrase or")
    print("  custodian recovery. Without the vault, the databases are unreadable.")
    return 0


def cmd_rekey(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    agent = _get_agent(data_dir, args.owner_id)

    old = _ask_passphrase("CURRENT vault passphrase: ")
    new = _ask_passphrase("New passphrase: ")
    confirm = _ask_passphrase("Confirm the new passphrase: ")
    if not _hmac.compare_digest(new, confirm):
        print("ERROR: the new passphrases do not match.")
        return 1
    if not new:
        print("ERROR: the new passphrase cannot be empty.")
        return 1

    try:
        stats = agent.rekey(old, new)
    except Exception as exc:
        print(f"ERROR: {exc}")
        print("Nothing was changed if the current passphrase was incorrect.")
        print("If the error occurred during rotation, rerun")
        print("`legacy rekey` with the same passphrases to complete it.")
        return 1

    agent.lock(new)
    print(" Passphrase rotated (keyslot rewrapped; payload intact).")
    print(f"  Artifacts migrated to store key: {stats['converted']} "
          f"(already migrated: {stats['skipped']})")
    if agent._vault.has_recovery_slot():
        print("  Custody: distributed shares remain valid.")
    print()
    print("REMINDER: if you delivered the old passphrase in a sealed envelope,")
    print("replace it; the old passphrase no longer opens anything.")
    return 0


def cmd_bundle_verify(args: argparse.Namespace) -> int:
    from legacy.agent.export_bundle import check_manifest
    from legacy.core.audit_trail import AuditTrail

    bundle = Path(args.bundle_dir)
    if not bundle.is_dir():
        print(f"ERROR: {bundle} does not exist or is not a directory.")
        return 1

    _print_separator()
    print(f"BUNDLE VERIFICATION — {bundle}")
    _print_separator()

    ok = True
    problems = check_manifest(bundle)
    if problems:
        ok = False
        print(f"✗ manifest         {len(problems)} problem(s):")
        for p in problems:
            print(f"    - {p}")
    else:
        print("✓ manifest         all hashes match")

    audit_db = bundle / "audit.db"
    if audit_db.is_file():
        result = AuditTrail(db_path=audit_db, hmac_key=b"").verify(hmac_key=b"")
        if result.valid:
            print(f"✓ audit_chain      {result.length} events, intact chain "
                  f"(hash-only)")
        else:
            ok = False
            print(f"✗ audit_chain      invalid from seq={result.first_invalid_seq}")
    else:
        ok = False
        print(" audit_chain      audit.db missing")

    print()
    print("✓ BUNDLE INTACT" if ok else "✗ BUNDLE ALTERED — request a new copy")
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
    print("DOCTOR — LEGACY HEALTH")
    _print_separator()
    for c in report.checks:
        mark = "" if c.ok else ""
        print(f"{mark} {c.name:<18} {c.detail}")
    print()
    print("✓ ALL CHECKS PASSED" if report.ok
          else "✗ PROBLEMS FOUND — review the marked checks")
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

    print(f"✓ Heir registered: {args.heir_id}")
    if secret:
        _print_separator()
        print("HEIR SECRET KEY — shown ONCE ONLY:")
        print(f"\n    {secret}\n")
        print("Only its hash remains in the vault; if lost, generate another.")
        print("Deliver it through a secure channel (sealed envelope or notary).")
        print("The heir uses it with: legacy heir <id> --heir-key <key>")
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
    print("MEMORY FIELD CONSOLIDATION")
    _print_separator()
    print(f"Duplicates merged    : {report.duplicates_merged}")
    print(f"Synapses pruned      : {report.synapses_pruned}")
    print(f"Promoted (frequency) : {report.promoted_to_reinforced}")
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
            print(f"ERROR: {path} does not exist.")
            return 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"ERROR: {exc}")
            return 1
        entries = kb.extract_chunks(text, source_path=str(path))
        print(f"✓ Extracted {len(entries)} entr(y/ies) from {path.name}")
        for e in entries[:3]:
            print(f"  [{e.domain.value}] {e.title} ({e.confidence})")

    elif args.knowledge_cmd == "search":
        results = kb.search(args.query, top_k=args.top_k)
        _print_separator()
        print(f"KNOWLEDGE BASE — '{args.query}' ({len(results)} result(s))")
        _print_separator()
        for r in results:
            print(f"\n[{r.domain.value}] {r.title} ({r.confidence})")
            print(f"  {r.summary[:200]}")
            if r.source_path:
                print(f"  Source: {r.source_path}")

    elif args.knowledge_cmd == "stats":
        stats = kb.stats()
        print(f"Total entries: {stats['total']}")
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
    print("VAULT STATUS")
    _print_separator()
    print(f"Directory  : {data_dir}")
    print(f"Vault      : {' exists' if vault_path.exists() else ' does not exist'}")
    print(f"Audit trail: {' exists' if audit_path.exists() else ' does not exist'}")
    print(f"Memory     : {' exists' if memory_path.exists() else ' does not exist'}")
    print(f"Knowledge  : {' exists' if kb_path.exists() else ' does not exist'}")

    if audit_path.exists():
        import sqlite3 as _sq
        try:
            conn = _sq.connect(audit_path)
            count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            last = conn.execute(
                "SELECT timestamp, event_type FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            conn.close()
            print(f"\nAudit trail: {count} event(s)")
            if last:
                print(f"Latest event: [{last[1]}] {last[0]}")
        except Exception:
            pass
    return 0


# Argument parser.

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="legacy",
        description="Digital Legacy — Memory Agent for a digital legacy",
    )
    parser.add_argument(
        "--data-dir",
        default=str(_default_data_dir()),
        help=f"Data directory (default: {_default_data_dir()})",
    )
    parser.add_argument(
        "--owner-id",
        default=os.environ.get("LEGACY_OWNER_ID", "owner"),
        help="Owner identifier",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize a new vault")
    p_init.add_argument("--inactivity-days", type=int,
                        help="Activate after N days of inactivity")
    p_init.add_argument("--unlock-date",
                        help="Activate on an ISO 8601 date (e.g. 2030-01-01T00:00:00+00:00)")
    p_init.add_argument("--manual", action="store_true",
                        help="Manual activation (for testing)")

    p_ingest = sub.add_parser("ingest", help="Ingest file(s)")
    p_ingest.add_argument("path", help="File or directory")
    p_ingest.add_argument("--tags", help="Comma-separated tags")
    p_ingest.add_argument("--notes", help="Notes about the artifact")
    p_ingest.add_argument("--extensions", help="Extensions to process (e.g. .pdf,.txt)")
    p_ingest.add_argument("--no-recursive", action="store_true",
                          help="Do not process subdirectories")
    p_ingest.add_argument("--knowledge", action="store_true",
                          help="Also extract into the knowledge database")

    p_query = sub.add_parser("query", help="Query the legacy")
    p_query.add_argument("question", help="Question in natural language")
    p_query.add_argument("--top-k", type=int, default=8,
                         help="Maximum results (default: 8)")

    sub.add_parser("summary", help="Summarize the legacy")

    p_heir = sub.add_parser("heir", help="Access as an heir")
    p_heir.add_argument("heir_id", help="Heir ID")
    p_heir.add_argument("--heir-key", help="Heir secret key")
    p_heir.add_argument("--query", help="Query immediately after access")

    p_guide = sub.add_parser("guide", help="Generate the heir guide (markdown)")
    p_guide.add_argument("--output", help="Output file (default: stdout)")

    p_arch = sub.add_parser("archive", help="Store an encrypted copy of a file")
    p_arch.add_argument("path", help="File to archive")

    p_rest = sub.add_parser("restore", help="Restore an archived artifact")
    p_rest.add_argument("hash", help="Artifact hash or unique prefix")
    p_rest.add_argument("--output", required=True, help="Destination path")

    p_exp = sub.add_parser("export",
                           help="Export a portable bundle for heirs")
    p_exp.add_argument("dest", help="Destination directory (new or empty)")

    p_hrev = sub.add_parser("heir-revoke", help="Revoke an heir")
    p_hrev.add_argument("heir_id", help="Heir identifier to revoke")

    p_cust = sub.add_parser(
        "custody",
        help="Recovery by custodian threshold (Shamir)",
    )
    cust_sub = p_cust.add_subparsers(dest="custody_cmd", required=True)
    p_cs = cust_sub.add_parser("setup", help="Distribute the recovery key")
    p_cs.add_argument("--shares", type=int, required=True,
                      help="Number of custodians (N)")
    p_cs.add_argument("--threshold", type=int, required=True,
                      help="Shares required for recovery (K)")
    p_cr = cust_sub.add_parser(
        "recover",
        help="Recover the legacy with K shares (interactive by default)",
    )
    p_cr.add_argument("--share", action="append",
                      help="Share argument (UNSAFE: visible in `ps` and shell "
                           "history; prefer interactive entry)")
    p_cr.add_argument("--shares-file",
                      help="File with one share per line (for automation)")
    p_cr.add_argument("--set-passphrase", action="store_true",
                      help="Set a new passphrase after recovery")
    p_cr.add_argument("--actor", help="Recovery actor (for the audit trail)")
    cust_sub.add_parser("status", help="Custody status (without a passphrase)")
    cust_sub.add_parser("remove", help="Remove custody (invalidates shares)")

    p_cal = cust_sub.add_parser(
        "calibrate", help="Measure squarings/sec and suggest --squarings")
    p_cal.add_argument("--days", type=float, help="Convert N days to --squarings")
    p_cal.add_argument("--modulus-bits", type=int, default=2048)
    p_tls = cust_sub.add_parser(
        "timelock-setup", help="Add a recovery path through a time-lock puzzle")
    p_tls.add_argument("--squarings", type=int, required=True,
                       help="Sequential squarings (work floor; see calibrate)")
    p_tls.add_argument("--modulus-bits", type=int, default=2048)
    p_tlr = cust_sub.add_parser(
        "timelock-recover", help="Recover by solving the puzzle (slow by design)")
    p_tlr.add_argument("--set-passphrase", action="store_true",
                       help="Set a new passphrase after recovery")
    p_tlr.add_argument("--actor", help="Recovery actor (for the audit trail)")
    cust_sub.add_parser("timelock-remove", help="Remove the time-lock slot")

    sub.add_parser("encrypt-db",
                   help="Encrypt memory.db at rest (KL-001)")

    sub.add_parser("rekey", help="Rotate the vault and artifact passphrases")

    p_bv = sub.add_parser("bundle-verify",
                          help="Verify the integrity of an exported bundle")
    p_bv.add_argument("bundle_dir", help="Bundle directory")

    sub.add_parser("doctor", help="Comprehensive legacy health check")

    p_hadd = sub.add_parser("heir-add", help="Register an heir")
    p_hadd.add_argument("heir_id", help="Heir identifier")
    p_hadd.add_argument("--name", help="Display name")
    p_hadd.add_argument("--email", help="Contact email")
    p_hadd.add_argument("--with-key", action="store_true",
                        help="Generate a secret key and add HeirKeyCondition")

    p_cons = sub.add_parser("consolidate",
                            help="Consolidate memory (deduplication, pruning, decay)")
    p_cons.add_argument("--forget-after-days", type=float, default=90.0,
                        help="Days without access before FORGOTTEN (default: 90)")

    sub.add_parser("verify", help="Verify the audit trail")

    sub.add_parser("heartbeat", help="Record owner activity")

    p_kn = sub.add_parser("knowledge", help="Professional knowledge database")
    kn_sub = p_kn.add_subparsers(dest="knowledge_cmd", required=True)
    p_kn_add = kn_sub.add_parser("add", help="Add a document")
    p_kn_add.add_argument("file", help="Text or Markdown file")
    p_kn_search = kn_sub.add_parser("search", help="Search the knowledge base")
    p_kn_search.add_argument("query")
    p_kn_search.add_argument("--top-k", type=int, default=5)
    kn_sub.add_parser("stats", help="Knowledge database statistics")

    sub.add_parser("status", help="Vault and data-file status")

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

    # Commands that modify state are protected by the agent lock.
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
