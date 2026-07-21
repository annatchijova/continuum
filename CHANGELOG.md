# Changelog — Continuum

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning follows
semantic versioning. This is the translated product history of the prototype;
security audit reports are intentionally not copied into Continuum.

## [Unreleased]

### Fixed

- Memory field retrieval scored plain term frequency with no inverse-document-
  frequency weighting, and its vocabulary cap discarded rare, distinctive
  terms (names, codewords, identifiers) in favor of common ones — the
  opposite of what a search index needs. `recall()` also trusted a memory's
  cached embedding whenever its length matched, which stayed true even after
  IDF made that embedding stale. All three compounded, found and fixed
  together; see [`RETRIEVAL_FIX_2026-07-19.md`](RETRIEVAL_FIX_2026-07-19.md).

## [0.7.0] — 2026-07-08

### Added

- Offline RSW96/LCS35 time-lock puzzles. `create_puzzle` wraps a secret so
  recovery requires `T` sequential modular squarings (`x → x² mod M`). Setup
  is fast through φ(M); solving is deliberately slow. Calibration measures
  squarings per second. Miller–Rabin is implemented without new dependencies.
- A `timelock` keyslot in vault v2, independent from passphrase and recovery
  slots and preserved by `rekey`.
- Agent and CLI operations for time-lock setup, recovery, and passphrase reset,
  with audit events `TIMELOCK_CONFIGURED`, `VAULT_RECOVERED_TIMELOCK`, and
  `PASSPHRASE_RESET_BY_TIMELOCK`.

### Documentation

KL-011 distinguishes the implemented sequential work floor from the future
wall-clock design. A wall-clock guarantee would require a network beacon,
timestamp authority, or trusted hardware, and would change the trust boundary.

### Tests

397 → 426 tests, including puzzle round trips, real sequential work,
fail-closed behavior, bounds, vault integration, slot independence,
`rekey` survival, and heir takeover.

## [0.6.1] — 2026-07-08

### Fixed

- A legacy `knowledge.db` could retain a live FTS5 shadow index containing
  plaintext content terms after `encrypt-db`. Encryption migration now drops
  `knowledge_fts` and its shadow tables before vacuuming. New databases never
  create the index.

### Tests

395 → 397 tests, including regression coverage for the migration path.

## [0.6.0] — 2026-07-08

### Added

- Encrypted `KnowledgeBase`: `title`, `content`, `summary`, `keywords_json`,
  and `source_path` use AES-256-GCM with the vault's `db_key`. Low-sensitivity
  metadata and `content_hash` remain plaintext for filtering and deduplication.
- `encrypt-db` now encrypts both databases, and the doctor reports both states.

### Changed

- Knowledge search now scans decrypted rows in memory and scores term overlap.
  Removing FTS5 is required to avoid an unencrypted content index; this makes
  search O(n), which is suitable for a personal legacy.
- `encrypt_database` returns `{"memory": {...}, "knowledge": {...}}`.

### Tests

384 → 395 tests, covering disk opacity, wrong-key failures, deduplication,
plaintext scrubbing, and recovery after heir access and `rekey`.

## [0.5.2] — 2026-07-07

### Changed

- `custody recover` is interactive by default. Shares are entered with
  `getpass`, without echo and outside process arguments. The explicit share
  option remains available for scripting but warns about exposure in `ps` and
  shell history.

### Added

- Composition tests covering encrypted memory access after recovery, policy
  access, `db_key` survival across `rekey`, idempotent migration, and
  crash-atomic migration. Mutation checks confirm the tests exercise the
  actual key wiring.

### Tests

378 → 384 tests.

## [0.5.1] — 2026-07-07

### Fixed

- Plaintext beginning with the ciphertext marker could be mistaken for already
  encrypted data and remain unencrypted. A `gcmf0:` escape form resolves the
  collision; field encryption now always encrypts, while callers determine
  migration idempotence with `is_encrypted()`.

### Tests

368 → 378 tests, including marker collisions, row movement, tamper detection,
and encrypted-database recovery cases.

## [0.5.0] — 2026-07-07

### Added

- Application-level AES-256-GCM field encryption for `memory.db`, with versioned
  values, row/column-bound AAD, transparent plaintext/ciphertext migration, and
  intact SQLite WAL behavior.
- Encrypted `content`, `embedding_json`, and `tags_json` in `MemoryField`.
  Migration is repeatable and scrubs residual plaintext using `VACUUM` and a
  WAL checkpoint.
- `LegacyAgent.encrypt_database` and `legacy encrypt-db`; the key is sealed in
  the vault before the first row is migrated and survives `rekey` and custody
  recovery.
- Doctor reporting for plaintext, encrypted, and incoherent mixed states.

### Fixed

- Memory-integrity verification and consolidation now decrypt before hashing or
  tokenizing. Without a key, encrypted memory is opaque and is not merged.

### Scope

`knowledge.db` was not encrypted yet because FTS5 exposed plaintext tokens.
That design limitation was resolved in 0.6.0 by removing FTS5.

### Tests

344 → 368 tests.

## [0.4.0] — 2026-07-07

### Fixed

- Vault sealing is fail-closed when a supplied passphrase does not match a
  readable envelope. Overwriting is allowed only for missing or unreadable
  envelopes, enabling disaster recovery without silently destroying custody.

### Added

- Continuous integration on Python 3.11 and 3.12.
- An installable `legacy` CLI and compatibility shim.

## [0.3.0] — 2026-07-07

### Added

- Shamir Secret Sharing over GF(2⁸), with one-line shares, verification digests,
  tamper detection, and a minimum threshold of two.
- Vault v2 with independent passphrase and recovery keyslots.
- Custody setup, recovery, status, and removal flows.
- ArtifactStore v2 with a random store key inside the vault; v1 artifacts remain
  readable and can be converted repeatably.
- Doctor checks for custody, vault version, keyslots, and artifact coherence.

### Changed

- `rekey` now persists the store key, converts artifacts, and rewraps the
  passphrase slot. Custodian shares remain valid after rotation.
- Artifact restoration and bundle verification resolve the secret from the
  artifact envelope, so v2 artifacts do not require the passphrase.

### Tests

279 → 337+ tests, including exhaustive field arithmetic, custody properties,
keyslot migration, artifact conversion, end-to-end inheritance, and crash
recovery during `rekey`.

## [0.2.0] — 2026-07-07

### Fixed

- Packaging metadata, canonical NFC verification, heartbeat persistence,
  keyword-boundary matching, chunk overlap progress, and a leaked SQLite
  connection.

### Added

- Encrypted content-addressed artifact storage and `archive`/`restore`.
- Cooperative `AgentLock` with stale-lock detection.
- Deterministic prioritized Heir Guide and comprehensive Doctor checks.
- Heir management, audited consolidation, portable export bundles, passphrase
  rotation, and knowledge extraction during ingestion.
- Initial README, changelog, and limitation documentation.

### Tests

203 → 279 tests.

## [0.1.0] — 2026-07-06

Initial release: AES-256-GCM vault, dual SHA-256/HMAC audit
chain, deterministic classifier, TF-IDF + STDP memory field, FTS5 knowledge
base, query engine, CLI, and standalone verifier.
