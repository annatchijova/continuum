# Known Limitations — Continuum

These are confirmed design limitations, not bugs. Each is an explicit choice
with documented consequences and an ID that can be referenced from code or an
external review.

## KL-001 — Database encryption at rest

**Area:** Cryptography / trust boundary  
**Risk:** MEDIUM → LOW when `encrypt-db` is enabled

The vault protects the artifact index, while memory and professional knowledge
live in separate databases. `legacy encrypt-db` encrypts sensitive fields with
AES-256-GCM and stores the 32-byte `db_key` inside the vault. Nonces and
row/column AAD prevent ciphertext from being moved between records. Migration
is repeatable, crash-safe, and scrubs residual plaintext from database pages and
WAL files.

`content_hash` and operational metadata remain visible by design. A hash can
confirm guessed content but cannot decrypt it; categories, counters,
timestamps, and synaptic links reveal structure and activity.

Since 0.6.0, `knowledge.db` is encrypted too. FTS5 was removed because its
shadow tables exposed plaintext terms. Search decrypts rows in memory and is
O(n), appropriate for hundreds or thousands of personal entries but not for
massive-scale data. Filesystem encryption (LUKS or equivalent) remains the
recommendation for complete at-rest coverage.

## KL-002 — Raw artifacts are not stored in the vault

**Area:** System scope  
**Risk:** INFO

The vault is a navigation index, not a raw-file backup. A deleted or lost
original cannot be recovered from its hash. `legacy archive` provides an
opt-in, AES-256-GCM, content-addressed encrypted copy, and `legacy restore`
verifies both the authentication tag and SHA-256 identifier. It is not an
automatic backup.

## KL-003 — STDP makes retrieval stateful

**Area:** Memory  
**Risk:** INFO

`recall()` updates access counters and synaptic weights. Identical consecutive
queries have stable ordering but different scores. This is intentional for the
Hebbian learning model; bit-for-bit read immutability would contradict the
design.

## KL-004 — Semantic contradictions are not detected

**Area:** Semantic integrity  
**Risk:** INFO

Contradictory documents, such as two wills or contract versions, are stored and
retrieved without a conflict signal. Pairwise comparison is expensive and
domain reasoning would produce false positives. The system is a faithful
archive, not a legal or semantic arbiter.

## KL-005 — There is no entity resolution

**Area:** Semantics / retrieval  
**Risk:** INFO

Names such as “Juan Pérez”, “Juan A. Pérez”, and “J. Pérez” are distinct
tokenizations. TF-IDF is a bag-of-words model; it provides no NER or
co-reference resolution.

## KL-006 — The audit chain verifies cryptographic, not semantic, integrity

**Area:** Audit trail  
**Risk:** LOW

`verify_chain()` detects inserted, deleted, or modified events through the hash
chain and optional HMAC. It does not decide whether event order makes business
sense: `ARTIFACT_READ` before `VAULT_CREATED` can still be cryptographically
valid. Semantic validation belongs to a domain-aware auditor or integration
tests.

## KL-007 — The vault is single-process by design

**Area:** Concurrency  
**Risk:** HIGH if bypassed

The vault is designed for one owner and one active process. The CLI uses the
cooperative `AgentLock` to reject concurrent writes and detect stale locks.
Direct API users must wrap operations in `with AgentLock(data_dir): ...`.
SQLite memory and audit databases support concurrent access through WAL and
exclusive transactions; the vault itself does not.

## KL-007b — Ghost memories are not visible before verification

`verify_memory_integrity()` can find memories in `memory.db` that lack a vault
artifact, but only after the vault is opened and verification is requested.
Running it during every owner open would increase startup time for large
legacies, so it is not the default.

## KL-008 — Memory storage and audit append are not atomic together

**Area:** Transactional consistency  
**Risk:** LOW

`ingest()` writes to `memory.db` and then to `audit.db` as separate operations.
A crash between them can leave memory without an audit event (or, less likely,
an audit event without memory). SQLite does not provide transactions across
multiple database files; a shared WAL or intent log would add disproportionate
complexity. Full integrity checks should run both memory and audit verification.

## KL-008b — A valid audit trail can coexist with corrupted memory

**Area:** Module composition  
**Risk:** MEDIUM

`verify_audit()` and `verify_memory_integrity()` are independent. Modifying
`memory.db` does not break the hash chain in `audit.db`. Including a complete
database hash or Merkle tree in every audit event would turn an event log into a
state log and make it prohibitively slow. Run both checks together.

## KL-009 — HMAC is optional

**Area:** Cryptography  
**Risk:** MEDIUM

Without `LEGACY_HMAC_KEY`, the public SHA-256 genesis allows an attacker with
write access to rewrite the entire chain and have verification accept it. With
HMAC configured, rewriting requires the secret key. Without HMAC, the trail is
accident detection, not adversary resistance.

## KL-010 — Memory score does not affect recall ranking

**Area:** Internal design  
**Risk:** INFO

`score` is increased by `reinforce()` and is intended to represent accumulated
importance, but `recall()` currently ranks by cosine TF-IDF, state multiplier,
and recency bonus. It is bounded to prevent overflow and reserved for future
explicit integration.

## KL-011 — AccessPolicy is not a cryptographic boundary

**Area:** Custody model / access control  
**Risk:** MEDIUM, depending on the custody model

`open_heir()` decrypts the vault with the passphrase before evaluating policy.
The policy controls the agent's logical unlocked state; anyone who already has
the passphrase can call the owner path or read the decrypted envelope. Inactivity
and date conditions are cooperative process barriers, not cryptographic
time-locks.

The recommended model delivers the passphrase only when the event occurs, for
example through a sealed-notary instruction or dead-man's-switch service. The
policy remains defense in depth and records `CONDITION_CHECK` events.

### Implemented custody mitigations

Shamir K-of-N custody (`legacy custody setup`) puts a recovery key in independent
keyslots. Without K shares the key is not on disk and cannot be derived; K-1
colluding custodians learn nothing. `rekey` preserves shares, while rerunning
custody setup revokes the previous set. Archived artifacts are recoverable
through the vault's store key.

The optional offline time-lock keyslot requires N sequential modular squarings.
It provides a cryptographic **work floor**, not a wall-clock date. The actual
time depends on the solver's hardware, so N must be selected against the
adversary's expected hardware.

### Future wall-clock designs

A true date-bound release requires an external temporal root of trust. Options
include a public randomness beacon such as drand (network dependency), an RFC
3161 timestamp authority (third-party trust), or a TEE/HSM monotonic clock
(hardware and supply-chain dependency). None is a configuration switch: each
moves the trust boundary away from an offline, self-contained system.

The current recovery paths—owner passphrase, Shamir K-of-N custody, and offline
time-lock puzzle—are independent vault v2 keyslots and all survive `rekey`.

---

*Continuum known limitations — translated from Digital Legacy, 2026-07-08*
