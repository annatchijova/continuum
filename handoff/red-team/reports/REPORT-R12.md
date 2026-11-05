# Red-team round R12: the filesystem boundary (C13-C16)

Branch: `main`, continuing from `claude/red-team-r12` after PR #1
(`claude/peaceful-gauss-09l0j9`, R8-R11) merged.

Full suite: 604 passed (597 at R11 + 7 new R12 tests).

## Method

Same as R8-R11 (see `HANDOFF.md` section 2): hypothesis with a falsifier,
reproduce against the real code, variant sweep, failing regression test
before the fix, negative controls, fix minimally, full suite, write up.

## R12-001 (Medium, hardening): `ArtifactStore._path_for` traversal via a
crafted id

**Target:** `legacy/vault/artifact_store.py` — this is candidate C14 from
the handoff ("is the hash in a path or the CLI argument validated?"),
examined before C13 because `_path_for` is the single choke point every
other method in the class depends on, including `restore()` (C13).

- **Abduction:** `_path_for` builds `store_dir / artifact_hash[:2] /
  f"{artifact_hash}.enc"` with no check that `artifact_hash` is the 64-hex
  SHA-256 digest it is documented to be. `Path.__truediv__` splits any `/`
  in its argument into path components, so an id containing `..` segments
  could resolve outside `store_dir`.
- **Deduction:** if true, calling `_write_envelope` (or any method that
  calls `_path_for`) with an id such as `"..s/../outside_target"` should
  create a file at `store_dir/../outside_target.enc`, i.e. one level above
  the store directory, and existing files there should be readable through
  `get()`/`exists()` with the same crafted id.
- **Induction — confirmed:**
  ```python
  store = ArtifactStore(store_dir)
  store._write_envelope("..s/../outside_target", b"ESCAPED WRITE", secret)
  # -> file written at store_dir/../outside_target.enc, outside store_dir
  ```
  Reproduced with the unmodified class (before this round's fix) in a throwaway
  tmp directory; a pre-existing file one level above the store directory was
  left untouched by the write (different filename), proving the path really
  resolves outside the store, not just that the string looks suspicious.
  PoC: `poc/r12/poc_r12_001.py`.
- **Causal chain:**
  ```
  artifact_hash supplied to any ArtifactStore method
      -> _path_for() joins store_dir / artifact_hash[:2] / f"{artifact_hash}.enc"
      -> no validation that artifact_hash is a 64-hex digest
      -> ".." segments in artifact_hash escape store_dir
      -> _write_envelope / get / restore / exists / envelope_version
         all operate on a path outside the store
  ```
- **Threat model this is confirmed under:** an attacker who can choose the
  `artifact_hash` string passed into `ArtifactStore`. **This precondition is
  not reachable today.** Every current caller passes an id that already came
  from `list_hashes()` (a disk enumeration of real `*.enc` files) or from
  `hashlib.sha256(data).hexdigest()` computed in-process:
  - `cmd_restore` in `legacy/cli.py` matches `args.hash` as a *prefix* against
    `list_hashes()`, then passes the matched (real, on-disk) id to
    `restore_artifact`.
  - `rekey`, `convert_to_key`, `export_bundle` all iterate `list_hashes()`.
  - `continuum_web/server.py` does not expose any route that reaches
    `ArtifactStore` with caller-supplied input.
  So this is **bucket: hygiene / defense-in-depth** (Part 2 of the
  methodology), not a vulnerability reachable in the shipped product today.
  It is fixed anyway because `_path_for` is a shared, load-bearing choke
  point: the next caller that trusts an external id (a Studio API route, a
  heir-facing restore feature) would otherwise inherit a real path-traversal
  primitive silently.
- **Fix:** `_path_for` now validates `artifact_hash` against
  `^[0-9a-f]{64}$` before building a path from it, raising
  `VaultNotFoundError` otherwise. Every other method (`get`, `restore`,
  `exists`, `envelope_version`, `verify`, `_write_envelope`) calls
  `_path_for` and inherits the check for free; no other file changed.
- **Controls:** `tests/test_security_r12.py` — four crafted ids rejected
  through every public method; a negative control proving the escaped file
  is never created; a positive control that a real content-addressed id
  still round-trips through `put_bytes`/`get`/`verify`/`envelope_version`;
  uppercase, truncated, and extended hex are also rejected (the format must
  be exact, not merely "looks like hex").

## C13 (destination path for `restore()`): closed without change

**Hypothesis:** `restore()`'s `dest` is caller-chosen; a pre-existing
symlink at `dest` could redirect the atomic `tmp.replace(dest)` write to an
attacker-chosen file outside the intended destination.

**Falsifier attempted:** created a symlink at `dest` pointing to an unrelated
file with known content, then ran the same `write-tmp, then .replace(dest)`
sequence `restore()` uses.

**Result — falsified.** `Path.replace()` (POSIX `rename()`) replaces the
directory entry atomically; it does not dereference a symlink at the
destination. The symlink itself is replaced by the new regular file; the
file the symlink pointed to is untouched. Reproduced directly:

```python
dest.symlink_to(outside_secret)
tmpfile.replace(dest)
# outside_secret content is unchanged; dest is now a regular file, not a symlink
```

Separately, in every real call site `dest` is chosen by the same local
operator who already holds the vault passphrase and is running the CLI with
their own filesystem privileges (`cmd_restore` takes `args.output` directly;
there is no heir- or network-reachable path to `restore()`). Even if the
symlink-replace behavior had gone the other way, there is no privilege
boundary for a `dest`-based attack to cross. Closed without change, same
pattern as C9/C3/C4/C5 in R10/R11.

## C15 (export bundle path injection via a crafted record): closed without
change

**Hypothesis:** a record title or filename could inject `../` into a
filename inside the heir export bundle (`export_bundle.py`), letting a
crafted record overwrite a file outside the bundle directory when the heir
extracts or reads it.

**Falsified by code reading**, no execution needed: `export_bundle()` never
derives a filename from record content. Artifact filenames inside the
bundle are exactly `artifacts/<hash[:2]>/<hash>.enc`, where `hash` is always
a value from `agent._store.list_hashes()` (a real, disk-enumerated,
already-valid id — and, after R12-001, additionally re-validated by
`_path_for` on every access). The only other bundle files are fixed names
(`HEIR_GUIDE.md`, `README.txt`, `audit.db`, `verify_legacy.py`,
`MANIFEST.json`). No record-controlled string ever becomes a path segment.

## C16 (`legacy/cli.py`, full review): not done this round

Out of scope for R12's time budget (1122 lines, never reviewed end to end,
per the handoff). What was checked opportunistically while tracing C13:
`_ask_passphrase` uses `getpass.getpass` (no echo, not in argv) for every
vault/heir passphrase prompt. `--heir-key` is still accepted as a CLI
argument (visible in `ps`/shell history), which is the heir's *key*, not
the owner passphrase, and is the documented scripting trade-off already
noted for `custody recover` in CHANGELOG 0.5.2 — not a new finding.
A spot check of artifact file permissions found mode `0o664` (group- and
world-readable) on `.enc` files; content is AES-256-GCM encrypted, so this
is a minor hygiene note (tighter would be `0o600`), not a disclosure path.
Neither is written up as a numbered finding; C16 remains open for a future
round that budgets time for the full file.

## Closed without change (this round)

| ID | Why |
|----|-----|
| C13 | `Path.replace()` does not follow a symlink at the destination; falsified by direct reproduction. No privilege boundary crosses `dest` regardless. |
| C15 | No record-derived string ever becomes a bundle path segment; falsified by code reading, filenames are fixed or hash-derived. |

## Next candidates

| ID | Hypothesis |
|----|------------|
| C16 | Full review of `legacy/cli.py` (1122 lines): argv/env exposure of secrets beyond the passphrase, created-file permissions across every command (not just artifacts), paths taken unsanitized from CLI arguments elsewhere. |
| C17 | Artifact envelope and vault file permissions are not deliberately set (observed `0o664` from default umask, not an explicit `chmod`). Check every file `legacy/` creates (`vault.json`, `memory.db`, `audit.db`, `.enc` artifacts) for a consistent, deliberate permission policy instead of relying on umask. |
