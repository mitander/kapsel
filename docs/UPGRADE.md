# Upgrade, backup, rollback, and downgrade

Status: active v0.2 beta operator contract.

Kind: guide and compatibility contract. Authority: the supported `v0.1.1` to v0.2 private-journal
upgrade, backup, restore, rollback, and downgrade procedure.

Owns: Required offline backup names and integrity, first-open recognition, failure handling, restore
cleanup, and the exact `v0.1.1` downgrade decision.

Does not own: Internal SQL or fixture construction, another release pair, release installation, or
Kubernetes lifecycle and receipt meaning.

See [Evaluator commands](COMMANDS.md) for the unchanged command grammar, [MCP](MCP.md) for EOF
shutdown, and [Build](BUILD.md#upgrade-and-rollback-fixture-gate) for the focused source-fixture
gate.

## Supported path

This procedure supports an owner-private journal last opened by exact Kapsel `v0.1.1` and the
published v0.2.0 binary on x86-64 GNU/Linux. The operation schema is identical between those
versions, so the upgrade does not transform operation rows or receipt facts. The v0.2 opener records
one private format marker after recognizing the store. It does not add a command or change the
adopted `provision-grant`, `operate`, `inspect`, or `mcp` grammar.

The marker changes database bytes, so an existing unmarked store requires a verified backup even
though its operation rows need no migration. The active database and exact backup must each be no
larger than 64 MiB. A rollback-journal artifact may be at most 65 MiB for bounded SQLite framing;
larger artifacts refuse before SQLite recovery. A newly created empty journal initializes directly.

## Before the first v0.2 open

Finish or stop every Kapsel CLI and MCP process that uses the journal, and prevent a supervisor from
restarting one. There must be no open SQLite connection, provider work, receipt publication, or
backup writer. The journal's immediate parent must remain an owner-owned mode-0700 real directory;
this private-parent boundary prevents another OS user from replacing its entries. Kapsel detects a
simple pathname replacement but does not claim defense against a malicious same-owner ABA sequence.

Run the following fail-fast block with GNU coreutils while Kapsel remains stopped. Replace only the
first path. Before running it, require `test "$(stat -c %s -- "$journal")" -le 67108864`. The block
requires exact owner, mode, link-count, sidecar, and digest syntax and creates both artifacts
without following or clobbering an existing or dangling-symlink name.

```bash
set -eu
set -C
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
backup="${journal}.kapsel-v011.backup"
checksum="${backup}.sha256"
owner=$(id -u)

require_private_file() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = "regular file"
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 600
  test "$(stat -c %h -- "$1")" = 1
}
require_private_directory() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = directory
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 700
}
digest_of() {
  value=$(sha256sum -- "$1")
  value=${value%% *}
  test "${#value}" -eq 64
  case "$value" in *[!0-9a-f]*) return 1 ;; esac
  printf '%s' "$value"
}

require_private_directory "$parent"
require_private_file "$journal"
for sidecar in "${journal}-journal" "${journal}-wal" "${journal}-shm"; do
  test ! -e "$sidecar" && test ! -L "$sidecar"
done
test ! -e "$backup" && test ! -L "$backup"
test ! -e "$checksum" && test ! -L "$checksum"

umask 077
: >"$backup"
chmod 600 "$backup"
cp --reflink=never -- "$journal" "$backup"
require_private_file "$backup"
source_digest=$(digest_of "$journal")
backup_digest=$(digest_of "$backup")
test "$source_digest" = "$backup_digest"

: >"$checksum"
printf '%s\n' "$backup_digest" >|"$checksum"
chmod 600 "$checksum"
require_private_file "$checksum"
test "$(wc -c <"$checksum")" -eq 65
IFS= read -r recorded_digest <"$checksum"
test "$recorded_digest" = "$backup_digest"
sync "$backup" "$checksum"
sync -f "$parent"
```

Do not hard-link any artifact. Keep the backup, sidecar, active journal, worker lock, and receipt
directory owner-private. Receipt files are not copied or moved by this journal procedure; their
absolute paths and exact bytes remain authoritative.

## Migration-only first open and reopen

Do not use `operate` for either initial open: it can submit or reconcile an operation immediately.
Instead, close MCP stdin without sending an initialization or tool frame. MCP constructs the
application before reading stdin and then exits successfully on clean EOF, so these commands cross
journal open without lifecycle work:

```bash
set -eu
kapsel=/absolute/path/to/v0.2/kapsel
operator_config=/absolute/path/to/operator.json
"$kapsel" mcp --operator-config "$operator_config" </dev/null
"$kapsel" mcp --operator-config "$operator_config" </dev/null
```

Both invocations must exit zero, produce no stdout, and emit no diagnostic. Only after both succeed
may the operator resume the ordinary documented `operate` command or an initialized MCP tool call.
Keep the backup and sidecar through the rollback window.

Before its marker transaction, the opener rejects WAL or another unsupported database mode without
checkpointing it, configures and verifies rollback-journal `DELETE` plus `synchronous=FULL`,
verifies an unmarked source and backup, takes exclusive SQLite ownership, rechecks the source
digest, runs the full structural integrity check, and recognizes the complete owned layout.
Recognition includes the normalized owned table definition, every ordinary/hidden column fact, the
exact implicit primary-key index, and absence of another table, view, trigger, or index. The marker
and any pre-existing private legacy maintenance then commit in one transaction. Exact `v0.1.1` rows
require no data migration.

If this candidate is terminated inside that transaction, SQLite may leave either a hot rollback
journal or a validated zero-header non-hot residual beside the active database. The next candidate
open accepts only that same owner-private, singly linked artifact. SQLite recovers a hot journal; if
the same validated journal remains with a cleared header, Kapsel removes only that non-hot residual
and synchronizes the parent before rechecking the source and verified backup. WAL, shared-memory,
replaced, linked, permissive, malformed, and still-hot residual artifacts remain bounded refusals
rather than speculative cleanup.

The source-fixture gate kills a real candidate test process for every one of the nine
provenance-bound `v0.1.1` states before the exclusive transaction, after the marker is set inside
the uncommitted transaction, and after marker commit. Only under the selected compile-time test
seam, a private probe table and bounded pages force a hot rollback journal without changing an
operation row. Because SQLite may keep its marker page pinned before commit, a controlled
`cfg(test)`-only direct marker-page write materializes marker 2 solely to exercise the recovery
branch; it does not claim that production SQLite naturally spills that page. Before kill, the parent
reads the database header and journal bytes directly and requires marker 2 plus a nonzero
rollback-journal header. A second real candidate pauses after ordinary recovery but before
re-marking; the parent then requires marker 0, the exact old schema and complete row, no probe
table, and no rollback journal. Normal re-mark and another reopen follow. The assertions also
compare expected state, provider-call-count file, backup path/bytes/digest/inode/owner/mode/link
identity, and frozen receipt bytes, path, digest, key ID, publication fact, and complete retained-v2
inspection report. The two `apply_started` fixtures retain zero and one provider calls respectively;
migration open has no provider adapter and cannot issue a mutation.

Normal and process-loss fixture opens preserve every lifecycle state, authorization and receiver
fact, provider-call-count fact, receipt byte, absolute path, digest, signing-key identity, and
retained receipt-v2 inspection meaning. Upgrade does not call Kubernetes or re-sign a receipt.

## Bounded failures

CLI and MCP retain their bounded configuration or operation failure classes; they do not print SQL,
database contents, receipt bytes, signing material, or new path details. If the migration-only MCP
command fails, stop and use these offline checks rather than `operate`:

- **Missing, permissive, symlinked, multiply linked, malformed, or mismatched artifact:** preserve
  the active source. Remove only the rejected backup pair you created, then repeat the stopped,
  fail-fast backup block from the unchanged source.
- **Source changed after backup:** stop the writer, remove the rejected backup pair, and repeat the
  complete offline procedure. Do not keep retrying the opener.
- **SQLite sidecar or WAL/unsupported mode:** do not delete or checkpoint it speculatively. Let the
  exact binary that created the state recover it, stop that binary cleanly, and begin again.
- **Integrity or exact-layout refusal:** preserve the journal, backup, digest, receipts, and worker
  lock. Do not edit database or receipt bytes.
- **Unknown or newer marker:** the candidate refuses before SQLite mutation. Use the matching newer
  binary or a backup proven to belong to this journal generation; never reset the marker.

A failed open does not authorize Kubernetes work, another mutation, receipt reconstruction, or
receipt movement.

## Restore and failed-upgrade rollback

Restore is supported only when the first v0.2 open failed and no later lifecycle work occurred. If
v0.2 advanced an operation or published a receipt, do not restore an older generation: use the
direct downgrade below or continue with v0.2.

Stop Kapsel and supervisor restarts. Require the active database and backup to be at most 64 MiB.
Require all three SQLite sidecars to be absent; if one exists, recover and stop the exact creating
binary rather than deleting it. The following fail-fast block revalidates the backup pair, prepares
and verifies a distinct replacement, copies and synchronizes the still-active generation into a new
quarantine, and finally atomically renames the prepared file over the still-present active journal.
There is no missing-active-path window.

```bash
set -eu
set -C
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
backup="${journal}.kapsel-v011.backup"
checksum="${backup}.sha256"
restore="${journal}.restore.$$"
quarantine="${journal}.quarantine.$(date +%s).$$"
quarantined="$quarantine/journal.sqlite3"
quarantined_checksum="$quarantine/journal.sqlite3.sha256"
owner=$(id -u)

require_private_file() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = "regular file"
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 600
  test "$(stat -c %h -- "$1")" = 1
}
require_private_directory() {
  test ! -L "$1"
  test "$(stat -c %F -- "$1")" = directory
  test "$(stat -c %u -- "$1")" = "$owner"
  test "$(stat -c %a -- "$1")" = 700
}
digest_of() {
  value=$(sha256sum -- "$1")
  value=${value%% *}
  test "${#value}" -eq 64
  case "$value" in *[!0-9a-f]*) return 1 ;; esac
  printf '%s' "$value"
}

require_private_directory "$parent"
require_private_file "$journal"
require_private_file "$backup"
require_private_file "$checksum"
test "$(wc -c <"$checksum")" -eq 65
IFS= read -r recorded_digest <"$checksum"
case "$recorded_digest" in *[!0-9a-f]*) exit 1 ;; esac
test "${#recorded_digest}" -eq 64
test "$recorded_digest" = "$(digest_of "$backup")"
for sidecar in "${journal}-journal" "${journal}-wal" "${journal}-shm"; do
  test ! -e "$sidecar" && test ! -L "$sidecar"
done
test ! -e "$restore" && test ! -L "$restore"
test ! -e "$quarantine" && test ! -L "$quarantine"

umask 077
: >"$restore"
chmod 600 "$restore"
cp --reflink=never -- "$backup" "$restore"
require_private_file "$restore"
test "$(digest_of "$restore")" = "$recorded_digest"
cmp -s -- "$backup" "$restore"
sync "$restore"

mkdir -m 700 -- "$quarantine"
require_private_directory "$quarantine"
: >"$quarantined"
chmod 600 "$quarantined"
cp --reflink=never -- "$journal" "$quarantined"
require_private_file "$quarantined"
active_digest=$(digest_of "$journal")
test "$(digest_of "$quarantined")" = "$active_digest"
: >"$quarantined_checksum"
printf '%s\n' "$active_digest" >|"$quarantined_checksum"
chmod 600 "$quarantined_checksum"
require_private_file "$quarantined_checksum"
sync "$quarantined" "$quarantined_checksum"
sync -f "$quarantine"

require_private_file "$journal"
test "$(digest_of "$restore")" = "$recorded_digest"
mv -T -- "$restore" "$journal"
require_private_file "$journal"
test "$(digest_of "$journal")" = "$recorded_digest"
sync "$journal"
sync -f "$parent"
sync -f "$quarantine"
```

Do not move or delete the receipt directory. Keep quarantine until the restored generation passes
the two migration-only MCP opens and expected operation/receipt inspection. If any step before
`mv -T` fails, the active pathname remains the old generation. The rename itself is namespace
atomic.

The source-fixture gate implements this restore sequence only in compile-time test code and kills
the real test process after the synchronized replacement is prepared but before publication, after
the quarantine and its checksum are synchronized while the active pathname still exists, and after
the atomic replacement. At each seam, deterministic test recovery selects the present non-empty
active pathname, removes only an unpublished prepared replacement, and performs two ordinary
candidate opens. A synchronized quarantine remains private through active recognition and invariant
checks and is removed only afterward by test cleanup. All nine historical states retain the same
lifecycle, provider-call, backup, and frozen-receipt facts described above. Corrupted backup/digest
attempts fail before replacement. Focused restore recovery also refuses existing and dangling
symlinks, hard links, permissive entries, and file/directory type substitutions at the replacement
and quarantine paths before opening or changing the active generation. Test cleanup classifies
entries with `symlink_metadata` and never follows a rejected link. All recognized artifacts require
the current owner, exact mode, and bounded link identity; a byte scan of every retained fixture file
rejects the fixed signing seed itself rather than inferring absence from filenames. This is evidence
for the documented operator protocol, not a restore API, CLI, or automatic production restore
feature.

## Downgrade to exact v0.1.1

The exact `v0.1.1` source at commit `ad799b39112ccd6ef06e1ec954c615b6635650f6` can directly reopen
the v0.2-marked store because this release pair has the same operation schema and lifecycle and
receipt semantics. The normal-open matrix proves that the exact old opener preserves database bytes
at every durable state, including both `apply_started` provider-call facts.

Stop v0.2 cleanly, preserve the backup pair, and start only exact `v0.1.1` against the same active
journal and receipt paths. Do not run both versions concurrently. This applies only to this exact
release pair. Downgrade never reverses a Kubernetes effect or authorizes a provider retry.

## Exact cleanup

After the rollback window and successful inspection, stop Kapsel. Remove only the named artifacts
from the procedure and synchronize their parent. Retaining them offline is safer.

```bash
set -eu
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
backup="${journal}.kapsel-v011.backup"
checksum="${backup}.sha256"
rm -- "$backup" "$checksum"
sync -f "$parent"
```

After the active generation and receipt references are verified, remove one known quarantine with:

```bash
set -eu
journal=/absolute/operator/path/journal.sqlite3
parent=$(dirname -- "$journal")
quarantine=/absolute/operator/path/journal.sqlite3.quarantine.EXACT-NAME
rm -- "$quarantine/journal.sqlite3" "$quarantine/journal.sqlite3.sha256"
rmdir -- "$quarantine"
sync -f "$parent"
```

The focused tests prove real process termination and restart at the named migration and restore
seams on the local host. Process termination is not sudden power loss. The gate does not prove a
filesystem that violates SQLite, atomic-rename, `fsync`, or directory-sync guarantees; storage or
hardware that acknowledges but loses synchronized writes; torn sectors; controller caches without
power-loss protection; a live copy; a moved receipt directory; a downloaded artifact; another
release pair; or restoration after lifecycle advancement.

## Unpublished snapshot journal

HEAD upgrades recognized format 2 journals transactionally to format 3, adding nullable approval and
preflight observation facts. Legacy rows and frozen receipts retain their original meanings and
bytes. Older binaries reject format 3. Format 0 still follows the backup prerequisite above. This is
not a new published v0.2.x upgrade promise. The
[effect-gateway owner](EFFECT_GATEWAY.md#exact-snapshot-approval-in-unpublished-head) defines exact
authority binding, legacy entry paths and receipt compatibility. The resident service requires a
snapshot grant and will not resume a legacy handle by replacing its authority.
