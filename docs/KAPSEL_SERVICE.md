# Kapsel service

Status: accepted unpublished service implementation; installer foundation, four recoverable fixed
identity mutations, and private host-file publication foundation implemented; complete installer
journey not implemented.

Kind: product contract. Authority: service process boundary, local protocol, installed assets,
installer trust and recovery, qualification envelope, unsupported behavior, and residual risk.

Owns: The `kapseld -> kapsel` composition, authenticated Unix socket, fixed filesystem roots,
systemd lifecycle, narrow Kubernetes RBAC, and the next installer's trust, credential, transaction,
recovery, and uninstall boundary.

Does not own: Authorization, effect lifecycle, receiver-result, `UNKNOWN`, or receipt semantics;
those remain owned by the [effect-gateway contract](EFFECT_GATEWAY.md). Runnable build and current
candidate commands are in [Build](BUILD.md), and proof requirements are in [Testing](TESTING.md).

## Boundary

```text
bounded local caller
  -> /run/kapsel/kapseld.sock
       -> kapseld under a separate OS identity
            -> kapsel::Application
                 -> sole SQLite effect journal
                 -> concrete Kubernetes adapter
```

The Kapsel service retains the sole `kubernetes.set_deployment_image` capability. The exact grant
binds one operation identity, namespace, Deployment, container, and immutable image digest. It does
not bind a Deployment UID or resource version; the gateway reads and freezes those facts after
submission. The [reconnectable agent action experiment](RECONNECTABLE_AGENT_ACTION.md) records why
that late binding cannot satisfy a workflow whose operator approval must preserve exact receiver
preconditions. `kapseld` composes `Application`; it does not sequence gateway internals.

The service process exists because the synchronous CLI and stdio MCP adapter do not provide
caller-independent lifetime, startup reconciliation, read-only reconnect/status, exact receipt
retrieval, or a separate installed authority identity. Wrapping either adapter would require an
unsupported status store, receipt copying, and supervision.

## Runtime inventory

| Item                        | Contract                                                                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Packages                    | Existing root `kapsel`; one unpublished `kapseld -> kapsel` package                                                                                           |
| Executables                 | Existing `/usr/bin/kapsel`; `/usr/libexec/kapsel/kapseld`; fixed `/usr/bin/kapsel-service-client` caller                                                      |
| Caller interface            | `/run/kapsel/kapseld.sock`; one length-prefixed JSON request and response per connection                                                                      |
| Authentication              | Parent `0750`, socket `0660`, owner `kapsel:kapsel-service-callers`; exact effective caller-group peer credential required                                    |
| Connection resources        | At most eight admitted connections; two-second read and write deadlines; no queue                                                                             |
| Durable stores              | Existing effect-gateway SQLite journal only                                                                                                                   |
| Operator configuration      | Generated fixed `/etc/kapsel/operator.json`; authority beneath `/etc/kapsel`; journal and receipts beneath `/var/lib/kapsel`                                  |
| Startup path validation     | Descriptor-relative fixed roots; exact owners/modes; regular single-link files; no symlinks; stable consumed bytes                                            |
| OS ownership                | Locked non-login `kapsel`; `0700` private roots and `0600` private files                                                                                      |
| Caller identity             | Fixed locked `kapsel-service-caller` with `kapsel-service-callers` as its primary group; no supplementary membership mutation                                 |
| Kubernetes authority        | Short-lived TokenRequest credential for `ServiceAccount/demo/kapsel-service`; namespaced `get` and `patch` on exact Deployment `agent-api`                    |
| Installed assets            | Three executables, systemd unit, sysusers record, non-secret RBAC manifest, and operator guide; no socket unit, tmpfiles rule, PID file, wrapper, or workload |
| Runtime dependencies        | Rust executables, Linux Unix sockets, systemd, existing SQLite and Kubernetes stack; no Python, shell, daemon framework, RPC SDK, or new DB                   |
| Supported failure domains   | Caller disconnect, service process loss, same-host restart, mutation/publication seams, bounded Kubernetes ambiguity                                          |
| Unsupported failure domains | Host or disk loss, backup, HA, fleet, partition tolerance, production, broad upgrade/rollback, identity rotation, or another operation                        |

The service adds no scheduler, queue, controller framework, protocol framework, provider
abstraction, policy engine, SDK, or second store.

## Authority and filesystem

The installer generates the root operator JSON using the existing grammar and these exact paths:

```text
/etc/kapsel/operator.json
/etc/kapsel/grant.bin
/etc/kapsel/authorization.pub
/etc/kapsel/kubeconfig.yaml
/etc/kapsel/receipt.seed
/var/lib/kapsel/journal.sqlite3
/var/lib/kapsel/receipts
```

Configuration and state roots are service-owned mode `0700`; operator files are regular,
single-link, service-owned mode `0600`. The caller group receives no read or traversal permission.
Journal, worker lock, and receipt files may be absent before first use; when present they remain
regular, single-link, service-owned mode `0600`.

Startup opens fixed `/etc/kapsel`, `/var/lib/kapsel`, `/var/lib/kapsel/receipts`, and `/run/kapsel`
roots descriptor-relatively. It validates exact owners, modes, file types, link counts, path
components, and stable consumed bytes. It retains handles for the configuration, state, receipt, and
runtime roots.

On Linux, journal and SQLite sidecar access, receipt publication and reads, and socket preparation
and bind resolve through `/proc/self/fd/<fd>` paths for those retained handles. Startup requires
each procfs path to resolve to the same device, inode, owner, group, type, and mode as its handle;
unavailable or inconsistent procfs fails before journal creation, reconciliation, or socket bind.
Frozen receipt references keep the fixed `/var/lib/kapsel/receipts` pathname in durable state, while
I/O maps only the already-validated receipt filename into the retained receipt directory. Renaming a
root or replacing its old name after validation cannot redirect state, receipts, or the listening
socket into the substitute. If the state root moves after SQLite opens, SQLite's file-move defense
rejects later writes with `SQLITE_READONLY_DBMOVED`; Kapsel returns an operation failure rather than
reopening the replacement. A renamed runtime root can make the fixed client socket pathname
unreachable until restart; startup through a substituted fixed root must validate that root anew.
Host root, procfs, the kernel, and the service identity remain trusted.

The locked `kapsel` identity exclusively owns operator files, Kubernetes credentials, grant trust,
receipt signing material, journal, worker lock, and receipts. The caller never selects or receives
an operator path, credential, grant/trust bytes, signing material, journal path, receipt path,
lifecycle transition, or Kubernetes patch.

## Protocol

Each connection carries one four-byte unsigned big-endian length, one UTF-8 JSON body, required
client write-half-close, one framed response, and close. Request length is 1–16 KiB. Ordinary
responses are at most 16 KiB and receipt responses at most 40 KiB. Aggregate frame-read and
response-write deadlines are two seconds. At most eight connections are admitted; saturation closes
immediately without reading a body or creating lifecycle work.

The socket accepts exactly three capability-specific requests:

```json
{"request":"get_set_deployment_image_status","operation_id":"operation-id"}
{"request":"get_set_deployment_image_receipt","operation_id":"operation-id"}
{"request":"submit_set_deployment_image","operation_id":"operation-id","namespace":"demo","deployment":"agent-api","container":"api","immutable_image_digest":"registry.example/agent-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

Input key order is insignificant. Duplicate, unknown, missing, null, wrong-typed, trailing,
cross-request, malformed UTF-8, oversized, timed-out, and out-of-grammar fields fail closed without
lifecycle effect.

Status returns `NOT_FOUND`, `IN_PROGRESS`, `NOT_ATTEMPTED` with its required `target_rejection`,
`SUCCEEDED`, `FAILED`, or `UNKNOWN` without Kubernetes access. Status responses contain only
`status`, except `NOT_ATTEMPTED`. Receipt responses are `{"status":"NOT_FOUND"}`,
`{"status":"NOT_READY"}`, or a ready record containing only `status:"READY"`, `receipt_hex`, and
`receipt_sha256`. The receipt is lowercase hexadecimal of exact journal-frozen bytes and retains the
journal-frozen lowercase digest.

A submission that acquires the sole execution slot, matches the configured grant, and installs the
background execution task returns `{"status":"ACCEPTED"}`. `ACCEPTED` means only that the process
owns execution and the in-flight slot. It is not a receiver result and may precede durable
visibility. Disconnect or response failure does not cancel execution. Completion is observed only
through status and receipt requests.

A submission that cannot acquire the slot immediately returns `{"status":"BUSY"}`. `BUSY` waits for
nothing, creates no queue, calls no `Application` method, and changes no lifecycle fact. Invalid
requests return `invalid_request`; application or exact-grant failures return the non-disclosing
`operation_failure`. Peer denial, framing failure, timeout, saturation, and an over-limit response
close without a response.

## Fixed service client

`/usr/bin/kapsel-service-client` is the sole service client. It has no socket, authority, path,
retry, lifecycle, or protocol configuration. Its exact grammar is:

```text
kapsel-service-client submit <operation-id> <namespace> <deployment> <container> <immutable-image-digest>
kapsel-service-client status <operation-id>
kapsel-service-client receipt <operation-id> <new-output-file>
```

It always connects to `/run/kapsel/kapseld.sock`, sends one contract-owned frame, write-half-closes,
reads one bounded response, and exits. `submit` and `status` print the exact one-line JSON response.
`receipt` accepts only `READY`, validates lowercase hexadecimal and the declared SHA-256, and
creates the output as one new regular mode-`0600` file without following or replacing a path. It
prints one bounded JSON record containing `status`, `receipt_sha256`, and the caller-selected output
pathname; it never prints receipt bytes. Other daemon statuses fail without creating an output.

The caller has no SDK or reusable protocol package. The supported operator journey invokes it as the
fixed `kapsel-service-caller` identity with primary and effective group `kapsel-service-callers`.
The group database member list remains empty; no supplementary membership is required or installed.

## Execution and process lifecycle

One execution `Application` and one projection `Application` may open the same configured operation
and journal. They are two handles to one lifecycle store. Projection reads use application-owned
status and frozen-receipt grammar; they neither call Kubernetes nor advance lifecycle state.

The exact ordinary argv is:

```text
/usr/libexec/kapsel/kapseld --operator-config /etc/kapsel/operator.json --socket /run/kapsel/kapseld.sock
```

Ordinary startup accepts no environment configuration or finite-connection input. It opens and
reconciles the execution application once before binding, opens the projection application, secures
the socket, and serves indefinitely. There is no periodic retry or automatic same-boot restart loop.

Before bind, `kapseld` removes an existing socket leaf only when no listener answers and metadata
shows an exact single-link socket owned by the service UID and caller-group GID with mode `0660`.
Every other leaf is left unchanged and startup fails. Systemd may then remove the service-owned
runtime directory and leaf. After bind, `kapseld` verifies exact socket type, owner, group, and mode
before admission.

Caller disconnect does not cancel an accepted operation. SIGTERM or process loss may interrupt any
durable window; the next explicit activation uses effect-gateway recovery. After `apply_started`,
recovery observes and never issues a blind second mutation attempt.

The systemd unit uses `Type=exec`, `User=kapsel`, `Group=kapsel-service-callers`,
`RuntimeDirectory=kapsel`, `RuntimeDirectoryMode=0750`, `StateDirectory=kapsel`,
`StateDirectoryMode=0700`, `UMask=0077`, `Restart=no`, null standard streams, disabled start-rate
limiting, the fixed argv above, and `WantedBy=multi-user.target`. Every boot, explicit start, or
explicit restart attempts startup once.

Identity installation begins with the `kapsel` private group, then creates `kapsel-service-callers`,
the locked `kapsel` user, and the locked external caller. The caller's primary group is
`kapsel-service-callers`; there is no `usermod` or supplementary-membership step. Numeric IDs are
transaction-preselected before mutation, and created users carry the exact transaction identity as
GECOS. The Debian preview appoints `/usr/sbin/groupadd`, `/usr/sbin/groupdel`, `/usr/sbin/useradd`,
`/usr/sbin/nologin`, `/usr/bin/getent`, `/usr/bin/systemctl`, and `/usr/bin/timeout`; all production
execution is direct without a shell. The installer does not preflight or invoke `/usr/sbin/usermod`
because no approved mutation uses supplementary membership.

The first identity mutation creates only the `kapsel` private group. After clean-install preflight,
the installer runs bounded `/usr/bin/getent group` and `/usr/bin/getent passwd`, accepts at most 64
KiB of stdout from each, and strictly parses every returned group GID and passwd primary GID. It
preselects the highest value unused by either database in the installer's fixed preview range
101–999, then requires bounded `/usr/bin/getent group <decimal-gid>` to report absence. Exhaustion,
malformed or oversized output, timeout, signal termination, or any result other than exact absence
fails before pending publication. Selection does not call this fixed range the host's system range,
consult `login.defs`, accept an ambient range, or permit a duplicate or existing primary GID.

The installer durably publishes `create_group` with exact name `kapsel`, the selected GID, and the
transaction identity before executing exactly:

```text
/usr/bin/timeout --signal=KILL 10s /usr/sbin/groupadd --system --gid <decimal-gid> kapsel
```

The installer gives the wrapper an inherited duplicate of its already-held installer-lock open file
description. The duplicate has close-on-exec cleared only for this serial spawn; the installer drops
its copy immediately after spawn. The wrapper and mutation child therefore retain the exclusive lock
if the installer dies, and recovery cannot acquire the installer lock until that command has exited.
The wrapper receives null standard input, kills the mutation at ten seconds, and discards stdout and
stderr. Failure to establish this inherited-lock lifetime fails before command execution. Completion
is established only by separate bounded queries `/usr/bin/getent group kapsel` and
`/usr/bin/getent group <decimal-gid>`, each with at most 4 KiB of stdout. Both absent means not
started; both must otherwise return the same single exact `kapsel:x:<decimal-gid>:` record,
including an empty member list, to establish completion under the already durable pending
transaction. One absent result, additional or malformed output, another name or GID, or any other
mismatch is an ownership conflict. Command exit alone never establishes completion. Exact completion
adds the group ownership record and clears pending in one durable successor. This evidence relies on
the supported host having no concurrent identity administrator: the group format has no transaction
marker, so another identity authority that creates the exact pending name/GID after clean preflight
is indistinguishable. Such concurrent administration is outside the disposable preview boundary.

The second identity mutation creates only the `kapsel-service-callers` group. After binding the
first group, the installer repeats the same bounded group and passwd enumeration, strict parsing,
highest-free selection in 101–999, and exact numeric-GID absence check. The first group's bound GID
is therefore unavailable to the second selection. It durably publishes `create_group` with exact
name `kapsel-service-callers`, the second selected GID, and the same transaction identity before
executing exactly:

```text
/usr/bin/timeout --signal=KILL 10s /usr/sbin/groupadd --system --gid <decimal-gid> kapsel-service-callers
```

Completion requires separate bounded `/usr/bin/getent group kapsel-service-callers` and
`/usr/bin/getent group <decimal-gid>` queries to return the same single exact
`kapsel-service-callers:x:<decimal-gid>:` record with an empty member list. Both absent means not
started. Every mixed, malformed, additional, replaced-name, replaced-GID, or member-bearing result
is an ownership conflict. Exact completion appends the second group ownership record and clears
pending in one durable successor. The inherited-lock lifetime, command and output bounds, and
exclusive identity-administration assumption are identical to the first group.

Install rollback removes bound groups in reverse creation order. For each last-owned group it
verifies the same two exact observations, durably publishes `remove_group` with the complete
recorded ownership, and executes exactly one of:

```text
/usr/bin/timeout --signal=KILL 10s /usr/sbin/groupdel kapsel-service-callers
/usr/bin/timeout --signal=KILL 10s /usr/sbin/groupdel kapsel
```

The same inherited installer-lock lifetime, null-input, ten-second kill, and discarded-output bounds
apply. Before publishing removal pending and again immediately before every `groupdel` attempt,
bounded `/usr/bin/getent passwd` must establish that no returned account has the recorded GID as its
primary GID. Both exact observations mean removal has not started and may be retried; both absent
establish completion and pop only that last ownership record while clearing pending in one durable
successor. Every mixed, replaced, or malformed observation is an ownership conflict and is never
deleted. The first group is never considered for removal while second-group ownership or pending
evidence remains. `remove_group` is an install-rollback action only; successful uninstall retains
identities as specified below.

The next two approved mutations preselect the highest UID unused by the strictly parsed passwd
enumeration in the same fixed preview range 101–999. Before pending publication, both the fixed name
and decimal UID must be exactly absent through separate bounded `/usr/bin/getent passwd` queries.
The `kapsel` user binds the already owned private-group GID; `kapsel-service-caller` binds the
already owned caller-group GID. The installer then publishes `create_user` with the complete
expected passwd identity, exact transaction GECOS, and required locked-shadow facts before executing
exactly:

```text
/usr/bin/timeout --signal=KILL 10s /usr/sbin/useradd --system --uid <service-uid> --gid <kapsel-gid> --no-create-home --home-dir /var/lib/kapsel --shell /usr/sbin/nologin --comment <transaction-id> --no-user-group --no-log-init --password '!' kapsel
/usr/bin/timeout --signal=KILL 10s /usr/sbin/useradd --system --uid <caller-uid> --gid <caller-group-gid> --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --comment <transaction-id> --no-user-group --no-log-init --password '!' kapsel-service-caller
```

The inherited installer-lock lifetime, null input, ten-second kill, and discarded output are the
same as for group creation. `--no-create-home`, `--no-user-group`, `--no-log-init`, and every passwd
field are explicit so hostile `useradd` and `login.defs` defaults cannot create a home, private
user-group, log initialization, or alternate shell, home, or GECOS. Both users have password field
exactly `!`; this is the required locked state.

Recovery performs separate NSS queries by name and UID and by shadow name. Each query executes
through `/usr/bin/timeout --signal=KILL 10s` with `/usr/bin/getent` as the direct child. Its stdout
collector reads at most 4,097 bytes before parsing, treats the 4,097th byte as an over-limit
sentinel, and retains at most 4 KiB as observation data. Exactly absent means all three queries exit
2 with empty output. Exactly complete means both passwd queries exit 0 and return the same exact
single newline-terminated seven-field record with the pending name, UID, primary GID, transaction
GECOS, home, and `/usr/sbin/nologin`. The shadow query must exit 0 and return exactly one
newline-terminated nine-field record with that name, password field exactly `!`, a nonempty
all-decimal last-change day, and all six remaining fields empty. A name or UID bound to another
account, or an expected account with a changed immutable field, is a conflict. Mixed passwd absence,
a missing or inconsistent shadow row, malformed, unterminated, additional, or over-limit output,
query timeout, signal termination, or an unclassifiable NSS result is ambiguous/partial. Command
exit and transport completion never establish absence or completion.

Exactly absent may retry the pending mutation. Exactly complete may bind the user ownership record
and continue. Conflict or ambiguous/partial evidence, including any query timeout, signal, or stdout
over-limit result, durably changes only the phase to terminal `identity_blocked` before returning an
error. Existing pending and ownership evidence remains unchanged. Recovery from `identity_blocked`
performs no observation, mutation, or rollback, so no later invocation can continue even if the
hostile or partial row disappears. The installer never invokes `userdel`. Once either user is
exactly complete, installer-created users and their primary groups are permanently retained,
including after failed install or uninstall. Group rollback remains legal only before any user
effect and only when no user ownership or pending user evidence exists and the bounded passwd scan
proves no primary-GID account.

The installer does not invoke `systemd-sysusers`; the installed sysusers record is a vendor asset
only and is never installer ownership or recovery evidence. The caller's supervisor sets effective
`Group=kapsel-service-callers`, matching the caller account's primary group. User creation and its
transaction recovery are implemented and covered by deterministic classifier and staged-bundle
crash-seam evidence.

Systemd state plus successful authenticated socket use is the health boundary. The socket exposes no
administration, key management, migration, purge, health, or shutdown request. Diagnostics are
limited to `ActiveState`, `SubState`, `Result`, `ExecMainCode`, `ExecMainStatus`, and `NRestarts`.

## Kubernetes authority and installed assets

Kubernetes authority is namespaced `get` and `patch` on exact Deployment `agent-api`. RBAC is not a
field policy; the concrete adapter remains responsible for the fixed conditional image patch.

| Repository input                          | Direct-install destination                         |
| ----------------------------------------- | -------------------------------------------------- |
| feature-free root `kapsel`                | `/usr/bin/kapsel`                                  |
| feature-free `kapsel-service-client`      | `/usr/bin/kapsel-service-client`                   |
| feature-free `kapseld`                    | `/usr/libexec/kapsel/kapseld`                      |
| `crates/kapseld/deploy/kapseld.service`   | `/usr/lib/systemd/system/kapseld.service`          |
| `crates/kapseld/deploy/kapseld.conf`      | `/usr/lib/sysusers.d/kapseld.conf`                 |
| `crates/kapseld/deploy/kapseld-rbac.yaml` | `/usr/share/kapsel/kapseld-rbac.yaml`              |
| `docs/KAPSEL_SERVICE_OPERATOR.md`         | `/usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md` |

The RBAC manifest contains one token-automount-disabled `ServiceAccount/demo/kapsel-service`, one
Role granting `apps/deployments` `get` and `patch` for `resourceNames: ["agent-api"]`, and one
RoleBinding. It creates no credential, token Secret, Namespace, Deployment, workload, ClusterRole,
wildcard, or field policy.

Removal stops and disables the service, waits for process, connection, and socket closure, revokes
Kubernetes authority, and only then removes all three executables, unit, sysusers record, RBAC
manifest, operator guide, and runtime socket. It retains identities, operator files, installer
transaction evidence, journal, and receipts. Destructive purge is unsupported.

## Approved installer contract

This section owns the next candidate's interface. It is approved contract, not an implemented or
qualified command.

### Authenticated acquisition and fixed interface

“One-command installation” begins only after the operator independently downloads and authenticates
one `x86_64-unknown-linux-gnu` `kapsel-installer` executable, its digest manifest, and its Sigstore
bundle. Authentication verifies the exact issuer, `kapsel-cloud/kapsel` repository, appointed
workflow, `refs/heads/master` ref, 40-hex source SHA, and `workflow_dispatch` trigger before the
manifest verifies the executable digest. The installer cannot authenticate itself. It performs no
runtime download and embeds the exact three service executables, systemd unit, sysusers record, RBAC
bytes, operator guide, license, and metadata. License and metadata are embedded bundle evidence
only; they have no install destination and are not host resources. The authenticated installer
executable is at most 64 MiB; a larger candidate is rejected before execution rather than adding a
second payload or runtime download.

The only planned mutating commands are:

```text
sudo kapsel-installer install \
  --operator-input /secure/kapsel \
  --kube-context nonprod

sudo kapsel-installer refresh-credential \
  --operator-input /secure/kapsel \
  --kube-context nonprod

sudo kapsel-installer uninstall \
  --operator-input /secure/kapsel \
  --kube-context nonprod
```

Each option is required exactly once. The operator-input path is absolute, and the context is an
explicit 1–253 byte Kubernetes name. There is no environment, ambient kubeconfig, current-directory,
network-download, archive, package-manager, reinstall, upgrade, purge, force, or unattended-refresh
alternative.

### Operator input and bootstrap authority

The operator-input directory contains exactly:

```text
grant.bin
authorization.pub
receipt.seed
receipt.trust
bootstrap-kubeconfig.yaml
```

The installer opens the absolute directory and every leaf descriptor-relatively without following
symlinks. The directory is root-owned mode `0700` and not replaced while open. Every input is a
stable root-owned regular single-link file, mode `0600`, at most 64 KiB; grant, key, seed, and trust
retain their smaller product grammar bounds. Unknown or missing leaves fail before mutation. The
installer verifies the signed grant, derives its exact authorization key identity and operation
tuple, verifies that `authorization.pub` is its appointed key, and verifies that `receipt.seed`
derives the key and key identity accepted by `receipt.trust`. The installer and root package consume
one unpublished fixed-purpose `kapsel-authority` implementation for this grant, receipt-trust, and
combined consistency validation. That source-only package is not installed and is not a public SDK
or runtime interface. `receipt.trust` is evaluator trust material: it is required for this
consistency check but is never installed, copied into service authority, or selected by a caller.

`bootstrap-kubeconfig.yaml` is administrative installer authority, never service authority. Its
bounded grammar is one `apiVersion: v1`, `kind: Config` document with exactly one cluster, user, and
context entry. The context name equals `--kube-context`, references those exact entries, and has no
namespace or namespace `demo`; `current-context`, when present, must equal the same explicit name.
The cluster contains only one absolute `https` server URL without user information, query, or
fragment and embedded `certificate-authority-data`. The user contains either one inline token or one
inline client-certificate/client-key pair. The document rejects aliases, duplicate or unknown
fields, extensions, proxy settings, insecure TLS, external certificate, key, CA, or token file
references, username/password, `exec`, and `auth-provider`. The YAML is at most 64 KiB; the decoded
CA, token, client certificate, and client key are each at most 16 KiB and are bounded before decode
allocation. The installer ignores `KUBECONFIG` and all client environment configuration.

The transaction binds the selected server URL, CA SHA-256, context, and opened input-directory
device, inode, UID, and mode. Bootstrap credential bytes may exist only in the operator-input
directory and the installer's memory; they never enter `/etc/kapsel`, the installer transaction,
service environment, output, or diagnostics. Every install, refresh, and uninstall requires that
same directory identity, context, server, CA, and four stable non-bootstrap input digests. A renewed
inline bootstrap token or client certificate/key may replace `bootstrap-kubeconfig.yaml` at the same
strongly owned directory. After strictly validating the renewed bootstrap input and before using
that credential, the installer durably publishes a same-phase successor changing only
`bootstrap_kubeconfig_sha256` to the new exact-file digest. The
`bootstrap_kubeconfig_initial_sha256` remains immutable. This renewal may change no action, phase,
pending action, resource array, transaction identity, directory identity, installer digest, cluster,
CA, context, grant, authorization key, receipt seed, or receipt trust.

### Short-lived service credential

After creating and UID-binding the fixed ServiceAccount, Role, and RoleBinding, the installer sends
one TokenRequest to `/api/v1/namespaces/demo/serviceaccounts/kapsel-service/token`. It requests
3,600 seconds, omits a bound object and custom audiences so the API server appoints its API
audience. The request has a ten-second deadline; its streamed response body is at most 64 KiB before
collection, and `status.token` is nonempty ASCII at most 16 KiB. The response must be
`authentication.k8s.io/v1` `TokenRequest` with a parseable `status.expirationTimestamp` 1,800–7,200
seconds after the installer's current wall time. No clock-skew correction or ambient time source is
used; an incorrectly set host clock fails closed. The generated service kubeconfig contains only the
selected server, embedded CA, one inline token, and one fixed service context; it contains no
bootstrap credential or external reference.

Credential refresh is explicit and operator-authorized; there is no timer or daemon refresh path.
`refresh-credential` is accepted when the recorded credential has at most 900 seconds remaining or
is expired. An earlier request is read-only and reports the existing expiration. At the threshold it
stops `kapseld`, obtains and validates a new TokenRequest response, writes a new mode-`0600`
service-owned kubeconfig to a same-directory temporary inode, syncs it, atomically renames it over
the old kubeconfig, syncs `/etc/kapsel`, and starts `kapseld`. Startup reconciliation completes
before socket bind. A failure before rename leaves the old kubeconfig intact and the service
stopped; a failure after rename recovers by validating the recorded inode and restarting with the
new bytes. Install and refresh have exact success output:

```text
{"status":"INSTALLED","credential_expiration":"<server RFC-3339 expirationTimestamp>"}
{"status":"CREDENTIAL_CURRENT","credential_expiration":"<recorded RFC-3339 expirationTimestamp>"}
{"status":"CREDENTIAL_REFRESHED","credential_expiration":"<server RFC-3339 expirationTimestamp>"}
```

Each is the sole stdout line for its case and exits 0. Partial uninstall exits 20 as specified
below; every other installer failure exits 1 with no stdout and at most one 4 KiB secret-free stderr
line.

The service loads one credential at startup. After expiration, Kubernetes calls authenticate no
longer; read-only status and frozen-receipt retrieval remain local while `kapseld` is running. A
failed refresh deliberately leaves the socket unavailable until refresh recovery starts the daemon;
already retrieved receipts remain inspectable offline. Pre-attempt API failure remains retryable
lifecycle state, while failure after `apply_started` can only reconcile from bounded receiver facts
or `UNKNOWN`. Expiration, authentication failure, outage, installer failure, or restart never
becomes receiver `FAILED` or `SUCCEEDED`. Continued operation beyond the issued lease requires the
explicit refresh command and reachable bootstrap authority.

### Durable installer transaction and ownership

`/run` and `/run/lock` are pre-existing platform directories; the installer never creates or repairs
them. Starting from the root directory, it opens both components descriptor-relatively without
following symlinks and requires root-owned directories. `/run` must not be writable by group or
other; a group- or other-writable `/run/lock` must have the sticky bit. The installer first opens
`kapsel-installer.lock` descriptor-relatively with
`O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and requests mode `0600`. Only on
`EEXIST` does it reopen without `O_CREAT | O_EXCL`. It may set exact mode `0600` only on an inode it
created successfully; it never changes, truncates, unlinks, or replaces an existing leaf. Before and
after taking a nonblocking exclusive `flock`, the retained descriptor must identify the same exact
root-owned regular single-link mode-`0600` inode. The descriptor holds the lock for the invocation.
The lock leaf is permitted pre-transaction coordination, not durable ownership evidence, and may be
reused after the crash-released lock. The pre-existing `/var` and `/var/lib` components are opened
descriptor-relatively without following symlinks; both must be root-owned directories not writable
by group or other, `/var/lib` must not have the set-group-ID bit inherited by child directories, and
the installer never creates or repairs either component. With the lock held, the only other mutation
allowed before a transaction exists is this bootstrap: create `/var/lib/kapsel-installer` no-replace
as root mode `0700` and sync `/var/lib`; open an unnamed mode-`0600` inode there with Linux
`O_TMPFILE`; write the complete initial record; sync that inode; link it no-replace as
`transaction.json`; then sync the installer directory. A crash before the link leaves no named
partial file. After a crash, an exact root-owned mode-`0700` empty installer directory resumes
creation, and an exact valid `transaction.json` resumes its recorded phase. The only additional
permitted leaf is the strongly marked `.transaction.next` update described below; it must be a valid
one-step successor and is completed before resource recovery. Any other leaf, invalid transaction,
unsupported unnamed-file operation, or concurrent Kapsel resource fails closed. The installer
directory and transaction are never removed.

For a new transaction, after acquiring the lock and before publishing any transaction inode, the
installer fills exactly 32 bytes using blocking-complete Linux `getrandom` calls with flags zero. It
retries interrupted calls and short successful reads, uses no fallback entropy, and encodes the
result as 64 lowercase hexadecimal characters. Entropy failure fails closed. Recovery of an empty
installer directory after a pre-link crash generates a new identity because no prior identity became
durable.

`installer_sha256` is SHA-256 over the complete bytes of the executing Linux inode opened through
the kernel-owned `/proc/self/exe` magic link. This is transaction identity evidence, not publisher
authentication. The retained descriptor must identify a stable nonempty regular file of at most 64
MiB. Unavailable procfs, a read or metadata change, or an invalid type or length fails closed. The
installer never derives or reopens this inode through argv, `PATH`, or `current_exe`.

The retained regular single-link transaction is at most 65,536 bytes and canonical UTF-8 JSON with
no byte-order mark, insignificant whitespace, or trailing newline. Object keys are ordered lexically
by their UTF-8 bytes at every depth, unsigned integers use shortest decimal form, and strings use
shortest JSON escapes without escaping `/` or printable UTF-8. Parsing is a strict typed decode
followed by canonical reserialization and exact byte comparison. Duplicate, unknown, reordered,
alternately escaped, noncanonical numeric, whitespace-padded, trailing, or over-limit records fail
closed. Resource arrays retain transaction creation order and are never sorted. Schema `1` has these
exact top-level keys; `null` is explicit where shown, and hashes and the transaction identity are
lowercase hexadecimal:

```json
{
  "action": "install | refresh-credential | uninstall",
  "bootstrap_kubeconfig_initial_sha256": "<64-hex>",
  "bootstrap_kubeconfig_sha256": "<64-hex>",
  "cluster": { "ca_sha256": "<64-hex>", "server": "https://..." },
  "credential_expiration": "<RFC-3339> | null",
  "host_resources": [],
  "input_directory": { "device": 1, "inode": 2, "mode": 448, "path": "/secure/kapsel", "uid": 0 },
  "installer_sha256": "<64-hex>",
  "kube_context": "nonprod",
  "kubernetes_resources": [],
  "operator_inputs": {
    "authorization.pub": "<64-hex>",
    "grant.bin": "<64-hex>",
    "receipt.seed": "<64-hex>",
    "receipt.trust": "<64-hex>"
  },
  "pending": null,
  "phase": "prepared",
  "schema": 1,
  "transaction_id": "<64-hex>"
}
```

The initial record is exactly `action: "install"`, `phase: "prepared"`, equal initial and current
bootstrap-kubeconfig digests, null expiration and pending action, and empty host and Kubernetes
resource arrays. Input digests cover the exact retained file bytes, the CA digest covers decoded CA
bytes, and `input_directory.mode` is the unsigned permission-bit value. No other action or phase may
be initially published.

A host file or directory record contains exactly `kind`, `path`, `device`, `inode`, `file_type`,
`uid`, `gid`, and `mode`, plus `length` and `sha256` for a file. A user record contains `kind`,
`name`, `uid`, `primary_gid`, `gecos_transaction_id`, `home`, `shell`, and `locked`; a group
contains `kind`, `name`, and `gid`. A systemd enablement record contains the unit inode and digest
plus each created enablement link's descriptor-relative path, device, inode, file type, and exact
target. A Kubernetes record contains exactly `api_version`, `kind`, `namespace`, `name`, `uid`, and
`transaction_id_annotation`. The record contains no token, bootstrap credential, private key, seed,
grant bytes, or trust bytes.

`pending` is `null` or one object with exact `action` plus these variant fields:

| Pending action       | Required fields                                                                                                                                                         | Recovery observation                                                                                                 |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `stage_host`         | `destination`, `staging`, `file_type`, `uid`, `gid`, `mode`, `length`, `sha256`, `transaction_id`, and `device`/`inode` as either both `null` or both unsigned integers | Bind only a staging inode carrying the transaction marker and every expected fact.                                   |
| `publish_host`       | `destination`, `staging`, `device`, `inode`, `file_type`, `uid`, `gid`, `mode`, `length`, `sha256`, and `transaction_id`                                                | Destination same inode with every frozen file fact is complete; staging is not started; every other shape conflicts. |
| `create_group`       | name, preselected GID, transaction identity                                                                                                                             | Absent is not started; exact name/GID under the pending transaction is complete; other identity conflicts.           |
| `create_user`        | name, preselected UID/primary GID, transaction GECOS, home, shell, and locked-shadow requirement                                                                        | Classify only exactly absent, exactly complete, conflict, or ambiguous/partial; only the first two permit action.    |
| `enable_service`     | unit device/inode/digest and exact enablement link path/target                                                                                                          | Bind link inodes only under exact unit and target identity; any pre-existing or changed link conflicts.              |
| `start_service`      | exact unit                                                                                                                                                              | Active exact unit is complete; inactive is not started; failed state is a typed activation failure.                  |
| `stop_service`       | exact unit                                                                                                                                                              | Inactive with no process/socket is complete; otherwise repeat stop and wait at most ten seconds for closure.         |
| `create_kubernetes`  | API version, kind, namespace, name, transaction annotation                                                                                                              | Bind UID only from the same cluster and annotation; absence is not started; mismatch conflicts.                      |
| `issue_credential`   | ServiceAccount UID, requested seconds, destination, staging leaf, owner/mode, transaction marker, then staged inode/digest/length/expiration when known                 | No leaf repeats issuance; a marked unbound leaf is removed and reissued; a bound inode continues publication.        |
| `replace_credential` | destination and recorded staged device/inode, expiration                                                                                                                | Destination same inode is complete; staging same inode is not started; every other shape conflicts.                  |
| `remove_group`       | complete recorded group ownership                                                                                                                                       | Absence is complete; exact name/GID is not started; changed identity conflicts.                                      |
| `disable_service`    | recorded enablement link identities                                                                                                                                     | All absent is complete; exact recorded links remain not started; any replacement conflicts.                          |
| `delete_kubernetes`  | complete recorded Kubernetes ownership                                                                                                                                  | Delete uses UID precondition; absence is complete; same UID remains not started; replacement conflicts.              |
| `remove_host`        | complete recorded host ownership                                                                                                                                        | Absence is complete; exact recorded inode remains not started; any replacement conflicts.                            |
| `daemon_reload`      | exact unit                                                                                                                                                              | Safe to repeat; it neither establishes nor removes ownership.                                                        |

A staged regular file is first represented by `stage_host` with both `device` and `inode` set to
`null`. They may move only together to the exact observed unsigned values in one same-variant
successor. The installer creates an unnamed `O_TMPFILE` inode in the destination parent, writes it,
sets and verifies a Linux extended attribute carrying the transaction identity, syncs the inode,
links it no-replace to the predeclared same-parent staging leaf, syncs the parent, then records its
device and inode before publication. The next successor is the exact `publish_host` record above; it
retains every frozen `stage_host` file fact and cannot change any of them. The final file ownership
successor is derived entirely from those retained facts. A crash before link leaves no named inode.
A staged directory uses a predeclared cryptographically random leaf containing the transaction
identity; recovery may bind it only while it is root-owned, exact-mode, empty, in the already opened
parent, and still named by that pending transaction, after which it sets and syncs the same
extended-attribute marker. Any other shape conflicts. If the filesystem cannot provide these
operations and markers, preflight rejects the host. No recovery binds an ordinary expected name or
matching bytes alone.

`issue_credential` owns TokenRequest through credential staging as one seam. After receiving a
token, the installer constructs the bounded kubeconfig in memory, writes and marks an unnamed
same-parent inode, syncs it, links it no-replace to the predeclared staging leaf, and syncs the
parent. It then atomically adds the staged device, inode, digest, length, and expiration to
`pending` and syncs the transaction. A crash before the link repeats TokenRequest. A crash after the
marked leaf appears but before its inode is bound removes only that marker-matching leaf, syncs its
parent, and reissues; the abandoned token remains inaccessible and expires within 7,200 seconds. A
bound staged inode continues to `publish_host` during install or `replace_credential` during
refresh.

Legal phase transitions are exact:

```text
prepared -> installing -> installed
installing -> identity_blocked
installing -> rolling_back -> rolled_back
rolled_back -> prepared
installed -> refreshing -> installed
installed -> uninstalling_local -> uninstalling_kubernetes
uninstalling_kubernetes -> partial_uninstall -> uninstalling_kubernetes
uninstalling_kubernetes -> uninstalling_static -> uninstalled
```

The `rolled_back -> prepared` transition requires the same installer, directory, cluster, and stable
inputs. The sole transaction marker is the extended attribute `user.kapsel.transaction-id`. Its
value is the exact 64 ASCII lowercase-hex bytes of `transaction_id`, without NUL or newline. The
installer sets it on an opened inode with create-only semantics, reads it back into a bounded
65-byte buffer, and requires an exact 64-byte match. Unsupported attributes, a pre-existing marker,
an over-limit value, or a mismatch fail closed; unrelated attributes are ignored.
`.transaction.next` always requires the marker. The initially published `transaction.json` has no
marker; after a successor rename its marker, when present, must match.

Every transaction update uses the same protocol: write the complete successor to an unnamed
`O_TMPFILE` inode in the installer directory, set and verify its transaction-identity extended
attribute, sync it, link it no-replace as `.transaction.next`, and sync the directory; then rename
it over `transaction.json` and sync the directory again. A crash before link leaves only the old
record. A crash after link leaves the old record plus `.transaction.next`; recovery accepts the
latter only when its marker, schema, transaction identity, immutable fields, and phase/pending
change are exactly one legal successor of the old record, then completes rename and directory sync.
Any other candidate conflicts. Thus no partial named JSON is ever parsed or discarded. At the
transaction-foundation boundary, a successor may either change only `phase` along one edge in the
legal phase graph while `pending` is null, or remain in the same phase and change only
`bootstrap_kubeconfig_sha256` to the digest of a strictly validated renewed bootstrap input before
credential use. Recovery accepts that digest successor only when the current validated bootstrap
input has its exact digest. The initial bootstrap digest is immutable. Every other field, including
both resource arrays, is byte-for-byte unchanged. In particular, `prepared -> installing` is a
phase-only successor. `action` remains `install` through install and rollback, changes to
`refresh-credential` only on `installed -> refreshing`, remains so on `refreshing -> installed`, and
changes to `uninstall` only on `installed -> uninstalling_local`, remaining so thereafter.
Pending-action and ownership-evidence successors become legal only with the later implementation of
their corresponding resource mutation; until then they fail closed rather than being treated as
opaque updates. The sole exception to the null-pending phase rule is
`installing -> identity_blocked`: it preserves the exact pending action and both resource arrays,
and is legal only after both group ownership records exist at a user-observation boundary.
`identity_blocked` has no successor.

Before every pending action, that update protocol durably installs the pending object. After
observation, it installs the successor that adds ownership evidence or removes the owned slot,
clears `pending`, and advances the phase when applicable. No later action starts until that boundary
is durable.

Host ownership is stronger than a name or matching bytes. Published files and directories retain the
recorded staged inode. Users and groups use transaction-selected numeric IDs recorded before
creation; users also carry the transaction identity in their GECOS field and bind exact primary GID,
home, shell, and locked-shadow facts. `kapseld.conf` is published only after the transaction has
durably bound every identity it names; rollback removes that asset before removing any created
identity, and no boot or recovery path may use sysusers to complete a pending identity action.
Kubernetes objects carry the random transaction identity annotation and are bound to the selected
server, CA, and returned UID. A lost Kubernetes create response may be recovered only by observing
that same annotation and then durably binding the returned UID. A missing or conflicting marker,
UID, inode, numeric identity, type, owner, mode, digest, link target, or cluster identity is an
ownership conflict, not permission to replace or delete.

### Recovery, rollback, and uninstall

Every command opens and validates the transaction before preflight or mutation. A nonterminal
install observes its exact pending seam. It retries an exactly absent identity action, continues an
exactly complete one, and durably enters terminal `identity_blocked` on conflict or
ambiguous/partial evidence. Reopening `identity_blocked` fails without another observation or
effect. Install rollback is available only before any user effect and removes strongly owned groups
in reverse creation order. It never invokes name-only `userdel`, and it never removes a group after
a user has been observed or bound with that primary GID. A nonterminal refresh never enters install
rollback: it retains all installed resources, observes or completes `replace_credential`, remains
stopped on failure, and resumes refresh until it can return to `installed`. An uninstall requested
during refresh first normalizes any credential replacement to one strongly identified installed
kubeconfig, without requiring service restart, then begins local revocation.

Every nonterminal uninstall resumes monotonically from its pending seam. It never rolls back caller
or service revocation, restores local caller access, restarts the service, or recreates Kubernetes
authority. It repeats exact stop/removal actions only under the pending table and cannot enter
static removal before UID-bound Kubernetes revocation.

No recovery deletes from an expected name, preflight absence, transaction intent, matching bytes, or
an RBAC shape alone. Ambiguous/partial, unresolved, or conflicting ownership stops recovery nonzero,
retains the record and resource, and consumes the disposable host; installation never continues
around it. A fully `rolled_back` first attempt may be retried with the same authenticated installer
and inputs. An `installed`, `partial_uninstall`, or `uninstalled` transaction can never install
again.

Uninstall orders revocation as follows:

1. disable and stop `kapseld`, wait for process and connection closure, and verify socket removal;
2. using the explicit bootstrap context, delete the recorded RoleBinding, ServiceAccount, and Role
   only when each observed UID and transaction annotation matches;
3. remove the strongly owned static service assets and reload systemd; and
4. enter `uninstalled` while retaining identities, `/etc/kapsel`, `/var/lib/kapsel`, journal, worker
   lock, receipts, and `/var/lib/kapsel-installer` evidence.

If Kubernetes authority is unavailable after local revocation, uninstall enters `partial_uninstall`,
retains every static asset and all transaction evidence needed for recovery, and exits with
status 20. Its sole stdout line is the exact compact JSON retry record:

```text
{"status":"PARTIAL_UNINSTALL","retry":["sudo","kapsel-installer","uninstall","--operator-input","/secure/kapsel","--kube-context","nonprod"]}
```

The two values are the original absolute input path and context from argv. Repeating that exact
command recovers first and resumes at Kubernetes revocation; it never re-enables local use. Static
removal and `uninstalled` are forbidden until all three UID-bound Kubernetes objects are absent or
were deleted under matching ownership. Absence is acceptable only after the transaction had already
bound that object's UID.

Successful uninstall deliberately leaves the disposable preview host non-reinstallable. Retained
identities, authority/state roots, and terminal transaction evidence are part of the proof and are
not adopted installation inputs. Reinstall, upgrade, purge, identity reuse, transaction reset, and
manual ownership override remain unsupported; use a fresh disposable host.

## Qualification envelope

The deterministic application, CLI, MCP, formatting, documentation, Clippy, and default repository
gates pass. Native Linux tests cover peer credentials, saturation, framing deadlines, process-local
execution, disconnect continuity, process loss, startup roots, socket identity, and static asset
bytes.

The direct-source path passed on one fresh x86-64 Debian 12 KVM VM with systemd 252, kind 0.32.0,
kubectl 1.33.13, and Kubernetes v1.33.12. The disposable qualification established separate locked
service and caller identities; caller denial from authority and state; exact-effective-GID
admission; boot, explicit start/restart, `Restart=no`, and bounded diagnostics; process-loss and
boot recovery without a second Deployment generation; exact stale-socket handling; named Deployment
RBAC allow/deny behavior; one successful image operation preserving Deployment UID and sidecar;
exact frozen receipt retrieval, offline inspection, replay, and restart; ordered caller and
Kubernetes authority revocation; retained operator, journal, and receipt bytes; and complete cluster
and VM cleanup.

The explicit live-kind gate also passed healthy, `ProgressDeadlineExceeded`, and deleted-after-patch
`UNKNOWN` cases against the pinned node image.

The installer bundle smoke additionally crossed all four fixed identity creates, exact name and
numeric-key observations, user shadow and immutable-field classification, durable ownership binds,
user crash and timeout recovery, ambiguous and conflicting partial-user refusal, a primary-GID
refusal, and pre-user reverse group rollback. Its private Linux host-file tests cross exact marker
readback, inode and parent sync, no-replace staging and publication, full-fact transaction
successors, destination-parent resolution, and probe cleanup. No production asset order invokes that
foundation. Its Debian 12 native lane uses `groupadd`, `groupdel`, `useradd`, `getent`, and
`timeout`. It established native exit 0 for creation and removal, exit 9 for duplicate-name
creation, exit 8 when `groupdel` encounters a primary-GID user, exit 2 with empty output for absent
`getent` group queries, the exact empty-member `name:x:gid:` record for name, numeric-key, and
enumeration queries, and exit 137 for `timeout --signal=KILL` termination. Fixed executable fixtures
provide the exhaustive deterministic identity crash-seam and hostile-output proof.

The separately runnable `./scripts/test-debian12-installer-identities.sh` experiment uses the pinned
Debian 12 slim image with explicit `linux/amd64`. With passwd 4.13, glibc 2.36, and sudo 1.9.13p3,
it crossed both exact useradd argv under hostile defaults. Each user mutation changed only
`/etc/passwd`, `/etc/passwd-`, `/etc/shadow`, and `/etc/shadow-` among all regular `/etc` files;
`/etc/group`, `/etc/group-`, `/etc/gshadow`, `/etc/gshadow-`, `/etc/subuid`, `/etc/subgid`,
`/var/log/lastlog`, and `/var/log/faillog` remained unchanged. Name and numeric NSS queries returned
the same exact passwd row, shadow carried password field `!`, no home was created, and both group
member lists stayed empty. Duplicate name and UID were conflicts with exits 9 and 4, an injected
pre-exec timeout was exactly absent despite exit 137, process loss after useradd returned was
exactly complete despite exit 137, and an injected passwd-only row was ambiguous/partial. The exact
`sudo -n -u kapsel-service-caller -g kapsel-service-callers -- id` path produced UID 996 and
effective GID 998 with no supplementary group membership. These numeric values and the fixed
transaction ID are experiment fixtures; production selection remains transaction-specific.

## Unsupported behavior

No published Kapsel service release, production use, host-loss continuity, backup, HA, fleet
management, concurrency queue, periodic controller, broad upgrade/rollback matrix, online key or
identity rotation, remote client, container package, SDK, plugin, second capability, arbitrary image
change, arbitrary provider input, hosted authority, managed coordination, or compatibility promise
is supported.

Do not add a socket-activation unit, admin interface, daemon/RPC framework, HTTP/TCP/MCP server,
client SDK, generic envelope, protocol package, second database, cache, queue, scheduler,
controller, lease, dashboard, metrics server, plugin loader, provider trait, policy engine,
container package, sandbox code, or another capability. Service status and diagnostics remain
systemd-owned.

## Residual risk

Source qualification covers one fresh x86-64 Debian 12/systemd 252 and Kubernetes 1.33 environment.
Identity recovery additionally relies on exclusive host identity administration while the installer
transaction is nonterminal. Group records cannot carry a transaction marker, and NSS observation
cannot prove which actor created an otherwise exact row. The two-group and user-argv container lanes
use Debian's x86-64 tools under the available Docker platform, which may be emulated by the host;
they are not fresh-VM or cross-distribution evidence. User recovery classification, both fixed user
mutations, and the private host-file publication foundation are implemented, but the staged fixture
is not fresh-VM identity or production-asset evidence. This finite evidence establishes no runnable
installer, production safety, another platform, upgrade compatibility, backup, HA, repeated external
operation, or protection from compromised host root, kernel, or service identity.
