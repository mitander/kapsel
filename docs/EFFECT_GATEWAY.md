# Kubernetes effect-gateway experiment boundary

Status: active experiment and v0.2 beta semantic owner.

This contract owns one operation's authorization, durable lifecycle, receiver observation, result
meaning, receipt bytes, and demonstration. It does not define a generic agent runtime, MCP or
Kubernetes protocol semantics, reusable provider seam, stable package format, external witnessing,
or production assurance.

## Short answer

An agent may request one bounded operation. The gateway verifies an owner-signed, fixed-purpose,
single-operation grant against application-configured trust, durably records the target and attempt,
issues at most one conditional mutation request, observes the receiver, reconciles after a crash,
and emits an inspectable receipt whose classifier inputs can be recomputed offline.

```text
agent intent
  -> owner-signed exact grant under application-configured trust
  -> durable pre-attempt rejection or target identity
  -> Kubernetes deployment-image request when eligible
  -> rollout observation or bounded unknown
  -> signed, classifier-complete receipt
```

The receipt is a consequence of the execution guarantee. It is not a compliance product, evidence of
complete capture, or a claim that a signature proves the Kubernetes state was true.

## One capability

The experiment accepts only `kubernetes.set_deployment_image` with:

- Kubernetes namespace;
- deployment name;
- container name; and
- immutable OCI image digest.

Authorization binds all four values and one stable local operation identity. The experiment uses
this deliberately narrow input grammar:

- operation and authorization identities are 1–128 ASCII bytes containing only letters, digits, `.`,
  `_`, `:`, or `-`;
- namespaces are 1–63 byte lowercase Kubernetes DNS labels;
- deployments are 1–253 byte lowercase Kubernetes DNS subdomains whose labels are each at most 63
  bytes;
- containers are 1–63 byte lowercase Kubernetes DNS labels; and
- the image is at most 512 ASCII bytes and has the exact form
  `<named-image>@sha256:<64-lowercase-hex>`. The named image is slash-separated lowercase components
  that begin and end with an ASCII letter or digit and contain only letters, digits, `.`, `_`, or
  `-`. This prototype subset excludes tags, registry ports, tag-plus-digest forms, digest-only
  values, empty components, and uppercase spelling even where a wider ecosystem grammar may allow
  them.

No wildcard namespace, deployment, container, tag, shell command, manifest, arbitrary patch, or
second Kubernetes operation is in scope. The prototype journal accepts at most 10,000 distinct
operation identities; an existing identical identity remains readable and idempotent at the limit.
The owner-signed grant carries one bounded authorization identity and an exact copy of the operation
identity, namespace, deployment, container, and image. It has no wildcards, policy rules, ambient
lookup, or expiry semantics. The application-configured grant trust contains one exact signing-key
identity and Ed25519 verifying key. The gateway accepts only the fixed effect-gateway grant purpose,
persists the signer identity and SHA-256 digest of the exact signed grant bytes, and does not accept
trust from the request or grant.

The release-owned experiment uses a local `kind` cluster. It does not require a cloud account,
hosted Kapsel service, or production credentials.

## Operation lifecycle

The experiment journal has explicit local states:

```text
requested
  -> authorized
       -> not_attempted
       -> apply_started
            -> receiver_observed
            -> receipt_prepared
            -> receipt_written
            -> finalized
```

- `requested` records the bounded input and stable operation identity.
- `authorized` records that the exact request matched an authentic fixed-purpose grant under the
  application-configured owner trust. The signer identity and digest of the exact signed grant bytes
  are frozen.
- From `authorized`, the adapter safely reads and validates the target Deployment and named
  container. A transient API error increments a durable retry count used as queue-order backoff;
  lower-count authorized operations run first, so one transient target cannot block later work. A
  crash before the next transition leaves the operation `authorized`, so this non-mutating read may
  be repeated.
- `not_attempted` is terminal and records exactly one bounded pre-attempt rejection:
  `deployment_not_found`, `container_not_found`, or `invalid_target`. No mutation marker, provider
  write, receiver observation, receiver result, or effect receipt exists for this disposition. It is
  never reported as receiver `FAILED` or `UNKNOWN`.
- `apply_started` atomically records the target Deployment UID, target resource version,
  write-strategy identity, and attempt marker before Kubernetes mutation. The strategic merge patch
  carries both target preconditions, changes the exact name-keyed container image, and writes the
  operation identity in the `kapsel.dev/kap0038-operation-id` Deployment annotation. Target
  precondition conflicts fail before mutating a different target. A successful patch response must
  return the same Deployment UID and a resource version; missing or replacement identity facts fail
  closed. Recovery from `apply_started` never issues a blind second patch.
- `receiver_observed` records every bounded classifier input and the resulting classification,
  including target and receiver identity, observed image and operation marker, current, requested,
  and observed generations, replica counts, and rollout condition, or explicit missing facts.
- `receipt_prepared` atomically freezes the exact signed receipt bytes, SHA-256 digest, path,
  signing key identity, and already-stored write strategy before external publication.
- `receipt_written` means those exact frozen bytes were installed at the frozen path.
- `finalized` is terminal and read-only.

After `apply_started`, recovery uses the stored Deployment UID, operation annotation, and requested
image digest to observe and classify the operation. It does not replay even the frozen conditional
patch: Kubernetes UID and resource-version preconditions bound persisted updates, but do not prevent
a stale replay from invoking mutating admission and its allowed out-of-band effects again. Decision
[0011](decisions/0011-retain-observation-only-recovery.md) owns the comparison and evidence.

When the patch response was lost, an exact matching UID, operation annotation, and image binds the
observed current generation to the request; without all three facts the requested generation remains
unknown. If a later template writer retains those three facts, that generation may satisfy the
classifier, but the result does not attribute that later rollout to the original patch. If the
available receiver facts cannot establish the result, the result is `UNKNOWN`; it is never guessed
from request success or a timeout.

## Durable facts and recovery

| State               | Durable facts written before entering the state                                                                                                                     | Recovery rule                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `requested`         | Operation identity plus bounded namespace, deployment, container, and image digest.                                                                                 | Re-run validation and grant verification before any Kubernetes call.                               |
| `authorized`        | Authorization identity, exact authorized tuple, grant signer identity, signed-grant digest, and target-read retry count.                                            | Safely read the target; transient errors defer fairly, while permanent rejection becomes terminal. |
| `not_attempted`     | One bounded permanent target-rejection reason and an explicit zero-attempt disposition.                                                                             | Read-only; do not observe Kubernetes, classify a receiver result, or prepare an effect receipt.    |
| `apply_started`     | Target UID and resource version, write-strategy identity, and attempt marker, atomically committed.                                                                 | Do not blindly patch again. Observe the deployment and classify from receiver facts or `UNKNOWN`.  |
| `receiver_observed` | Target and receiver UID, observed image and operation marker, current/requested/observed generations, resource versions, replica counts, rollout condition, result. | Prepare the receipt from frozen facts only. Do not call Kubernetes to improve the result.          |
| `receipt_prepared`  | Exact signed receipt bytes, SHA-256 digest, path, receipt signing-key identity, and stored write strategy.                                                          | Publish only the frozen bytes to the frozen path; never re-sign from process configuration.        |
| `receipt_written`   | Confirmation that the frozen bytes were collision-safely installed at the frozen path.                                                                              | Verify or restore the frozen bytes at the frozen path; then finalize.                              |
| `finalized`         | Terminal state and receipt reference.                                                                                                                               | Read-only.                                                                                         |

The implementation explicitly uses SQLite's rollback journal with `synchronous=FULL` and verifies
both settings whenever it opens the journal. The main journal and exact offline backup are each at
most 64 MiB; a rollback-journal artifact is at most 65 MiB to allow bounded SQLite framing around
the owned database pages. Every persisted text or blob value is additionally at most 16 KiB,
SQLite's per-value-or-row allocation limit is 64 KiB, and every reopen checks those bounds and the
10,000-row ceiling before operation loading. Files are exact mode 0600 and their parent is exact
mode 0700. Larger, permissive, linked, or replaced artifacts fail before SQLite reads or recovery.
These physical and logical caps bound integrity checking, backup hashing, and persisted allocation
even when an owner-controlled journal is malformed; they are not a storage-capacity or retention
promise beyond the finite operation ceiling.

The implementation holds one crash-released exclusive worker lock around provider and receiver I/O
so two processes cannot advance the same journal concurrently. A contender performs no provider or
receiver call and changes no public fact. The implementation may add other internal lease or
scheduling fields, but those fields are not public facts and must not change result meaning.

## Result meaning

For operations that reached `apply_started`, the receiver result is exactly one of:

| Result      | Establishes                                                                                                                                                              | Does not establish                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `SUCCEEDED` | The observed deployment reached the requested generation and reports an available rollout for the requested image digest.                                                | Causation, workload correctness, complete cluster health, or universal capture. |
| `FAILED`    | The same deployment UID and requested image are observed at the requested generation, and Kubernetes reports `Progressing=False` with reason `ProgressDeadlineExceeded`. | Permanence, why Kubernetes failed, or whether another actor later changed it.   |
| `UNKNOWN`   | The experiment could not establish either defined observed outcome within its bounded reconciliation procedure.                                                          | That the request failed, was not received, or was later harmless.               |

`not_attempted` is a local pre-attempt disposition, not a receiver result. An accepted Kubernetes
request is not a rollout result. A healthy rollout does not prove that no other change occurred. A
conditional patch conflict is never forced or blindly retried and does not by itself establish a
failed rollout. `ReplicaFailure=True` may be retained as an observed condition but does not by
itself classify `FAILED`. A local observation timeout always classifies `UNKNOWN`. Deployment UIDs,
resource versions, operation markers, and condition reasons retained from Kubernetes are ASCII and
at most 128 bytes each. Generations and replica counts must be nonnegative. The requested and
observed image remains subject to the 512-byte immutable-image grammar above. Target observation and
the conditional strategic merge patch each have a ten-second request deadline. The root CLI/MCP
composition rejects any single Kubernetes HTTP response body above 2 MiB while it is streamed,
before kube-client can collect or deserialize it; this applies with content-length, chunked, or
close-delimited framing. An oversized target read is transient and cannot create a mutation marker.
An oversized patch response may leave the already marked provider attempt ambiguous, so restart
observes without another patch. An oversized receiver response contributes no facts and therefore
cannot strengthen `UNKNOWN` into another result.

Receiver observation has a 30-second overall deadline and performs at most 30 Deployment reads: one
immediately, then at most 29 more at one-second intervals. It stops only when the current generation
has been observed with the defined available or progress-deadline signal. Exhausting this budget,
object deletion, API unavailability, identity mismatch, an oversized response, or incomplete facts
classifies `UNKNOWN`; timeout never classifies `FAILED`.

## Authorization and secrets

The experiment accepts only a canonical signed grant for the exact operation parameters. The owner
signs it for the fixed purpose `kapsel.kap0038.kubernetes-set-deployment-image-grant.v1`; the
gateway verifies it against one application-configured key identity and Ed25519 verifying key. The
evaluator application loads this trust out of band and does not let agent input choose it. Grant
parsing is bounded and canonical. Wrong purpose, key identity, signature, tuple, or grammar fails
before request persistence or Kubernetes calls. The grant has these prototype-specific magic
prefixes:

| Document        | Magic                                     |
| --------------- | ----------------------------------------- |
| Grant statement | `KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V1\0` |
| Signed grant    | `KAPSEL-KAP0038-K8S-GRANT-V1\0`           |

The grant statement contains exactly the authorization identity, operation identity, namespace,
Deployment, container, and immutable image digest in that order. The signed grant contains exactly
the fixed purpose, signing-key identity, statement bytes, and Ed25519 signature. The signing input
is the exact byte string `purpose`, one zero byte, then the statement bytes.

The v0.2 beta continues to accept canonical grant v1 bytes emitted by `v0.1.1` and preserves this
exact wire across v0.2.x. The canonical signed known answer is
[`vectors/effect-gateway-grant.hex`](../vectors/effect-gateway-grant.hex); it uses the fixed
authorization, seed, and signer identity in the owner test rather than defining another vector
format. That bounded compatibility appoints no new trust, adds no expiry or revocation semantics,
and creates no generic grant format or promise beyond the v0.2.x beta line.

Kubernetes credentials and signing seeds are owner-controlled private inputs; they never enter agent
requests, SQLite, receipts, reports, or errors. Public signing-key identities and digests are not
secrets and are frozen to identify the accepted authority. The grant does not itself grant
Kubernetes authority, prove a human made a decision, or replace Kubernetes RBAC. The experiment must
reject unsafe paths and must not print secrets or unbounded provider response bodies.

## Receipt and inspection

The experiment writes one signed, portable receipt and supports offline inspection under separately
provided trust, explicit evaluation time, and explicit resource limits. Its bytes, report language,
and trust inputs remain capability-specific beta surfaces. v0.2 continues offline inspection of
canonical receipt and trust v2 bytes emitted by `v0.1.1`, emits the same receipt v2 wire, and
preserves that wire across v0.2.x. This bounded compatibility never re-signs frozen bytes, appoints
receipt-carried trust, creates a generic receipt format, or promises compatibility beyond the v0.2.x
beta line. A later format must use a new identifier and explicit migration/inspection policy rather
than reuse or rename these bytes. The canonical `v0.1.1` receipt, statement, and trust known answers
remain [`vectors/effect-gateway-receipt.hex`](../vectors/effect-gateway-receipt.hex),
[`vectors/effect-gateway-statement.hex`](../vectors/effect-gateway-statement.hex), and
[`vectors/effect-gateway-trust.hex`](../vectors/effect-gateway-trust.hex).

The prototype bytes are fixed-order length-delimited records with these magic prefixes:

| Document  | Magic                               |
| --------- | ----------------------------------- |
| Statement | `KAPSEL-KAP0038-K8S-STATEMENT-V2\0` |
| Receipt   | `KAPSEL-KAP0038-K8S-RECEIPT-V2\0`   |
| Trust     | `KAPSEL-KAP0038-K8S-TRUST-V2\0`     |

A record is encoded as a one-byte field number, a four-byte big-endian length, and that many value
bytes. Fields must appear exactly once in strictly increasing field-number order. Unknown,
duplicate, missing, reordered, trailing, or truncated records fail closed. Text is UTF-8 ASCII in
the grammar and length stated here. Integers are signed or unsigned big-endian fixed-width values as
owned by the durable facts. Canonical receipt bytes are the original parsed bytes; inspection never
re-encodes and verifies a different representation.

The statement is built only from already frozen durable facts and contains exactly:

| Field | Meaning                                                             |
| ----- | ------------------------------------------------------------------- |
| 1     | operation identity                                                  |
| 2     | authorization identity                                              |
| 3     | authorization grant signing-key identity                            |
| 4     | SHA-256 digest of the exact signed authorization grant bytes        |
| 5     | Kubernetes namespace                                                |
| 6     | Deployment name                                                     |
| 7     | container name                                                      |
| 8     | requested immutable image digest                                    |
| 9     | stored write strategy identity, `conditional-strategic-merge-patch` |
| 10    | target Deployment UID                                               |
| 11    | target resource version                                             |
| 12    | receiver Deployment UID, or empty when not observed                 |
| 13    | observed image digest, or empty when not observed                   |
| 14    | observed operation marker, or empty when not observed               |
| 15    | current generation, or `-1` when not observed                       |
| 16    | requested generation, or `-1` when not established                  |
| 17    | observed generation, or `-1` when not observed                      |
| 18    | observed resource version, or empty when not observed               |
| 19    | desired replica count, or `-1` when not observed                    |
| 20    | updated replica count, or `-1` when not observed                    |
| 21    | available replica count, or `-1` when not observed                  |
| 22    | unavailable replica count, or `-1` when not observed                |
| 23    | rollout condition type, or empty when not observed                  |
| 24    | rollout condition status, or empty when not observed                |
| 25    | rollout condition reason, or empty when not observed                |
| 26    | result, one of `SUCCEEDED`, `FAILED`, or `UNKNOWN`                  |
| 27    | non-claims token list                                               |

The inspector reconstructs the bounded request, apply identity, and receiver observation from these
fields and runs the same pure classifier. A signed statement is structurally rejected when its
stated result differs from the recomputed result. `INSPECTED` therefore authenticates both the
classifier inputs and their deterministic effect-gateway classification; it still does not establish
that Kubernetes reported truthful facts.

The non-claims field is the exact ASCII token list
`no-exactly-once;no-causation;no-kubernetes-truth;no-complete-capture;no-witnessing;not-production`.
It is a signed statement field so report consumers see the experiment's limits even when the report
is separated from the owner document. The statement has no timestamps, no Kubernetes response body,
no secret, no policy, no package identifier, no verifier profile, and no generic capability field.

A receipt contains exactly:

| Field | Meaning                                                        |
| ----- | -------------------------------------------------------------- |
| 1     | signing purpose, `kapsel.kap0038.kubernetes-effect-receipt.v2` |
| 2     | signing key identifier                                         |
| 3     | statement bytes as encoded above                               |
| 4     | Ed25519 signature over the receipt signing input               |

The receipt signing input is the exact byte string `purpose`, then one zero byte, then the statement
bytes.

The key identifier is 1–128 ASCII bytes containing only letters, digits, `.`, `_`, `:`, or `-`.
Signing uses Ed25519 with a 32-byte verifying key supplied by external trust. The receipt does not
carry trust anchors, fetch keys, appoint authority, or define an issuer policy.

A trust document contains exactly:

| Field | Meaning                                            |
| ----- | -------------------------------------------------- |
| 1     | trusted signing key identifier                     |
| 2     | 32-byte Ed25519 verifying key                      |
| 3     | accepted signing purpose                           |
| 4     | inclusive not-before evaluation time, Unix seconds |
| 5     | exclusive not-after evaluation time, Unix seconds  |

Inspection takes receipt bytes, trust bytes, explicit evaluation time, and explicit limits. It
performs no network, filesystem discovery, ambient clock read, environment lookup, or trust lookup.
Evaluation time must be within the trust interval, the trust purpose must equal the receipt purpose,
and the trust key identifier must equal the receipt key identifier before the signature result can
be reported as trusted. Weak or malformed keys, bad signatures, wrong purpose, wrong key, and time
window failures all produce bounded reports or typed failures without panics.

Resource limits are part of the public inspection contract: receipt bytes are at most 16 KiB,
statement bytes are at most 8 KiB, trust bytes are at most 1 KiB, and any text field is at most 512
bytes unless an earlier grammar bound is smaller. The implementation may accept lower
caller-supplied limits but must not exceed these maxima.

Offline inspection reports an aggregate status using only this vocabulary:

| Status               | Meaning                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| `STRUCTURE_REJECTED` | Receipt, statement, or trust bytes did not parse within the limits.                                  |
| `SIGNATURE_REJECTED` | Structure parsed, but signature bytes did not authenticate.                                          |
| `UNTRUSTED_SIGNER`   | Signature authenticated, but external trust did not accept the key, purpose, or time.                |
| `INSPECTED`          | Structure, signature, and supplied trust matched; the report states the frozen facts and non-claims. |

Inspected and authenticated-but-untrusted reports disclose the signed fixed non-claims with the
parsed statement. Inspection must never report `VERIFIED`. `INSPECTED` means only that the disclosed
bytes were signed by a supplied trusted key for this prototype purpose at the explicit evaluation
time. It does not mean the Kubernetes facts were true, causal, complete, witnessed,
policy-authorized, or safe.

Receipt filenames are derived by the application from the operation identity and the SHA-256 digest
of the final receipt bytes: `kap0038-<operation-id>-<64-lowercase-hex-receipt-sha256>.receipt`. The
operation identity is already path-component safe by the request grammar. Publication requires a
pre-existing owner-private output directory and installs owner-private immutable bytes without
following symlinks or replacing different existing bytes. This descriptor-relative publication
implementation supports Unix platforms only. The stored receipt digest is the SHA-256 of the exact
installed receipt bytes, not of decoded statement facts or report text.

## Required release demonstration

The release-owned Unix harness runs from one repository command against one uniquely named,
disposable `kind` cluster. In the fixed archive layout, the script safely locates its adjacent
public vector and the separate demonstration executable; source mode and explicit artifact overrides
remain available for repository and packaging proofs. It uses the supported
`kapsel provision-grant`, `kapsel operate`, and `kapsel inspect` grammar and fixed operator-owned
files.

Before creating a workspace or inspecting clusters, the harness reports the detected prerequisite
versions and refuses an unavailable Docker daemon, `kind` older than 0.32, unavailable or pre-1.30
`kubectl`, Python older than 3.11, an unparsable tool version, or unsafe artifact inputs with a
concrete corrective action. It refuses any pre-existing `kind` cluster or colliding harness
directory before creating or mutating resources. A kind node-preparation failure remains a failed
demonstration and identifies the Docker/kind compatibility check to perform; it cannot weaken an
ownership check or continue to mutation.

Every phase reports elapsed time. The final evidence summary distinguishes the durable attempt, both
exact process terminations, restart-only reconciliation, the exactly-one harness apply count,
receiver disposition and its owned condition, frozen receipt identity, offline inspection path, and
the explicit `UNKNOWN` boundary. It does not promote a phase, process exit, timeout, or provider
response into a receiver outcome. The harness removes only the cluster and host directory it
created, reports successful cleanup, and gives an exact owner-scoped retry action if cleanup fails.
Signal and failure cleanup remain ownership-safe; captured command and cluster logs are individually
capped at 64 KiB and contain no configured seeds, credentials, grant bytes, or provider bodies.

The harness demonstrates:

1. an agent submits an authorized request for one immutable image digest and a healthy fixture
   reaches `SUCCEEDED` without changing the untargeted container;
2. a second authorized request uses one unavailable immutable image and Kapsel durably records
   `apply_started` before crossing the Kubernetes mutation seam;
3. the exact `kapsel operate` process is killed after the mutation returns but before its outcome is
   recorded;
4. restart reconciles rather than blindly patching again, the harness-owned apply counter remains
   exactly one, and the unavailable image reaches `FAILED` only from `ProgressDeadlineExceeded`
   receiver facts;
5. exact receipt bytes are durably prepared and installed, then the exact `kapsel operate` process
   is killed before `receipt_written` is recorded;
6. restart under a rotated receipt key and changed output directory finalizes only the frozen bytes,
   leaving the rotated directory empty and preserving the frozen receipt digest; and
7. `kapsel inspect` runs with unavailable network and ambient Kubernetes configuration and reports
   `INSPECTED`, `FAILED`, the signed classifier inputs exposed by the inspector, and the fixed
   non-claims without `VERIFIED` vocabulary.

Fault control is not part of the agent request, operator JSON, ordinary command grammar, public Rust
interface, journal, or receipt. The harness builds the same `kapsel` binary with the private
`demo-harness` compile-time feature and supplies an owner-private control directory plus exactly one
of two fixed process-environment values: `after_apply` or `after_receipt_publish`. At the selected
internal seam Kapsel creates one owner-private readiness marker, syncs it, and waits to be
terminated. The mutation seam also creates a no-replace `provider-apply-count` file containing `1`;
encountering it again fails closed. Builds without `demo-harness` do not read these variables or
contain the pause behavior. The harness never accepts a lifecycle state, arbitrary fault point,
marker path, shell, manifest, patch, credential, or receipt byte from agent input.

Deterministic black-box tests run the feature-built production executable against a local HTTP
fixture and kill it at both fixed seams. Existing internal tests still exercise every durable
transition. The visual demo runs against `kind`; no live cluster behavior is presented as
deterministic test evidence.

## Explicit exclusions

Do not add:

- arbitrary shell, `kubectl` passthrough, manifests, patches, tags, or credentials in agent input;
- a second capability or provider;
- a generic provider, capability, queue, policy, authorization, receipt, package, trust, or verifier
  module;
- runtime plugins, hosted storage, multi-tenant operation, dashboard, or transparency backend;
- a claim of exactly-once Kubernetes mutation, complete audit capture, compliance, or production
  readiness.

One adapter remains a hypothesis, not a reusable seam. Keep the experiment deep around its one
operation: the caller crosses one narrow experiment interface while the implementation owns
journaling, Kubernetes interaction, recovery, observation, receipt construction, and inspection.
