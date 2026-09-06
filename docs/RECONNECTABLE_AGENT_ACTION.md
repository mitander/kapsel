# Reconnectable agent action experiment

Status: completed on repository HEAD `9df5fad` and later in a disposable kind environment; one
inconclusive handoff and one strict-approval rejection were produced live. The earlier stop
condition is retained below because it explains the experiment's design.

Kind: experiment evidence.

Owns: The recorded outcome of the reconnectable agent action workflow: setup, invocation, caller and
service loss, reconnect, receiver observation, stale approvals, human handoff, and the measured
practical cost of exact-snapshot approval.

Does not own: A new grant format, authorization policy, observation lifecycle, agent integration, or
product decision. Canonical behavior remains owned by [effect-gateway](EFFECT_GATEWAY.md) and the
[service contract](KAPSEL_SERVICE.md). Reproduction commands live in
`scripts/test-kind-agent-action-workflow.sh`.

## Intended workflow

The experiment asked whether an operator could approve one exact Deployment image change, let an
agent submit it through the fixed service client, lose both caller and service processes, and let a
later caller continue from the same durable operation identity without guessing or mutating again.
The approval had to bind the target identity and expected-state preconditions so a change or
recreation after approval could not silently refresh them.

## Setup

One disposable kind cluster (pinned Kubernetes v1.33.12) hosted the receiver: namespace `demo`,
Deployment `agent-api`, one container running a pinned `registry.k8s.io/pause` digest. One
disposable Linux container ran the unpublished `kapseld` composition with the documented fixed
paths, a dedicated service identity, a caller identity whose effective group matched the socket's
caller group, and a scoped RBAC kubeconfig (`get` and `patch` on the single named Deployment). The
operator binary ran on the host: `provision-snapshot-grant` acquired the Deployment UID and
resourceVersion through the administrator kubeconfig and signed the exact-snapshot grant. Every step
above is a command of the harness script.

The caller boundary was the fixed `kapsel-service-client` grammar exposed through a thin wrapper
that forwards only `submit`, `status`, and `receipt`. Real agent sessions (Claude Code, driven
non-interactively with the wrapper as their sole executable capability) proposed the change, invoked
the handle, and reconnected after their own session loss.

## What was exercised

1. An agent proposed an immutable image change; the operator authorized the exact operation, target
   identity, and expected snapshot with `provision-snapshot-grant`.
2. An agent session read the operator's handle record, verified the configured boundary, checked
   status, and submitted the handle; the service returned `ACCEPTED` and the session ended while the
   rollout was still executing.
3. The service was lost at the `after_apply` seam (the existing demonstration pause point, after the
   conditional patch persisted) by SIGKILL, then restarted. Startup reconciliation observed the
   receiver without resending; the operation finalized while the rollout was still settling.
4. A new agent session reconnected to the same handle, polled status, retrieved the frozen receipt,
   and reported without re-submitting.
5. A separate approval was invalidated by a same-name recreation and by ordinary status churn; both
   submissions durably terminated as `NOT_ATTEMPTED / STALE_APPROVAL` with zero PATCHes.
6. An inconclusive action was handed to a human: the operator retrieved the frozen receipt and
   verified it offline with `kapsel inspect`.

## Results

- Healthy run, no faults: `ACCEPTED` at T+0, `SUCCEEDED` with the rollout complete inside the
  service's observation window; the frozen receipt shows `write_strategy`
  `conditional-strategic-merge-patch`, the requested operation marker on the receiver, and
  `approved_target` distinct from `observed_target` (same UID, later resourceVersion).
- Service loss at the mutation seam: recovery stayed observation-only, never re-sent, and the
  receipt froze one observation snapshot. That snapshot caught the previous replica still
  terminating (`unavailable_replicas` 1, `Available` condition already `True`), so the result was
  terminal `UNKNOWN` even though Kubernetes completed the rollout roughly forty seconds later. The
  human handoff worked exactly as designed: the signed receipt gave the operator every receiver fact
  needed to decide, but the operation itself was already terminal.
- The service's receiver-observation window is bounded at 30 seconds. The experiment's rollout
  (60-second `minReadySeconds`) could not settle inside it after a restart, which is what produced
  the `UNKNOWN` above. The bounded window is shorter than the 45-180 second observation span this
  workflow asks for.
- Stale approvals: two of five submission attempts were durably rejected as
  `NOT_ATTEMPTED / STALE_APPROVAL` with zero PATCHes. Both invalidating changes were ordinary and
  irrelevant to the requested intent: a Deployment status update between approval and submission
  moved the resourceVersion, and the receiver observation projected the observed resourceVersion
  alongside the approved one so the mismatch was explicit. Reapproval cost was measured at two
  seconds and three operator commands (new snapshot grant, service restart to load it, new handle
  record); no existing handle ever acquired replacement authority.
- Real agents and asserted authority: on first contact, both real agent sessions refused a
  submission requested through prompt-asserted authority alone, treating it as an injection. The
  invocation succeeded only after the operator published standing caller configuration and a handle
  record the agent could read and verify itself. Kapsel's model (authority lives in the operator
  grant, never in caller input) matches how real agents actually behave; integration plans must
  budget for publishing verifiable handle records.
- Reconnecting agent behavior: the reconnected session checked status before anything else, refused
  to re-submit a handle that already had an outcome, attempted receipt retrieval for a status-only
  rejection (correctly refused by the client with no output), and reported the honest result. No
  caller-side recovery code was written by any agent session.
- The frozen receipt was sufficient for the human decision; signature verification added no
  additional consumer decision in this experiment beyond trusting that the frozen bytes were the
  journal's.

## Outcome

Kapsel reduced caller-side recovery logic to zero and made every outcome inspectable from durable
evidence; no session needed bespoke continuation code, and no outcome had to be guessed after
ambiguity. It did not reduce operator effort relative to an ordinary protected typed tool: strict
snapshot approval converted two ordinary, intent-irrelevant target churns into reapprovals, and the
bounded observation window converted one ordinary healthy rollout into a terminal `UNKNOWN` handoff.
The broker thesis survives on evidence quality and authority isolation, not on operator effort.

## Smallest concrete gaps recorded

- The 30-second receiver-observation window is shorter than this workflow's own 45-180 second
  observation span, so post-`apply_started` recovery can terminalize a still-settling rollout as
  `UNKNOWN`.
- Whole-object resourceVersion churn from Kubernetes status updates invalidates exact-snapshot
  approvals even when nothing about the requested mutation's intent changed; the experiment records
  this as the measured cost of the accepted design, not as a defect.

## Earlier stop condition (retained)

The first attempt at this experiment stopped before creating any cluster or issuing any Kubernetes
request. The signed grant's authorization statement contained exactly the authorization identity,
operation identity, namespace, Deployment name, container name, and immutable image digest; it
contained no Deployment UID or resource version. Only after submission did the adapter read the
current Deployment and freeze its identity at `apply_started`, so a Deployment changed or recreated
between approval and submission could silently supply a later identity while the original grant
still matched. That violated the experiment's authority condition before the agent integration
began. The gap was subsequently decided, specified, and implemented as exact-snapshot approval, and
proven by deterministic regressions and the live kind lane before this workflow was run.

## Evidence boundary

The workflow results above were produced in one disposable environment from the harness script and
destroyed afterwards; exact per-case timestamps, status projections, and receipts were recorded in
the experiment's tracker evidence. No claim here extends past the single operation, the pinned
receiver, and the unpublished service composition. Deterministic regressions for the same semantics
run without any model call.
