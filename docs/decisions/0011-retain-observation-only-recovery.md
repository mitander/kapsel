# Retain observation-only recovery after an ambiguous patch

Status: accepted.

Kind: decision. Date: 2026-09-05.

Owns: Whether recovery after `apply_started` observes, replays the frozen conditional patch, or
hands retry scheduling to a durable-workflow runtime.

Does not own: Receiver-result classification, a workflow-engine integration, another capability, or
receipt bytes.

## Context

A process can die after Kapsel commits `apply_started` but before any network send. Observation-only
recovery abandons that still-authorized action. Replaying the exact frozen operation could complete
it while the original Deployment UID and resource version remain current.

The same journal state also covers a request accepted by Kubernetes whose response was lost. A
recovery policy cannot distinguish those windows. UID and resource-version preconditions bound
persistence, but they do not protect all earlier Kubernetes request processing.

The comparison used one immutable operation tuple:

```text
operation ID + Deployment UID + resourceVersion + immutable image +
conditional-strategic-merge-patch
```

Every replay used those original values. It never refreshed authorization, target identity, or a
precondition from later state.

## Evidence

The deterministic test
`recovery_policy_tests::frozen_recovery_policy_matrix_separates_requests_admission_and_effects` uses
an independent receiver model rather than Kapsel's classifier. It compares:

1. current observation-only recovery;
2. exactly one replay of the frozen patch; and
3. a projection of a Temporal Activity with explicit `MaximumAttempts: 2`.

The Temporal row is a semantic projection of documented at-least-once Activity execution. The test
does not claim to execute Temporal.

Each cell below is
`caller invocations / PATCH requests / mutating admission invocations / out-of-band admission effects / persisted Deployment changes / controller effects / authorized actions left unsent / caller conclusions`.

| Scenario                                         | Observe only                      | One frozen replay                 | Temporal projection               |
| ------------------------------------------------ | --------------------------------- | --------------------------------- | --------------------------------- |
| Death immediately before send                    | `1/0/0/0/0/0/1/UNKNOWN`           | `1/1/1/0/1/1/0/SUCCEEDED`         | `1/1/1/0/1/1/0/SUCCEEDED`         |
| Accepted mutation, response lost                 | `1/1/1/0/1/1/0/SUCCEEDED`         | `1/2/2/0/1/1/0/SUCCEEDED`         | `1/2/2/0/1/1/0/SUCCEEDED`         |
| Two callers, identical original preconditions    | `2/2/2/0/1/1/0/SUCCEEDED+UNKNOWN` | `2/2/2/0/1/1/0/SUCCEEDED+UNKNOWN` | `2/2/2/0/1/1/0/SUCCEEDED+UNKNOWN` |
| Intervening writer before recovery               | `1/0/0/0/1/1/1/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           |
| Target deletion and recreation                   | `1/0/0/0/1/1/1/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           | `1/1/1/0/1/1/0/UNKNOWN`           |
| Later template change retaining marker/image     | `1/1/1/0/2/2/0/SUCCEEDED*`        | `1/2/2/0/2/2/0/SUCCEEDED*`        | `1/2/2/0/2/2/0/SUCCEEDED*`        |
| Admission out-of-band effect after response loss | `1/1/1/1/1/1/0/SUCCEEDED`         | `1/2/2/2/1/1/0/SUCCEEDED`         | `1/2/2/2/1/1/0/SUCCEEDED`         |

The concurrent row has two separately authorized operation IDs with the same frozen Deployment
identity, resource version, image, and strategy. Both initial requests run, one persists, and the
other returns a conflict. No ambiguous result is injected in that row, so none of the three recovery
policies adds a request.

`SUCCEEDED*` is only a conclusion from the later observed state. A writer changed the template after
the original patch while retaining its image and marker. The current classifier can use that later
current generation as the requested generation. Neither replay nor Temporal identifies the original
patch generation, so this row is not evidence that the original effect caused the later rollout. The
receipt's no-causation claim remains material.

The live command `./scripts/test-kind-effect-gateway.sh` adds a pinned Kubernetes v1.33.12 proof. An
instrumented mutating webhook records each unique AdmissionReview UID and operation ID as an
out-of-band log effect. The first frozen strategic patch persists and creates one new ReplicaSet.
Replaying the identical stale patch invokes the webhook again, then returns Kubernetes API
`409 Conflict`. The post-replay Deployment UID, resource version, generation, complete desired spec,
operation annotation, both container images, and ReplicaSet count equal the post-first-patch state.

That ordering is expected from the pinned Kubernetes source. Strategic PATCH invokes mutating
admission while producing the updated object inside `GuaranteedUpdate`; storage checks the stale
resource version afterward:

- [PATCH handler admission and update, Kubernetes v1.33.12](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L628-L704)
- [registry storage update checks, Kubernetes v1.33.12](https://github.com/kubernetes/kubernetes/blob/v1.33.12/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L649-L733)

Kubernetes'
[admission webhook good practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
say webhooks should avoid out-of-band side effects and be idempotent. They also permit real-request
side effects through `sideEffects: NoneOnDryRun`. The frozen operation annotation is not a
receiver-enforced idempotency key, so Kapsel cannot assume every admission component deduplicates
it.

## Workflow baseline

Temporal provides durable Workflow Event History, Activity timeouts, and retry scheduling. Its
[Activity execution](https://docs.temporal.io/activity-execution) is at least once, so a worker loss
can execute the Activity again.
[Retry policies](https://docs.temporal.io/encyclopedia/retry-policies) must be explicitly bounded
for this comparison; the projected second attempt uses the original opaque Activity payload and
treats conflict as ambiguity before observation. Temporal does not make the Kubernetes effect atomic
with Activity completion.

An equivalent implementation still needs resident provider authority, a frozen versioned operation
payload, Kubernetes-aware conflict handling, read-only receiver classification, durable receipt
semantics, and admission-side-effect idempotence outside Temporal. Self-hosting also adds the
[Temporal service](https://docs.temporal.io/temporal-service), persistence, schema, worker, upgrade,
and backup operations. The official [SDK Core repository](https://github.com/temporalio/sdk-core)
states that its Rust SDK is under development, adding either an experimental SDK or another worker
language to this Rust repository.

## Decision

Retain observation-only recovery after `apply_started`.

No replay means death before send can abandon an authorized action. This is reported as `UNKNOWN`,
not hidden as success or failure. Exact replay improves that one completion window, but after a lost
response, conflict, or replacement it adds another mutating-admission invocation and can repeat an
out-of-band receiver effect that frozen UID and resource version cannot prevent. No-replay therefore
passes the decision test because it prevents a concrete receiver effect that frozen replay cannot
prevent.

Do not adopt Temporal for this operation. Its bounded Activity retry has the same receiver exposure
as exact replay and does not replace the capability-specific authority, receiver, or receipt logic.
It adds materially more implementation and operational machinery.

For reconnectable callers, continuation is exact: after `apply_started`, a new caller or process
resumes the same operation by observation only. It must not issue a new operation identity, refresh
authority or preconditions, or resend through caller or workflow retry. `UNKNOWN` stops dependent
automation and hands the frozen evidence to a human.

## Consequences and limits

- Kapsel prevents recovery-induced duplicate admission effects. It cannot prevent admission
  reinvocation internal to one API request or duplicates from independent pre-attempt callers.
- Frozen UID/resource-version replay does prevent overwriting an intervening writer or replacement
  Deployment in the tested races. It does not prevent the extra request or admission effect.
- The live result qualifies the pinned v1.33.12 kind receiver, not every Kubernetes version or
  admission implementation.
- Reconsider replay only with a receiver-enforced idempotency key covering the whole admission and
  persistence pipeline, or an enforced admission profile that excludes side effects.
- The later-generation attribution limitation is shared by all three policies and remains visible.
  It is not a reason to count replay as useful completion.
