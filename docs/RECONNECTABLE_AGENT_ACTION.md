# Reconnectable agent action experiment

Status: stopped at the first authority gap; no Kubernetes mutation was attempted.

Kind: experiment evidence.

Owns: Why the current service cannot yet run an agent workflow whose approval freezes an exact
Deployment identity and expected-state preconditions.

Does not own: A new grant format, authorization policy, observation lifecycle, agent integration, or
product decision.

## Intended workflow

The experiment asked whether an operator could approve one exact Deployment image change, let an
agent submit it through the fixed service client, lose both caller and service processes, and let a
later caller continue from the same durable operation identity without guessing or mutating again.
The approval had to bind the target identity and expected-state preconditions so a change or
recreation after approval could not silently refresh them.

The current service otherwise has the required shape. The caller supplies only the stable operation
identity and bounded image-change tuple. `kapseld` owns execution independently of the caller. A new
client can read status and retrieve the frozen receipt by operation identity. Recovery after
`apply_started` follows the accepted observation-only policy and cannot send a second patch.

## Stop condition

The signed grant's authorization statement contains exactly:

```text
authorization identity
operation identity
namespace
Deployment name
container name
immutable image digest
```

It contains no Deployment UID or resource version. The service accepts the same request tuple from
the caller. Only after submission and grant verification does the Kubernetes adapter read the
current Deployment. The gateway then freezes that observed UID and resource version when it commits
`apply_started`, immediately before the conditional patch.

These conditional-patch preconditions protect against a target replacement or intervening write
between target identification and patch persistence. They do not preserve the target identity or
resource version that existed when the operator approved the grant. If the named Deployment changes
or is deleted and recreated between approval and submission, the current service can read the later
object and freeze its later UID and resource version. The authorization still matches because those
facts were never part of it.

That violates the experiment's authority condition before the agent integration or live mutation
begins. Running the remaining workflow would demonstrate a weaker, name-bound approval and could not
satisfy the stated acceptance criteria. The experiment therefore stopped without creating a kind
cluster or issuing a Kubernetes request.

## Smallest semantic gap

Kapsel has no contract for operator-approved receiver preconditions that survive the interval
between grant creation and target identification.

Before this workflow can continue, the authorization owner must decide:

- which receiver identity and expected-state facts the operator approves;
- how those facts are represented in a new or explicitly versioned authorization statement;
- whether a stale approved precondition becomes `NOT_ATTEMPTED` and with which bounded rejection;
- how compatibility with existing grants remains honest; and
- which facts may cross the caller response and signed receipt boundaries.

This is an authority and compatibility decision, not a service-client retry or workflow-history
problem. The agent must not compensate by reading Kubernetes, minting a new operation identity, or
asking Kapsel to refresh preconditions after approval.

## Evidence boundary

This result comes from the checked-in authorization grammar, service protocol, and lifecycle order.
No paid model call, live cluster, provider request, service fault injection, receipt inspection, or
45–180 second rollout observation was needed or claimed. Those later acceptance steps remain
unproved until the authority gap is resolved.
