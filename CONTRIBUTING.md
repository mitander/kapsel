# Contributing to Kapsel

Start by checking Git status and preserving unrelated work. Then read
[Why Kapsel exists](README.md#why-kapsel-exists), the [technical scope](docs/SCOPE.md), the
[documentation map](docs/INDEX.md), and the direct contract, implementation, tests, and vectors for
the surface you will change. Contracts own behavior; decisions explain why; guides own runnable
commands; tests provide executable evidence.

The published v0.2.0 developer beta and repository HEAD are different promises. The service and
installer in HEAD remain unpublished. Link their exact owners rather than presenting them as
released or supported.

## Engineering rules

Prioritize the boundaries that make Kapsel useful:

1. Preserve authority and effect boundaries.
2. Make durable states and transitions explicit.
3. Bound hostile input and resource use before allocation, I/O, or diagnostics.
4. Keep provider acceptance, receiver observation, and transport outcomes distinct.
5. Prefer small, deep interfaces over reusable frameworks.
6. Test contracts at the layer that owns them.

The [technical scope](docs/SCOPE.md) owns the product boundary. The
[effect-gateway contract](docs/EFFECT_GATEWAY.md) owns exact authorization, lifecycle, recovery,
receiver-result, and receipt semantics. Do not duplicate those contracts here.

### Hostile input and operating failures

Untrusted bytes must not acquire authority from their contents, trigger network access during
offline inspection, panic the gateway or inspector, allocate or recurse without enforced bounds, or
advance evidence state without the required external fact. Use checked arithmetic and conversions
for hostile lengths. Bound individual items, cumulative work, and diagnostics.

Use always-on assertions only for invariants controlled by valid internal code. Return typed errors
for caller input, signatures, trust, provider responses, time, configuration, filesystem, SQLite,
and other operating failures. Never assert a fact controlled by a caller, receiver, or provider.
Production `expect()` calls must state the invariant that makes the panic unreachable; do not use an
unexplained `unwrap()` where an operating or adversarial failure is possible.

### Types, interfaces, and modules

Keep these facts distinct in types and exhaustive states where collapsing them could change security
meaning. Avoid wildcard matches when adding an enum variant should force a policy decision:

```text
bounded request
  -> authorized operation
  -> durable mutation attempt
  -> provider acceptance
  -> receiver observation
  -> classified outcome
  -> signed disclosure
  -> inspected under supplied trust
```

Pass authority, time, trust, paths, and limits explicitly. A helper must not discover them through
the environment, filesystem, network, or ambient configuration.

A function should perform one coherent phase at one level of abstraction. Treat length as a review
prompt, not a metric: split validation, mutation, I/O, and presentation when they represent distinct
responsibilities, not merely to satisfy a line count. Use identity and unit newtypes when accidental
interchange would compile and could change meaning.

Add an interface only when it contains policy, preserves a durable state or format owner, keeps I/O
from pure logic, maintains dependency direction, or provides a useful deterministic seam. Prefer a
concrete type or exhaustive enum until multiple real consumers establish the need for a trait or
generic framework. Prefer `pub(crate)` or narrower visibility. Avoid generic `util`, `common`,
provider, or package seams without multiple real consumers or a measured dependency boundary. Name
functions for the fact they establish.

### Documentation and dependencies

Public Rust documentation states caller-visible input, bounds, authority, side effects, failures,
and important non-claims. Every externally reachable public item needs rustdoc. Public `Result`
functions need `# Errors`; document caller-reachable panics with `# Panics`, though removing the
panic is usually better. Unsafe APIs require `# Safety`; this workspace currently forbids unsafe
code, and any exception requires an explicit security review and accepted decision. Use applicable
rustdoc sections in this order: `# Errors`, `# Panics`, `# Safety`, `# Cancellation safety`,
`# Performance` or `# Complexity`, platform-specific behavior, then `# Examples`. Examples compile
as doctests and handle errors without `unwrap()` or `expect()`.

Prefer a better name, type, state, assertion, or smaller scope over a comment. Comments should
explain a non-local invariant, security or crash-recovery subtlety, compatibility constraint, or why
the obvious alternative is wrong. Dependencies are design choices; use maintained cryptographic and
encoding libraries rather than custom implementations.

## Tests and commands

Place a test at the lowest layer whose interface owns the behavior. Higher layers prove composition,
authority separation, durable outcomes, observable output, and non-disclosure instead of repeating
the same parser or classifier matrix. The [testing strategy](docs/TESTING.md) owns proof placement
and evidence classes; [Build and test](docs/BUILD.md) owns commands and prerequisites.

Authored Rust has a 100-byte physical-line limit. Reshape expressions rather than shortening precise
names or adding an abstraction solely to satisfy the limit. Keep embedded SQL readable and
multiline. Markdown prose wraps at 100 columns; tables, URLs, and code blocks are exempt where
wrapping harms clarity. Automate only objective, stable rules; naming, module ownership, comments,
and abstraction quality remain review judgments. Before review, run:

```sh
./scripts/format.sh
./scripts/ci-local.sh
```

Use the narrowest owning gate first when the full deterministic gate is impractical.
Documentation-only changes still require formatting, local link and anchor checks, focused
terminology checks, and `git diff --check`.

## Commits and review

Use a plain domain-oriented, imperative commit subject:

```text
<domain>: <imperative result>
```

Examples: `k8s: preserve receiver generation across recovery` and
`docs: tighten the active capability contract`.

Before handing off a change, check:

- the direct contract owner is correct and no second source of truth was introduced;
- caller input gained no authority, credential, path, lifecycle control, or unbounded field;
- durable state is committed before its effect and recovery cannot blindly repeat a mutation;
- request acceptance, timeout, crash, or transport completion cannot become a receiver result;
- `SUCCEEDED`, `FAILED`, `UNKNOWN`, `NOT_ATTEMPTED`, and `INSPECTED` retain their exact
  owner-defined meanings;
- trust, time, limits, and authority are explicit rather than ambient;
- operating and adversarial failures are typed, bounded, and non-disclosing;
- new interfaces and dependencies have a current concrete need;
- tests sit at the owning layer and the narrowest meaningful gate passed; and
- documentation links resolve, status is current, and the diff contains no stale or duplicated
  truth.

State what changed, what ran, and what remains unproved. No mandatory report template is required.
