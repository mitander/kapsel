# Adapt Tiger Style to Kapsel

Status: accepted.

Kind: decision. Date: 2026-07-11.

Owns: Kapsel's engineering philosophy, simplicity criterion, and use of explicit states, bounds, and
typed failures without copying storage-engine rules literally.

## Context

Kapsel parses hostile bytes, handles cryptographic material, recovers durable operation state, calls
a consequential provider, and emits security-sensitive claims. Idiomatic Rust does not by itself
force bounded work, explicit transition ordering, or a clear distinction between programmer errors
and adversarial input.

Literal TigerBeetle rules target a storage engine with different allocation and latency constraints.
Copying them would add ceremony without sharpening Kapsel's actual risks.

## Decision

### Simplicity is the design criterion

Simple means minimizing the knowledge needed to understand and safely modify Kapsel, not minimizing
lines, types, or tests. Assess complexity through:

- **Change amplification:** how many places must change to revise one rule?
- **Cognitive load:** how many facts must a reader hold to make a correct change?
- **Unknown unknowns:** which dependencies or invariants could a reader miss entirely?

Prefer deep modules with small, complete interfaces. A module should hide a coherent mechanism, not
pass its details through a shorter call signature. Keep domain complexity explicit, including
authority, durable states, bounds, and failure semantics. Hide accidental mechanism complexity
behind the module that owns it. For example, callers should not need to reconstruct journal ordering
to invoke the effect gateway safely.

Give each rule one implementation owner and one documentation owner. Consumers delegate to the
implementation and link to the canonical contract rather than restating the rule. Prefer established
project vocabulary and patterns over local novelty. Remove obsolete paths and explanations instead
of preserving parallel truths.

Before freezing a durable format, public command, configuration surface, package boundary, or
lifecycle transition, require two concrete candidate designs. Compare the knowledge each exposes,
its failure behavior, and the cost of changing it later. Choose the smaller complete boundary, not
necessarily the shorter implementation. This is a design check, not permission to expand product
scope or override a direct contract.

Judge functions and files by cohesion and reasons to change, not arbitrary size limits. Split
unrelated responsibilities, but keep a complete mechanism together when splitting would force
readers to reconstruct it across helpers.

### Tiger-style safety supports simplicity

Explicit states, bounds, and typed failures can require more code while reducing hidden assumptions.
The Tiger-style discipline makes those facts auditable. Simplicity does not justify collapsing
domain states, weakening checks, or hiding uncertainty.

Adopt the discipline, not the costume:

- small, deep interfaces;
- explicit state machines and visible transition ordering;
- named bounds on hostile input, I/O, time, and durable growth;
- assertions for programmer-controlled invariants;
- typed errors for input, operating, and adversarial failures;
- deterministic tests around mutation and recovery seams;
- normal Rust naming; and
- comments only for context code cannot carry.

Allocation remains allowed after bounds are checked. Exact operation semantics live in owner
documents and tests, not the style guide.

## Consequences

The project accepts explicit code in exchange for auditable state and authority transitions. It does
not add custom lint infrastructure until repeated objective drift justifies it. The
[contributor complexity review](../../CONTRIBUTING.md#complexity-review) applies this criterion to
nontrivial architectural or contract changes without imposing a report on mechanical edits.
