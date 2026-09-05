# Kapsel contributor guide

This repository owns Kapsel's code, technical contracts, tests, release evidence, and public
technical claims.

## Start here

1. Check Git status and preserve unrelated work.
2. Read [`README.md`](README.md), [`docs/SCOPE.md`](docs/SCOPE.md), and
   [`docs/INDEX.md`](docs/INDEX.md).
3. Read [ADR 0001](docs/decisions/0001-kapsel-style.md) for the design criterion, then follow
   [Contributing](CONTRIBUTING.md), including its
   [complexity review](CONTRIBUTING.md#complexity-review).
4. Read the direct contract, implementation, tests, and vectors for the surface you will change.
5. Run `./scripts/format.sh`; it formats Rust and Markdown and expands Markdown tables.
6. Choose the narrowest useful gate from [`docs/BUILD.md`](docs/BUILD.md).

## Find technical truth

[`docs/SCOPE.md`](docs/SCOPE.md) owns the current product boundary.
[`docs/EFFECT_GATEWAY.md`](docs/EFFECT_GATEWAY.md) owns authorization, lifecycle, receiver-result,
recovery, and receipt semantics. [`docs/INDEX.md`](docs/INDEX.md) routes every other question.

The published `v0.2.0` developer beta and repository HEAD are different promises. Source may contain
unpublished service or installer work; do not present it as a released or supported path until its
release owner says so.

When code and an owner disagree:

1. stop the conflicting edit;
2. compare the direct owner with `docs/SCOPE.md`;
3. correct the canonical owner before implementation; and
4. leave unresolved contradictions visible.

Contracts define behavior. Decisions explain why. Guides describe commands that actually exist.
Tests provide executable evidence.

## Keep the direction visible

Read [Why Kapsel exists](README.md#why-kapsel-exists) as the public technical motivation. Kapsel is
being built as a controlled execution component beneath fallible autonomous systems. Kubernetes is
the first proving ground, not its permanent identity or a general reliability-service promise.

Preserve the separation between authorization, execution evidence, and decision quality. Improve the
concrete operation and its usability under failure rather than adding speculative platform
machinery. The wider direction does not expand the current scope or establish distributed
guarantees.

## Keep the product narrow

- Keep `kubernetes.set_deployment_image` as the only active capability.
- Keep credentials, grants, trust, signing material, paths, and lifecycle controls outside caller
  input.
- Keep authorization, durable ordering, recovery, receiver classification, `UNKNOWN`, and receipts
  inside the deep effect-gateway module.
- Treat MCP as one fixed stdio adapter, not Kapsel's identity or a generic interface.
- Do not add runtime plugins, a provider SDK, policy language, workflow engine, queue, hosted
  control plane, dashboard, second capability, or speculative package seam.
- Never turn timeout, request acceptance, transport completion, or provider ambiguity into receiver
  success or failure.
- Keep public content reproducible and technical. Omit private operational or company context.

## Documentation

Write for a technical reader who is new to this mechanism.

- Keep the high-level idea visible: narrow authority, durable state before the effect,
  observation-only recovery after ambiguity, honest `UNKNOWN`, and an inspectable receipt.
- Explain why a mechanism exists before listing its exact rules.
- Start with the shortest useful mental model or runnable path, then link deeper.
- Use short sections, concrete examples, diagrams, and plain language. Define unavoidable jargon.
- Separate tutorials, how-to guides, explanations, and reference when combining them makes the page
  harder to use.
- Prefer one canonical owner over repeated summaries. Delete stale explanation instead of preserving
  it as another truth source.
- Keep the tone calm and interesting. Fun comes from the engineering ideas and examples, not from
  weakening limits or forcing jokes.

Security and compatibility contracts may be dense when precision requires it. Entry points and
learning material should not make readers cross that density before they understand the idea.

## Validate the change

Documentation-only work still checks local links and anchors, focused terminology, formatting, and
`git diff --check`. Code or contract changes add the smallest owner-specific test before broader
gates. The live Kubernetes lane is separate and requires Docker plus `kind`.

Before finishing, run the narrowest relevant proof and then the owning broader gate when practical.
State what changed, what ran, and what remains unproved. Do not commit or push unless asked.
