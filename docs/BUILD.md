# Build and test Kapsel

Use this page to find runnable commands and prerequisites. [Testing](TESTING.md) explains proof
strategy; direct contracts own behavior and evidence limits.

## Prerequisites

The deterministic gate uses Rust 1.98, rustfmt from nightly-2026-07-03, Python 3.11+, Node.js 24,
and Prettier 3.6.2 as pinned by the repository. Additional lanes require:

- Docker, kind 0.32+, kubectl 1.30+, and OpenSSL for live Kubernetes;
- kubectl 1.30+ for the public demonstration;
- cargo-fuzz 0.13+ and the pinned Rust nightly for fuzzing;
- Linux and `sg` for the ignored distinct-effective-group service test;
- Docker with `linux/amd64` support and OpenSSL for the installer bundle lane;
- Docker for release-artifact lanes; and
- Docker, kind, kubectl, cargo-fuzz, Rust nightly, cargo-audit 0.22.2, Trivy 0.72.0 with current
  databases, the pinned builder image, and the host Cargo registry for finite qualification.

## Deterministic gate and formatting

Run the complete local gate:

```sh
./scripts/ci-local.sh
```

Format Rust and Markdown, or check formatting without changing files:

```sh
./scripts/format.sh
./scripts/format.sh --check
```

Use the tracked pre-commit and pre-push hooks:

```sh
git config core.hooksPath .githooks
```

If `git config core.hooksPath` already reports a custom path, inspect it before replacing it. The
pre-commit hook runs formatting, Rust width, native workspace Clippy, and the portable installer
package tests. It is offline-capable after Cargo dependencies are present and never starts Docker.
It refuses unstaged or untracked files so the checked worktree is the staged snapshot.

The pre-push hook consumes Git's pushed-ref list. Deletion-only pushes need no content gate. Every
other pushed object must resolve to the current `HEAD` tree, and the worktree must be clean. The
hook records that exact tree under `.git` after the complete local gate passes and skips a later
push of the same tree. The complete gate checks formatting, Rust line width, native Clippy with
warnings denied, rustdoc with warnings denied, deterministic Rust tests, doctests, Markdown links,
and link-checker regressions. It does not start Docker.

## Focused gates

| Change                           | Smallest useful command                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------ |
| Effect-gateway library           | `cargo test --locked -p kapsel`                                                            |
| Effect-gateway Clippy            | `cargo clippy --locked -p kapsel --all-targets -- -D warnings`                             |
| Kapsel service                   | `cargo test --locked -p kapseld --features test-harness`                                   |
| Service operator-input seam      | `cargo test --locked -p kapsel-authority`                                                  |
| Installer skeleton               | `cargo test --locked -p kapsel-installer`                                                  |
| Linux-only installer/bundle code | `python3 scripts/test-kapsel-installer-bundle.py`                                          |
| Debian 12 identity argv contract | `./scripts/test-debian12-installer-identities.sh`                                          |
| Service installed assets         | `cargo test --locked -p kapseld --test install_assets`                                     |
| MCP adapter                      | `cargo test --locked --test e2e_mcp_adapter`                                               |
| Upgrade and rollback             | `python3 scripts/test-v011-upgrade-fixtures.py`                                            |
| Crash-demo harness               | `./scripts/test-demo-harness.sh`                                                           |
| Seeded lifecycle simulation      | `./scripts/test-simulation.sh`                                                             |
| Receipt-inspection fuzz smoke    | `./scripts/test-fuzz.sh`                                                                   |
| Live Kubernetes behavior         | `./scripts/test-kind-effect-gateway.sh`                                                    |
| Full local demonstration         | `./scripts/demo-kind-crash-recovery.sh`                                                    |
| Release artifact                 | `python3 scripts/assemble-release-artifact.py --output-directory dist`                     |
| Finite beta qualification        | `python3 scripts/run-beta-qualification.py --output /tmp/beta-qualification-baseline.json` |

## Kapsel service candidate

The service in repository HEAD is unpublished. Run its package, lint, and private-harness gates:

```sh
cargo test --locked -p kapseld
cargo clippy --locked -p kapseld --all-targets -- -D warnings
cargo test --locked -p kapseld --features test-harness
```

Run the Linux-only process test:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process
```

On Linux with `sg`, run the ignored distinct-effective-group case:

```sh
cargo test --locked -p kapseld --features test-harness --test linux_process \
  distinct_effective_gid_is_denied_before_frame_read -- --ignored --exact
```

See [Kapsel service](KAPSEL_SERVICE.md) for exact service evidence and limits.

## Kapsel installer skeleton

The installer in repository HEAD is partial and unpublished. Run its fixed authority seam and
portable package gates:

```sh
cargo test --locked -p kapsel-authority
```

```sh
cargo test --locked -p kapsel-installer
cargo clippy --locked -p kapsel-installer --all-targets --all-features -- -D warnings
```

Run the Linux/Docker bundle scenarios:

```sh
python3 scripts/test-kapsel-installer-bundle.py
```

CI enforces this lane after native Linux workspace Clippy. Default builds stop at
`bundle_unavailable`; the Docker lane uses test-only staged payloads to run the ignored, named Rust
integration tests in `linux_installer_scenarios`. Those tests own the HTTPS fixture, fake host
state, transaction parsing, process control, and assertions for crash, ambiguity, conflict, timeout,
lock, rollback, preflight, transaction, and native-tool cases. The Python wrapper only stages the
bundle and operator input, generates disposable TLS material, mounts caches, and starts the
container.

The launcher binds three build-only caches below `~/.cache/kapsel/installer`, or below
`KAPSEL_INSTALLER_CACHE_DIR` when set. The cache key includes the pinned builder digest, Rust 1.98,
`x86_64-unknown-linux-gnu`, and `Cargo.lock`. The staged bundle, operator input, fake host, TLS
server state, transaction state, and process state remain fresh for every container. A warm run
therefore avoids toolchain synchronization, registry downloads, and unchanged dependency compilation
without reusing test-host evidence. CI persists only those build caches.

[Architecture](ARCHITECTURE.md#partial-installer) summarizes the current implementation, and
[Kapsel service](KAPSEL_SERVICE.md) owns its exact boundary.

Run the separate direct identity experiment against its pinned Debian 12 x86-64 container:

```sh
./scripts/test-debian12-installer-identities.sh
```

This experiment requires Docker, network access to install `sudo` inside the disposable container,
and `linux/amd64` execution. It qualifies approved useradd argv and recovery observations. It does
not implement or qualify installer user creation, and remains separate from the single
installer-through-native-tools composition scenario in the bundle lane.

### Installer runtime profile

On the pre-refactor macOS host, warm native workspace Clippy took 0.71 seconds. The old cold
Linux/Docker bundle command exceeded its 1,200-second bound while synchronizing Rust, downloading
the registry, and compiling dependencies.

After the portable split, warm native workspace Clippy took 0.27 seconds and the portable installer
package tests took 5.24 seconds. On the same arm64 macOS host, initial cache fill exceeded 1,500
seconds and the resumed emulated `linux/amd64` dependency compilation exceeded 2,100 seconds. A
post-migration debug Linux check completed in 47.76 seconds and warm Linux Clippy in 5.85 seconds,
but a release integration build still exceeded a further 600-second bound under emulation. Each
stopped attempt had its disposable container removed.

On native x86-64 Linux with the pinned builder image already present, an empty build cache completed
all nine release-mode scenarios in 139 seconds. An unchanged warm rerun completed in 61 seconds
without toolchain synchronization, registry downloads, or dependency compilation. The separate
Debian 12 identity experiment completed in 20 seconds. The persistent cache retained only build
inputs and compiler output. The launcher allows 2,400 seconds for cache fill and execution, leaving
five minutes for the 45-minute CI job's setup and cleanup.

## Upgrade and rollback fixture gate

Run the source fixture matrix without Kubernetes or network access:

```sh
python3 scripts/test-v011-upgrade-fixtures.py
```

See [Upgrade and rollback](UPGRADE.md) for supported behavior and limits.

## Robustness lanes

Check the fuzz target with the pinned nightly, or run the bounded smoke script:

```sh
rustup run nightly-2026-07-03 cargo fuzz check --manifest-path fuzz/Cargo.toml inspect_receipt
./scripts/test-fuzz.sh
```

For a longer session, run `cargo +nightly fuzz run inspect_receipt` from `fuzz/`.

Run the seeded lifecycle simulation:

```sh
./scripts/test-simulation.sh
```

Override its defaults for replay or a longer run:

```sh
KAPSEL_SIMULATION_SEED=21182435914953528 \
KAPSEL_SIMULATION_CASES=10000 \
./scripts/test-simulation.sh
```

## Candidate qualification

Run every finite qualification lane against one committed clean candidate:

```sh
python3 scripts/run-beta-qualification.py --output /tmp/beta-qualification-baseline.json
```

Validate the resulting baseline:

```sh
python3 scripts/validate-beta-qualification-baseline.py \
  /absolute/beta-qualification-baseline.json
```

Qualification is finite candidate evidence, not a production or support claim.

## Live Kubernetes gate

With Docker, kind 0.32+, kubectl 1.30+, and OpenSSL:

```sh
./scripts/test-kind-effect-gateway.sh
```

The script owns creation, failure-log export, and cleanup of its uniquely named cluster. It also
installs an instrumented mutating webhook and proves on the pinned Kubernetes v1.33.12 receiver that
an identical stale patch reaches admission again without a second Deployment or controller effect.
This lane is separate from deterministic CI.

## Public crash-recovery demonstration

With Docker, kind 0.32+, kubectl 1.30+, and Python 3.11+:

```sh
./scripts/demo-kind-crash-recovery.sh
```

Test the demonstration harness without Docker:

```sh
./scripts/test-demo-harness.sh
```

## Evaluator CLI

Build the executable:

```sh
cargo build --locked --bin kapsel
```

Run its fixed forms:

```sh
target/debug/kapsel provision-grant \
  --authorization /absolute/authorization.json \
  --signing-seed /absolute/owner.seed \
  --signing-key-id owner-key \
  --output /absolute/grant.bin

target/debug/kapsel operate \
  --request /absolute/request.json \
  --operator-config /absolute/operator.json

target/debug/kapsel inspect \
  --receipt /absolute/result.receipt \
  --trust /absolute/receipt.trust \
  --evaluation-time-unix-s 150
```

See [Evaluator commands](COMMANDS.md) for input, authority, output, and exit contracts.

## MCP adapter

Run the black-box proof and start the fixed stdio process:

```sh
cargo test --locked --test e2e_mcp_adapter
target/debug/kapsel mcp --operator-config /absolute/operator.json
```

See [MCP](MCP.md) for protocol details.

## Release artifact

The sole release target is `x86_64-unknown-linux-gnu`. Assemble files under `dist/`:

```sh
python3 scripts/assemble-release-artifact.py --output-directory dist
```

Run the complete two-assembly proof outside the worktree:

```sh
a_dir=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-release-a.XXXXXX")
archive_a=$(python3 scripts/assemble-release-artifact.py --output-directory "$a_dir")
python3 scripts/test-release-artifact.py --archive "$archive_a"
python3 scripts/test-release-reproducibility.py --reference-archive "$archive_a"
```

Remove `"$a_dir"` afterward. [Release artifacts](RELEASE.md) owns layout, authentication,
publication, evidence, and withdrawal rules.

From an extracted artifact top-level directory, run the live demonstration:

```sh
./share/kapsel/demo-kind-crash-recovery.sh
```

Or run a named archive from a checkout:

```sh
python3 scripts/smoke-release-artifact.py \
  --archive /absolute/kapsel-<version>-x86_64-unknown-linux-gnu.tar.gz \
  --live-demo
```

## Coverage

Generate informational source coverage:

```sh
cargo llvm-cov --locked --workspace --codecov --output-path codecov.json
```

Coverage is non-blocking information, not correctness evidence.

## Toolchain ownership

Executable build inputs are `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`,
`rustfmt-nightly.toml`, `clippy.toml`, `.github/workflows/ci.yml`, `scripts/format.sh`, and
`scripts/ci-local.sh`. When prose and an executable command disagree, correct the guide and its
direct contract before relying on the prose.
