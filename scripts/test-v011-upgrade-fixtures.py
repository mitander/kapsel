#!/usr/bin/env python3
"""Generate and verify v0.1.1 upgrade proof fixtures from the exact v0.1.1 source tag."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Callable
import pathlib
import shutil
import subprocess
import tempfile

TAG = "v0.1.1"
TAG_OBJECT = "9085414ad329edfa5afe49577afd1d1409a30a5d"
SOURCE_COMMIT = "ad799b39112ccd6ef06e1ec954c615b6635650f6"
GENERATION_TEST = "gateway::tests::v011_upgrade::v011_fixture_generation"
VERIFICATION_TEST = "gateway::tests::v011_upgrade::v011_fixture_verification"
PROCESS_LOSS_TEST = "gateway::tests::v011_upgrade::v011_process_loss_verification"
OLD_REOPEN_TEST = "gateway::tests::v011_upgrade::v011_marked_fixture_reopen"
MATRIX_TEST = (
    "gateway::tests::v011_upgrade::"
    "v011_upgrade_matrix_names_every_historical_state_and_ambiguity"
)
MODULE = """

mod v011_upgrade {
    use super::*;

    include!(\"v011_upgrade.rs\");
}
"""


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str] | None = None) -> None:
    shown = " ".join(command)
    print(f"+ (cd {cwd} && {shown})", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def output(command: list[str], cwd: pathlib.Path) -> str:
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publish_offline_backups(fixtures: pathlib.Path) -> None:
    for fixture in sorted(fixtures.iterdir()):
        if not fixture.is_dir():
            continue
        source = fixture / "journal.sqlite3"
        backup = pathlib.Path(f"{source}.kapsel-v011.backup")
        sidecar = pathlib.Path(f"{backup}.sha256")
        if backup.exists() or sidecar.exists():
            raise RuntimeError(f"upgrade backup already exists for {fixture.name}")
        shutil.copyfile(source, backup)
        backup.chmod(0o600)
        with backup.open("rb") as handle:
            os.fsync(handle.fileno())
        sidecar.write_text(f"{sha256(backup)}\n")
        sidecar.chmod(0o600)
        with sidecar.open("rb") as handle:
            os.fsync(handle.fileno())
        directory = os.open(fixture, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if sha256(source) != sha256(backup):
            raise RuntimeError(f"offline backup does not match source for {fixture.name}")


def require_sha256(path: pathlib.Path, expected: str, phase: str) -> None:
    actual = sha256(path)
    if actual != expected:
        raise RuntimeError(
            f"historical test overlay changed {phase}: expected {expected}, got {actual}"
        )


def registered_worktrees(root: pathlib.Path) -> set[pathlib.Path]:
    raw = subprocess.check_output(
        ["git", "worktree", "list", "--porcelain", "-z"], cwd=root
    )
    prefix = b"worktree "
    return {
        pathlib.Path(os.fsdecode(field[len(prefix) :])).resolve()
        for field in raw.split(b"\0")
        if field.startswith(prefix)
    }


def cleanup_worktree(
    root: pathlib.Path, historical: pathlib.Path, worktree_parent: pathlib.Path
) -> None:
    historical = historical.resolve()
    removal_failure: str | None = None
    if historical in registered_worktrees(root):
        result = subprocess.run(
            ["git", "worktree", "remove", "--force", str(historical)],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            removal_failure = (
                f"git worktree remove failed for {historical} "
                f"with exit {result.returncode}: {detail}"
            )
    if historical in registered_worktrees(root):
        detail = removal_failure or "git still reports the worktree as registered"
        raise RuntimeError(
            f"refusing filesystem cleanup while stale worktree metadata remains: {detail}"
        )
    shutil.rmtree(worktree_parent)
    if removal_failure is not None:
        raise RuntimeError(removal_failure)


def run_with_cleanup(action: Callable[[], None], cleanup: Callable[[], None]) -> None:
    try:
        action()
    except BaseException as primary_failure:
        try:
            cleanup()
        except BaseException as cleanup_failure:
            raise BaseExceptionGroup(
                "fixture action and cleanup both failed",
                [primary_failure, cleanup_failure],
            ) from None
        raise
    cleanup()


def verify_provenance(root: pathlib.Path) -> None:
    object_type = output(["git", "cat-file", "-t", TAG], root)
    tag_object = output(["git", "rev-parse", TAG], root)
    source_commit = output(["git", "rev-parse", f"{TAG}^{{}}"], root)
    if object_type != "tag":
        raise RuntimeError(f"{TAG} must remain an annotated tag, got {object_type!r}")
    if tag_object != TAG_OBJECT:
        raise RuntimeError(f"{TAG} object changed: {tag_object}")
    if source_commit != SOURCE_COMMIT:
        raise RuntimeError(f"{TAG} peeled commit changed: {source_commit}")


def overlay_harness(root: pathlib.Path, historical: pathlib.Path) -> pathlib.Path:
    source = root / "src/gateway/tests/v011_upgrade.rs"
    destination = historical / "src/gateway/tests/v011_upgrade.rs"
    if destination.exists():
        raise RuntimeError("the historical tag unexpectedly contains the upgrade harness")
    shutil.copyfile(source, destination)
    historical_matrix = historical / "tests/fixtures/v011-upgrade-matrix.json"
    historical_matrix.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        root / "tests/fixtures/v011-upgrade-matrix.json",
        historical_matrix,
    )
    module_file = historical / "src/gateway/tests/mod.rs"
    original = module_file.read_text()
    if "mod v011_upgrade" in original:
        raise RuntimeError("the historical test module already names the upgrade harness")
    module_file.write_text(original.rstrip() + MODULE)
    return destination


def cargo_test_command(test_name: str, ignored: bool) -> list[str]:
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "kapsel",
        "--lib",
        test_name,
        "--",
    ]
    if ignored:
        command.append("--ignored")
    command.extend(["--exact", "--nocapture", "--test-threads=1"])
    return command


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-directory",
        type=pathlib.Path,
        help=(
            "retain fixtures at this new final path; receipt-bearing fixtures must be "
            "verified in place and never copied"
        ),
    )
    parser.add_argument(
        "--self-test-cleanup",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def self_test_cleanup() -> None:
    with tempfile.TemporaryDirectory(prefix="kapsel-v011-upgrade-cleanup-test-") as temporary:
        repository = pathlib.Path(temporary) / "repository"
        repository.mkdir()
        run(["git", "init", "--quiet"], repository)
        run(["git", "config", "user.name", "v0.1.1 upgrade proof cleanup test"], repository)
        run(["git", "config", "user.email", "cleanup-test@example.invalid"], repository)
        (repository / "tracked").write_text("fixture\n")
        run(["git", "add", "tracked"], repository)
        run(["git", "commit", "--quiet", "-m", "fixture"], repository)

        partial_parent = pathlib.Path(temporary) / "partial-parent"
        partial = partial_parent / "source"
        partial_parent.mkdir()

        def partial_action() -> None:
            run(["git", "worktree", "add", "--detach", "--quiet", str(partial)], repository)
            raise RuntimeError("forced failure immediately after worktree registration")

        try:
            run_with_cleanup(
                partial_action,
                lambda: cleanup_worktree(repository, partial, partial_parent),
            )
        except RuntimeError as error:
            if str(error) != "forced failure immediately after worktree registration":
                raise
        else:
            raise AssertionError("the forced primary worktree-add failure was not preserved")
        if partial_parent.exists() or partial.resolve() in registered_worktrees(repository):
            raise AssertionError("partial worktree registration was not cleaned")

        locked_parent = pathlib.Path(temporary) / "locked-parent"
        locked = locked_parent / "source"
        locked_parent.mkdir()
        run(["git", "worktree", "add", "--detach", "--quiet", str(locked)], repository)
        run(["git", "worktree", "lock", "--reason", "cleanup-test", str(locked)], repository)
        try:
            cleanup_worktree(repository, locked, locked_parent)
        except RuntimeError as error:
            if "stale worktree metadata remains" not in str(error):
                raise
        else:
            raise AssertionError("locked worktree cleanup failure was not observable")
        if locked.resolve() not in registered_worktrees(repository) or not locked_parent.exists():
            raise AssertionError("failed Git cleanup removed registered worktree storage")
        run(["git", "worktree", "unlock", str(locked)], repository)
        cleanup_worktree(repository, locked, locked_parent)

        primary = RuntimeError("primary fixture failure")
        cleanup = RuntimeError("cleanup failure")
        try:
            run_with_cleanup(
                lambda: (_ for _ in ()).throw(primary),
                lambda: (_ for _ in ()).throw(cleanup),
            )
        except BaseExceptionGroup as failures:
            if failures.exceptions != (primary, cleanup):
                raise AssertionError("primary and cleanup failures were not both preserved")
        else:
            raise AssertionError("combined primary and cleanup failure was not reported")
    print("cleanup failure self-test: OK", flush=True)


def main() -> None:
    args = parse_args()
    if args.self_test_cleanup:
        self_test_cleanup()
        return
    root = pathlib.Path(__file__).resolve().parent.parent
    matrix = root / "tests/fixtures/v011-upgrade-matrix.json"
    verify_provenance(root)

    automatic_output: tempfile.TemporaryDirectory[str] | None = None
    if args.output_directory is None:
        automatic_output = tempfile.TemporaryDirectory(prefix="kapsel-v011-upgrade-fixtures-")
        fixtures = pathlib.Path(automatic_output.name) / "v011"
    else:
        fixtures = args.output_directory.expanduser().resolve()
        fixtures.parent.mkdir(parents=True, exist_ok=True)
        if fixtures.exists():
            raise RuntimeError(f"fixture output must not already exist: {fixtures}")

    worktree_parent = pathlib.Path(tempfile.mkdtemp(prefix="kapsel-v011-upgrade-source-"))
    historical = worktree_parent / "source"
    target = root / "target/v011-upgrade-fixtures"

    def generate_and_verify() -> None:
        run(["git", "worktree", "add", "--detach", "--quiet", str(historical), TAG], root)
        harness = overlay_harness(root, historical)
        harness_sha256 = sha256(harness)
        base_environment = os.environ.copy()
        base_environment["KAPSEL_V011_UPGRADE_FIXTURES"] = str(fixtures)
        base_environment["KAPSEL_V011_UPGRADE_HARNESS_SHA256"] = harness_sha256
        base_environment["KAPSEL_V011_UPGRADE_MATRIX"] = str(matrix)
        current_environment = base_environment.copy()
        current_environment["CARGO_TARGET_DIR"] = str(target / "current")
        historical_environment = base_environment.copy()
        historical_environment["CARGO_TARGET_DIR"] = str(target / "historical")
        # The v0.1.1 adapter predates the receiver-observation outcome binding. The
        # overlaid harness carries both observe forms; this cfg selects the historical one.
        historical_environment["RUSTFLAGS"] = (
            "--cfg=historical_v011 --check-cfg=cfg(historical_v011)"
        )

        run(cargo_test_command(MATRIX_TEST, ignored=False), root, current_environment)
        require_sha256(harness, harness_sha256, "before historical Cargo invocation")
        run(
            cargo_test_command(GENERATION_TEST, ignored=True),
            historical,
            historical_environment,
        )
        require_sha256(harness, harness_sha256, "after historical Cargo invocation")
        print(
            f"historical compiled overlay sha256 verified: {harness_sha256}",
            flush=True,
        )
        publish_offline_backups(fixtures)
        print("published owner-private offline backups and SHA-256 sidecars", flush=True)
        run(cargo_test_command(PROCESS_LOSS_TEST, ignored=True), root, current_environment)
        print(
            "verified candidate process loss at migration and restore seams",
            flush=True,
        )
        run(cargo_test_command(VERIFICATION_TEST, ignored=True), root, current_environment)
        run(cargo_test_command(OLD_REOPEN_TEST, ignored=True), historical, historical_environment)
        print(
            f"verified nine provenance-bound v0.1.1 fixtures in place at {fixtures}",
            flush=True,
        )
        if args.output_directory is None:
            print("temporary fixtures will now be removed", flush=True)
        else:
            print(
                "retained receipt paths are absolute; do not copy or relocate this directory",
                flush=True,
            )

    def cleanup() -> None:
        failures: list[Exception] = []
        try:
            cleanup_worktree(root, historical, worktree_parent)
        except Exception as error:
            failures.append(error)
        if automatic_output is not None:
            try:
                automatic_output.cleanup()
            except Exception as error:
                failures.append(error)
        if failures:
            raise ExceptionGroup("fixture resource cleanup failed", failures)

    run_with_cleanup(generate_and_verify, cleanup)


if __name__ == "__main__":
    main()
