use std::{
    collections::BTreeSet,
    fs, io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use rusqlite::{types::Value as SqlValue, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TAG_OBJECT: &str = "9085414ad329edfa5afe49577afd1d1409a30a5d";
const SOURCE_COMMIT: &str = "ad799b39112ccd6ef06e1ec954c615b6635650f6";
const FIXTURE_FORMAT: &str = "kapsel.v011-upgrade.fixture-manifest.v1";
const MATRIX_FORMAT: &str = "kapsel.v011-upgrade.matrix.v1";
const OPERATION_ID: &str = "op-001";
const RECEIPT_KEY_ID: &str = "v011-upgrade-receipt-key";
const NEW_BINARY: &str = "v0.2.0 candidate journal opener";
const BACKUP_FACT: &str =
    "owner_private_offline_raw_copy_matches_source_and_sha256_before_atomic_marker";
const PERMITTED_OPERATOR_ACTION: &str =
    "start_or_reopen_v020; exact_v011_direct_reopen; verified_backup_restore_before_retry";
const MATRIX_BYTES: &[u8] =
    include_bytes!("../../../tests/fixtures/v011-upgrade-matrix.json");
const MIGRATION_SEAMS: &[&str] = &[
    "before_exclusive_transaction",
    "marker_set_inside_exclusive_transaction",
    "after_marker_commit",
];
/// Nullable columns the format-3 journal appends to every recognized layout.
const SNAPSHOT_COLUMN_NAMES: [&str; 4] = [
    "approved_uid",
    "approved_resource_version",
    "preflight_uid",
    "preflight_resource_version",
];
const RESTORE_SEAMS: &[&str] = &[
    "before_publication",
    "after_synchronized_quarantine",
    "after_atomic_replacement",
];

struct FixtureCase {
    name: &'static str,
    state: &'static str,
    crash_point: &'static str,
    provider_call_count: usize,
    receipt_identity: &'static str,
}

const FIXTURE_CASES: &[FixtureCase] = &[
    FixtureCase {
        name: "requested",
        state: "requested",
        crash_point: "after_requested_commit",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "authorized",
        state: "authorized",
        crash_point: "after_authorized_commit",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "not_attempted",
        state: "not_attempted",
        crash_point: "after_target_rejected_commit",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "apply_started_before_call",
        state: "apply_started",
        crash_point: "after_apply_started_commit_before_provider_call",
        provider_call_count: 0,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "apply_started_after_side_effect",
        state: "apply_started",
        crash_point: "process_loss_after_one_provider_side_effect_before_response",
        provider_call_count: 1,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "receiver_observed",
        state: "receiver_observed",
        crash_point: "after_receiver_observed_commit",
        provider_call_count: 1,
        receipt_identity: "absent",
    },
    FixtureCase {
        name: "receipt_prepared",
        state: "receipt_prepared",
        crash_point: "after_receipt_prepared_commit_before_publication",
        provider_call_count: 1,
        receipt_identity: "frozen_in_journal_not_published",
    },
    FixtureCase {
        name: "receipt_written",
        state: "receipt_written",
        crash_point: "after_receipt_written_commit",
        provider_call_count: 1,
        receipt_identity: "frozen_and_published",
    },
    FixtureCase {
        name: "finalized",
        state: "finalized",
        crash_point: "after_finalized_commit",
        provider_call_count: 1,
        receipt_identity: "frozen_and_published",
    },
];

struct SideEffectAdapter {
    ready_path: PathBuf,
    call_count_path: PathBuf,
}

struct MutationChild {
    child: Option<Child>,
}

impl MutationChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.as_mut().unwrap().try_wait()
    }

    fn terminate_and_wait(&mut self) -> io::Result<ExitStatus> {
        let status = {
            let child = self.child.as_mut().unwrap();
            if child.try_wait()?.is_none() {
                if let Err(kill_error) = child.kill() {
                    if child.try_wait()?.is_none() {
                        return Err(kill_error);
                    }
                }
            }
            child.wait()?
        };
        self.child = None;
        Ok(status)
    }
}

impl Drop for MutationChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[allow(unexpected_cfgs)]
#[allow(
    clippy::unused_async_trait_impl,
    reason = "the fixture adapter mirrors the production async provider seam"
)]
impl DeploymentImageAdapter for SideEffectAdapter {
    async fn identify(
        &mut self,
        _: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        Ok(TargetIdentity {
            deployment_uid: "deployment-uid-1".into(),
            resource_version: "resource-version-0".into(),
        })
    }

    async fn apply(
        &mut self,
        _: &SetDeploymentImageRequest,
        _: &TargetIdentity,
    ) -> Result<ApplyOutcome, ()> {
        fs::write(&self.call_count_path, b"1").map_err(|_| ())?;
        fs::write(&self.ready_path, b"provider-side-effect-complete").map_err(|_| ())?;
        std::future::pending::<Result<ApplyOutcome, ()>>().await
    }

    // The v0.1.1 adapter seam predates the receiver-observation outcome binding. The
    // historical upgrade build selects its two-parameter observe via `--cfg=historical_v011`
    // supplied by scripts/test-v011-upgrade-fixtures.py.
    #[cfg(historical_v011)]
    async fn observe(
        &mut self,
        _: &SetDeploymentImageRequest,
    ) -> Result<ReceiverObservation, ()> {
        Err(())
    }

    #[cfg(not(historical_v011))]
    async fn observe(
        &mut self,
        _: &SetDeploymentImageRequest,
        _: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        Err(())
    }
}

#[test]
fn v011_upgrade_matrix_names_every_historical_state_and_ambiguity() {
    let matrix: Value = serde_json::from_slice(MATRIX_BYTES).unwrap();
    assert_eq!(required_str(&matrix, "format"), MATRIX_FORMAT);
    let old_binary = format!(
        "v0.1.1 lifecycle test binary built from tagged source {SOURCE_COMMIT} with the recorded \
         test-only harness overlay"
    );
    let new_binary = NEW_BINARY;
    assert_eq!(required_str(&matrix, "old_binary"), old_binary);
    assert_eq!(required_str(&matrix, "new_binary"), new_binary);
    let cases = matrix["cases"].as_array().unwrap();
    assert_eq!(cases.len(), FIXTURE_CASES.len());
    let mut names = BTreeSet::new();
    for (actual, expected) in cases.iter().zip(FIXTURE_CASES) {
        assert!(names.insert(required_str(actual, "name")));
        assert_eq!(required_str(actual, "name"), expected.name);
        assert_eq!(required_str(actual, "initial_state"), expected.state);
        assert_eq!(required_str(actual, "crash_point"), expected.crash_point);
        assert_eq!(required_str(actual, "expected_state"), expected.state);
        assert_eq!(required_str(actual, "old_binary"), old_binary);
        assert_eq!(required_str(actual, "new_binary"), new_binary);
        assert_eq!(
            actual["provider_call_count"].as_u64().unwrap(),
            expected.provider_call_count as u64
        );
        assert_eq!(
            required_str(actual, "receipt_identity"),
            expected.receipt_identity
        );
        assert_eq!(required_str(actual, "backup_fact"), BACKUP_FACT);
        assert_eq!(
            required_str(actual, "permitted_operator_action"),
            PERMITTED_OPERATOR_ACTION
        );
    }
}

#[test]
#[ignore = "invoked by the pinned-tag v0.1.1 upgrade proof fixture generation script"]
fn v011_fixture_mutation_child() {
    if std::env::var_os("KAPSEL_V011_UPGRADE_MUTATION_CHILD").is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_DATABASE").unwrap());
    let ready_path = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_READY").unwrap());
    let call_count_path =
        PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_CALL_COUNT").unwrap());
    let mut gateway = Gateway::open_for_test(database).unwrap();
    let mut adapter = SideEffectAdapter {
        ready_path,
        call_count_path,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(gateway.run_once_with_adapter(&mut adapter, None))
        .unwrap();
    unreachable!("the fixture parent must stop this process after the side effect");
}

#[tokio::test]
#[ignore = "invoked only in an overlaid, detached v0.1.1 source worktree"]
async fn v011_fixture_generation() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.1");
    let output = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_FIXTURES").unwrap());
    assert!(!output.exists(), "fixture output must not already exist");
    create_private_directory(&output);
    let output = fs::canonicalize(output).unwrap();
    for case in FIXTURE_CASES {
        generate_fixture(&output, case).await;
    }
}

#[test]
#[ignore = "invoked by the v0.1.1 upgrade proof real-process matrix parent"]
fn v011_migration_open_child() {
    if std::env::var_os("KAPSEL_V011_UPGRADE_MIGRATION_CHILD").is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_DATABASE").unwrap());
    drop(Gateway::open_for_test(database).unwrap());
    unreachable!("the migration child must park at its selected seam");
}

#[test]
#[ignore = "invoked by the v0.1.1 upgrade proof hot-rollback recovery parent"]
fn v011_migration_recovery_child() {
    if std::env::var_os("KAPSEL_V011_UPGRADE_RECOVERY_CHILD").is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_DATABASE").unwrap());
    drop(Gateway::open_for_test(database).unwrap());
    unreachable!("the recovery child must park after hot rollback and before re-marking");
}

#[test]
#[ignore = "invoked by the v0.1.1 upgrade proof real-process restore parent"]
fn v011_restore_child() {
    if std::env::var_os("KAPSEL_V011_UPGRADE_RESTORE_CHILD").is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_DATABASE").unwrap());
    let seam = std::env::var("KAPSEL_V011_UPGRADE_RESTORE_SEAM").unwrap();
    run_test_restore_protocol(&database, &seam);
    unreachable!("the restore child must park at its selected seam");
}

#[test]
#[ignore = "invoked by the v0.1.1 upgrade proof malformed restore-path parent"]
fn v011_restore_recovery_child() {
    if std::env::var_os("KAPSEL_V011_UPGRADE_RESTORE_RECOVERY_CHILD").is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_DATABASE").unwrap());
    recover_test_restore(&database);
}

#[test]
#[ignore = "invoked against freshly generated v0.1.1 fixtures"]
fn v011_process_loss_verification() {
    let output = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_FIXTURES").unwrap());
    let output = fs::canonicalize(output).unwrap();
    for case in FIXTURE_CASES {
        verify_process_loss_case(&output.join(case.name), case);
    }
}

#[test]
#[ignore = "invoked against freshly generated v0.1.1 fixtures"]
fn v011_fixture_verification() {
    let output = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_FIXTURES").unwrap());
    let output = fs::canonicalize(output).unwrap();
    let harness_sha256 = std::env::var("KAPSEL_V011_UPGRADE_HARNESS_SHA256").unwrap();
    let matrix_path = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_MATRIX").unwrap());
    assert_eq!(fs::read(&matrix_path).unwrap(), MATRIX_BYTES);
    for case in FIXTURE_CASES {
        verify_fixture(&output, case, &harness_sha256);
    }
}

#[test]
#[ignore = "invoked in the exact v0.1.1 worktree after the candidate marked every fixture"]
fn v011_marked_fixture_reopen() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.1");
    let output = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_FIXTURES").unwrap());
    let output = fs::canonicalize(output).unwrap();
    for case in FIXTURE_CASES {
        let database = output.join(case.name).join("journal.sqlite3");
        let row_before = durable_row(&database);
        let digest_before = sha256_file(&database);
        let gateway = Gateway::open_for_test(&database).unwrap();
        assert_eq!(
            gateway.get(OPERATION_ID).unwrap(),
            Some(operation_state(case.state))
        );
        assert_decoded_operation_state(&gateway, case.state);
        drop(gateway);
        assert_eq!(journal_version(&database), 3);
        assert_eq!(durable_row(&database), row_before);
        assert_eq!(sha256_file(&database), digest_before);
    }
}

async fn generate_fixture(output: &Path, case: &FixtureCase) {
    let fixture = output.join(case.name);
    create_private_directory(&fixture);
    let receipts = fixture.join("receipts");
    create_private_directory(&receipts);
    let receipts = fs::canonicalize(receipts).unwrap();
    let database = fixture.join("journal.sqlite3");
    let operation = request();
    assert_eq!(operation.operation_id, OPERATION_ID);

    let provider_call_count = match case.name {
        "requested" => {
            let gateway = Gateway::open_for_test(&database).unwrap();
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &operation,
                    &authorization(&operation),
                    Some(FaultPoint::RequestedCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            0
        },
        "authorized" => {
            let gateway = Gateway::open_for_test(&database).unwrap();
            assert!(matches!(
                gateway.submit_exact_with_fault_for_test(
                    &operation,
                    &authorization(&operation),
                    Some(FaultPoint::AuthorizedCommitted),
                ),
                Err(GatewayError::InjectedFault)
            ));
            0
        },
        "not_attempted" => {
            let mut gateway = submitted_gateway(&database, &operation);
            let mut adapter = TargetRoutingAdapter::permanent(
                OPERATION_ID,
                TargetRejection::ContainerNotFound,
            );
            assert!(matches!(
                gateway
                    .run_once_with_adapter(
                        &mut adapter,
                        Some(FaultPoint::TargetRejectedCommitted),
                    )
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            adapter.apply_order.len()
        },
        "apply_started_before_call" => {
            let mut gateway = submitted_gateway(&database, &operation);
            let mut adapter = failed_adapter(&database, &operation);
            assert!(matches!(
                gateway
                    .run_once_with_adapter(
                        &mut adapter,
                        Some(FaultPoint::ApplyStartedCommitted),
                    )
                    .await,
                Err(GatewayError::InjectedFault)
            ));
            adapter.apply_calls
        },
        "apply_started_after_side_effect" => {
            let gateway = submitted_gateway(&database, &operation);
            drop(gateway);
            generate_ambiguous_side_effect(&database, &fixture);
            1
        },
        "receiver_observed" | "receipt_prepared" | "receipt_written" | "finalized" => {
            generate_receiver_or_receipt_fixture(case.name, &database, &receipts, &operation).await
        },
        _ => unreachable!("the static fixture matrix contains only known cases"),
    };
    assert_eq!(provider_call_count, case.provider_call_count);
    write_private_file(
        &fixture.join("provider-call-count.txt"),
        provider_call_count.to_string().as_bytes(),
    );
    write_manifest(&fixture, case);
}

fn submitted_gateway(database: &Path, operation: &SetDeploymentImageRequest) -> Gateway {
    let gateway = Gateway::open_for_test(database).unwrap();
    gateway
        .submit_exact_for_test(operation, &authorization(operation))
        .unwrap();
    gateway
}

async fn generate_receiver_or_receipt_fixture(
    name: &str,
    database: &Path,
    receipts: &Path,
    operation: &SetDeploymentImageRequest,
) -> usize {
    let mut gateway = submitted_gateway(database, operation);
    let mut adapter = failed_adapter(database, operation);
    let receiver_fault =
        (name == "receiver_observed").then_some(FaultPoint::ReceiverObservedCommitted);
    let result = gateway
        .run_once_with_adapter(&mut adapter, receiver_fault)
        .await;
    if receiver_fault.is_some() {
        assert!(matches!(result, Err(GatewayError::InjectedFault)));
    } else {
        assert_eq!(result.unwrap(), Some(OperationState::ReceiverObserved));
    }
    if name == "receiver_observed" {
        return adapter.apply_calls;
    }

    let settings = ReceiptSettings {
        signing_seed: &[41_u8; 32],
        key_id: RECEIPT_KEY_ID,
        output_directory: receipts,
    };
    let fault = match name {
        "receipt_prepared" => FaultPoint::ReceiptPreparedCommitted,
        "receipt_written" => FaultPoint::ReceiptWrittenCommitted,
        "finalized" => FaultPoint::FinalizedCommitted,
        _ => unreachable!("receipt generation receives a receipt fixture name"),
    };
    assert!(matches!(
        gateway.finalize_receipt_once_with_fault(&settings, Some(fault)),
        Err(GatewayError::InjectedFault)
    ));
    adapter.apply_calls
}

fn generate_ambiguous_side_effect(database: &Path, fixture: &Path) {
    let ready = fixture.join("provider-side-effect-complete");
    let call_count = fixture.join("provider-call-count.txt");
    let mut child = spawn_mutation_child(database, &ready, &call_count);
    wait_for_mutation_side_effect(&mut child, &ready).unwrap();
    let status = child.terminate_and_wait().unwrap();
    assert!(!status.success());
    assert_eq!(fs::read_to_string(&call_count).unwrap(), "1");
    set_private_file_mode(&ready);
    set_private_file_mode(&call_count);
}

fn wait_for_mutation_side_effect(child: &mut MutationChild, ready: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ready.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!(
                "historical mutation child exited before its side effect: {status}"
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("historical mutation child did not reach its side effect".into())
}

fn spawn_mutation_child(database: &Path, ready: &Path, call_count: &Path) -> MutationChild {
    MutationChild::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::v011_upgrade::v011_fixture_mutation_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_V011_UPGRADE_MUTATION_CHILD", "1")
            .env("KAPSEL_V011_UPGRADE_DATABASE", database)
            .env("KAPSEL_V011_UPGRADE_READY", ready)
            .env("KAPSEL_V011_UPGRADE_CALL_COUNT", call_count)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn mutation_child_guard_reaps_a_pending_child_when_the_parent_path_fails() {
    let database = database_path("mutation-child-guard-failure");
    let operation = request();
    let gateway = submitted_gateway(&database, &operation);
    drop(gateway);
    let fixture = database.parent().unwrap();
    let ready = fixture.join("guard-provider-side-effect-complete");
    let call_count = fixture.join("guard-provider-call-count.txt");
    let child_id;
    let forced_failure: Result<(), &str> = {
        let mut child = spawn_mutation_child(&database, &ready, &call_count);
        child_id = child.id();
        wait_for_mutation_side_effect(&mut child, &ready).unwrap();
        Err("forced parent failure after child readiness")
    };
    assert_eq!(
        forced_failure,
        Err("forced parent failure after child readiness")
    );
    let raw_pid = i32::try_from(child_id).unwrap();
    let pid = rustix::process::Pid::from_raw(raw_pid).unwrap();
    assert_eq!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    );
    fs::remove_dir_all(fixture).unwrap();
}

fn write_manifest(fixture: &Path, case: &FixtureCase) {
    let database = fixture.join("journal.sqlite3");
    let worker_lock = fixture.join("journal.sqlite3.kap0038-worker.lock");
    assert!(worker_lock.is_file());
    let receipt = receipt_facts(&database);
    let receipt_value = if let Some((path, digest, bytes, key_id)) = receipt {
        let receipt_path = PathBuf::from(&path);
        let published = receipt_path.is_file();
        assert_eq!(published, case.receipt_identity == "frozen_and_published");
        assert_eq!(sha256_bytes(&bytes), digest);
        let relative_path = receipt_path.strip_prefix(fixture).unwrap();
        json!({
            "identity": case.receipt_identity,
            "frozen_absolute_path": path,
            "relative_path": relative_path,
            "digest": digest,
            "bytes_sha256": sha256_bytes(&bytes),
            "key_id": key_id,
            "published": published,
        })
    } else {
        assert_eq!(case.receipt_identity, "absent");
        json!({ "identity": "absent" })
    };
    let manifest = json!({
        "format": FIXTURE_FORMAT,
        "tag_object": TAG_OBJECT,
        "source_commit": SOURCE_COMMIT,
        "cargo_package_version": env!("CARGO_PKG_VERSION"),
        "test_harness_sha256": std::env::var("KAPSEL_V011_UPGRADE_HARNESS_SHA256").unwrap(),
        "case": case.name,
        "durable_state": case.state,
        "crash_point": case.crash_point,
        "provider_call_count": case.provider_call_count,
        "database": {
            "relative_path": "journal.sqlite3",
            "sha256": sha256_file(&database),
        },
        "worker_lock_relative_path": "journal.sqlite3.kap0038-worker.lock",
        "receipt": receipt_value,
        "receipt_path_portability":
            "absolute_final_fixture_path; verify_in_place_only; do_not_copy_or_relocate",
    });
    let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    bytes.push(b'\n');
    write_private_file(&fixture.join("manifest.json"), &bytes);
}

fn verify_fixture(output: &Path, case: &FixtureCase, harness_sha256: &str) {
    let fixture = output.join(case.name);
    assert_private_directory(&fixture);
    assert_private_directory(&fixture.join("receipts"));
    let manifest_bytes = fs::read(fixture.join("manifest.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(required_str(&manifest, "format"), FIXTURE_FORMAT);
    assert_eq!(required_str(&manifest, "tag_object"), TAG_OBJECT);
    assert_eq!(required_str(&manifest, "source_commit"), SOURCE_COMMIT);
    assert_eq!(required_str(&manifest, "cargo_package_version"), "0.1.1");
    assert_eq!(
        required_str(&manifest, "test_harness_sha256"),
        harness_sha256
    );
    assert_eq!(required_str(&manifest, "case"), case.name);
    assert_eq!(required_str(&manifest, "durable_state"), case.state);
    assert_eq!(required_str(&manifest, "crash_point"), case.crash_point);
    assert_eq!(
        manifest["provider_call_count"].as_u64().unwrap(),
        case.provider_call_count as u64
    );
    assert_eq!(
        required_str(&manifest, "receipt_path_portability"),
        "absolute_final_fixture_path; verify_in_place_only; do_not_copy_or_relocate"
    );

    let database = fixture.join("journal.sqlite3");
    let lock = fixture.join("journal.sqlite3.kap0038-worker.lock");
    assert_private_file(&database);
    assert_private_file(&lock);
    let before_sha256 = sha256_file(&database);
    assert_eq!(required_str(&manifest["database"], "sha256"), before_sha256);
    let backup = PathBuf::from(format!("{}.kapsel-v011.backup", database.display()));
    let backup_digest = PathBuf::from(format!("{}.sha256", backup.display()));
    assert_private_file(&backup);
    assert_private_file(&backup_digest);
    assert_eq!(sha256_file(&backup), before_sha256);
    assert_eq!(fs::read_to_string(&backup_digest).unwrap(), format!("{before_sha256}\n"));
    let row_before = durable_row(&database);
    let gateway = Gateway::open_for_test(&database).unwrap();
    assert_eq!(
        gateway.get(OPERATION_ID).unwrap(),
        Some(operation_state(case.state))
    );
    assert_decoded_operation_state(&gateway, case.state);
    drop(gateway);
    assert_eq!(journal_version(&database), 3);
    // The format-3 migration appends the four nullable snapshot columns null.
    let mut migrated_row = row_before;
    migrated_row.extend(std::iter::repeat_n(SqlValue::Null, SNAPSHOT_COLUMN_NAMES.len()));
    assert_eq!(durable_row(&database), migrated_row);
    assert_ne!(sha256_file(&database), before_sha256);
    let marked_sha256 = sha256_file(&database);
    drop(Gateway::open_for_test(&database).unwrap());
    assert_eq!(sha256_file(&database), marked_sha256);
    assert_eq!(durable_row(&database), migrated_row);
    assert_eq!(sha256_file(&backup), before_sha256);
    assert_eq!(
        fs::read_to_string(fixture.join("provider-call-count.txt")).unwrap(),
        case.provider_call_count.to_string()
    );

    let receipt = receipt_facts(&database);
    if case.receipt_identity == "absent" {
        assert!(receipt.is_none());
        assert_eq!(required_str(&manifest["receipt"], "identity"), "absent");
        assert_eq!(fs::read_dir(fixture.join("receipts")).unwrap().count(), 0);
    } else {
        let (path, digest, bytes, key_id) = receipt.unwrap();
        assert_eq!(
            required_str(&manifest["receipt"], "identity"),
            case.receipt_identity
        );
        assert_eq!(required_str(&manifest["receipt"], "frozen_absolute_path"), path);
        assert_eq!(required_str(&manifest["receipt"], "digest"), digest);
        assert_eq!(required_str(&manifest["receipt"], "bytes_sha256"), digest);
        assert_eq!(required_str(&manifest["receipt"], "key_id"), key_id);
        assert_eq!(key_id, RECEIPT_KEY_ID);
        assert_eq!(sha256_bytes(&bytes), digest);
        let trust = ReceiptTrust {
            key_id: RECEIPT_KEY_ID.into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[41_u8; 32])
                .verifying_key()
                .to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 0,
            not_after_unix_s: 1_000,
        }
        .encode()
        .unwrap();
        assert_eq!(
            inspect_receipt(&bytes, &trust, 150, InspectionLimits::default()).status(),
            InspectionStatus::Inspected
        );
        let path = PathBuf::from(path);
        assert_eq!(path.parent().unwrap(), fixture.join("receipts"));
        let should_be_published = case.receipt_identity == "frozen_and_published";
        assert_eq!(path.is_file(), should_be_published);
        assert_eq!(manifest["receipt"]["published"].as_bool().unwrap(), should_be_published);
        if should_be_published {
            assert_private_file(&path);
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}

type FixtureSchemaEntry = (String, String, String, Option<String>);
type FixtureColumnFact = (i64, String, String, i64, Option<String>, i64, i64);

struct FixtureSnapshot {
    row: Vec<SqlValue>,
    schema: Vec<FixtureSchemaEntry>,
    columns: Vec<FixtureColumnFact>,
    provider_call_count: String,
    backup_identity: (u64, u64, u64, u32, u32, u64),
    backup_bytes: Vec<u8>,
    digest_identity: (u64, u64, u64, u32, u32, u64),
    digest_bytes: Vec<u8>,
    receipt: Option<(String, String, Vec<u8>, String)>,
    published_receipt: Option<Vec<u8>>,
    inspection: Option<InspectionReport>,
}

fn verify_process_loss_case(fixture: &Path, case: &FixtureCase) {
    let database = fixture.join("journal.sqlite3");
    let backup = upgrade_backup_path(&database);
    let snapshot = fixture_snapshot(fixture, case);

    for seam in MIGRATION_SEAMS {
        reset_active_from_backup(&database);
        let ready = fixture.join(format!("migration-{seam}.ready"));
        let mut child = spawn_migration_open_child(&database, seam, &ready);
        wait_for_child_marker(&mut child, &ready, "migration").unwrap();
        assert_eq!(fs::read(&ready).unwrap(), seam.as_bytes());
        if *seam == "marker_set_inside_exclusive_transaction" {
            assert_hot_rollback_before_kill(&database);
        }
        let status = child.terminate_and_wait().unwrap();
        assert!(!status.success());
        fs::remove_file(&ready).unwrap();

        if *seam == "marker_set_inside_exclusive_transaction" {
            prove_hot_rollback_before_remark(fixture, &database, case, &snapshot);
        }
        eprintln!("reopening {} after migration seam {seam}", case.name);
        let gateway = Gateway::open_for_test(&database).unwrap();
        assert_eq!(gateway.get(OPERATION_ID).unwrap(), Some(operation_state(case.state)));
        assert_decoded_operation_state(&gateway, case.state);
        drop(gateway);
        assert_eq!(journal_version(&database), 3);
        let after_first_reopen = sha256_file(&database);
        drop(Gateway::open_for_test(&database).unwrap());
        assert_eq!(sha256_file(&database), after_first_reopen);
        assert_fixture_snapshot(fixture, case, &snapshot);
    }

    reset_active_from_backup(&database);
    drop(Gateway::open_for_test(&database).unwrap());
    for seam in RESTORE_SEAMS {
        remove_restore_artifacts(&database);
        let ready = fixture.join(format!("restore-{seam}.ready"));
        let mut child = spawn_restore_child(&database, seam, &ready);
        wait_for_child_marker(&mut child, &ready, "restore").unwrap();
        assert_eq!(fs::read(&ready).unwrap(), seam.as_bytes());
        let status = child.terminate_and_wait().unwrap();
        assert!(!status.success());
        fs::remove_file(&ready).unwrap();
        eprintln!("recovering {} after restore seam {seam}", case.name);
        recover_test_restore(&database);

        let gateway = Gateway::open_for_test(&database).unwrap();
        assert_eq!(gateway.get(OPERATION_ID).unwrap(), Some(operation_state(case.state)));
        assert_decoded_operation_state(&gateway, case.state);
        drop(gateway);
        assert_eq!(journal_version(&database), 3);
        let after_first_reopen = sha256_file(&database);
        drop(Gateway::open_for_test(&database).unwrap());
        assert_eq!(sha256_file(&database), after_first_reopen);
        assert_fixture_snapshot(fixture, case, &snapshot);
        cleanup_test_restore_after_validation(&database);

        reset_active_from_backup(&database);
        drop(Gateway::open_for_test(&database).unwrap());
    }

    if case.name == "requested" {
        prove_failed_process_paths_are_non_destructive(fixture, &database, &snapshot);
    }
    assert_eq!(fs::read(&backup).unwrap(), snapshot.backup_bytes);
    reset_active_from_backup(&database);
    assert_eq!(journal_version(&database), 0);
    assert_fixture_snapshot(fixture, case, &snapshot);
}

fn spawn_migration_open_child(database: &Path, seam: &str, ready: &Path) -> MutationChild {
    MutationChild::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::v011_upgrade::v011_migration_open_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_V011_UPGRADE_MIGRATION_CHILD", "1")
            .env("KAPSEL_V011_UPGRADE_MIGRATION_SEAM", seam)
            .env("KAPSEL_V011_UPGRADE_MIGRATION_READY", ready)
            .env("KAPSEL_V011_UPGRADE_DATABASE", database)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn spawn_migration_recovery_child(database: &Path, ready: &Path) -> MutationChild {
    MutationChild::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::v011_upgrade::v011_migration_recovery_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_V011_UPGRADE_RECOVERY_CHILD", "1")
            .env("KAPSEL_V011_UPGRADE_RECOVERY_READY", ready)
            .env("KAPSEL_V011_UPGRADE_DATABASE", database)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn spawn_restore_child(database: &Path, seam: &str, ready: &Path) -> MutationChild {
    MutationChild::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::v011_upgrade::v011_restore_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_V011_UPGRADE_RESTORE_CHILD", "1")
            .env("KAPSEL_V011_UPGRADE_RESTORE_SEAM", seam)
            .env("KAPSEL_V011_UPGRADE_RESTORE_READY", ready)
            .env("KAPSEL_V011_UPGRADE_DATABASE", database)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn spawn_restore_recovery_child(database: &Path) -> MutationChild {
    MutationChild::new(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::v011_upgrade::v011_restore_recovery_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_V011_UPGRADE_RESTORE_RECOVERY_CHILD", "1")
            .env("KAPSEL_V011_UPGRADE_DATABASE", database)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn wait_for_child_marker(
    child: &mut MutationChild,
    ready: &Path,
    protocol: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if fs::metadata(ready).is_ok_and(|metadata| metadata.len() > 0) {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!("{protocol} child exited before its seam: {status}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(format!("{protocol} child did not reach its seam"))
}

fn wait_for_child_exit(
    child: &mut MutationChild,
    protocol: &str,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Ok(child.terminate_and_wait().unwrap_or(status));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(format!(
        "{protocol} child did not exit after bounded malformed input"
    ))
}

fn assert_hot_rollback_before_kill(database: &Path) {
    assert_eq!(raw_header_version(database), 3);
    let journal = rollback_journal_path(database);
    assert_private_file(&journal);
    let bytes = fs::read(&journal).unwrap();
    assert!(bytes.len() > 512);
    assert_ne!(&bytes[..8], &[0_u8; 8]);
    eprintln!(
        "hot rollback before kill: marker=2 journal_header={}",
        sha256_bytes(&bytes[..8])
    );
}

fn prove_hot_rollback_before_remark(
    fixture: &Path,
    database: &Path,
    case: &FixtureCase,
    expected: &FixtureSnapshot,
) {
    let ready = fixture.join("hot-rollback-restored.ready");
    let mut child = spawn_migration_recovery_child(database, &ready);
    wait_for_child_marker(&mut child, &ready, "hot rollback recovery").unwrap();
    assert_eq!(fs::read(&ready).unwrap(), b"hot_rollback_restored");
    assert_eq!(raw_header_version(database), 0);
    assert_entry_absent(&rollback_journal_path(database));
    assert_eq!(durable_row(database), expected.row);
    assert_eq!(database_schema(database), expected.schema);
    assert_eq!(database_columns(database), expected.columns);
    assert!(!database_schema(database)
        .iter()
        .any(|(_, name, _, _)| name == "v011_upgrade_hot_rollback_probe"));
    eprintln!("hot rollback recovered: marker=0 exact_schema_row=true probe_absent=true");
    assert_eq!(
        fs::read_to_string(fixture.join("provider-call-count.txt")).unwrap(),
        case.provider_call_count.to_string()
    );
    let status = child.terminate_and_wait().unwrap();
    assert!(!status.success());
    fs::remove_file(ready).unwrap();
}

fn raw_header_version(database: &Path) -> u32 {
    let bytes = fs::read(database).unwrap();
    u32::from_be_bytes(bytes[60..64].try_into().unwrap())
}

fn rollback_journal_path(database: &Path) -> PathBuf {
    PathBuf::from(format!("{}-journal", database.display()))
}

fn fixture_snapshot(fixture: &Path, case: &FixtureCase) -> FixtureSnapshot {
    let database = fixture.join("journal.sqlite3");
    let backup = upgrade_backup_path(&database);
    let digest = upgrade_digest_path(&database);
    let receipt = receipt_facts(&database);
    let published_receipt = receipt.as_ref().and_then(|(path, _, _, _)| fs::read(path).ok());
    let inspection = receipt.as_ref().map(|(_, _, bytes, _)| inspect_fixture_receipt(bytes));
    assert_eq!(
        published_receipt.is_some(),
        case.receipt_identity == "frozen_and_published"
    );
    FixtureSnapshot {
        row: durable_row(&database),
        schema: database_schema(&database),
        columns: database_columns(&database),
        provider_call_count: fs::read_to_string(fixture.join("provider-call-count.txt")).unwrap(),
        backup_identity: file_identity(&backup),
        backup_bytes: fs::read(&backup).unwrap(),
        digest_identity: file_identity(&digest),
        digest_bytes: fs::read(&digest).unwrap(),
        receipt,
        published_receipt,
        inspection,
    }
}

fn assert_fixture_snapshot(fixture: &Path, case: &FixtureCase, expected: &FixtureSnapshot) {
    let database = fixture.join("journal.sqlite3");
    let backup = upgrade_backup_path(&database);
    let digest = upgrade_digest_path(&database);
    // Format 3 appends the four nullable snapshot columns to the v0.1.1 layout
    // without altering any historical fact. Only a migrated journal carries them;
    // the final comparison runs against the raw v0.1.1 backup before migration.
    let migrated = journal_version(&database) == 3;
    let mut expected_row = expected.row.clone();
    if migrated {
        expected_row.extend(
            std::iter::repeat_n(SqlValue::Null, SNAPSHOT_COLUMN_NAMES.len()),
        );
    }
    assert_eq!(durable_row(&database), expected_row);
    // SQLite rewrites the stored CREATE statement during ALTER TABLE ADD COLUMN,
    // appending the four snapshot column definitions before the closing paren.
    let schema_addition = "\n                , approved_uid TEXT, approved_resource_version TEXT, \
         preflight_uid TEXT, preflight_resource_version TEXT";
    let schema_tail = "\n                ) STRICT";
    let expected_schema: Vec<FixtureSchemaEntry> = expected
        .schema
        .iter()
        .map(|(kind, name, table, sql)| {
            let sql = sql.as_ref().map(|sql| {
                if name != "kubernetes_image_operations" || !migrated {
                    return sql.clone();
                }
                sql.strip_suffix(schema_tail)
                    .map_or_else(|| sql.clone(), |head| {
                        format!("{head}{schema_addition}) STRICT")
                    })
            });
            (kind.clone(), name.clone(), table.clone(), sql)
        })
        .collect();
    assert_eq!(database_schema(&database), expected_schema);
    let mut expected_columns = expected.columns.clone();
    if migrated {
        let first_snapshot_cid = i64::try_from(expected_columns.len()).unwrap();
        for (index, name) in SNAPSHOT_COLUMN_NAMES.iter().enumerate() {
            expected_columns.push((
                first_snapshot_cid + i64::try_from(index).unwrap(),
                (*name).into(),
                "TEXT".into(),
                0,
                None,
                0,
                0,
            ));
        }
    }
    assert_eq!(database_columns(&database), expected_columns);
    assert_eq!(
        fs::read_to_string(fixture.join("provider-call-count.txt")).unwrap(),
        expected.provider_call_count
    );
    assert_eq!(file_identity(&backup), expected.backup_identity);
    assert_eq!(fs::read(&backup).unwrap(), expected.backup_bytes);
    assert_eq!(file_identity(&digest), expected.digest_identity);
    assert_eq!(fs::read(&digest).unwrap(), expected.digest_bytes);
    let receipt = receipt_facts(&database);
    assert_eq!(receipt, expected.receipt);
    let published = receipt.as_ref().and_then(|(path, _, _, _)| fs::read(path).ok());
    assert_eq!(published, expected.published_receipt);
    let inspection = receipt
        .as_ref()
        .map(|(_, _, bytes, _)| inspect_fixture_receipt(bytes));
    assert_eq!(inspection, expected.inspection);
    assert_eq!(
        receipt.is_some(),
        case.receipt_identity != "absent"
    );
    assert_no_permissive_or_signing_artifacts(fixture);
}

fn inspect_fixture_receipt(bytes: &[u8]) -> InspectionReport {
    let trust = ReceiptTrust {
        key_id: RECEIPT_KEY_ID.into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[41_u8; 32])
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 0,
        not_after_unix_s: 1_000,
    }
    .encode()
    .unwrap();
    inspect_receipt(bytes, &trust, 150, InspectionLimits::default())
}

fn file_identity(path: &Path) -> (u64, u64, u64, u32, u32, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.uid(),
        metadata.mode() & 0o777,
        metadata.nlink(),
    )
}

fn reset_active_from_backup(database: &Path) {
    remove_restore_artifacts(database);
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", database.display()));
        assert!(!sidecar.exists());
    }
    fs::copy(upgrade_backup_path(database), database).unwrap();
    fs::set_permissions(database, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fs::metadata(database).unwrap().len() > 0);
}

fn upgrade_backup_path(database: &Path) -> PathBuf {
    PathBuf::from(format!("{}.kapsel-v011.backup", database.display()))
}

fn upgrade_digest_path(database: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sha256", upgrade_backup_path(database).display()))
}

fn restore_replacement_path(database: &Path) -> PathBuf {
    PathBuf::from(format!("{}.v011_upgrade.restore", database.display()))
}

fn restore_quarantine_path(database: &Path) -> PathBuf {
    PathBuf::from(format!("{}.v011_upgrade.quarantine", database.display()))
}

fn run_test_restore_protocol(database: &Path, selected_seam: &str) {
    let backup = upgrade_backup_path(database);
    let digest = upgrade_digest_path(database);
    let replacement = restore_replacement_path(database);
    let quarantine = restore_quarantine_path(database);
    let recorded = fs::read_to_string(&digest).unwrap();
    assert_eq!(recorded, format!("{}\n", sha256_file(&backup)));
    assert_entry_absent(&replacement);
    assert_entry_absent(&quarantine);

    copy_new_private(&backup, &replacement);
    assert_eq!(sha256_file(&replacement), sha256_file(&backup));
    restore_process_loss_seam(selected_seam, "before_publication");

    fs::create_dir(&quarantine).unwrap();
    fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
    let quarantined = quarantine.join("journal.sqlite3");
    let quarantined_digest = quarantine.join("journal.sqlite3.sha256");
    copy_new_private(database, &quarantined);
    write_new_private(
        &quarantined_digest,
        format!("{}\n", sha256_file(database)).as_bytes(),
    );
    sync_directory(&quarantine);
    assert!(database.is_file());
    restore_process_loss_seam(selected_seam, "after_synchronized_quarantine");

    fs::rename(&replacement, database).unwrap();
    assert_eq!(sha256_file(database), sha256_file(&backup));
    restore_process_loss_seam(selected_seam, "after_atomic_replacement");
    fs::File::open(database).unwrap().sync_all().unwrap();
    sync_directory(database.parent().unwrap());
}

fn restore_process_loss_seam(selected: &str, current: &str) {
    use std::io::Write as _;

    if selected != current {
        return;
    }
    let ready = PathBuf::from(std::env::var_os("KAPSEL_V011_UPGRADE_RESTORE_READY").unwrap());
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(ready)
        .unwrap();
    marker.write_all(current.as_bytes()).unwrap();
    marker.sync_all().unwrap();
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

fn copy_new_private(source: &Path, destination: &Path) {
    use std::io::Write as _;

    let bytes = fs::read(source).unwrap();
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .unwrap();
    output.write_all(&bytes).unwrap();
    output.sync_all().unwrap();
    assert_private_file(destination);
}

fn write_new_private(destination: &Path, bytes: &[u8]) {
    use std::io::Write as _;

    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .unwrap();
    output.write_all(bytes).unwrap();
    output.sync_all().unwrap();
    assert_private_file(destination);
}

fn sync_directory(path: &Path) {
    fs::File::open(path).unwrap().sync_all().unwrap();
}

fn recover_test_restore(database: &Path) {
    assert_private_file(database);
    assert!(fs::symlink_metadata(database).unwrap().len() > 0);
    validate_restore_artifacts(database);
    drop(Gateway::open_for_test(database).unwrap());
    let replacement = restore_replacement_path(database);
    if entry_present(&replacement) {
        assert_private_file(&replacement);
        fs::remove_file(&replacement).unwrap();
    }
    sync_directory(database.parent().unwrap());
    assert_entry_absent(&replacement);
}

fn validate_restore_artifacts(database: &Path) {
    let replacement = restore_replacement_path(database);
    if entry_present(&replacement) {
        assert_private_file(&replacement);
    }
    let quarantine = restore_quarantine_path(database);
    if entry_present(&quarantine) {
        assert_private_restore_directory(&quarantine);
        let quarantined = quarantine.join("journal.sqlite3");
        let quarantined_digest = quarantine.join("journal.sqlite3.sha256");
        assert_private_file(&quarantined);
        assert_private_file(&quarantined_digest);
        let names = fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([
                quarantined.file_name().unwrap().to_owned(),
                quarantined_digest.file_name().unwrap().to_owned(),
            ])
        );
    }
}

fn cleanup_test_restore_after_validation(database: &Path) {
    validate_restore_artifacts(database);
    let quarantine = restore_quarantine_path(database);
    if entry_present(&quarantine) {
        fs::remove_file(quarantine.join("journal.sqlite3")).unwrap();
        fs::remove_file(quarantine.join("journal.sqlite3.sha256")).unwrap();
        fs::remove_dir(&quarantine).unwrap();
        sync_directory(database.parent().unwrap());
    }
    assert_entry_absent(&restore_replacement_path(database));
    assert_entry_absent(&quarantine);
}

fn remove_restore_artifacts(database: &Path) {
    let replacement = restore_replacement_path(database);
    if entry_present(&replacement) {
        assert_private_file(&replacement);
        fs::remove_file(&replacement).unwrap();
    }
    let quarantine = restore_quarantine_path(database);
    if entry_present(&quarantine) {
        validate_restore_artifacts(database);
        fs::remove_file(quarantine.join("journal.sqlite3")).unwrap();
        fs::remove_file(quarantine.join("journal.sqlite3.sha256")).unwrap();
        fs::remove_dir(quarantine).unwrap();
    }
}

fn prove_failed_process_paths_are_non_destructive(
    fixture: &Path,
    database: &Path,
    snapshot: &FixtureSnapshot,
) {
    reset_active_from_backup(database);
    let active_before = fs::read(database).unwrap();
    let backup = upgrade_backup_path(database);
    let mut backup_bytes = fs::read(&backup).unwrap();
    let last = backup_bytes.len() - 1;
    backup_bytes[last] ^= 1;
    fs::write(&backup, &backup_bytes).unwrap();
    let ready = fixture.join("malformed-migration.ready");
    let mut child = spawn_migration_open_child(database, MIGRATION_SEAMS[0], &ready);
    assert!(
        !wait_for_child_exit(&mut child, "malformed migration")
            .unwrap()
            .success()
    );
    assert_entry_absent(&ready);
    assert_eq!(fs::read(database).unwrap(), active_before);
    fs::write(&backup, &snapshot.backup_bytes).unwrap();

    reset_active_from_backup(database);
    drop(Gateway::open_for_test(database).unwrap());
    let marked_before = fs::read(database).unwrap();
    let digest = upgrade_digest_path(database);
    fs::write(&digest, format!("{}\n", "0".repeat(64))).unwrap();
    let ready = fixture.join("malformed-restore.ready");
    let mut child = spawn_restore_child(database, RESTORE_SEAMS[0], &ready);
    assert!(
        !wait_for_child_exit(&mut child, "malformed restore")
            .unwrap()
            .success()
    );
    assert_entry_absent(&ready);
    assert_eq!(fs::read(database).unwrap(), marked_before);
    assert_entry_absent(&restore_replacement_path(database));
    assert_entry_absent(&restore_quarantine_path(database));
    fs::write(&digest, &snapshot.digest_bytes).unwrap();
    prove_malformed_restore_artifacts_are_refused(fixture, database);
    assert_fixture_snapshot(fixture, &FIXTURE_CASES[0], snapshot);
}

fn prove_malformed_restore_artifacts_are_refused(fixture: &Path, database: &Path) {
    use std::os::unix::fs::symlink;

    const CASES: &[&str] = &[
        "replacement-symlink",
        "replacement-dangling-symlink",
        "replacement-hardlink",
        "replacement-permissive",
        "replacement-wrong-type",
        "quarantine-symlink",
        "quarantine-dangling-symlink",
        "quarantine-hardlink",
        "quarantine-permissive",
        "quarantine-wrong-type",
    ];
    for name in CASES {
        remove_malformed_restore_entries(fixture, database);
        let replacement = restore_replacement_path(database);
        let quarantine = restore_quarantine_path(database);
        let auxiliary = fixture.join(format!("malformed-{name}-source"));
        match *name {
            "replacement-symlink" => {
                write_new_private(&auxiliary, b"outside replacement target");
                symlink(&auxiliary, &replacement).unwrap();
            },
            "replacement-dangling-symlink" => {
                symlink(&auxiliary, &replacement).unwrap();
            },
            "replacement-hardlink" => {
                write_new_private(&auxiliary, b"linked replacement target");
                fs::hard_link(&auxiliary, &replacement).unwrap();
            },
            "replacement-permissive" => {
                write_new_private(&replacement, b"permissive replacement");
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();
            },
            "replacement-wrong-type" => {
                fs::create_dir(&replacement).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
            },
            "quarantine-symlink" => {
                fs::create_dir(&auxiliary).unwrap();
                fs::set_permissions(&auxiliary, fs::Permissions::from_mode(0o700)).unwrap();
                symlink(&auxiliary, &quarantine).unwrap();
            },
            "quarantine-dangling-symlink" => {
                symlink(&auxiliary, &quarantine).unwrap();
            },
            "quarantine-hardlink" => {
                create_malformed_quarantine(&quarantine);
                write_new_private(&auxiliary, b"linked quarantine journal");
                fs::hard_link(&auxiliary, quarantine.join("journal.sqlite3")).unwrap();
                write_new_private(&quarantine.join("journal.sqlite3.sha256"), b"digest\n");
            },
            "quarantine-permissive" => {
                fs::create_dir(&quarantine).unwrap();
                fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o755)).unwrap();
            },
            "quarantine-wrong-type" => {
                write_new_private(&quarantine, b"not a quarantine directory");
            },
            _ => unreachable!("the malformed restore case list is closed"),
        }
        let active_before = fs::read(database).unwrap();
        let mut child = spawn_restore_recovery_child(database);
        assert!(!wait_for_child_exit(&mut child, name).unwrap().success());
        assert_eq!(fs::read(database).unwrap(), active_before);
        assert!(entry_present(if name.starts_with("replacement") {
            &replacement
        } else {
            &quarantine
        }));
        remove_malformed_restore_entries(fixture, database);
        assert_entry_absent(&replacement);
        assert_entry_absent(&quarantine);
    }
    eprintln!("malformed restore artifacts refused without active change: 10 cases");
}

fn create_malformed_quarantine(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn remove_malformed_restore_entries(fixture: &Path, database: &Path) {
    remove_entry_without_following(&restore_replacement_path(database));
    remove_entry_without_following(&restore_quarantine_path(database));
    let entries = fs::read_dir(fixture).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    for entry in entries {
        if entry.file_name().to_string_lossy().starts_with("malformed-") {
            remove_entry_without_following(&entry.path());
        }
    }
}

fn remove_entry_without_following(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            return;
        },
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path).unwrap();
    } else {
        assert!(metadata.is_dir());
        let entries = fs::read_dir(path).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        for entry in entries {
            let child = entry.path();
            let child_metadata = fs::symlink_metadata(&child).unwrap();
            assert!(!child_metadata.is_dir());
            fs::remove_file(child).unwrap();
        }
        fs::remove_dir(path).unwrap();
    }
}

fn assert_no_permissive_or_signing_artifacts(root: &Path) {
    fn visit(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        if metadata.is_dir() {
            assert_eq!(metadata.mode() & 0o777, 0o700);
            for entry in fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path());
            }
        } else {
            assert!(metadata.is_file());
            assert_eq!(metadata.uid(), current_uid());
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.mode() & 0o777, 0o600);
            let bytes = fs::read(path).unwrap();
            assert!(!bytes.windows(32).any(|window| window == [41_u8; 32]));
        }
    }
    visit(root);
}

fn database_schema(database: &Path) -> Vec<FixtureSchemaEntry> {
    let connection = Connection::open(database).unwrap();
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn database_columns(database: &Path) -> Vec<FixtureColumnFact> {
    let connection = Connection::open(database).unwrap();
    let mut statement = connection
        .prepare("PRAGMA table_xinfo(kubernetes_image_operations)")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn durable_row(database: &Path) -> Vec<SqlValue> {
    let connection = Connection::open(database).unwrap();
    let column_count = usize::try_from(
        connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('kubernetes_image_operations')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
    )
    .unwrap();
    connection
        .query_row(
            "SELECT * FROM kubernetes_image_operations WHERE operation_id = ?1",
            [OPERATION_ID],
            |row| (0..column_count).map(|index| row.get(index)).collect(),
        )
        .unwrap()
}

fn journal_version(database: &Path) -> u32 {
    Connection::open(database)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

fn receipt_facts(database: &Path) -> Option<(String, String, Vec<u8>, String)> {
    let connection = Connection::open(database).unwrap();
    connection
        .query_row(
            "SELECT receipt_path, receipt_digest, receipt_bytes, receipt_key_id
             FROM kubernetes_image_operations
             WHERE operation_id = ?1
                   AND receipt_path IS NOT NULL
                   AND receipt_digest IS NOT NULL
                   AND receipt_bytes IS NOT NULL
                   AND receipt_key_id IS NOT NULL",
            [OPERATION_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .unwrap()
}

fn assert_decoded_operation_state(gateway: &Gateway, state: &str) {
    assert_eq!(
        gateway
            .journal
            .operation_snapshot(OPERATION_ID)
            .unwrap()
            .unwrap()
            .state,
        operation_state(state)
    );
}

fn operation_state(state: &str) -> OperationState {
    match state {
        "requested" => OperationState::Requested,
        "authorized" => OperationState::Authorized,
        "not_attempted" => OperationState::NotAttempted,
        "apply_started" => OperationState::ApplyStarted,
        "receiver_observed" => OperationState::ReceiverObserved,
        "receipt_prepared" => OperationState::ReceiptPrepared,
        "receipt_written" => OperationState::ReceiptWritten,
        "finalized" => OperationState::Finalized,
        _ => unreachable!("the static fixture matrix contains only durable states"),
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&fs::read(path).unwrap())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
}

fn create_private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    set_private_file_mode(path);
}

fn set_private_file_mode(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn entry_present(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            false
        },
    }
}

fn assert_entry_absent(path: &Path) {
    assert!(!entry_present(path));
}

fn assert_private_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), current_uid());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

fn assert_private_restore_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), current_uid());
    assert!(metadata.nlink() >= 2);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

fn assert_private_file(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), current_uid());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}
