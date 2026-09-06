//! Replayable long lifecycle simulations over the private deterministic adapter seam.

use std::{error::Error, fs, io, os::unix::fs::PermissionsExt, path::Path};

use crate::{
    ApplyOutcome, DeploymentImageAdapter, ExactAuthorization, FaultPoint, Gateway, GatewayError,
    OperationResult, OperationState, ReceiptSettings, ReceiverObservation,
    SetDeploymentImageRequest, TargetIdentity, TargetReadError,
};

const DEFAULT_SEED: u64 = 0x004b_4150_3030_3338;
const DEFAULT_CASES: usize = 10_000;

struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn index(&mut self, length: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(length).unwrap()).unwrap()
    }
}

type SimulationResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy)]
struct CaseSchedule {
    target_deferrals: usize,
    receiver_reopens: usize,
    apply_fault: FaultPoint,
    publication_fault: FaultPoint,
}

#[derive(Clone, Copy)]
struct SimulationPaths<'a> {
    journal: &'a Path,
    output: &'a Path,
    root: &'a Path,
}

struct SimulationAdapter {
    transient_reads_remaining: usize,
    apply_calls: usize,
    observation: ReceiverObservation,
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "the simulation adapter mirrors the production async provider seam"
)]
impl DeploymentImageAdapter for SimulationAdapter {
    async fn identify(
        &mut self,
        _: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        if self.transient_reads_remaining > 0 {
            self.transient_reads_remaining -= 1;
            Err(TargetReadError::Transient)
        } else {
            Ok(TargetIdentity {
                deployment_uid: "simulation-deployment-uid".into(),
                resource_version: "simulation-resource-version-1".into(),
            })
        }
    }

    async fn apply(
        &mut self,
        _: &SetDeploymentImageRequest,
        _: &TargetIdentity,
    ) -> Result<ApplyOutcome, ()> {
        self.apply_calls += 1;
        Ok(ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some("simulation-deployment-uid".into()),
            resource_version: Some("simulation-resource-version-2".into()),
        })
    }

    async fn observe(
        &mut self,
        _: &SetDeploymentImageRequest,
        _: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        Ok(self.observation.clone())
    }
}

#[tokio::test]
#[ignore = "long replayable lane; run through scripts/test-simulation.sh"]
async fn seeded_lifecycle_crash_simulation_preserves_invariants() {
    let seed = environment_number("KAPSEL_SIMULATION_SEED", DEFAULT_SEED);
    let cases = usize::try_from(environment_number(
        "KAPSEL_SIMULATION_CASES",
        u64::try_from(DEFAULT_CASES).unwrap(),
    ))
    .unwrap();
    assert!(cases > 0, "seed={seed} requires at least one case");

    let shard_count = usize::try_from(environment_number("KAPSEL_SIMULATION_SHARDS", 1)).unwrap();
    let shard_index =
        usize::try_from(environment_number("KAPSEL_SIMULATION_SHARD_INDEX", 0)).unwrap();
    assert!(
        shard_count > 0 && shard_count <= 8 && shard_index < shard_count,
        "seed={seed} invalid shard {shard_index}/{shard_count}"
    );

    let result = run_simulation(seed, cases, shard_index, shard_count).await;
    assert!(
        result.is_ok(),
        "seed={seed} shard={shard_index}/{shard_count} result={result:?}"
    );
}

async fn run_simulation(
    seed: u64,
    cases: usize,
    shard_index: usize,
    shard_count: usize,
) -> SimulationResult {
    let root = std::env::temp_dir().join(format!(
        "kapsel-lifecycle-simulation-{}-{seed}-{shard_index}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root)?;
    let output_directory = root.join("receipts");
    private_directory(&output_directory)?;
    let output_directory = fs::canonicalize(output_directory)?;
    let journal_path = root.join("journal.sqlite3");
    let paths = SimulationPaths {
        journal: &journal_path,
        output: &output_directory,
        root: &root,
    };
    let mut generator = Generator(seed);
    let apply_faults = [
        FaultPoint::TargetObserved,
        FaultPoint::ApplyStartedCommitted,
        FaultPoint::ApplyReturned,
        FaultPoint::ApplyOutcomeCommitted,
        FaultPoint::ReceiverRead,
        FaultPoint::ReceiverObservedCommitted,
    ];
    let publication_faults = [
        FaultPoint::ReceiptPreparedCommitted,
        FaultPoint::ReceiptPublished,
        FaultPoint::ReceiptWrittenCommitted,
        FaultPoint::FinalizedCommitted,
    ];

    for case in 0..cases {
        let schedule = CaseSchedule {
            target_deferrals: generator.index(4),
            receiver_reopens: generator.index(4),
            apply_fault: apply_faults[generator.index(apply_faults.len())],
            publication_fault: publication_faults[generator.index(publication_faults.len())],
        };
        if case % shard_count == shard_index {
            run_case(seed, case, paths, schedule).await?;
        }
    }

    fs::remove_dir_all(root)?;
    Ok(())
}

async fn run_case(
    seed: u64,
    case: usize,
    paths: SimulationPaths<'_>,
    schedule: CaseSchedule,
) -> SimulationResult {
    let request = request(case);
    let authorization = authorization(&request, case);
    let mut adapter = failed_adapter(&request, schedule.target_deferrals);
    let gateway = Gateway::open_for_test(paths.journal)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    drop(gateway);

    for deferral in 0..schedule.target_deferrals {
        let mut gateway = Gateway::open_for_test(paths.journal)?;
        let result = gateway.run_once_with_adapter(&mut adapter, None).await;
        assert!(
            matches!(result, Err(GatewayError::KubernetesTargetObservation)),
            "seed={seed} case={case} deferral={deferral} result={result:?}"
        );
        assert_eq!(
            gateway.get(&request.operation_id)?,
            Some(OperationState::Authorized),
            "seed={seed} case={case} deferral={deferral}"
        );
        assert_eq!(adapter.apply_calls, 0, "seed={seed} case={case}");
    }

    let mut gateway = Gateway::open_for_test(paths.journal)?;
    let result = gateway
        .run_once_with_adapter(&mut adapter, Some(schedule.apply_fault))
        .await;
    assert!(
        matches!(result, Err(GatewayError::InjectedFault)),
        "seed={seed} case={case} apply_fault={:?} result={result:?}",
        schedule.apply_fault
    );
    drop(gateway);

    let mut gateway = recover_receiver(seed, case, paths.journal, &request, &mut adapter).await?;
    for reopen in 0..schedule.receiver_reopens {
        drop(gateway);
        gateway = Gateway::open_for_test(paths.journal)?;
        assert_eq!(
            gateway.run_once_with_adapter(&mut adapter, None).await?,
            None,
            "seed={seed} case={case} receiver_reopen={reopen}"
        );
        assert_eq!(
            gateway.get(&request.operation_id)?,
            Some(OperationState::ReceiverObserved),
            "seed={seed} case={case} receiver_reopen={reopen}"
        );
    }

    let expected_apply_calls =
        usize::from(schedule.apply_fault != FaultPoint::ApplyStartedCommitted);
    assert_eq!(
        adapter.apply_calls, expected_apply_calls,
        "seed={seed} case={case} apply_fault={:?}",
        schedule.apply_fault
    );
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Failed),
        "seed={seed} case={case}"
    );
    recover_receipt(seed, case, paths, schedule, gateway, &request)
}

async fn recover_receiver(
    seed: u64,
    case: usize,
    journal_path: &Path,
    request: &SetDeploymentImageRequest,
    adapter: &mut SimulationAdapter,
) -> SimulationResult<Gateway> {
    let mut gateway = Gateway::open_for_test(journal_path)?;
    let state = gateway
        .get(&request.operation_id)?
        .ok_or_else(|| io::Error::other("simulation operation disappeared"))?;
    if matches!(
        state,
        OperationState::Authorized | OperationState::ApplyStarted
    ) {
        assert_eq!(
            gateway.run_once_with_adapter(adapter, None).await?,
            Some(OperationState::ReceiverObserved),
            "seed={seed} case={case}"
        );
    } else {
        assert_eq!(state, OperationState::ReceiverObserved);
    }
    Ok(gateway)
}

fn recover_receipt(
    seed: u64,
    case: usize,
    paths: SimulationPaths<'_>,
    schedule: CaseSchedule,
    gateway: Gateway,
    request: &SetDeploymentImageRequest,
) -> SimulationResult {
    let settings = ReceiptSettings {
        signing_seed: &[13_u8; 32],
        key_id: "simulation-receipt-key",
        output_directory: paths.output,
    };
    let result =
        gateway.finalize_receipt_once_with_fault(&settings, Some(schedule.publication_fault));
    assert!(
        matches!(result, Err(GatewayError::InjectedFault)),
        "seed={seed} case={case} publication_fault={:?} result={result:?}",
        schedule.publication_fault
    );
    drop(gateway);

    let gateway = Gateway::open_for_test(paths.journal)?;
    if gateway.get(&request.operation_id)? != Some(OperationState::Finalized) {
        assert_eq!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &[99_u8; 32],
                key_id: "rotated-simulation-key",
                output_directory: paths.root,
            })?,
            Some(OperationState::Finalized),
            "seed={seed} case={case} publication_fault={:?}",
            schedule.publication_fault
        );
    }
    assert_eq!(
        gateway.get(&request.operation_id)?,
        Some(OperationState::Finalized),
        "seed={seed} case={case}"
    );
    let receipt = gateway
        .receipt_reference(&request.operation_id)?
        .ok_or_else(|| io::Error::other("simulation receipt disappeared"))?;
    assert_eq!(
        receipt.path.parent(),
        Some(paths.output),
        "seed={seed} case={case}"
    );
    assert!(receipt.path.exists(), "seed={seed} case={case}");
    Ok(())
}

fn environment_number(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |value| value.parse().unwrap())
}

fn private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn request(case: usize) -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: format!("simulation-op-{case}"),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    }
}

fn authorization(request: &SetDeploymentImageRequest, case: usize) -> ExactAuthorization {
    ExactAuthorization {
        approved_target: None,
        authorization_id: format!("simulation-auth-{case}"),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    }
}

fn failed_adapter(
    request: &SetDeploymentImageRequest,
    transient_reads_remaining: usize,
) -> SimulationAdapter {
    SimulationAdapter {
        transient_reads_remaining,
        apply_calls: 0,
        observation: ReceiverObservation {
            deployment_uid: Some("simulation-deployment-uid".into()),
            resource_version: Some("simulation-resource-version-3".into()),
            current_generation: Some(2),
            observed_generation: Some(2),
            image: Some(request.immutable_image_digest.clone()),
            operation_marker: Some(request.operation_id.clone()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: Some("Progressing".into()),
            rollout_condition_status: Some("False".into()),
            rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
        },
    }
}
