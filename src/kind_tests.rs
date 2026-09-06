//! Explicit live-cluster proof for the effect-gateway Deployment-image operation.

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

use ed25519_dalek::SigningKey;
use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec, ReplicaSet},
        core::v1::{Container, Namespace, Pod, PodSpec, PodTemplateSpec},
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use kube::{
    api::{Api, DeleteParams, ListParams, LogParams, Patch, PatchParams, PostParams},
    Client,
};

use crate::{
    inspect_receipt, test_deployment_patch_document, DeploymentImageAdapter, ExactAuthorization,
    FaultPoint, Gateway, GatewayError, InspectionLimits, InspectionStatus,
    KubernetesDeploymentImageAdapter, OperationResult, OperationState, ReceiptSettings,
    ReceiptTrust, SetDeploymentImageRequest, TargetIdentity,
};

const NAMESPACE: &str = "kapsel-effect-gateway";
const FAILED_NAMESPACE: &str = "kapsel-effect-gateway-failed";
const UNKNOWN_NAMESPACE: &str = "kapsel-effect-gateway-unknown";
const POLICY_NAMESPACE: &str = "kapsel-recovery-policy";
const DEPLOYMENT: &str = "image-demo";
const FAILED_DEPLOYMENT: &str = "image-demo-failed";
const UNKNOWN_DEPLOYMENT: &str = "image-demo-unknown";
const POLICY_DEPLOYMENT: &str = "image-demo-policy";
const TARGET_IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
);
const FAILED_IMAGE: &str = concat!(
    "registry.example.invalid/kapsel/unhealthy@sha256:",
    "1111111111111111111111111111111111111111111111111111111111111111"
);
const FIXTURE_IMAGE: &str = "registry.k8s.io/pause:3.10.1";

struct CountingAdapter {
    inner: KubernetesDeploymentImageAdapter,
    apply_calls: usize,
}

impl CountingAdapter {
    fn new(client: Client) -> Self {
        Self {
            inner: KubernetesDeploymentImageAdapter::new(client),
            apply_calls: 0,
        }
    }
}

impl DeploymentImageAdapter for CountingAdapter {
    async fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<crate::TargetIdentity, crate::TargetReadError> {
        self.inner.identify(request).await
    }

    async fn apply(
        &mut self,
        request: &SetDeploymentImageRequest,
        target: &crate::TargetIdentity,
    ) -> Result<crate::ApplyOutcome, ()> {
        self.apply_calls += 1;
        self.inner.apply(request, target).await
    }

    async fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
        outcome: &crate::ApplyOutcome,
    ) -> Result<crate::ReceiverObservation, ()> {
        self.inner.observe(request, outcome).await
    }
}

#[tokio::test]
#[ignore = "requires scripts/test-kind-effect-gateway.sh"]
async fn kind_changes_exactly_one_container_through_the_gateway() {
    assert_eq!(std::env::var("KAPSEL_KIND_TEST").as_deref(), Ok("1"));
    let client = Client::try_default().await.unwrap();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(NAMESPACE.into()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let proof = tokio::time::timeout(
        std::time::Duration::from_mins(1),
        run_gateway_proof(client.clone()),
    )
    .await
    .map_or_else(
        |_| Err("kind gateway proof exceeded 60 seconds".into()),
        |result| result.map_err(|error| error.to_string()),
    );
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.delete(NAMESPACE, &DeleteParams::default()),
    )
    .await
    .map_or_else(
        |_| Err("kind cleanup exceeded 10 seconds".into()),
        |result| result.map(|_| ()).map_err(|error| error.to_string()),
    );
    assert!(cleanup.is_ok(), "kind fixture cleanup failed");
    proof.unwrap();
}

#[tokio::test]
#[ignore = "requires scripts/test-kind-effect-gateway.sh"]
async fn kind_failed_rollout_recovers_and_inspects_classifier_complete_receipt() {
    assert_eq!(std::env::var("KAPSEL_KIND_TEST").as_deref(), Ok("1"));
    let client = Client::try_default().await.unwrap();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(FAILED_NAMESPACE.into()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let proof = tokio::time::timeout(
        std::time::Duration::from_mins(1),
        run_failed_rollout_proof(client.clone()),
    )
    .await
    .map_or_else(
        |_| Err("kind failed-rollout proof exceeded 60 seconds".into()),
        |result| result.map_err(|error| error.to_string()),
    );
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.delete(FAILED_NAMESPACE, &DeleteParams::default()),
    )
    .await
    .map_or_else(
        |_| Err("kind failed-rollout cleanup exceeded 10 seconds".into()),
        |result| result.map(|_| ()).map_err(|error| error.to_string()),
    );
    assert!(
        cleanup.is_ok(),
        "kind failed-rollout fixture cleanup failed"
    );
    proof.unwrap();
}

#[tokio::test]
#[ignore = "requires scripts/test-kind-effect-gateway.sh"]
async fn kind_deleted_after_patch_recovers_to_classifier_complete_unknown_receipt() {
    assert_eq!(std::env::var("KAPSEL_KIND_TEST").as_deref(), Ok("1"));
    let client = Client::try_default().await.unwrap();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(UNKNOWN_NAMESPACE.into()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let proof = tokio::time::timeout(
        std::time::Duration::from_mins(1),
        run_unknown_rollout_proof(client.clone()),
    )
    .await
    .map_or_else(
        |_| Err("kind unknown proof exceeded 60 seconds".into()),
        |result| result.map_err(|error| error.to_string()),
    );
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        namespaces.delete(UNKNOWN_NAMESPACE, &DeleteParams::default()),
    )
    .await
    .map_or_else(
        |_| Err("kind unknown cleanup exceeded 15 seconds".into()),
        |result| result.map(|_| ()).map_err(|error| error.to_string()),
    );
    assert!(cleanup.is_ok(), "kind unknown fixture cleanup failed");
    proof.unwrap();
}

#[tokio::test]
#[ignore = "requires scripts/test-kind-effect-gateway.sh"]
async fn kind_stale_exact_replay_reaches_admission_without_a_second_persisted_change() {
    assert_eq!(std::env::var("KAPSEL_KIND_TEST").as_deref(), Ok("1"));
    let client = Client::try_default().await.unwrap();
    let namespaces: Api<Namespace> = Api::all(client.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        namespaces.create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(POLICY_NAMESPACE.into()),
                    labels: Some(BTreeMap::from([(
                        "kapsel.dev/recovery-policy".into(),
                        "true".into(),
                    )])),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let proof = tokio::time::timeout(
        std::time::Duration::from_mins(1),
        run_recovery_policy_proof(client.clone()),
    )
    .await
    .map_or_else(
        |_| Err("kind recovery-policy proof exceeded 60 seconds".into()),
        |result| result.map_err(|error| error.to_string()),
    );
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        namespaces.delete(POLICY_NAMESPACE, &DeleteParams::default()),
    )
    .await
    .map_or_else(
        |_| Err("kind recovery-policy cleanup exceeded 15 seconds".into()),
        |result| result.map(|_| ()).map_err(|error| error.to_string()),
    );
    assert!(cleanup.is_ok(), "kind recovery-policy cleanup failed");
    proof.unwrap();
}

async fn run_recovery_policy_proof(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), POLICY_NAMESPACE);
    let replica_sets: Api<ReplicaSet> = Api::namespaced(client.clone(), POLICY_NAMESPACE);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.create(
            &PostParams::default(),
            &fixture_deployment_for(POLICY_NAMESPACE, POLICY_DEPLOYMENT),
        ),
    )
    .await??;
    wait_for_deployment_rollout(&deployments, POLICY_DEPLOYMENT).await?;

    let request = policy_request();
    let mut adapter = KubernetesDeploymentImageAdapter::new(client.clone());
    let frozen_target = adapter.identify(&request).await.map_err(|error| {
        format!("could not freeze policy target before the first patch: {error:?}")
    })?;
    let before = deployments.get(POLICY_DEPLOYMENT).await?;
    let before_generation = before
        .metadata
        .generation
        .ok_or("missing initial generation")?;
    let selector = ListParams::default().labels("app=image-demo-policy");
    let replica_sets_before = replica_sets.list(&selector).await?.items.len();

    let first = adapter
        .apply(&request, &frozen_target)
        .await
        .map_err(|()| "first frozen patch was rejected")?;
    assert_eq!(
        first.deployment_uid.as_deref(),
        Some(frozen_target.deployment_uid.as_str())
    );
    wait_for_deployment_rollout(&deployments, POLICY_DEPLOYMENT).await?;
    let after_first = deployments.get(POLICY_DEPLOYMENT).await?;
    let first_generation = after_first
        .metadata
        .generation
        .ok_or("missing generation after first patch")?;
    assert_eq!(first_generation, before_generation + 1);
    let replica_sets_after_first = replica_sets.list(&selector).await?.items.len();
    assert_eq!(replica_sets_after_first, replica_sets_before + 1);
    let admission_after_first = admission_effects(&client, "kind-policy-op-001").await?;
    assert_eq!(admission_after_first.len(), 1);

    assert_stale_replay_conflicts(&deployments, &request, &frozen_target).await?;
    let after_replay = deployments.get(POLICY_DEPLOYMENT).await?;
    assert_eq!(after_replay.metadata.uid, after_first.metadata.uid);
    assert_eq!(
        after_replay.metadata.resource_version,
        after_first.metadata.resource_version
    );
    assert_eq!(after_replay.metadata.generation, Some(first_generation));
    assert_eq!(after_replay.spec, after_first.spec);
    assert_eq!(
        deployment_container_image(&after_replay, "target"),
        Some(TARGET_IMAGE)
    );
    assert_eq!(
        deployment_container_image(&after_replay, "untouched"),
        Some(FIXTURE_IMAGE)
    );
    assert_eq!(
        after_replay
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get("kapsel.dev/kap0038-operation-id"))
            .map(String::as_str),
        Some("kind-policy-op-001")
    );
    assert_eq!(
        replica_sets.list(&selector).await?.items.len(),
        replica_sets_after_first
    );
    let admission_after_replay =
        wait_for_admission_effects(&client, "kind-policy-op-001", 2).await?;
    assert_eq!(admission_after_replay.len(), 2);
    let admission_uids = admission_after_replay
        .iter()
        .filter_map(|line| line.split_once("uid=").map(|(_, value)| value))
        .filter_map(|value| value.split_once(' ').map(|(uid, _)| uid))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(admission_uids.len(), 2);
    report_recovery_policy_evidence(
        before_generation,
        first_generation,
        replica_sets_before,
        replica_sets_after_first,
        &admission_after_replay,
    );
    Ok(())
}

async fn assert_stale_replay_conflicts(
    deployments: &Api<Deployment>,
    request: &SetDeploymentImageRequest,
    target: &TargetIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let replay = deployments
        .patch(
            POLICY_DEPLOYMENT,
            &PatchParams::default(),
            &Patch::Strategic(test_deployment_patch_document(request, target)),
        )
        .await;
    match replay {
        Err(kube::Error::Api(response)) if response.code == 409 => Ok(()),
        Err(kube::Error::Api(response)) => Err(format!(
            "stale replay returned Kubernetes API status {}",
            response.code
        )
        .into()),
        Err(error) => Err(format!("stale replay returned a non-API error: {error}").into()),
        Ok(_) => Err("stale replay unexpectedly persisted".into()),
    }
}

async fn admission_effects(
    client: &Client,
    operation_id: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), "kapsel-recovery-policy-webhook");
    let webhook_pods = pods
        .list(&ListParams::default().labels("app=recovery-policy-webhook"))
        .await?;
    let pod = webhook_pods.items.first().ok_or("missing webhook pod")?;
    let pod_name = pod
        .metadata
        .name
        .as_deref()
        .ok_or("webhook pod missing name")?;
    let logs = pods.logs(pod_name, &LogParams::default()).await?;
    Ok(logs
        .lines()
        .filter(|line| {
            line.contains("KAPSEL_ADMISSION_EFFECT")
                && line.contains(&format!("operation_id={operation_id}"))
        })
        .map(str::to_owned)
        .collect())
}

async fn wait_for_admission_effects(
    client: &Client,
    operation_id: &str,
    expected: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let effects = admission_effects(client, operation_id).await?;
            if effects.len() >= expected {
                return Ok::<Vec<String>, Box<dyn std::error::Error>>(effects);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "admission effect did not become observable within 10 seconds")?
}

fn deployment_container_image<'a>(
    deployment: &'a Deployment,
    container_name: &str,
) -> Option<&'a str> {
    deployment
        .spec
        .as_ref()?
        .template
        .spec
        .as_ref()?
        .containers
        .iter()
        .find(|container| container.name == container_name)?
        .image
        .as_deref()
}

#[allow(clippy::print_stdout)]
fn report_recovery_policy_evidence(
    before_generation: i64,
    after_generation: i64,
    replica_sets_before: usize,
    replica_sets_after: usize,
    admission_effects: &[String],
) {
    println!(
        "[kind recovery-policy] patch_requests=2 replay_status=409 admission_effects={} \
         persisted_deployment_changes=1 controller_effects=1 \
         generation={before_generation}->{after_generation} \
         replica_sets={replica_sets_before}->{replica_sets_after}",
        admission_effects.len()
    );
    for effect in admission_effects {
        println!("[kind recovery-policy] {effect}");
    }
}

async fn run_gateway_proof(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NAMESPACE);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.create(
            &PostParams::default(),
            &fixture_deployment_for(NAMESPACE, DEPLOYMENT),
        ),
    )
    .await??;
    wait_for_deployment_rollout(&deployments, DEPLOYMENT).await?;
    let request = request();
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "kind-auth-001".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    };
    let directory = private_test_directory_for("success");
    let database = directory.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&database)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    let mut adapter = KubernetesDeploymentImageAdapter::new(client.clone());
    match gateway
        .run_once_with_adapter(&mut adapter, Some(FaultPoint::ApplyReturned))
        .await
    {
        Err(GatewayError::InjectedFault) => {},
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("kind fault injection did not stop after the patch".into()),
    }
    assert_eq!(
        gateway.get(&request.operation_id)?,
        Some(OperationState::ApplyStarted)
    );
    drop(gateway);
    let mut gateway = Gateway::open_for_test(&database)?;

    let state = gateway.run_once(client).await?;

    assert_eq!(state, Some(OperationState::ReceiverObserved));
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Succeeded)
    );
    let observed = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.get(DEPLOYMENT),
    )
    .await??;
    let containers = &observed
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .ok_or("missing fixture pod spec")?
        .containers;
    assert_eq!(containers.len(), 2);
    assert_eq!(
        containers
            .iter()
            .find(|container| container.name == "target")
            .and_then(|container| container.image.as_deref()),
        Some(TARGET_IMAGE)
    );
    assert_eq!(
        containers
            .iter()
            .find(|container| container.name == "untouched")
            .and_then(|container| container.image.as_deref()),
        Some(FIXTURE_IMAGE)
    );
    drop(gateway);
    fs::remove_dir_all(directory)?;
    Ok(())
}

async fn run_unknown_rollout_proof(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), UNKNOWN_NAMESPACE);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.create(
            &PostParams::default(),
            &fixture_deployment_for(UNKNOWN_NAMESPACE, UNKNOWN_DEPLOYMENT),
        ),
    )
    .await??;
    wait_for_deployment_rollout(&deployments, UNKNOWN_DEPLOYMENT).await?;
    let request = unknown_request();
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "kind-unknown-auth-001".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    };
    let directory = private_test_directory_for("unknown");
    let receipt_directory = directory.join("receipts");
    fs::create_dir(&receipt_directory)?;
    fs::set_permissions(&receipt_directory, fs::Permissions::from_mode(0o700))?;
    let database = directory.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&database)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    let mut first_adapter = CountingAdapter::new(client.clone());
    match gateway
        .run_once_with_adapter(&mut first_adapter, Some(FaultPoint::ApplyReturned))
        .await
    {
        Err(GatewayError::InjectedFault) => {},
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("kind unknown fault did not stop after patch".into()),
    }
    assert_eq!(first_adapter.apply_calls, 1);
    drop(gateway);

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.delete(UNKNOWN_DEPLOYMENT, &DeleteParams::default()),
    )
    .await??;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if deployments.get_opt(UNKNOWN_DEPLOYMENT).await?.is_none() {
                return Ok::<(), kube::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "deleted Deployment remained observable for 10 seconds")??;

    let mut gateway = Gateway::open_for_test(&database)?;
    let mut recovery_adapter = CountingAdapter::new(client);
    assert_eq!(
        gateway
            .run_once_with_adapter(&mut recovery_adapter, None)
            .await?,
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(recovery_adapter.apply_calls, 0);
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Unknown)
    );

    let receipt_seed = [43_u8; 32];
    assert_eq!(
        gateway.finalize_receipt_once(&ReceiptSettings {
            signing_seed: &receipt_seed,
            key_id: "kind-unknown-receipt-key",
            output_directory: &receipt_directory,
        })?,
        Some(OperationState::Finalized)
    );
    let reference = gateway
        .receipt_reference(&request.operation_id)?
        .ok_or("missing unknown receipt reference")?;
    let receipt_bytes = fs::read(reference.path)?;
    let trust = ReceiptTrust {
        key_id: "kind-unknown-receipt-key".into(),
        public_key: SigningKey::from_bytes(&receipt_seed)
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()?;
    let report = inspect_receipt(&receipt_bytes, &trust, 150, InspectionLimits::default());
    assert_eq!(report.status(), InspectionStatus::Inspected);
    let statement = report.statement().ok_or("missing inspected statement")?;
    assert_eq!(statement.result(), OperationResult::Unknown);
    assert_eq!(statement.observed_image(), None);
    assert_eq!(statement.observed_operation_marker(), None);
    drop(gateway);
    fs::remove_dir_all(directory)?;
    Ok(())
}

async fn run_failed_rollout_proof(client: Client) -> Result<(), Box<dyn std::error::Error>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), FAILED_NAMESPACE);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        deployments.create(
            &PostParams::default(),
            &fixture_deployment_for(FAILED_NAMESPACE, FAILED_DEPLOYMENT),
        ),
    )
    .await??;
    wait_for_deployment_rollout(&deployments, FAILED_DEPLOYMENT).await?;
    let request = failed_request();
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "kind-failed-auth-001".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    };
    let directory = private_test_directory_for("failed");
    let receipt_directory = directory.join("receipts");
    fs::create_dir(&receipt_directory)?;
    fs::set_permissions(&receipt_directory, fs::Permissions::from_mode(0o700))?;
    let database = directory.join("journal.sqlite3");
    let mut gateway = Gateway::open_for_test(&database)?;
    gateway.submit_exact_for_test(&request, &authorization)?;
    let mut first_adapter = CountingAdapter::new(client.clone());
    match gateway
        .run_once_with_adapter(&mut first_adapter, Some(FaultPoint::ApplyReturned))
        .await
    {
        Err(GatewayError::InjectedFault) => {},
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("kind failed-rollout fault did not stop after patch".into()),
    }
    assert_eq!(first_adapter.apply_calls, 1);
    drop(gateway);

    let mut gateway = Gateway::open_for_test(&database)?;
    let mut recovery_adapter = CountingAdapter::new(client);
    assert_eq!(
        gateway
            .run_once_with_adapter(&mut recovery_adapter, None)
            .await?,
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(recovery_adapter.apply_calls, 0);
    assert_eq!(
        gateway.result(&request.operation_id)?,
        Some(OperationResult::Failed)
    );

    let receipt_seed = [41_u8; 32];
    assert_eq!(
        gateway.finalize_receipt_once(&ReceiptSettings {
            signing_seed: &receipt_seed,
            key_id: "kind-failed-receipt-key",
            output_directory: &receipt_directory,
        })?,
        Some(OperationState::Finalized)
    );
    let reference = gateway
        .receipt_reference(&request.operation_id)?
        .ok_or("missing failed-rollout receipt reference")?;
    let receipt_bytes = fs::read(reference.path)?;
    let trust = ReceiptTrust {
        key_id: "kind-failed-receipt-key".into(),
        public_key: SigningKey::from_bytes(&receipt_seed)
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()?;
    let report = inspect_receipt(&receipt_bytes, &trust, 150, InspectionLimits::default());
    assert_eq!(report.status(), InspectionStatus::Inspected);
    let statement = report.statement().ok_or("missing inspected statement")?;
    assert_eq!(statement.result(), OperationResult::Failed);
    assert_eq!(
        statement.rollout_condition_reason(),
        Some("ProgressDeadlineExceeded")
    );
    assert_eq!(statement.observed_image(), Some(FAILED_IMAGE));
    assert_eq!(
        statement.observed_operation_marker(),
        Some("kind-failed-op-001")
    );
    drop(gateway);
    fs::remove_dir_all(directory)?;
    Ok(())
}

#[allow(clippy::print_stdout)]
async fn wait_for_deployment_rollout(
    deployments: &Api<Deployment>,
    deployment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let deployment = deployments.get(deployment_name).await?;
            let generation = deployment.metadata.generation;
            let ready = deployment.status.as_ref().is_some_and(|status| {
                status.observed_generation == generation
                    && status.available_replicas == Some(1)
                    && status.updated_replicas == Some(1)
            });
            if ready {
                return Ok::<(), kube::Error>(());
            }
            println!("waiting for the disposable kind fixture rollout");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| "fixture rollout exceeded 30 seconds")??;
    Ok(())
}

fn request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "kind-op-001".into(),
        namespace: NAMESPACE.into(),
        deployment: DEPLOYMENT.into(),
        container: "target".into(),
        immutable_image_digest: TARGET_IMAGE.into(),
    }
}

fn unknown_request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "kind-unknown-op-001".into(),
        namespace: UNKNOWN_NAMESPACE.into(),
        deployment: UNKNOWN_DEPLOYMENT.into(),
        container: "target".into(),
        immutable_image_digest: TARGET_IMAGE.into(),
    }
}

fn policy_request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "kind-policy-op-001".into(),
        namespace: POLICY_NAMESPACE.into(),
        deployment: POLICY_DEPLOYMENT.into(),
        container: "target".into(),
        immutable_image_digest: TARGET_IMAGE.into(),
    }
}

fn failed_request() -> SetDeploymentImageRequest {
    SetDeploymentImageRequest {
        operation_id: "kind-failed-op-001".into(),
        namespace: FAILED_NAMESPACE.into(),
        deployment: FAILED_DEPLOYMENT.into(),
        container: "target".into(),
        immutable_image_digest: FAILED_IMAGE.into(),
    }
}

fn fixture_deployment_for(namespace: &str, deployment: &str) -> Deployment {
    let labels = BTreeMap::from([("app".into(), deployment.into())]);
    Deployment {
        metadata: ObjectMeta {
            name: Some(deployment.into()),
            namespace: Some(namespace.into()),
            ..ObjectMeta::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..LabelSelector::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..ObjectMeta::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![
                        Container {
                            name: "target".into(),
                            image: Some(FIXTURE_IMAGE.into()),
                            ..Container::default()
                        },
                        Container {
                            name: "untouched".into(),
                            image: Some(FIXTURE_IMAGE.into()),
                            ..Container::default()
                        },
                    ],
                    ..PodSpec::default()
                }),
            },
            progress_deadline_seconds: Some(15),
            ..DeploymentSpec::default()
        }),
        ..Deployment::default()
    }
}

fn private_test_directory_for(scenario: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kapsel-kind-proof-{}-{scenario}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::canonicalize(path).unwrap()
}
