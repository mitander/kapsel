//! Public application-interface contract tests.

#![allow(
    clippy::unwrap_used,
    reason = "controlled test-fixture failures must fail the contract test immediately"
)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use kapsel::{
    open_application_from_fixed_operator_document, provision_exact_grant,
    validate_service_operator_inputs, AgentRequest, Application, ApplicationError,
    AuthorizationTrust, ExactAuthorization, GrantProvisioning, OperationState,
    OperatorConfiguration, ReceiptTrust, SetDeploymentImageReceipt, SetDeploymentImageStatus,
    TargetRejection,
};
use tower_test::mock;

fn request() -> AgentRequest {
    AgentRequest {
        operation_id: "application-op-1".into(),
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

fn authorization(request: &AgentRequest) -> ExactAuthorization {
    ExactAuthorization {
        approved_target: None,
        authorization_id: "application-auth-1".into(),
        operation_id: request.operation_id.clone(),
        namespace: request.namespace.clone(),
        deployment: request.deployment.clone(),
        container: request.container.clone(),
        immutable_image_digest: request.immutable_image_digest.clone(),
    }
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

type KubernetesHandle =
    mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>;

fn configuration(root: &Path) -> OperatorConfiguration {
    configuration_and_handle(root).0
}

fn configuration_and_handle(root: &Path) -> (OperatorConfiguration, KubernetesHandle) {
    let request = request();
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let signed_authorization_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization(&request),
        signing_seed: &authorization_seed,
        signing_key_id: "application-authorization-key",
    })
    .unwrap();
    let output = root.join("receipts");
    if !output.exists() {
        private_directory(&output);
    }
    let output = fs::canonicalize(output).unwrap();
    let (service, handle) =
        mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
    let configuration = OperatorConfiguration {
        journal_path: fs::canonicalize(root).unwrap().join("journal.sqlite3"),
        receipt_output_directory: output,
        authorization_trust: AuthorizationTrust {
            key_id: "application-authorization-key".into(),
            public_key: authorization_key.verifying_key().to_bytes(),
        },
        signed_authorization_grant,
        kubernetes_client: kube::Client::new(service, "demo"),
        receipt_signing_seed: [42_u8; 32],
        receipt_signing_key_id: "application-receipt-key".into(),
    };
    (configuration, handle)
}

fn deployment_response(body: &serde_json::Value) -> http::Response<kube::client::Body> {
    http::Response::builder()
        .status(http::StatusCode::OK)
        .body(kube::client::Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn respond_with_terminal_result(
    mut handle: KubernetesHandle,
    result: SetDeploymentImageStatus,
) -> KubernetesHandle {
    let old_image = concat!(
        "registry.example/agent-api@sha256:",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    let image = request().immutable_image_digest;
    let (_, send) = handle.next_request().await.unwrap();
    send.send_response(deployment_response(&serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1",
            "resourceVersion": "1", "generation": 1},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {"metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{"name": "api", "image": old_image}]}}},
        "status": {"observedGeneration": 1}
    })));
    let (_, send) = handle.next_request().await.unwrap();
    send.send_response(deployment_response(&serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1",
            "resourceVersion": "2", "generation": 2},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {"metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{"name": "api", "image": image}]}}}
    })));
    let failed = result == SetDeploymentImageStatus::Failed;
    let unknown = result == SetDeploymentImageStatus::Unknown;
    let (_, send) = handle.next_request().await.unwrap();
    send.send_response(deployment_response(&serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "agent-api", "namespace": "demo",
            "uid": if unknown { "other-uid" } else { "uid-1" },
            "resourceVersion": "3", "generation": 2,
            "annotations": {"kapsel.dev/kap0038-operation-id": "application-op-1"}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
            "template": {"metadata": {"labels": {"app": "agent-api"}},
                "spec": {"containers": [{"name": "api", "image": image}]}}},
        "status": {"observedGeneration": 2,
            "updatedReplicas": i32::from(!failed),
            "availableReplicas": i32::from(!failed),
            "unavailableReplicas": i32::from(failed),
            "conditions": [if failed {
                serde_json::json!({"type": "Progressing", "status": "False",
                    "reason": "ProgressDeadlineExceeded"})
            } else {
                serde_json::json!({"type": "Available", "status": "True",
                    "reason": "MinimumReplicasAvailable"})
            }]}
    })));
    handle
}

#[tokio::test]
async fn status_reports_only_the_configured_absent_operation_without_kubernetes() {
    let root =
        std::env::temp_dir().join(format!("kapsel-application-status-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (configuration, mut handle) = configuration_and_handle(&root);
    let application = Application::open(configuration).unwrap();

    assert_eq!(
        application
            .read_set_deployment_image_status(&request().operation_id)
            .unwrap(),
        SetDeploymentImageStatus::NotFound
    );
    assert_eq!(
        application
            .read_set_deployment_image_status("other-operation")
            .unwrap(),
        SetDeploymentImageStatus::NotFound
    );
    assert_eq!(
        application
            .read_set_deployment_image_receipt(&request().operation_id)
            .unwrap(),
        SetDeploymentImageReceipt::NotFound
    );
    assert_eq!(
        application
            .read_set_deployment_image_receipt("other-operation")
            .unwrap(),
        SetDeploymentImageReceipt::NotFound
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), handle.next_request())
            .await
            .is_err()
    );

    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn reads_fail_closed_when_the_configured_grant_does_not_own_the_existing_row() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-read-authorization-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (initial_configuration, mut handle) = configuration_and_handle(&root);
    let mut application = Application::open(initial_configuration).unwrap();
    let responder = tokio::spawn(async move {
        let (_, send) = handle.next_request().await.unwrap();
        send.send_response(
            http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(Vec::<u8>::new()))
                .unwrap(),
        );
    });
    application.execute(&request()).await.unwrap();
    responder.await.unwrap();
    drop(application);

    let authorization_seed = [41_u8; 32];
    let mut different_request = request();
    different_request.container = "other".into();
    let mut different_tuple = configuration(&root);
    different_tuple.signed_authorization_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization(&different_request),
        signing_seed: &authorization_seed,
        signing_key_id: "application-authorization-key",
    })
    .unwrap();
    let application = Application::open(different_tuple).unwrap();
    assert!(matches!(
        application.read_set_deployment_image_status(&request().operation_id),
        Err(ApplicationError::OperationFailure)
    ));
    assert!(matches!(
        application.read_set_deployment_image_receipt(&request().operation_id),
        Err(ApplicationError::OperationFailure)
    ));
    drop(application);

    let replacement_seed = [43_u8; 32];
    let replacement_key = SigningKey::from_bytes(&replacement_seed);
    let mut different_authority = configuration(&root);
    different_authority.authorization_trust = AuthorizationTrust {
        key_id: "replacement-authorization-key".into(),
        public_key: replacement_key.verifying_key().to_bytes(),
    };
    different_authority.signed_authorization_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization(&request()),
        signing_seed: &replacement_seed,
        signing_key_id: "replacement-authorization-key",
    })
    .unwrap();
    let application = Application::open(different_authority).unwrap();
    assert!(matches!(
        application.read_set_deployment_image_status(&request().operation_id),
        Err(ApplicationError::OperationFailure)
    ));
    assert!(matches!(
        application.read_set_deployment_image_receipt(&request().operation_id),
        Err(ApplicationError::OperationFailure)
    ));

    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn status_projects_an_active_operation_without_advancing_it() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-active-status-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (configuration, mut handle) = configuration_and_handle(&root);
    let mut application = Application::open(configuration).unwrap();
    let operation = request();

    let mut execution = Box::pin(application.execute(&operation));
    let (_, response) = tokio::select! {
        request = handle.next_request() => request.unwrap(),
        result = &mut execution => panic!("execution completed before target response: {result:?}"),
    };
    drop(execution);
    drop(response);

    assert_eq!(
        application
            .read_set_deployment_image_status(&operation.operation_id)
            .unwrap(),
        SetDeploymentImageStatus::InProgress
    );
    assert_eq!(
        application
            .read_set_deployment_image_status(&operation.operation_id)
            .unwrap(),
        SetDeploymentImageStatus::InProgress
    );
    for _ in 0..2 {
        assert_eq!(
            application
                .read_set_deployment_image_receipt(&operation.operation_id)
                .unwrap(),
            SetDeploymentImageReceipt::NotReady
        );
    }
    let responder = tokio::spawn(respond_with_terminal_result(
        handle,
        SetDeploymentImageStatus::Succeeded,
    ));
    let report = application.execute(&operation).await.unwrap();
    let mut handle = responder.await.unwrap();
    assert_eq!(report.state, OperationState::Finalized);
    assert_eq!(
        application
            .read_set_deployment_image_status(&operation.operation_id)
            .unwrap(),
        SetDeploymentImageStatus::Succeeded
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), handle.next_request())
            .await
            .is_err()
    );

    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn execute_owns_target_rejection_lifecycle() {
    let root =
        std::env::temp_dir().join(format!("kapsel-application-execute-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (configuration, mut handle) = configuration_and_handle(&root);
    let mut application = Application::open(configuration).unwrap();
    let responder = tokio::spawn(async move {
        let (_, send) = handle.next_request().await.unwrap();
        send.send_response(
            http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "deployments.apps agent-api not found",
                        "reason": "NotFound",
                        "details": {
                            "name": "agent-api",
                            "group": "apps",
                            "kind": "deployments"
                        },
                        "code": 404
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });

    let report = application.execute(&request()).await.unwrap();

    assert_eq!(report.state, OperationState::NotAttempted);
    assert_eq!(
        report.target_rejection,
        Some(TargetRejection::DeploymentNotFound)
    );
    assert_eq!(report.result, None);
    assert_eq!(report.receipt, None);
    assert_eq!(
        application
            .read_set_deployment_image_status(&request().operation_id)
            .unwrap(),
        SetDeploymentImageStatus::NotAttempted(TargetRejection::DeploymentNotFound)
    );
    assert_eq!(
        application
            .read_set_deployment_image_status(&request().operation_id)
            .unwrap(),
        SetDeploymentImageStatus::NotAttempted(TargetRejection::DeploymentNotFound)
    );
    assert_eq!(
        application
            .read_set_deployment_image_receipt(&request().operation_id)
            .unwrap(),
        SetDeploymentImageReceipt::NotReady
    );
    assert_eq!(
        fs::metadata(root.join("journal.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    responder.await.unwrap();
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn terminal_status_and_exact_receipt_reads_preserve_frozen_receiver_facts() {
    for (name, expected) in [
        ("succeeded", SetDeploymentImageStatus::Succeeded),
        ("failed", SetDeploymentImageStatus::Failed),
        ("unknown", SetDeploymentImageStatus::Unknown),
    ] {
        let root = std::env::temp_dir().join(format!(
            "kapsel-application-terminal-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        private_directory(&root);
        let (configuration, handle) = configuration_and_handle(&root);
        let mut application = Application::open(configuration).unwrap();
        let responder = tokio::spawn(respond_with_terminal_result(handle, expected));

        let report = application.execute(&request()).await.unwrap();
        let mut handle = responder.await.unwrap();
        let reference = report.receipt.unwrap();
        let expected_bytes = fs::read(&reference.path).unwrap();

        assert_eq!(
            application
                .read_set_deployment_image_status(&request().operation_id)
                .unwrap(),
            expected
        );
        assert_eq!(
            application
                .read_set_deployment_image_receipt(&request().operation_id)
                .unwrap(),
            SetDeploymentImageReceipt::Ready {
                bytes: expected_bytes,
                sha256: reference.digest,
            }
        );
        assert_eq!(
            application
                .read_set_deployment_image_status(&request().operation_id)
                .unwrap(),
            expected
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), handle.next_request())
                .await
                .is_err()
        );

        drop(application);
        fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn status_and_receipt_fail_closed_for_incomplete_finalized_receipt_facts() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-corrupt-finalized-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (configuration, handle) = configuration_and_handle(&root);
    let journal_path = configuration.journal_path.clone();
    let mut application = Application::open(configuration).unwrap();
    let responder = tokio::spawn(respond_with_terminal_result(
        handle,
        SetDeploymentImageStatus::Succeeded,
    ));
    application.execute(&request()).await.unwrap();
    let _ = responder.await.unwrap();

    let connection = rusqlite::Connection::open(journal_path).unwrap();
    connection
        .execute(
            "UPDATE kubernetes_image_operations
             SET receipt_key_id = NULL
             WHERE operation_id = ?1",
            [&request().operation_id],
        )
        .unwrap();
    assert!(matches!(
        application.read_set_deployment_image_status(&request().operation_id),
        Err(ApplicationError::OperationFailure)
    ));
    assert!(matches!(
        application.read_set_deployment_image_receipt(&request().operation_id),
        Err(ApplicationError::OperationFailure)
    ));

    drop(connection);
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn receipt_read_fails_closed_for_hostile_finalized_storage() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-hostile-receipt-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let (configuration, handle) = configuration_and_handle(&root);
    let mut application = Application::open(configuration).unwrap();
    let responder = tokio::spawn(respond_with_terminal_result(
        handle,
        SetDeploymentImageStatus::Succeeded,
    ));
    let report = application.execute(&request()).await.unwrap();
    let _ = responder.await.unwrap();
    let reference = report.receipt.unwrap();
    let path = reference.path;
    let original = fs::read(&path).unwrap();
    let receipt = || application.read_set_deployment_image_receipt(&request().operation_id);
    let assert_rejected = || assert!(matches!(receipt(), Err(ApplicationError::OperationFailure)));

    fs::remove_file(&path).unwrap();
    assert_rejected();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    fs::write(&path, b"changed").unwrap();
    assert_rejected();
    fs::write(&path, &original).unwrap();

    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert_rejected();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let hard_link = root.join("receipt-hard-link");
    fs::hard_link(&path, &hard_link).unwrap();
    assert_rejected();
    fs::remove_file(hard_link).unwrap();

    let real_receipt = root.join("real-receipt");
    fs::rename(&path, &real_receipt).unwrap();
    std::os::unix::fs::symlink(&real_receipt, &path).unwrap();
    assert_rejected();
    fs::remove_file(&path).unwrap();
    fs::rename(&real_receipt, &path).unwrap();

    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_rejected();
    fs::remove_dir(&path).unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    fs::write(&path, vec![0_u8; 16 * 1024 + 1]).unwrap();
    assert_rejected();
    fs::write(&path, &original).unwrap();

    let receipt_directory = path.parent().unwrap();
    fs::set_permissions(receipt_directory, fs::Permissions::from_mode(0o500)).unwrap();
    assert_rejected();
    fs::set_permissions(receipt_directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        receipt().unwrap(),
        SetDeploymentImageReceipt::Ready {
            bytes: original,
            sha256: reference.digest,
        }
    );

    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn service_operator_inputs_return_only_consistent_public_identity() {
    let request = request();
    let authorization_seed = [81_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization(&request),
        signing_seed: &authorization_seed,
        signing_key_id: "service-authorization-key",
    })
    .unwrap();
    let receipt_seed = [82_u8; 32];
    let receipt_trust = ReceiptTrust {
        key_id: "service-receipt-key".into(),
        public_key: SigningKey::from_bytes(&receipt_seed)
            .verifying_key()
            .to_bytes(),
        accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
        not_before_unix_s: 100,
        not_after_unix_s: 200,
    }
    .encode()
    .unwrap();

    let validated = validate_service_operator_inputs(
        &grant,
        &authorization_key.verifying_key().to_bytes(),
        &receipt_seed,
        &receipt_trust,
    )
    .unwrap();

    assert_eq!(validated.authorization, authorization(&request));
    assert_eq!(
        validated.authorization_signing_key_id,
        "service-authorization-key"
    );
    assert_eq!(validated.receipt_signing_key_id, "service-receipt-key");
}

#[test]
fn service_operator_inputs_reject_every_inconsistent_authority() {
    let request = request();
    let authorization_seed = [83_u8; 32];
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization(&request),
        signing_seed: &authorization_seed,
        signing_key_id: "service-authorization-key",
    })
    .unwrap();
    let authorization_public_key = SigningKey::from_bytes(&authorization_seed)
        .verifying_key()
        .to_bytes();
    let receipt_seed = [84_u8; 32];
    let trust = |seed: &[u8; 32], purpose: &str| {
        ReceiptTrust {
            key_id: "service-receipt-key".into(),
            public_key: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
            accepted_purpose: purpose.into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap()
    };
    let receipt_trust = trust(&receipt_seed, "kapsel.kap0038.kubernetes-effect-receipt.v2");

    for result in [
        validate_service_operator_inputs(
            b"not-a-grant",
            &authorization_public_key,
            &receipt_seed,
            &receipt_trust,
        ),
        validate_service_operator_inputs(
            &grant,
            &SigningKey::from_bytes(&[85_u8; 32])
                .verifying_key()
                .to_bytes(),
            &receipt_seed,
            &receipt_trust,
        ),
        validate_service_operator_inputs(
            &grant,
            &authorization_public_key,
            &[86_u8; 32],
            &receipt_trust,
        ),
        validate_service_operator_inputs(
            &grant,
            &authorization_public_key,
            &receipt_seed,
            &trust(&receipt_seed, "wrong-purpose"),
        ),
    ] {
        assert!(matches!(
            result,
            Err(ApplicationError::InvalidOperatorConfiguration)
        ));
    }
}

#[tokio::test]
async fn request_match_validation_exposes_only_exact_grant_match_without_mutation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-request-match-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let mut application = Application::open(configuration(&root)).unwrap();
    let exact = request();
    assert!(application.request_matches_authorized_grant(&exact));

    for mismatched in [
        AgentRequest {
            operation_id: "other".into(),
            ..exact.clone()
        },
        AgentRequest {
            namespace: "other".into(),
            ..exact.clone()
        },
        AgentRequest {
            deployment: "other".into(),
            ..exact.clone()
        },
        AgentRequest {
            container: "other".into(),
            ..exact.clone()
        },
        AgentRequest {
            immutable_image_digest: concat!(
                "registry.k8s.io/pause@sha256:",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            .into(),
            ..exact
        },
    ] {
        assert!(!application.request_matches_authorized_grant(&mismatched));
    }
    assert_eq!(application.reconcile().await.unwrap(), None);
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn fixed_operator_document_composes_the_existing_application_grammar() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-fixed-operator-document-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let root = fs::canonicalize(root).unwrap();
    let receipts = root.join("receipts");
    private_directory(&receipts);
    let journal = root.join("journal.sqlite3");
    let access = root.join("retained");
    private_directory(&access);
    let access_receipts = access.join("receipts");
    private_directory(&access_receipts);
    let access_journal = access.join("journal.sqlite3");
    let request = request();
    let authorization_seed = [91_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let mut approved = authorization(&request);
    approved.approved_target = Some(kapsel::ApprovedTarget {
        uid: "uid".into(),
        resource_version: "rv".into(),
    });
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &approved,
        signing_seed: &authorization_seed,
        signing_key_id: "owner-key",
    })
    .unwrap();
    let receipt_seed = [92_u8; 32];
    let document = serde_json::to_vec(&serde_json::json!({
        "signed_authorization_grant": "/etc/kapsel/grant.bin",
        "authorization_key_id": "owner-key",
        "authorization_public_key": "/etc/kapsel/authorization.pub",
        "kubeconfig": "/etc/kapsel/kubeconfig.yaml",
        "journal": journal,
        "receipt_directory": receipts,
        "receipt_signing_seed": "/etc/kapsel/receipt.seed",
        "receipt_signing_key_id": "receipt-key"
    }))
    .unwrap();
    let kubeconfig = concat!(
        "apiVersion: v1\nkind: Config\ncurrent-context: fixture\n",
        "clusters:\n- name: fixture\n  cluster:\n",
        "    server: http://127.0.0.1:1234\n",
        "contexts:\n- name: fixture\n  context:\n",
        "    cluster: fixture\n    user: fixture\n",
        "users:\n- name: fixture\n  user: {}\n"
    );

    let application = open_application_from_fixed_operator_document(
        &document,
        &root.join("journal.sqlite3"),
        &root.join("receipts"),
        &access_journal,
        &access_receipts,
        |path, maximum| {
            let bytes = match path.to_str().unwrap() {
                "/etc/kapsel/grant.bin" => grant.clone(),
                "/etc/kapsel/authorization.pub" => {
                    authorization_key.verifying_key().to_bytes().to_vec()
                },
                "/etc/kapsel/kubeconfig.yaml" => kubeconfig.as_bytes().to_vec(),
                "/etc/kapsel/receipt.seed" => receipt_seed.to_vec(),
                _ => return Err(ApplicationError::InvalidOperatorConfiguration),
            };
            if bytes.len() > maximum {
                return Err(ApplicationError::InvalidOperatorConfiguration);
            }
            Ok(bytes)
        },
    )
    .await
    .unwrap();

    assert_eq!(
        application
            .read_set_deployment_image_status(&request.operation_id)
            .unwrap(),
        SetDeploymentImageStatus::NotFound
    );
    assert!(access_journal.is_file());
    assert!(!journal.exists());
    drop(application);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn fixed_operator_document_rejects_changed_state_paths_before_file_reads() {
    let document = br#"{
        "signed_authorization_grant":"/etc/kapsel/grant.bin",
        "authorization_key_id":"owner-key",
        "authorization_public_key":"/etc/kapsel/authorization.pub",
        "kubeconfig":"/etc/kapsel/kubeconfig.yaml",
        "journal":"/var/lib/kapsel/other.sqlite3",
        "receipt_directory":"/var/lib/kapsel/receipts",
        "receipt_signing_seed":"/etc/kapsel/receipt.seed",
        "receipt_signing_key_id":"receipt-key"
    }"#;
    let mut reads = 0;

    let result = open_application_from_fixed_operator_document(
        document,
        Path::new("/var/lib/kapsel/journal.sqlite3"),
        Path::new("/var/lib/kapsel/receipts"),
        Path::new("/proc/self/fd/7/journal.sqlite3"),
        Path::new("/proc/self/fd/8"),
        |_, _| {
            reads += 1;
            Err(ApplicationError::InvalidOperatorConfiguration)
        },
    )
    .await;

    assert!(matches!(
        result,
        Err(ApplicationError::InvalidOperatorConfiguration)
    ));
    assert_eq!(reads, 0);
}

#[tokio::test]
async fn invalid_operator_configuration_precedes_journal_creation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-configuration-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let mut configuration = configuration(&root);
    configuration.signed_authorization_grant = b"self-appointed".to_vec();
    let journal = configuration.journal_path.clone();

    assert!(matches!(
        Application::open(configuration),
        Err(ApplicationError::InvalidAuthorizationConfiguration)
    ));
    assert!(!journal.exists());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn relative_receipt_directory_is_rejected_before_journal_creation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-relative-receipts-{}",
        std::process::id()
    ));
    let relative_name = format!("kapsel-relative-receipts-{}", std::process::id());
    let relative_absolute = std::env::current_dir().unwrap().join(&relative_name);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&relative_absolute);
    private_directory(&root);
    private_directory(&relative_absolute);
    let mut configuration = configuration(&root);
    configuration.receipt_output_directory = PathBuf::from(&relative_name);
    let journal = configuration.journal_path.clone();

    assert!(matches!(
        Application::open(configuration),
        Err(ApplicationError::InvalidReceiptOutputDirectory)
    ));
    assert!(!journal.exists());

    fs::remove_dir_all(relative_absolute).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn unsafe_journal_path_is_rejected_before_creation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-journal-path-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let mut configuration = configuration(&root);
    configuration.journal_path = PathBuf::from("relative-journal.sqlite3");

    assert!(matches!(
        Application::open(configuration),
        Err(ApplicationError::InvalidJournalPath)
    ));
    assert!(!Path::new("relative-journal.sqlite3").exists());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn mismatched_intent_does_not_create_an_operation() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-application-mismatch-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let mut application = Application::open(configuration(&root)).unwrap();
    let mut mismatched = request();
    mismatched.container = "other".into();

    assert!(matches!(
        application.execute(&mismatched).await,
        Err(ApplicationError::RequestRejected)
    ));
    assert_eq!(application.reconcile().await.unwrap(), None);
    drop(application);
    fs::remove_dir_all(root).unwrap();
}
