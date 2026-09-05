//! Concrete Kubernetes Deployment-image adapter for the effect gateway.
//!
//! This module owns one conditional strategic image patch and bounded Deployment observation. It
//! is not a generic Kubernetes adapter interface.

use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use kube::{
    api::{Api, Patch, PatchParams},
    Client,
};
use serde_json::{json, Value};

use super::{
    super::{DeploymentImageAdapter, SetDeploymentImageRequest, TargetReadError, TargetRejection},
    facts::{ApplyOutcome, ReceiverObservation, TargetIdentity},
};

const OPERATION_ANNOTATION: &str = "kapsel.dev/kap0038-operation-id";
const OBSERVATION_ATTEMPTS_MAX: usize = 30;
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);
const OBSERVATION_DEADLINE: Duration = Duration::from_secs(30);
const PROVIDER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const _: () = assert!(OBSERVATION_ATTEMPTS_MAX > 0);
const _: () = assert!(
    (OBSERVATION_ATTEMPTS_MAX as u64 - 1) * OBSERVATION_INTERVAL.as_secs()
        < OBSERVATION_DEADLINE.as_secs()
);

pub(crate) struct KubernetesDeploymentImageAdapter {
    client: Client,
    observation_attempts: usize,
    observation_interval: Duration,
    observation_deadline: Duration,
    provider_request_timeout: Duration,
}

impl KubernetesDeploymentImageAdapter {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            observation_attempts: OBSERVATION_ATTEMPTS_MAX,
            observation_interval: OBSERVATION_INTERVAL,
            observation_deadline: OBSERVATION_DEADLINE,
            provider_request_timeout: PROVIDER_REQUEST_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_observation_schedule(
        client: Client,
        observation_attempts: usize,
        observation_interval: Duration,
    ) -> Self {
        Self::with_observation_limits(
            client,
            observation_attempts,
            observation_interval,
            Duration::from_secs(1),
        )
    }

    #[cfg(test)]
    fn with_observation_limits(
        client: Client,
        observation_attempts: usize,
        observation_interval: Duration,
        observation_deadline: Duration,
    ) -> Self {
        assert!(observation_attempts > 0);
        assert!(observation_attempts <= OBSERVATION_ATTEMPTS_MAX);
        assert!(!observation_deadline.is_zero());
        Self {
            client,
            observation_attempts,
            observation_interval,
            observation_deadline,
            provider_request_timeout: Duration::from_secs(1),
        }
    }

    fn deployments(&self, namespace: &str) -> Api<Deployment> {
        Api::namespaced(self.client.clone(), namespace)
    }

    async fn observe_until_terminal(
        &self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> ReceiverObservation {
        let mut latest_observation = ReceiverObservation::unknown();
        for attempt in 0..self.observation_attempts {
            latest_observation = self
                .deployments(&request.namespace)
                .get(&request.deployment)
                .await
                .map_or_else(
                    |_| ReceiverObservation::unknown(),
                    |deployment| receiver_observation(request, &deployment),
                );
            if latest_observation.observation_is_complete(request, outcome)
                || attempt + 1 == self.observation_attempts
            {
                break;
            }
            tokio::time::sleep(self.observation_interval).await;
        }
        latest_observation
    }
}

impl DeploymentImageAdapter for KubernetesDeploymentImageAdapter {
    async fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> Result<TargetIdentity, TargetReadError> {
        let deployment = tokio::time::timeout(
            self.provider_request_timeout,
            self.deployments(&request.namespace)
                .get(&request.deployment),
        )
        .await
        .map_err(|_| TargetReadError::Transient)?
        .map_err(target_get_error)?;

        let container_exists = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.template.spec.as_ref())
            .is_some_and(|spec| {
                spec.containers
                    .iter()
                    .any(|container| container.name == request.container)
            });
        if !container_exists {
            return Err(TargetReadError::Permanent(
                TargetRejection::ContainerNotFound,
            ));
        }

        let deployment_uid = deployment
            .metadata
            .uid
            .ok_or(TargetReadError::Permanent(TargetRejection::InvalidTarget))?;
        let resource_version = deployment
            .metadata
            .resource_version
            .ok_or(TargetReadError::Permanent(TargetRejection::InvalidTarget))?;

        let target = TargetIdentity {
            deployment_uid,
            resource_version,
        };
        target
            .validate()
            .map_err(|_| TargetReadError::Permanent(TargetRejection::InvalidTarget))?;
        Ok(target)
    }

    async fn apply(
        &mut self,
        request: &SetDeploymentImageRequest,
        target: &TargetIdentity,
    ) -> Result<ApplyOutcome, ()> {
        let deployment = tokio::time::timeout(
            self.provider_request_timeout,
            self.deployments(&request.namespace).patch(
                &request.deployment,
                &PatchParams::default(),
                &Patch::Strategic(deployment_patch_document(request, target)),
            ),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

        let deployment_uid = deployment.metadata.uid.ok_or(())?;
        if deployment_uid != target.deployment_uid {
            return Err(());
        }

        let resource_version = deployment.metadata.resource_version.ok_or(())?;
        Ok(ApplyOutcome {
            accepted: true,
            requested_generation: deployment.metadata.generation,
            deployment_uid: Some(deployment_uid),
            resource_version: Some(resource_version),
        })
    }

    async fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> Result<ReceiverObservation, ()> {
        Ok(tokio::time::timeout(
            self.observation_deadline,
            self.observe_until_terminal(request, outcome),
        )
        .await
        .unwrap_or_else(|_| ReceiverObservation::unknown()))
    }
}

fn target_get_error(error: kube::Error) -> TargetReadError {
    match error {
        kube::Error::Api(response) if response.code == 404 => {
            TargetReadError::Permanent(TargetRejection::DeploymentNotFound)
        },
        _ => TargetReadError::Transient,
    }
}

fn deployment_patch_document(
    request: &SetDeploymentImageRequest,
    target: &TargetIdentity,
) -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": request.deployment,
            "namespace": request.namespace,
            "uid": target.deployment_uid,
            "resourceVersion": target.resource_version,
            "annotations": {
                OPERATION_ANNOTATION: request.operation_id,
            },
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": request.container,
                        "image": request.immutable_image_digest,
                    }],
                },
            },
        },
    })
}

#[cfg(test)]
pub(crate) fn deployment_patch_document_for_test(
    request: &SetDeploymentImageRequest,
    target: &TargetIdentity,
) -> Value {
    deployment_patch_document(request, target)
}

fn receiver_observation(
    request: &SetDeploymentImageRequest,
    deployment: &Deployment,
) -> ReceiverObservation {
    let image = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .and_then(|spec| {
            spec.containers
                .iter()
                .find(|container| container.name == request.container)
        })
        .and_then(|container| container.image.clone());
    let operation_marker = deployment
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(OPERATION_ANNOTATION))
        .cloned();
    let status = deployment.status.as_ref();
    let conditions = status.and_then(|status| status.conditions.as_ref());
    let rollout_condition = conditions.and_then(|conditions| {
        conditions
            .iter()
            .find(|condition| {
                condition.type_ == "Progressing"
                    && condition.status == "False"
                    && condition.reason.as_deref() == Some("ProgressDeadlineExceeded")
            })
            .or_else(|| {
                conditions
                    .iter()
                    .find(|condition| condition.type_ == "Available" && condition.status == "True")
            })
    });
    ReceiverObservation {
        deployment_uid: deployment.metadata.uid.clone(),
        resource_version: deployment.metadata.resource_version.clone(),
        current_generation: deployment.metadata.generation,
        observed_generation: status.and_then(|status| status.observed_generation),
        image,
        operation_marker,
        desired_replicas: deployment.spec.as_ref().and_then(|spec| spec.replicas),
        updated_replicas: status.map(|status| status.updated_replicas.unwrap_or(0)),
        available_replicas: status.map(|status| status.available_replicas.unwrap_or(0)),
        unavailable_replicas: status.map(|status| status.unavailable_replicas.unwrap_or(0)),
        rollout_condition_type: rollout_condition.map(|condition| condition.type_.clone()),
        rollout_condition_status: rollout_condition.map(|condition| condition.status.clone()),
        rollout_condition_reason: rollout_condition.and_then(|condition| condition.reason.clone()),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, future::pending};

    use http::{Method, Request, Response, StatusCode};
    use kube::client::Body;
    use serde_json::json;
    use tower_test::mock;

    use super::*;
    use crate::gateway::ValidatedRequest;

    fn request() -> SetDeploymentImageRequest {
        SetDeploymentImageRequest {
            operation_id: "op-001".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        }
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            deployment_uid: "deployment-uid-1".into(),
            resource_version: "resource-version-1".into(),
        }
    }

    fn apply_outcome() -> ApplyOutcome {
        ApplyOutcome {
            accepted: true,
            requested_generation: Some(2),
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-2".into()),
        }
    }

    fn deployment_response(progress_deadline_exceeded: bool) -> Value {
        let request = request();
        let conditions = if progress_deadline_exceeded {
            json!([{
                "type": "Progressing",
                "status": "False",
                "reason": "ProgressDeadlineExceeded"
            }])
        } else {
            json!([{
                "type": "Available",
                "status": "True",
                "reason": "MinimumReplicasAvailable"
            }])
        };
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "agent-api",
                "namespace": "demo",
                "uid": "deployment-uid-1",
                "resourceVersion": "resource-version-2",
                "generation": 2,
                "annotations": {
                    OPERATION_ANNOTATION: "op-001"
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {"app": "agent-api"}
                },
                "template": {
                    "metadata": {
                        "labels": {"app": "agent-api"}
                    },
                    "spec": {
                        "containers": [{
                            "name": "api",
                            "image": request.immutable_image_digest
                        }]
                    }
                }
            },
            "status": {
                "observedGeneration": 2,
                "replicas": 1,
                "updatedReplicas": i32::from(!progress_deadline_exceeded),
                "availableReplicas": i32::from(!progress_deadline_exceeded),
                "unavailableReplicas": i32::from(progress_deadline_exceeded),
                "conditions": conditions
            }
        })
    }

    fn test_adapter() -> (
        KubernetesDeploymentImageAdapter,
        mock::Handle<Request<Body>, Response<Body>>,
    ) {
        test_adapter_with_attempts(1)
    }

    fn test_adapter_with_attempts(
        observation_attempts: usize,
    ) -> (
        KubernetesDeploymentImageAdapter,
        mock::Handle<Request<Body>, Response<Body>>,
    ) {
        let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(mock_service, "default");
        (
            KubernetesDeploymentImageAdapter::with_observation_schedule(
                client,
                observation_attempts,
                Duration::ZERO,
            ),
            handle,
        )
    }

    fn progressing_response() -> Value {
        let mut response = deployment_response(false);
        response["status"]["updatedReplicas"] = json!(0);
        response["status"]["availableReplicas"] = json!(0);
        response["status"]["unavailableReplicas"] = json!(1);
        response["status"]["conditions"] = json!([{
            "type": "Progressing",
            "status": "True",
            "reason": "ReplicaSetUpdated"
        }]);
        response
    }

    #[test]
    fn patch_document_changes_only_the_exact_image_and_operation_annotation() {
        let request = request();

        assert_eq!(
            deployment_patch_document(&request, &target()),
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "agent-api",
                    "namespace": "demo",
                    "uid": "deployment-uid-1",
                    "resourceVersion": "resource-version-1",
                    "annotations": {
                        "kapsel.dev/kap0038-operation-id": "op-001"
                    }
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "api",
                                "image": request.immutable_image_digest
                            }]
                        }
                    }
                }
            })
        );
    }

    #[tokio::test]
    async fn target_identification_uses_one_bounded_deployment_get() {
        let (mut adapter, mut handle) = test_adapter();
        let responder = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), Method::GET);
            assert_eq!(
                request.uri().path(),
                "/apis/apps/v1/namespaces/demo/deployments/agent-api"
            );
            send.send_response(Response::new(Body::from(
                serde_json::to_vec(&deployment_response(false)).unwrap(),
            )));
        });

        let target = adapter.identify(&request()).await.unwrap();

        assert_eq!(target.deployment_uid, "deployment-uid-1");
        assert_eq!(target.resource_version, "resource-version-2");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn identification_rejects_a_missing_container_before_apply() {
        let (mut adapter, mut handle) = test_adapter();
        let responder = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            let mut response = deployment_response(false);
            response["spec"]["template"]["spec"]["containers"][0]["name"] = json!("other");
            send.send_response(Response::new(Body::from(
                serde_json::to_vec(&response).unwrap(),
            )));
        });

        assert_eq!(
            adapter.identify(&request()).await,
            Err(TargetReadError::Permanent(
                TargetRejection::ContainerNotFound
            ))
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn missing_deployment_is_a_permanent_pre_attempt_rejection() {
        let (mut adapter, mut handle) = test_adapter();
        let responder = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from(
                        serde_json::to_vec(&json!({
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

        assert_eq!(
            adapter.identify(&request()).await,
            Err(TargetReadError::Permanent(
                TargetRejection::DeploymentNotFound
            ))
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn identification_requires_uid_and_resource_version() {
        for missing_field in ["uid", "resourceVersion"] {
            let (mut adapter, mut handle) = test_adapter();
            let responder = tokio::spawn(async move {
                let (_, send) = handle.next_request().await.unwrap();
                let mut response = deployment_response(false);
                response["metadata"]
                    .as_object_mut()
                    .unwrap()
                    .remove(missing_field);
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&response).unwrap(),
                )));
            });

            assert_eq!(
                adapter.identify(&request()).await,
                Err(TargetReadError::Permanent(TargetRejection::InvalidTarget))
            );
            responder.await.unwrap();
        }
    }

    #[tokio::test]
    async fn target_and_apply_requests_each_have_a_deadline() {
        let (mut identify_adapter, mut identify_handle) = test_adapter();
        identify_adapter.provider_request_timeout = Duration::from_millis(10);
        let identify_responder = tokio::spawn(async move {
            let (_request, _send) = identify_handle.next_request().await.unwrap();
            pending::<()>().await;
        });
        assert_eq!(
            identify_adapter.identify(&request()).await,
            Err(TargetReadError::Transient)
        );
        identify_responder.abort();

        let (mut apply_adapter, mut apply_handle) = test_adapter();
        apply_adapter.provider_request_timeout = Duration::from_millis(10);
        let apply_responder = tokio::spawn(async move {
            let (_request, _send) = apply_handle.next_request().await.unwrap();
            pending::<()>().await;
        });
        assert_eq!(apply_adapter.apply(&request(), &target()).await, Err(()));
        apply_responder.abort();
    }

    #[tokio::test]
    async fn apply_uses_conditional_strategic_patch_and_returns_acceptance_facts() {
        let (mut adapter, mut handle) = test_adapter();
        let expected_request = request();
        let expected_target = target();
        let responder_request = expected_request.clone();
        let responder_target = expected_target.clone();
        let responder = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), Method::PATCH);
            assert_eq!(
                request.uri().path(),
                "/apis/apps/v1/namespaces/demo/deployments/agent-api"
            );
            let query: BTreeMap<_, _> = request
                .uri()
                .query()
                .unwrap()
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .collect();
            assert!(!query.contains_key("fieldManager"));
            assert!(!query.contains_key("force"));
            assert_eq!(
                request.headers().get("content-type").unwrap(),
                "application/strategic-merge-patch+json"
            );
            let body: Value =
                serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                    .unwrap();
            assert_eq!(
                body,
                deployment_patch_document(&responder_request, &responder_target)
            );
            send.send_response(Response::new(Body::from(
                serde_json::to_vec(&deployment_response(false)).unwrap(),
            )));
        });

        let outcome = adapter
            .apply(&expected_request, &expected_target)
            .await
            .unwrap();

        assert!(outcome.accepted);
        assert_eq!(outcome.requested_generation, Some(2));
        assert_eq!(outcome.deployment_uid.as_deref(), Some("deployment-uid-1"));
        assert_eq!(
            outcome.resource_version.as_deref(),
            Some("resource-version-2")
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn apply_response_requires_the_same_uid_and_a_resource_version() {
        for (case, field, replacement) in [
            ("missing deployment UID", "uid", None),
            ("missing resource version", "resourceVersion", None),
            ("changed deployment UID", "uid", Some("replacement-uid")),
        ] {
            let (mut adapter, mut handle) = test_adapter();
            let responder = tokio::spawn(async move {
                let (_, send) = handle.next_request().await.unwrap();
                let mut response = deployment_response(false);
                let metadata = response["metadata"].as_object_mut().unwrap();
                if let Some(replacement) = replacement {
                    metadata.insert(field.into(), json!(replacement));
                } else {
                    metadata.remove(field);
                }
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&response).unwrap(),
                )));
            });

            assert_eq!(
                adapter.apply(&request(), &target()).await,
                Err(()),
                "{case}"
            );
            responder.await.unwrap();
        }
    }

    #[tokio::test]
    async fn observation_ignores_terminal_conditions_from_a_stale_generation() {
        let (mut adapter, mut handle) = test_adapter_with_attempts(2);
        let responder = tokio::spawn(async move {
            let mut stale = deployment_response(false);
            stale["status"]["observedGeneration"] = json!(1);
            for response in [stale, deployment_response(true)] {
                let (_, send) = handle.next_request().await.unwrap();
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&response).unwrap(),
                )));
            }
        });

        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();

        assert_eq!(
            observation.rollout_condition_reason.as_deref(),
            Some("ProgressDeadlineExceeded")
        );
        assert_eq!(observation.observed_generation, Some(2));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn observation_retains_the_exact_selected_available_condition_reason() {
        let (mut adapter, mut handle) = test_adapter();
        let responder = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            let mut response = deployment_response(false);
            response["status"]["conditions"][0]["reason"] = json!("DifferentObservedReason");
            send.send_response(Response::new(Body::from(
                serde_json::to_vec(&response).unwrap(),
            )));
        });

        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();

        assert_eq!(
            observation.rollout_condition_type.as_deref(),
            Some("Available")
        );
        assert_eq!(
            observation.rollout_condition_status.as_deref(),
            Some("True")
        );
        assert_eq!(
            observation.rollout_condition_reason.as_deref(),
            Some("DifferentObservedReason")
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn omitted_zero_replica_counts_can_still_report_success() {
        let (mut adapter, mut handle) = test_adapter();
        let responder = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            let mut response = deployment_response(false);
            response["status"]
                .as_object_mut()
                .unwrap()
                .remove("unavailableReplicas");
            send.send_response(Response::new(Body::from(
                serde_json::to_vec(&response).unwrap(),
            )));
        });

        let request = request();
        let outcome = apply_outcome();
        let observation = adapter.observe(&request, &outcome).await.unwrap();

        assert_eq!(observation.unavailable_replicas, Some(0));
        assert_eq!(
            observation.classify(&ValidatedRequest::try_from(&request).unwrap(), &outcome),
            crate::OperationResult::Succeeded
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn observation_is_bounded_and_stops_on_progress_deadline() {
        let (mut adapter, mut handle) = test_adapter_with_attempts(3);
        let responder = tokio::spawn(async move {
            for response in [
                progressing_response(),
                progressing_response(),
                deployment_response(true),
            ] {
                let (request, send) = handle.next_request().await.unwrap();
                assert_eq!(request.method(), Method::GET);
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&response).unwrap(),
                )));
            }
        });

        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();

        assert_eq!(
            observation.rollout_condition_reason.as_deref(),
            Some("ProgressDeadlineExceeded")
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn observation_budget_exhaustion_remains_unknown() {
        let (mut adapter, mut handle) = test_adapter_with_attempts(3);
        let responder = tokio::spawn(async move {
            for _ in 0..3 {
                let (_, send) = handle.next_request().await.unwrap();
                send.send_response(Response::new(Body::from(
                    serde_json::to_vec(&progressing_response()).unwrap(),
                )));
            }
        });

        let request = request();
        let outcome = apply_outcome();
        let observation = adapter.observe(&request, &outcome).await.unwrap();

        assert!(!observation.observation_is_complete(&request, &outcome));
        assert_eq!(
            observation.classify(&ValidatedRequest::try_from(&request).unwrap(), &outcome),
            crate::OperationResult::Unknown
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn stalled_deployment_read_is_stopped_by_the_observation_deadline() {
        let (mock_service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(mock_service, "default");
        let mut adapter = KubernetesDeploymentImageAdapter::with_observation_limits(
            client,
            OBSERVATION_ATTEMPTS_MAX,
            Duration::ZERO,
            Duration::from_millis(10),
        );
        let responder = tokio::spawn(async move {
            let (_request, _send) = handle.next_request().await.unwrap();
            pending::<()>().await;
        });

        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();

        assert_eq!(observation, ReceiverObservation::unknown());
        responder.abort();
    }

    #[tokio::test]
    async fn observation_maps_progress_deadline_without_treating_acceptance_as_success() {
        let (mut adapter, mut handle) = test_adapter();
        let responder = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), Method::GET);
            send.send_response(Response::new(Body::from(
                serde_json::to_vec(&deployment_response(true)).unwrap(),
            )));
        });

        let observation = adapter.observe(&request(), &apply_outcome()).await.unwrap();

        assert_eq!(
            observation.rollout_condition_reason.as_deref(),
            Some("ProgressDeadlineExceeded")
        );
        assert_eq!(observation.observed_generation, Some(2));
        assert_eq!(observation.operation_marker.as_deref(), Some("op-001"));
        responder.await.unwrap();
    }
}
