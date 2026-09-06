//! Deep implementation of the one authorized Kubernetes Deployment image operation.
//!
//! This module owns orchestration and its private test seams. The crate root remains a compact map
//! of the caller-visible interface and concrete internal owners.

mod authorization;
#[cfg(feature = "demo-harness")]
mod demo_control;
mod journal;
mod kubernetes;
mod receipt;

use std::{
    error::Error,
    fmt,
    future::Future,
    path::{Path, PathBuf},
};

use authorization::VerifiedAuthorization;
pub(crate) use authorization::{
    sign_authorization_grant, validate_authorization_trust, verify_authorization_grant,
};
pub use authorization::{ApprovedTarget, AuthorizationTrust, ExactAuthorization};
use journal::Journal;
pub(crate) use kubernetes::KubernetesDeploymentImageAdapter;
#[cfg(test)]
pub(crate) use kubernetes::{
    deployment_patch_document_for_test as test_deployment_patch_document,
    ApplyOutcome as TestApplyOutcome,
    KubernetesDeploymentImageAdapter as TestKubernetesDeploymentImageAdapter,
    ReceiverObservation as TestReceiverObservation, TargetIdentity as TestTargetIdentity,
};
use kubernetes::{ApplyOutcome, ReceiverObservation, TargetIdentity, ValidatedTargetIdentity};
pub use receipt::{
    inspect_receipt, InspectionLimits, InspectionReport, InspectionStatus, ReceiptError,
    ReceiptStatement, ReceiptTrust,
};
use receipt::{publication, sign_statement};
pub(crate) use receipt::{publication::validate_private_directory, validate_key_id};

/// The one bounded Kubernetes effect accepted by the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetDeploymentImageRequest {
    /// Stable local identity for this operation.
    pub operation_id: String,
    /// Exact Kubernetes namespace containing the target Deployment.
    pub namespace: String,
    /// Exact target Deployment name.
    pub deployment: String,
    /// Exact target container name within the Deployment pod template.
    pub container: String,
    /// Narrow named image reference pinned by a lowercase SHA-256 digest.
    pub immutable_image_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationId(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Namespace(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeploymentName(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContainerName(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImmutableImageDigest(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct ValidatedRequest {
    operation_id: OperationId,
    namespace: Namespace,
    deployment: DeploymentName,
    container: ContainerName,
    immutable_image: ImmutableImageDigest,
}

impl TryFrom<&SetDeploymentImageRequest> for ValidatedRequest {
    type Error = GatewayError;

    fn try_from(request: &SetDeploymentImageRequest) -> Result<Self, Self::Error> {
        validate_identity(InputField::OperationId, &request.operation_id)?;
        validate_dns_label(InputField::Namespace, &request.namespace)?;
        validate_dns_subdomain(InputField::Deployment, &request.deployment)?;
        validate_dns_label(InputField::Container, &request.container)?;
        validate_immutable_image(&request.immutable_image_digest)?;
        Ok(Self {
            operation_id: OperationId(request.operation_id.clone()),
            namespace: Namespace(request.namespace.clone()),
            deployment: DeploymentName(request.deployment.clone()),
            container: ContainerName(request.container.clone()),
            immutable_image: ImmutableImageDigest(request.immutable_image_digest.clone()),
        })
    }
}

impl ValidatedRequest {
    pub(in crate::gateway) fn operation_id(&self) -> &str {
        &self.operation_id.0
    }

    pub(in crate::gateway) fn namespace(&self) -> &str {
        &self.namespace.0
    }

    pub(in crate::gateway) fn deployment(&self) -> &str {
        &self.deployment.0
    }

    pub(in crate::gateway) fn container(&self) -> &str {
        &self.container.0
    }

    pub(in crate::gateway) fn immutable_image_digest(&self) -> &str {
        &self.immutable_image.0
    }

    fn to_adapter_request(&self) -> SetDeploymentImageRequest {
        SetDeploymentImageRequest {
            operation_id: self.operation_id().to_owned(),
            namespace: self.namespace().to_owned(),
            deployment: self.deployment().to_owned(),
            container: self.container().to_owned(),
            immutable_image_digest: self.immutable_image_digest().to_owned(),
        }
    }
}

pub(in crate::gateway) struct AuthorizedRequest {
    request: ValidatedRequest,
    authorization: VerifiedAuthorization,
}

impl AuthorizedRequest {
    fn bind(
        request: ValidatedRequest,
        authorization: VerifiedAuthorization,
    ) -> Result<Self, GatewayError> {
        if !authorization_matches(&authorization.authorization, &request) {
            return Err(GatewayError::AuthorizationMismatch);
        }
        Ok(Self {
            request,
            authorization,
        })
    }

    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        &self.request
    }

    pub(in crate::gateway) fn authorization(&self) -> &VerifiedAuthorization {
        &self.authorization
    }
}

/// Bounded receiver identity/version facts, with explicit missing observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTarget {
    /// Receiver UID, when observed.
    pub uid: Option<String>,
    /// Opaque receiver version, when observed.
    pub resource_version: Option<String>,
}

/// Distinct approval, observation, and mutation-precondition projections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "contract names distinguish approval from observations and attempts"
)]
pub struct OperationTargets {
    /// Signed object version, absent for legacy authority.
    pub approved_target: Option<ApprovedTarget>,
    /// Frozen receiver observation or preflight read, never an inferred approval.
    pub observed_target: Option<ObservedTarget>,
    /// Frozen mutation preconditions, absent before apply_started.
    pub attempt_target: Option<ApprovedTarget>,
}

/// Public durable states defined by the effect-gateway owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationState {
    /// Bounded request facts are durable.
    Requested,
    /// Authentic grant identity, signer, digest, and exact tuple are durable.
    Authorized,
    /// A permanent target rejection was frozen before any mutation attempt.
    NotAttempted,
    /// The provider attempt marker is durable.
    ApplyStarted,
    /// Bounded receiver facts and result are frozen.
    ReceiverObserved,
    /// Exact signed receipt bytes and publication identity are durable.
    ReceiptPrepared,
    /// The frozen receipt bytes are installed at the frozen path.
    ReceiptWritten,
    /// The operation is terminal and read-only.
    Finalized,
}

/// Outcome of submitting an exact authorized request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubmissionResult {
    /// A new authorized operation was recorded.
    Created,
    /// The same authorized operation already exists in this state.
    Existing(OperationState),
}

/// Bounded permanent target rejection recorded before any mutation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetRejection {
    /// Kubernetes reported that the exact Deployment does not exist.
    DeploymentNotFound,
    /// The exact named container does not exist in the target Deployment.
    ContainerNotFound,
    /// The target lacked a valid bounded UID or resource version.
    InvalidTarget,
    /// The observed object identity or version differs from the signed approval.
    StaleApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetReadError {
    Transient,
    Permanent(TargetRejection),
}

/// Receiver result vocabulary owned by the effect gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationResult {
    /// The requested generation and image reached the bounded available predicate.
    Succeeded,
    /// Kubernetes reported the requested generation exceeded its progress deadline.
    Failed,
    /// Bounded receiver facts established neither defined outcome.
    Unknown,
}

pub(crate) const WRITE_STRATEGY: &str = "conditional-strategic-merge-patch";

pub(crate) trait DeploymentImageAdapter {
    fn identify(
        &mut self,
        request: &SetDeploymentImageRequest,
    ) -> impl Future<Output = Result<TargetIdentity, TargetReadError>> + Send;

    fn apply(
        &mut self,
        request: &SetDeploymentImageRequest,
        target: &TargetIdentity,
    ) -> impl Future<Output = Result<ApplyOutcome, ()>> + Send;

    fn observe(
        &mut self,
        request: &SetDeploymentImageRequest,
        outcome: &ApplyOutcome,
    ) -> impl Future<Output = Result<ReceiverObservation, ()>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultPoint {
    RequestedCommitted,
    AuthorizedCommitted,
    TargetRejectedCommitted,
    ApplyStartedCommitted,
    TargetObserved,
    ApplyReturned,
    ApplyOutcomeCommitted,
    ReceiverRead,
    ReceiverObservedCommitted,
    #[cfg(test)]
    ReceiptPreparedCommitted,
    #[cfg(test)]
    ReceiptPublished,
    #[cfg(test)]
    ReceiptWrittenCommitted,
    #[cfg(test)]
    FinalizedCommitted,
}

/// Signing and output settings supplied by application composition.
pub(crate) struct ReceiptSettings<'a> {
    /// Fixed prototype signing seed owned by the application.
    pub(crate) signing_seed: &'a [u8; 32],
    /// External trust key identifier for the signing key.
    pub(crate) key_id: &'a str,
    /// Owner-controlled output directory for immutable receipt bytes.
    pub(crate) output_directory: &'a Path,
}

/// Immutable receipt reference stored after finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptReference {
    /// Path where exact receipt bytes were installed.
    pub path: PathBuf,
    /// SHA-256 digest of exact receipt bytes.
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct FrozenReceipt {
    operation_id: String,
    bytes: Vec<u8>,
    digest: String,
    path: PathBuf,
    key_id: String,
}

pub(in crate::gateway) struct ReceiptToPrepare {
    receipt: FrozenReceipt,
}

impl ReceiptToPrepare {
    pub(in crate::gateway) fn receipt(&self) -> &FrozenReceipt {
        &self.receipt
    }
}

/// SQLite-backed entry point for the one operation.
pub(crate) struct Gateway {
    journal: Journal,
    authorization_trust: AuthorizationTrust,
}

impl Gateway {
    /// Opens or creates the prototype journal.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        authorization_trust: AuthorizationTrust,
    ) -> Result<Self, GatewayError> {
        validate_authorization_trust(&authorization_trust)?;
        Ok(Self {
            journal: Journal::open(path)?,
            authorization_trust,
        })
    }

    /// Submits one request under an owner-signed exact authorization grant.
    pub(crate) fn submit_authorized(
        &self,
        request: &SetDeploymentImageRequest,
        signed_grant: &[u8],
    ) -> Result<SubmissionResult, GatewayError> {
        self.submit_authorized_with_fault(request, signed_grant, None)
    }

    fn submit_authorized_with_fault(
        &self,
        request: &SetDeploymentImageRequest,
        signed_grant: &[u8],
        fault: Option<FaultPoint>,
    ) -> Result<SubmissionResult, GatewayError> {
        let request = ValidatedRequest::try_from(request)?;
        let verified = verify_authorization_grant(signed_grant, &self.authorization_trust)?;
        let authorized = AuthorizedRequest::bind(request, verified)?;
        if let Some(existing) = self.journal.existing_submission(&authorized)? {
            if existing == OperationState::Requested {
                self.mark_requested_authorized(&authorized)?;
                if fault == Some(FaultPoint::AuthorizedCommitted) {
                    return Err(GatewayError::InjectedFault);
                }
                return Ok(SubmissionResult::Created);
            }
            return Ok(SubmissionResult::Existing(existing));
        }
        self.journal.insert_requested(&authorized)?;
        if fault == Some(FaultPoint::RequestedCommitted) {
            return Err(GatewayError::InjectedFault);
        }
        self.mark_requested_authorized(&authorized)?;
        if fault == Some(FaultPoint::AuthorizedCommitted) {
            return Err(GatewayError::InjectedFault);
        }
        Ok(SubmissionResult::Created)
    }

    fn mark_requested_authorized(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<(), GatewayError> {
        let operation = self
            .journal
            .operation(authorized.request().operation_id())?
            .ok_or(GatewayError::InvalidPersistedState)?;
        let journal::LoadedOperation::Requested(requested) = operation else {
            return Err(GatewayError::InvalidTransition);
        };
        self.journal.mark_authorized(&requested, authorized)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        use ed25519_dalek::SigningKey;

        let seed = [7_u8; 32];
        Self::open(
            path,
            AuthorizationTrust {
                key_id: "effect-gateway-authorization-test-key".into(),
                public_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn submit_exact_for_test(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &ExactAuthorization,
    ) -> Result<SubmissionResult, GatewayError> {
        self.submit_exact_with_fault_for_test(request, authorization, None)
    }

    #[cfg(test)]
    fn submit_exact_with_fault_for_test(
        &self,
        request: &SetDeploymentImageRequest,
        authorization: &ExactAuthorization,
        fault: Option<FaultPoint>,
    ) -> Result<SubmissionResult, GatewayError> {
        let signed = sign_authorization_grant(
            authorization,
            &[7_u8; 32],
            "effect-gateway-authorization-test-key",
        )?;
        self.submit_authorized_with_fault(request, &signed, fault)
    }

    /// Reads the durable public state for one local operation identity.
    #[cfg(test)]
    pub(crate) fn get(&self, operation_id: &str) -> Result<Option<OperationState>, GatewayError> {
        self.journal.state(operation_id)
    }

    pub(crate) fn authorized_operation(
        &self,
        request: &SetDeploymentImageRequest,
        signed_grant: &[u8],
    ) -> Result<Option<journal::LoadedOperation>, GatewayError> {
        let verified = verify_authorization_grant(signed_grant, &self.authorization_trust)?;
        let request = ValidatedRequest::try_from(request)?;
        let authorized = AuthorizedRequest::bind(request, verified)?;
        self.journal.authorized_operation(&authorized)
    }

    /// Reads a frozen receiver result when observation has completed.
    #[cfg(test)]
    pub(crate) fn result(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationResult>, GatewayError> {
        self.journal.result(operation_id)
    }

    /// Reads a terminal pre-attempt target rejection, distinct from receiver result.
    #[cfg(test)]
    pub(crate) fn target_rejection(
        &self,
        operation_id: &str,
    ) -> Result<Option<TargetRejection>, GatewayError> {
        self.journal.target_rejection(operation_id)
    }

    /// Writes or finalizes one receipt from frozen receiver facts without Kubernetes access.
    #[cfg(test)]
    pub(crate) fn finalize_receipt_once(
        &self,
        settings: &ReceiptSettings<'_>,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.finalize_receipt_once_with_fault(settings, None)
    }

    pub(crate) fn finalize_operation_receipt_once(
        &self,
        operation_id: &str,
        settings: &ReceiptSettings<'_>,
        access_directory: Option<&Path>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        self.finalize_locked_operation_receipt_once(operation_id, settings, access_directory, None)
    }

    #[cfg(test)]
    fn finalize_operation_receipt_once_with_fault(
        &self,
        operation_id: &str,
        settings: &ReceiptSettings<'_>,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        self.finalize_locked_operation_receipt_once(operation_id, settings, None, fault)
    }

    // Queue-oriented tests select only an exact identity while holding worker exclusion, then cross
    // the same operation-selected implementation used by Application.
    #[cfg(test)]
    pub(crate) fn finalize_receipt_once_with_fault(
        &self,
        settings: &ReceiptSettings<'_>,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        let operation = self.journal.next_receipt_finalization_operation()?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        self.finalize_locked_operation_receipt_once(
            operation.request().operation_id(),
            settings,
            None,
            fault,
        )
    }

    fn finalize_locked_operation_receipt_once(
        &self,
        operation_id: &str,
        settings: &ReceiptSettings<'_>,
        access_directory: Option<&Path>,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        #[cfg(not(test))]
        let _ = fault;
        loop {
            let Some(operation) = self.journal.operation(operation_id)? else {
                return Ok(None);
            };
            match operation {
                journal::LoadedOperation::ReceiverObserved(operation) => {
                    let receipt = Self::build_receipt(&operation, settings)?;
                    publication::validate_private_directory(
                        access_directory.unwrap_or(settings.output_directory),
                    )
                    .map_err(publication_error)?;
                    self.journal.prepare_receipt(&operation, &receipt)?;
                    #[cfg(test)]
                    if fault == Some(FaultPoint::ReceiptPreparedCommitted) {
                        return Err(GatewayError::InjectedFault);
                    }
                },
                journal::LoadedOperation::ReceiptPrepared(operation) => {
                    let receipt = operation.receipt();
                    let access_path =
                        receipt_access_path(receipt, settings.output_directory, access_directory)?;
                    publication::publish_receipt(&access_path, &receipt.bytes)
                        .map_err(publication_error)?;
                    #[cfg(feature = "demo-harness")]
                    demo_control::checkpoint_after_receipt_publish()
                        .map_err(|()| GatewayError::ReceiptPublication)?;
                    #[cfg(test)]
                    if fault == Some(FaultPoint::ReceiptPublished) {
                        return Err(GatewayError::InjectedFault);
                    }
                    self.journal.mark_receipt_written(&operation)?;
                },
                journal::LoadedOperation::ReceiptWritten(operation) => {
                    #[cfg(test)]
                    if fault == Some(FaultPoint::ReceiptWrittenCommitted) {
                        return Err(GatewayError::InjectedFault);
                    }
                    let receipt = operation.receipt();
                    let access_path =
                        receipt_access_path(receipt, settings.output_directory, access_directory)?;
                    if !stored_receipt_matches(&access_path, &receipt.bytes)? {
                        publication::publish_receipt(&access_path, &receipt.bytes)
                            .map_err(publication_error)?;
                    }
                    self.journal.mark_finalized(&operation)?;
                    #[cfg(test)]
                    if fault == Some(FaultPoint::FinalizedCommitted) {
                        return Err(GatewayError::InjectedFault);
                    }
                    return Ok(Some(OperationState::Finalized));
                },
                journal::LoadedOperation::Requested(_)
                | journal::LoadedOperation::Authorized(_)
                | journal::LoadedOperation::NotAttempted(_)
                | journal::LoadedOperation::ApplyStarted(_)
                | journal::LoadedOperation::Finalized(_) => return Ok(None),
            }
        }
    }

    fn build_receipt(
        operation: &journal::ReceiverObservedOperation,
        settings: &ReceiptSettings<'_>,
    ) -> Result<ReceiptToPrepare, GatewayError> {
        let operation_id = operation.operation_id();
        let bytes = sign_statement(
            operation.statement(),
            settings.signing_seed,
            settings.key_id,
        )
        .map_err(GatewayError::Receipt)?;
        let digest = publication::receipt_digest_hex(&bytes);
        let path = settings
            .output_directory
            .join(publication::receipt_filename(operation_id, &digest));
        if path.to_str().is_none() {
            return Err(GatewayError::ReceiptPublication);
        }
        Ok(ReceiptToPrepare {
            receipt: FrozenReceipt {
                operation_id: operation_id.to_owned(),
                bytes,
                digest,
                path,
                key_id: settings.key_id.to_owned(),
            },
        })
    }

    pub(crate) fn read_loaded_receipt(
        operation: journal::LoadedOperation,
        output_directory: &Path,
        access_directory: Option<&Path>,
    ) -> Result<(Vec<u8>, String), GatewayError> {
        let journal::LoadedOperation::Finalized(operation) = operation else {
            return Err(GatewayError::InvalidPersistedState);
        };
        let receipt = operation.receipt();
        let access_path = receipt_access_path(receipt, output_directory, access_directory)?;
        let bytes = publication::read_receipt(&access_path).map_err(publication_error)?;
        if bytes != receipt.bytes || publication::receipt_digest_hex(&bytes) != receipt.digest {
            return Err(GatewayError::ReceiptDigestMismatch);
        }
        Ok((bytes, receipt.digest.clone()))
    }

    /// Reads the terminal receipt reference for a finalized operation.
    #[cfg(test)]
    pub(crate) fn receipt_reference(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptReference>, GatewayError> {
        self.journal.receipt_reference(operation_id)
    }

    /// Advances at most one operation using explicitly supplied Kubernetes authority.
    ///
    /// Application composition owns the client and keeps it outside request-only caller input. The
    /// concrete client does not establish a generic provider interface.
    #[cfg(test)]
    pub(crate) async fn run_once(
        &mut self,
        client: kube::Client,
    ) -> Result<Option<OperationState>, GatewayError> {
        let mut adapter = KubernetesDeploymentImageAdapter::new(client);
        self.run_once_with_adapter(&mut adapter, None).await
    }

    pub(crate) async fn run_operation_once(
        &mut self,
        operation_id: &str,
        client: kube::Client,
    ) -> Result<Option<OperationState>, GatewayError> {
        let mut adapter = KubernetesDeploymentImageAdapter::new(client);
        self.run_operation_once_with_adapter_and_fault(operation_id, &mut adapter, None)
            .await
    }

    #[cfg(test)]
    async fn run_operation_once_with_adapter<A: DeploymentImageAdapter + Send>(
        &mut self,
        operation_id: &str,
        adapter: &mut A,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.run_operation_once_with_adapter_and_fault(operation_id, adapter, None)
            .await
    }

    // The exclusive mutable caller borrow and worker lock prevent overlapping journal transitions
    // while provider I/O is pending.
    #[allow(clippy::needless_pass_by_ref_mut)]
    async fn run_operation_once_with_adapter_and_fault<A: DeploymentImageAdapter + Send>(
        &mut self,
        operation_id: &str,
        adapter: &mut A,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let Some(_worker_lock) = self.journal.try_lock_worker()? else {
            return Ok(None);
        };
        let Some(operation) = self.journal.operation(operation_id)? else {
            return Ok(None);
        };
        match operation {
            journal::LoadedOperation::Authorized(operation) => {
                let adapter_request = operation.request().to_adapter_request();
                let target = match adapter.identify(&adapter_request).await {
                    Ok(target) => target,
                    Err(TargetReadError::Transient) => {
                        self.journal.defer_target_retry(&operation)?;
                        return Err(GatewayError::KubernetesTargetObservation);
                    },
                    Err(TargetReadError::Permanent(rejection)) => {
                        self.journal.mark_not_attempted(&operation, rejection)?;
                        if fault == Some(FaultPoint::TargetRejectedCommitted) {
                            return Err(GatewayError::InjectedFault);
                        }
                        return Ok(Some(OperationState::NotAttempted));
                    },
                };
                if fault == Some(FaultPoint::TargetObserved) {
                    return Err(GatewayError::InjectedFault);
                }
                let target = ValidatedTargetIdentity::try_from(target)
                    .map_err(|_| GatewayError::InvalidKubernetesFact)?;
                let Some(target) = self.journal.begin_attempt(&operation, target)? else {
                    return Ok(Some(OperationState::NotAttempted));
                };
                if fault == Some(FaultPoint::ApplyStartedCommitted) {
                    return Err(GatewayError::InjectedFault);
                }
                let Some(journal::LoadedOperation::ApplyStarted(started)) =
                    self.journal.operation(operation_id)?
                else {
                    return Err(GatewayError::InvalidPersistedState);
                };
                let adapter_target = target.to_adapter_target();
                let outcome = adapter
                    .apply(&adapter_request, &adapter_target)
                    .await
                    .map_err(|()| GatewayError::KubernetesApply)?;
                #[cfg(feature = "demo-harness")]
                demo_control::checkpoint_after_apply()
                    .map_err(|()| GatewayError::KubernetesApply)?;
                if fault == Some(FaultPoint::ApplyReturned) {
                    return Err(GatewayError::InjectedFault);
                }
                self.journal.record_apply_outcome(&started, &outcome)?;
                if fault == Some(FaultPoint::ApplyOutcomeCommitted) {
                    return Err(GatewayError::InjectedFault);
                }
                let Some(journal::LoadedOperation::ApplyStarted(started)) =
                    self.journal.operation(operation_id)?
                else {
                    return Err(GatewayError::InvalidPersistedState);
                };
                let outcome = started.classification_outcome();
                let observation = adapter
                    .observe(&adapter_request, &outcome)
                    .await
                    .map_err(|()| GatewayError::KubernetesReceiverObservation)?;
                if fault == Some(FaultPoint::ReceiverRead) {
                    return Err(GatewayError::InjectedFault);
                }
                self.journal.freeze_observation(&started, &observation)?;
                if fault == Some(FaultPoint::ReceiverObservedCommitted) {
                    return Err(GatewayError::InjectedFault);
                }
                Ok(Some(OperationState::ReceiverObserved))
            },
            // Loaded ApplyStarted is recovery-only here. It has no path to adapter.apply.
            journal::LoadedOperation::ApplyStarted(operation) => {
                let adapter_request = operation.request().to_adapter_request();
                let outcome = operation.classification_outcome();
                let observation = adapter
                    .observe(&adapter_request, &outcome)
                    .await
                    .map_err(|()| GatewayError::KubernetesReceiverObservation)?;
                self.journal.freeze_observation(&operation, &observation)?;
                if fault == Some(FaultPoint::ReceiverObservedCommitted) {
                    return Err(GatewayError::InjectedFault);
                }
                Ok(Some(OperationState::ReceiverObserved))
            },
            journal::LoadedOperation::Requested(_)
            | journal::LoadedOperation::NotAttempted(_)
            | journal::LoadedOperation::ReceiverObserved(_)
            | journal::LoadedOperation::ReceiptPrepared(_)
            | journal::LoadedOperation::ReceiptWritten(_)
            | journal::LoadedOperation::Finalized(_) => Ok(None),
        }
    }

    // Queue-oriented tests select only an exact identity, then cross the same operation-selected
    // implementation used by Application. The delegated implementation holds worker exclusion
    // across every provider and receiver call.
    #[allow(clippy::needless_pass_by_ref_mut, dead_code)]
    pub(crate) async fn run_once_with_adapter<A: DeploymentImageAdapter + Send>(
        &mut self,
        adapter: &mut A,
        fault: Option<FaultPoint>,
    ) -> Result<Option<OperationState>, GatewayError> {
        let operation = self.journal.next_executable_operation()?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        self.run_operation_once_with_adapter_and_fault(
            operation.request().operation_id(),
            adapter,
            fault,
        )
        .await
    }
}

fn publication_error(_: publication::PublicationError) -> GatewayError {
    GatewayError::ReceiptPublication
}

fn receipt_access_path(
    receipt: &FrozenReceipt,
    output_directory: &Path,
    access_directory: Option<&Path>,
) -> Result<PathBuf, GatewayError> {
    let Some(access_directory) = access_directory else {
        return Ok(receipt.path.clone());
    };
    if receipt.path.parent() != Some(output_directory) {
        return Err(GatewayError::InvalidPersistedState);
    }
    let name = receipt
        .path
        .file_name()
        .ok_or(GatewayError::InvalidPersistedState)?;
    Ok(access_directory.join(name))
}

fn stored_receipt_matches(path: &Path, expected: &[u8]) -> Result<bool, GatewayError> {
    match publication::read_receipt(path) {
        Ok(existing) if existing == expected => Ok(true),
        Ok(_) => Err(GatewayError::ReceiptDigestMismatch),
        Err(publication::PublicationError::MissingDestination) => Ok(false),
        Err(error) => Err(publication_error(error)),
    }
}

/// Name of an input field rejected by the bounded request grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputField {
    /// Operation identity.
    OperationId,
    /// Authorization identity.
    AuthorizationId,
    /// Kubernetes namespace.
    Namespace,
    /// Kubernetes Deployment name.
    Deployment,
    /// Kubernetes container name.
    Container,
    /// Immutable named image reference.
    ImmutableImageDigest,
}

/// Failure before or during the gateway's durable submission boundary.
#[derive(Debug)]
pub(crate) enum GatewayError {
    /// SQLite rejected a journal operation.
    Database(rusqlite::Error),
    /// The operating system rejected private journal-file protection.
    JournalFile(std::io::Error),
    /// The operating system rejected the crash-released worker lock.
    WorkerLock(std::io::Error),
    /// The operating system rejected an owner-created offline upgrade backup.
    JournalBackup(std::io::Error),
    /// An offline upgrade backup did not exactly match its source and SHA-256 sidecar.
    JournalBackupMismatch,
    /// The private journal marker is not recognized by this binary.
    UnsupportedJournalVersion,
    /// Hostile or unsupported input failed its named bound.
    InvalidInput(InputField),
    /// Signed authorization-grant bytes violated their bounded canonical shape.
    InvalidAuthorizationGrant,
    /// The signed grant did not authenticate under the configured owner trust.
    UntrustedAuthorizationGrant,
    /// An authentic authorization grant did not exactly match the request.
    AuthorizationMismatch,
    /// An operation identity was reused for different durable facts.
    OperationIdentityConflict,
    /// SQLite contained a state outside the effect lifecycle.
    InvalidPersistedState,
    /// A guarded durable transition did not affect exactly one row.
    InvalidTransition,
    /// Kubernetes target observation failed without exposing an unbounded diagnostic.
    KubernetesTargetObservation,
    /// Kubernetes conditional image patch failed without exposing an unbounded diagnostic.
    KubernetesApply,
    /// Kubernetes receiver observation failed without exposing an unbounded diagnostic.
    KubernetesReceiverObservation,
    /// Kubernetes returned a malformed or unbounded typed fact.
    InvalidKubernetesFact,
    /// Deterministic test fault stopped execution at a named crash window.
    InjectedFault,
    /// The bounded prototype journal contains its maximum distinct operations.
    JournalFull,
    /// Prototype receipt bytes could not be built or inspected.
    Receipt(receipt::ReceiptError),
    /// Immutable receipt publication failed.
    ReceiptPublication,
    /// Published receipt bytes differ from the durable digest.
    ReceiptDigestMismatch,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::Database(_) => "database",
            Self::JournalFile(_) => "journal_file",
            Self::WorkerLock(_) => "worker_lock",
            Self::JournalBackup(_) => "journal_backup",
            Self::JournalBackupMismatch => "journal_backup_mismatch",
            Self::UnsupportedJournalVersion => "unsupported_journal_version",
            Self::InvalidInput(_) => "invalid_input",
            Self::InvalidAuthorizationGrant => "invalid_authorization_grant",
            Self::UntrustedAuthorizationGrant => "untrusted_authorization_grant",
            Self::AuthorizationMismatch => "authorization_mismatch",
            Self::OperationIdentityConflict => "operation_identity_conflict",
            Self::InvalidPersistedState => "invalid_persisted_state",
            Self::InvalidTransition => "invalid_transition",
            Self::KubernetesTargetObservation => "kubernetes_target_observation",
            Self::KubernetesApply => "kubernetes_apply",
            Self::KubernetesReceiverObservation => "kubernetes_receiver_observation",
            Self::InvalidKubernetesFact => "invalid_kubernetes_fact",
            Self::InjectedFault => "injected_fault",
            Self::JournalFull => "journal_full",
            Self::Receipt(_) => "receipt",
            Self::ReceiptPublication => "receipt_publication",
            Self::ReceiptDigestMismatch => "receipt_digest_mismatch",
        };
        write!(formatter, "Kubernetes effect-gateway failure: {class}")
    }
}

impl Error for GatewayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::JournalFile(error) | Self::WorkerLock(error) | Self::JournalBackup(error) => {
                Some(error)
            },
            Self::Receipt(error) => Some(error),
            Self::InvalidInput(_)
            | Self::JournalBackupMismatch
            | Self::UnsupportedJournalVersion
            | Self::InvalidAuthorizationGrant
            | Self::UntrustedAuthorizationGrant
            | Self::AuthorizationMismatch
            | Self::OperationIdentityConflict
            | Self::InvalidPersistedState
            | Self::InvalidTransition
            | Self::KubernetesTargetObservation
            | Self::KubernetesApply
            | Self::KubernetesReceiverObservation
            | Self::InvalidKubernetesFact
            | Self::InjectedFault
            | Self::JournalFull
            | Self::ReceiptPublication
            | Self::ReceiptDigestMismatch => None,
        }
    }
}

pub(crate) fn validate_identity(field: InputField, value: &str) -> Result<(), GatewayError> {
    if kapsel_authority::identity_is_valid(value) {
        Ok(())
    } else {
        Err(GatewayError::InvalidInput(field))
    }
}

pub(crate) fn validate_dns_label(field: InputField, value: &str) -> Result<(), GatewayError> {
    if kapsel_authority::dns_label_is_valid(value) {
        Ok(())
    } else {
        Err(GatewayError::InvalidInput(field))
    }
}

pub(crate) fn validate_dns_subdomain(field: InputField, value: &str) -> Result<(), GatewayError> {
    if kapsel_authority::dns_subdomain_is_valid(value) {
        Ok(())
    } else {
        Err(GatewayError::InvalidInput(field))
    }
}

pub(crate) fn validate_immutable_image(value: &str) -> Result<(), GatewayError> {
    if kapsel_authority::immutable_image_is_valid(value) {
        Ok(())
    } else {
        Err(GatewayError::InvalidInput(InputField::ImmutableImageDigest))
    }
}

fn authorization_matches(authorization: &ExactAuthorization, request: &ValidatedRequest) -> bool {
    authorization.operation_id == request.operation_id()
        && authorization.namespace == request.namespace()
        && authorization.deployment == request.deployment()
        && authorization.container == request.container()
        && authorization.immutable_image_digest == request.immutable_image_digest()
}

#[cfg(test)]
mod tests;
