//! Application-owned composition for the one effect-gateway operation.
//!
//! This module separates request-only agent intent from operator-owned authorization, Kubernetes
//! authority, receipt signing material, and durable paths. It owns the one shared operator-document
//! grammar but is not a command adapter.

use std::{
    error::Error,
    fmt, fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use http_body_util::Limited;
use kube::{config::KubeConfigOptions, Config};
use serde::Deserialize;
use tower_http::map_response_body::MapResponseBodyLayer;

use crate::gateway::{
    sign_authorization_grant, validate_key_id, validate_private_directory,
    verify_authorization_grant, AuthorizationTrust, ExactAuthorization, Gateway, GatewayError,
    OperationResult, OperationState, ReceiptReference, ReceiptSettings, SetDeploymentImageRequest,
    SubmissionResult, TargetRejection,
};

/// Request-only caller input for the sole supported operation.
pub type AgentRequest = SetDeploymentImageRequest;

/// Inputs controlled by the operator before an application instance opens durable state.
///
/// The signed grant, trust, Kubernetes client, signing seed, and paths must come from application
/// composition rather than agent request fields. This type deliberately does not implement
/// `Debug`, preventing accidental diagnostics from printing its secret-bearing fields.
pub struct OperatorConfiguration {
    /// Journal location owned by the operator.
    pub journal_path: PathBuf,
    /// Pre-existing owner-private receipt output directory.
    pub receipt_output_directory: PathBuf,
    /// Out-of-band trust for the exact authorization-grant signer.
    pub authorization_trust: AuthorizationTrust,
    /// One owner-signed exact grant used for request submission.
    pub signed_authorization_grant: Vec<u8>,
    /// Kubernetes authority constructed outside agent input.
    pub kubernetes_client: kube::Client,
    /// Receipt-signing seed controlled by the operator.
    pub receipt_signing_seed: [u8; 32],
    /// Public identity for the receipt-signing key.
    pub receipt_signing_key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorDocument {
    signed_authorization_grant: PathBuf,
    authorization_key_id: String,
    authorization_public_key: PathBuf,
    kubeconfig: PathBuf,
    journal: PathBuf,
    receipt_directory: PathBuf,
    receipt_signing_seed: PathBuf,
    receipt_signing_key_id: String,
}

/// Opens the application from the existing operator document and caller-owned file reader.
///
/// The supplied reader owns file-opening policy and must return bytes from the opened file. This
/// prototype-scoped composition seam exists only to keep the CLI, MCP, and Kapsel service on one
/// operator grammar.
///
/// # Errors
///
/// Returns a typed application configuration error when the document, one input, or application
/// composition is invalid.
pub async fn open_application_from_operator_document(
    document: &[u8],
    read_file: impl FnMut(&Path, usize) -> Result<Vec<u8>, ApplicationError>,
) -> Result<Application, ApplicationError> {
    let operator = parse_operator_document(document)?;
    open_operator_document(operator, None, read_file).await
}

/// Opens the application only when the operator document uses the supplied fixed state paths.
///
/// The access paths must resolve through retained handles for the same journal and receipt roots.
/// The supplied reader owns file-opening policy and must return bytes from the validated opened
/// inode. Kapsel service startup uses this form to retain the existing grammar without allowing
/// another journal or receipt root.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidOperatorConfiguration`] when the document is malformed, its
/// state paths differ from the fixed paths, or the supplied reader rejects an input. Other typed
/// application configuration errors are preserved.
pub async fn open_application_from_fixed_operator_document(
    document: &[u8],
    fixed_journal_path: &Path,
    fixed_receipt_directory: &Path,
    journal_access_path: &Path,
    receipt_access_directory: &Path,
    read_file: impl FnMut(&Path, usize) -> Result<Vec<u8>, ApplicationError>,
) -> Result<Application, ApplicationError> {
    let operator = parse_operator_document(document)?;
    let fixed_paths = FixedStatePaths {
        journal: fixed_journal_path,
        receipt_directory: fixed_receipt_directory,
        journal_access: journal_access_path,
        receipt_access: receipt_access_directory,
    };
    open_operator_document(operator, Some(fixed_paths), read_file).await
}

#[derive(Clone, Copy)]
struct FixedStatePaths<'a> {
    journal: &'a Path,
    receipt_directory: &'a Path,
    journal_access: &'a Path,
    receipt_access: &'a Path,
}

fn parse_operator_document(document: &[u8]) -> Result<OperatorDocument, ApplicationError> {
    serde_json::from_slice(document).map_err(|_| ApplicationError::InvalidOperatorConfiguration)
}

async fn open_operator_document(
    operator: OperatorDocument,
    fixed_state_paths: Option<FixedStatePaths<'_>>,
    mut read_file: impl FnMut(&Path, usize) -> Result<Vec<u8>, ApplicationError>,
) -> Result<Application, ApplicationError> {
    for path in [
        &operator.signed_authorization_grant,
        &operator.authorization_public_key,
        &operator.kubeconfig,
        &operator.journal,
        &operator.receipt_directory,
        &operator.receipt_signing_seed,
    ] {
        if !path.is_absolute() {
            return Err(ApplicationError::InvalidOperatorConfiguration);
        }
    }
    if let Some(paths) = fixed_state_paths {
        if operator.journal != paths.journal
            || operator.receipt_directory != paths.receipt_directory
        {
            return Err(ApplicationError::InvalidOperatorConfiguration);
        }
    }
    let persisted_receipt_directory =
        fixed_state_paths.map(|paths| paths.receipt_directory.to_owned());
    let receipt_access_directory = fixed_state_paths.map(|paths| paths.receipt_access.to_owned());
    let journal_path = fixed_state_paths.map_or_else(
        || operator.journal.clone(),
        |paths| paths.journal_access.to_owned(),
    );
    let receipt_output_directory = receipt_access_directory
        .clone()
        .unwrap_or_else(|| operator.receipt_directory.clone());
    let signed_authorization_grant = read_operator_file(
        &mut read_file,
        &operator.signed_authorization_grant,
        4 * 1024,
    )?;
    let authorization_public_key =
        read_operator_exact_32(&mut read_file, &operator.authorization_public_key)?;
    let receipt_signing_seed =
        read_operator_exact_32(&mut read_file, &operator.receipt_signing_seed)?;
    if fixed_state_paths.is_some() {
        let grant = verify_authorization_grant(
            &signed_authorization_grant,
            &AuthorizationTrust {
                key_id: operator.authorization_key_id.clone(),
                public_key: authorization_public_key,
            },
        )
        .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
        if grant.authorization.approved_target.is_none() {
            return Err(ApplicationError::InvalidOperatorConfiguration);
        }
    }
    let kubeconfig = read_operator_file(&mut read_file, &operator.kubeconfig, 16 * 1024)?;
    let kubernetes_client = load_operator_kubernetes_client(&kubeconfig).await?;

    let mut application = Application::open(OperatorConfiguration {
        journal_path,
        receipt_output_directory,
        authorization_trust: AuthorizationTrust {
            key_id: operator.authorization_key_id,
            public_key: authorization_public_key,
        },
        signed_authorization_grant,
        kubernetes_client,
        receipt_signing_seed,
        receipt_signing_key_id: operator.receipt_signing_key_id,
    })?;
    if let Some(persisted_directory) = persisted_receipt_directory {
        application.persisted_receipt_directory = Some(persisted_directory.clone());
        application.receipt_output_directory = persisted_directory;
        application.receipt_access_directory = receipt_access_directory;
    }
    Ok(application)
}

fn read_operator_file(
    read_file: &mut impl FnMut(&Path, usize) -> Result<Vec<u8>, ApplicationError>,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ApplicationError> {
    let bytes = read_file(path, maximum)?;
    if bytes.len() > maximum {
        return Err(ApplicationError::InvalidOperatorConfiguration);
    }
    Ok(bytes)
}

fn read_operator_exact_32(
    read_file: &mut impl FnMut(&Path, usize) -> Result<Vec<u8>, ApplicationError>,
    path: &Path,
) -> Result<[u8; 32], ApplicationError> {
    read_operator_file(read_file, path, 32)?
        .try_into()
        .map_err(|_| ApplicationError::InvalidOperatorConfiguration)
}

async fn load_operator_kubernetes_client(bytes: &[u8]) -> Result<kube::Client, ApplicationError> {
    const KUBERNETES_RESPONSE_BYTES_MAX: usize = 2 * 1024 * 1024;

    let text =
        std::str::from_utf8(bytes).map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
    let mut kubeconfig = kube::config::Kubeconfig::from_yaml(text)
        .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
    let proxy_placeholder_was_added = configure_explicit_kubeconfig(&mut kubeconfig)?;
    let mut client_config =
        Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?;
    if proxy_placeholder_was_added {
        client_config.proxy_url = None;
    }
    let response_limit =
        MapResponseBodyLayer::new(|body| Limited::new(body, KUBERNETES_RESPONSE_BYTES_MAX));
    Ok(kube::client::ClientBuilder::try_from(client_config)
        .map_err(|_| ApplicationError::InvalidOperatorConfiguration)?
        .with_layer(&response_limit)
        .build())
}

fn configure_explicit_kubeconfig(
    kubeconfig: &mut kube::config::Kubeconfig,
) -> Result<bool, ApplicationError> {
    let current = kubeconfig
        .current_context
        .as_deref()
        .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|context| context.name == current)
        .and_then(|context| context.context.as_ref())
        .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
    let cluster_name = context.cluster.clone();
    let user_name = context.user.clone();
    let cluster = kubeconfig
        .clusters
        .iter_mut()
        .find(|cluster| cluster.name == cluster_name)
        .and_then(|cluster| cluster.cluster.as_mut())
        .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
    if cluster.certificate_authority.is_some() {
        return Err(ApplicationError::InvalidOperatorConfiguration);
    }
    if let Some(user_name) = user_name {
        let user = kubeconfig
            .auth_infos
            .iter()
            .find(|user| user.name == user_name)
            .and_then(|user| user.auth_info.as_ref())
            .ok_or(ApplicationError::InvalidOperatorConfiguration)?;
        if user.token_file.is_some()
            || user.client_certificate.is_some()
            || user.client_key.is_some()
            || user.auth_provider.is_some()
            || user.exec.is_some()
        {
            return Err(ApplicationError::InvalidOperatorConfiguration);
        }
    }
    if cluster.proxy_url.as_deref().is_none_or(str::is_empty) {
        cluster.proxy_url = Some(String::from("http://127.0.0.1"));
        Ok(true)
    } else {
        Ok(false)
    }
}

pub use kapsel_authority::ValidatedServiceOperatorInputs;

/// Validates the service grant, authorization key, receipt seed, and evaluator trust together.
///
/// The returned value contains only public identity. This function performs no filesystem,
/// network, environment, clock, or durable-state access.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidOperatorConfiguration`] when any input is malformed or the
/// grant, public key, receipt seed, and trust do not appoint one consistent authority.
pub fn validate_service_operator_inputs(
    signed_authorization_grant: &[u8],
    authorization_public_key: &[u8; 32],
    receipt_signing_seed: &[u8; 32],
    receipt_trust: &[u8],
) -> Result<ValidatedServiceOperatorInputs, ApplicationError> {
    kapsel_authority::validate_service_operator_inputs(
        signed_authorization_grant,
        authorization_public_key,
        receipt_signing_seed,
        receipt_trust,
    )
    .map_err(|_| ApplicationError::InvalidOperatorConfiguration)
}

/// Operator-only inputs for provisioning one exact authorization grant.
///
/// This type deliberately does not implement `Debug` because it contains signing material.
pub struct GrantProvisioning<'a> {
    /// Exact operation tuple the owner is authorizing.
    pub authorization: &'a ExactAuthorization,
    /// Owner-controlled Ed25519 signing seed.
    pub signing_seed: &'a [u8; 32],
    /// Public identity for the authorization signing key.
    pub signing_key_id: &'a str,
}

/// Produces the canonical fixed-purpose grant supplied later through operator configuration.
///
/// # Errors
///
/// Returns [`ApplicationError::InvalidGrantProvisioning`] when the authorization tuple or signing
/// key identity violates the bounded grant grammar.
pub fn provision_exact_grant(
    provisioning: &GrantProvisioning<'_>,
) -> Result<Vec<u8>, ApplicationError> {
    sign_authorization_grant(
        provisioning.authorization,
        provisioning.signing_seed,
        provisioning.signing_key_id,
    )
    .map_err(|_| ApplicationError::InvalidGrantProvisioning)
}

/// Acquires the operator-selected Deployment version and signs one snapshot grant.
///
/// No snapshot fields are accepted in the proposal. Kubernetes authority is an explicit bounded
/// kubeconfig, never ambient configuration. The production adapter owns target validation and GET
/// deadline. This function does not mutate Kubernetes or create a journal.
///
/// # Errors
///
/// Returns a bounded configuration or provisioning failure for invalid input or failed acquisition.
pub async fn provision_snapshot_grant(
    provisioning: &GrantProvisioning<'_>,
    kubeconfig: &[u8],
) -> Result<Vec<u8>, ApplicationError> {
    use crate::gateway::{
        ApprovedTarget, DeploymentImageAdapter, KubernetesDeploymentImageAdapter,
    };
    if kubeconfig.len() > 16 * 1024 || provisioning.authorization.approved_target.is_some() {
        return Err(ApplicationError::InvalidGrantProvisioning);
    }
    // Validate the entire proposal and signer before network access. These bytes are not published.
    provision_exact_grant(provisioning)?;
    let client = load_operator_kubernetes_client(kubeconfig).await?;
    let mut adapter = KubernetesDeploymentImageAdapter::new(client);
    let proposal = provisioning.authorization;
    let request = AgentRequest {
        operation_id: proposal.operation_id.clone(),
        namespace: proposal.namespace.clone(),
        deployment: proposal.deployment.clone(),
        container: proposal.container.clone(),
        immutable_image_digest: proposal.immutable_image_digest.clone(),
    };
    let observed = adapter
        .identify(&request)
        .await
        .map_err(|_| ApplicationError::InvalidGrantProvisioning)?;
    let mut authorization = proposal.clone();
    authorization.approved_target = Some(ApprovedTarget {
        uid: observed.deployment_uid,
        resource_version: observed.resource_version,
    });
    provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: provisioning.signing_seed,
        signing_key_id: provisioning.signing_key_id,
    })
}

/// Application-level report shared by the local CLI and fixed MCP adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReport {
    /// Stable operation identity fixed by the configured authorization grant.
    pub operation_id: String,
    /// Current durable lifecycle state.
    pub state: OperationState,
    /// Receiver result, present only after receiver observation.
    pub result: Option<OperationResult>,
    /// Pre-attempt target rejection, distinct from a receiver result.
    pub target_rejection: Option<TargetRejection>,
    /// Frozen receipt reference, present only after finalization.
    pub receipt: Option<ReceiptReference>,
    /// Distinct durable approval, observation and mutation-precondition facts.
    pub targets: crate::OperationTargets,
}

/// Read-only exact receipt projection for the configured Deployment image operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetDeploymentImageReceipt {
    /// No durable operation exists for the supplied identity.
    NotFound,
    /// The operation exists but has no finalized receipt.
    NotReady,
    /// Exact frozen receipt bytes and their expected lowercase SHA-256 digest.
    Ready {
        /// Exact canonical receipt bytes read from validated private storage.
        bytes: Vec<u8>,
        /// Expected SHA-256 digest frozen in the lifecycle journal.
        sha256: String,
    },
}

/// Read-only status projection for the configured Deployment image operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetDeploymentImageStatus {
    /// No durable operation exists for the supplied identity.
    NotFound,
    /// The operation exists but has not reached a terminal disposition.
    InProgress,
    /// The exact target was rejected before a mutation attempt.
    NotAttempted(TargetRejection),
    /// Receiver facts established the bounded success predicate.
    Succeeded,
    /// Receiver facts established the bounded failure predicate.
    Failed,
    /// Receiver facts established neither success nor failure.
    Unknown,
}

/// Compile-time composition root for the evaluator application.
pub struct Application {
    gateway: Gateway,
    kubernetes_client: kube::Client,
    signed_authorization_grant: Vec<u8>,
    authorized_request: AgentRequest,
    receipt_signing_key: SigningKey,
    receipt_signing_key_id: String,
    receipt_output_directory: PathBuf,
    receipt_access_directory: Option<PathBuf>,
    persisted_receipt_directory: Option<PathBuf>,
}

impl Application {
    /// Validates operator configuration before opening or creating the journal.
    ///
    /// Grant trust, canonical grant bytes, receipt key identity, and output-directory safety are
    /// checked before durable state is opened. Constructing the Kubernetes client and protecting
    /// its credentials remain operator responsibilities.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error when grant trust, receipt authority, or paths are
    /// unsafe. Journal open, durability, migration, and filesystem failures are returned as
    /// [`ApplicationError::OperationFailure`].
    pub fn open(configuration: OperatorConfiguration) -> Result<Self, ApplicationError> {
        let verified_grant = verify_authorization_grant(
            &configuration.signed_authorization_grant,
            &configuration.authorization_trust,
        )
        .map_err(|_| ApplicationError::InvalidAuthorizationConfiguration)?;
        validate_key_id(&configuration.receipt_signing_key_id)
            .map_err(|_| ApplicationError::InvalidReceiptConfiguration)?;
        if !configuration.receipt_output_directory.is_absolute() {
            return Err(ApplicationError::InvalidReceiptOutputDirectory);
        }
        validate_private_directory(&configuration.receipt_output_directory)
            .map_err(|_| ApplicationError::InvalidReceiptOutputDirectory)?;
        validate_journal_path(&configuration.journal_path)?;

        let authorized_request = AgentRequest {
            operation_id: verified_grant.authorization.operation_id,
            namespace: verified_grant.authorization.namespace,
            deployment: verified_grant.authorization.deployment,
            container: verified_grant.authorization.container,
            immutable_image_digest: verified_grant.authorization.immutable_image_digest,
        };
        let gateway = Gateway::open(
            &configuration.journal_path,
            configuration.authorization_trust,
        )
        .map_err(|_| ApplicationError::OperationFailure)?;
        Ok(Self {
            gateway,
            kubernetes_client: configuration.kubernetes_client,
            signed_authorization_grant: configuration.signed_authorization_grant,
            authorized_request,
            receipt_signing_key: SigningKey::from_bytes(&configuration.receipt_signing_seed),
            receipt_signing_key_id: configuration.receipt_signing_key_id,
            receipt_output_directory: configuration.receipt_output_directory,
            receipt_access_directory: None,
            persisted_receipt_directory: None,
        })
    }

    /// Reports only whether request-only intent matches the grant verified during [`Self::open`].
    ///
    /// This non-mutating check exposes no grant facts, trust input, or durable lifecycle state.
    #[must_use]
    pub fn request_matches_authorized_grant(&self, request: &AgentRequest) -> bool {
        request == &self.authorized_request
    }

    /// Projects the durable status of the configured Deployment image operation.
    ///
    /// A different operation identity is indistinguishable from an absent operation. This method
    /// performs no Kubernetes access and advances no lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::OperationFailure`] when durable state is unreadable or
    /// internally inconsistent.
    pub fn read_set_deployment_image_status(
        &self,
        operation_id: &str,
    ) -> Result<SetDeploymentImageStatus, ApplicationError> {
        self.read_set_deployment_image_status_with_targets(operation_id)
            .map(|(status, _)| status)
    }

    /// Reads disposition and target facts from one authority-checked SQLite snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded operation failure for inconsistent or inaccessible durable state.
    pub fn read_set_deployment_image_status_with_targets(
        &self,
        operation_id: &str,
    ) -> Result<(SetDeploymentImageStatus, crate::OperationTargets), ApplicationError> {
        if operation_id != self.authorized_request.operation_id {
            return Ok((
                SetDeploymentImageStatus::NotFound,
                crate::OperationTargets::default(),
            ));
        }
        let Some(report) = self.report()? else {
            return Ok((
                SetDeploymentImageStatus::NotFound,
                crate::OperationTargets::default(),
            ));
        };
        let status = match report.state {
            OperationState::Requested
            | OperationState::Authorized
            | OperationState::ApplyStarted
            | OperationState::ReceiverObserved
            | OperationState::ReceiptPrepared
            | OperationState::ReceiptWritten => Ok(SetDeploymentImageStatus::InProgress),
            OperationState::NotAttempted => report
                .target_rejection
                .map(SetDeploymentImageStatus::NotAttempted)
                .ok_or(ApplicationError::OperationFailure),
            OperationState::Finalized => match report.result {
                Some(OperationResult::Succeeded) => Ok(SetDeploymentImageStatus::Succeeded),
                Some(OperationResult::Failed) => Ok(SetDeploymentImageStatus::Failed),
                Some(OperationResult::Unknown) => Ok(SetDeploymentImageStatus::Unknown),
                None => Err(ApplicationError::OperationFailure),
            },
        }?;
        Ok((status, report.targets))
    }

    /// Reads the exact finalized receipt for the configured Deployment image operation.
    ///
    /// A different operation identity is indistinguishable from an absent operation. This method
    /// performs no Kubernetes access and advances no lifecycle state. Private storage paths never
    /// cross this interface.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::OperationFailure`] when durable facts or receipt storage are
    /// unreadable, unsafe, inconsistent, or digest-mismatched.
    pub fn read_set_deployment_image_receipt(
        &self,
        operation_id: &str,
    ) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        if operation_id != self.authorized_request.operation_id {
            return Ok(SetDeploymentImageReceipt::NotFound);
        }
        let Some(snapshot) = self
            .gateway
            .authorized_operation(&self.authorized_request, &self.signed_authorization_grant)
            .map_err(|_| ApplicationError::OperationFailure)?
        else {
            return Ok(SetDeploymentImageReceipt::NotFound);
        };
        if snapshot
            .frozen_receipt_path()
            .is_some_and(|path| !self.persisted_receipt_path_is_allowed(path))
        {
            return Err(ApplicationError::OperationFailure);
        }
        if snapshot.state() != OperationState::Finalized {
            return Ok(SetDeploymentImageReceipt::NotReady);
        }
        let (bytes, sha256) = Gateway::read_loaded_receipt(
            snapshot,
            &self.receipt_output_directory,
            self.receipt_access_directory.as_deref(),
        )
        .map_err(|_| ApplicationError::OperationFailure)?;
        Ok(SetDeploymentImageReceipt::Ready { bytes, sha256 })
    }

    /// Submits request-only intent under the operator-configured exact grant.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::RequestRejected`] when intent is malformed or differs from the
    /// configured exact grant. Durable conflicts and persistence failures return
    /// [`ApplicationError::OperationFailure`].
    fn submit(&self, request: &AgentRequest) -> Result<SubmissionResult, ApplicationError> {
        self.gateway
            .submit_authorized(request, &self.signed_authorization_grant)
            .map_err(|error| map_operation_error(&error))
    }

    /// Submits request-only intent and owns all subsequent lifecycle sequencing.
    ///
    /// # Errors
    ///
    /// Returns a submission or reconciliation error, including bounded Kubernetes ambiguity,
    /// durable-state failure, or receipt-publication failure.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation may occur after request persistence or the durable mutation marker. It does not
    /// establish that Kubernetes was untouched. Reopen the application with the same operator
    /// configuration and call [`Application::reconcile`] to resume without a blind second mutation.
    pub async fn execute(
        &mut self,
        request: &AgentRequest,
    ) -> Result<OperationReport, ApplicationError> {
        self.submit(request)?;
        self.reconcile()
            .await?
            .ok_or(ApplicationError::OperationFailure)
    }

    /// Recovers and advances the configured operation to its next externally blocked or terminal
    /// report without allowing an adapter to sequence durable states.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::OperationFailure`] when recovery cannot read or advance durable
    /// state, perform bounded Kubernetes interaction, or publish the frozen receipt.
    ///
    /// # Cancellation safety
    ///
    /// Cancellation preserves the last committed lifecycle state. A later call with the same
    /// operator configuration resumes that exact operation; after `apply_started`, recovery
    /// observes rather than blindly issuing another mutation.
    pub async fn reconcile(&mut self) -> Result<Option<OperationReport>, ApplicationError> {
        loop {
            let Some(report) = self.report()? else {
                return Ok(None);
            };
            match report.state {
                OperationState::Requested => {
                    self.gateway
                        .submit_authorized(
                            &self.authorized_request,
                            &self.signed_authorization_grant,
                        )
                        .map_err(|error| map_operation_error(&error))?;
                },
                OperationState::Authorized | OperationState::ApplyStarted => {
                    let operation_state_after_run = self
                        .gateway
                        .run_operation_once(
                            &self.authorized_request.operation_id,
                            self.kubernetes_client.clone(),
                        )
                        .await
                        .map_err(|_| ApplicationError::OperationFailure)?;
                    if operation_state_after_run.is_none() {
                        return self.report();
                    }
                },
                OperationState::ReceiverObserved
                | OperationState::ReceiptPrepared
                | OperationState::ReceiptWritten => {
                    let receipt_settings = ReceiptSettings {
                        signing_seed: self.receipt_signing_key.as_bytes(),
                        key_id: &self.receipt_signing_key_id,
                        output_directory: &self.receipt_output_directory,
                    };
                    let receipt_state_after_finalization = self
                        .gateway
                        .finalize_operation_receipt_once(
                            &self.authorized_request.operation_id,
                            &receipt_settings,
                            self.receipt_access_directory.as_deref(),
                        )
                        .map_err(|_| ApplicationError::OperationFailure)?;
                    if receipt_state_after_finalization.is_none() {
                        return self.report();
                    }
                },
                OperationState::NotAttempted | OperationState::Finalized => {
                    return Ok(Some(report));
                },
            }
        }
    }

    /// Reports the configured operation without provider or network access.
    fn report(&self) -> Result<Option<OperationReport>, ApplicationError> {
        let operation_id = &self.authorized_request.operation_id;
        let Some(snapshot) = self
            .gateway
            .authorized_operation(&self.authorized_request, &self.signed_authorization_grant)
            .map_err(|_| ApplicationError::OperationFailure)?
        else {
            return Ok(None);
        };
        if snapshot
            .frozen_receipt_path()
            .is_some_and(|path| !self.persisted_receipt_path_is_allowed(path))
        {
            return Err(ApplicationError::OperationFailure);
        }
        Ok(Some(OperationReport {
            operation_id: operation_id.clone(),
            state: snapshot.state(),
            result: snapshot.result(),
            target_rejection: snapshot.target_rejection(),
            receipt: snapshot.receipt_reference(),
            targets: snapshot.targets(),
        }))
    }

    fn persisted_receipt_path_is_allowed(&self, path: &Path) -> bool {
        self.persisted_receipt_directory
            .as_deref()
            .is_none_or(|directory| receipt_path_is_beneath(directory, path))
    }
}

fn receipt_path_is_beneath(directory: &Path, path: &Path) -> bool {
    path.parent() == Some(directory) && path.file_name().is_some()
}

fn map_operation_error(error: &GatewayError) -> ApplicationError {
    match error {
        GatewayError::InvalidInput(field) => {
            let _ = field;
            ApplicationError::RequestRejected
        },
        GatewayError::AuthorizationMismatch => ApplicationError::RequestRejected,
        _ => ApplicationError::OperationFailure,
    }
}

fn validate_journal_path(path: &Path) -> Result<(), ApplicationError> {
    if !path.is_absolute() || !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(ApplicationError::InvalidJournalPath);
    }
    let parent = path.parent().ok_or(ApplicationError::InvalidJournalPath)?;
    validate_private_directory(parent).map_err(|_| ApplicationError::InvalidJournalPath)?;
    validate_private_file_or_missing(path)?;

    let mut worker_lock_path = path.as_os_str().to_os_string();
    worker_lock_path.push(".kap0038-worker.lock");
    validate_private_file_or_missing(Path::new(&worker_lock_path))
}

fn validate_private_file_or_missing(path: &Path) -> Result<(), ApplicationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode().trailing_zeros() >= 6 =>
        {
            Ok(())
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(ApplicationError::InvalidJournalPath),
    }
}

/// Bounded application composition or operation failure.
#[derive(Debug)]
pub enum ApplicationError {
    /// The shared operator document or one of its fixed files was invalid.
    InvalidOperatorConfiguration,
    /// Operator grant-signing inputs were invalid.
    InvalidGrantProvisioning,
    /// Configured grant bytes or trust were invalid.
    InvalidAuthorizationConfiguration,
    /// Receipt signing-key identity was invalid.
    InvalidReceiptConfiguration,
    /// Journal path was relative, unsafe, symlinked, or outside an owner-private directory.
    InvalidJournalPath,
    /// Receipt output was absent, unsafe, or not owner-private.
    InvalidReceiptOutputDirectory,
    /// Request intent was malformed or did not match the operator-configured exact grant.
    RequestRejected,
    /// Durable state, provider interaction, or receipt publication could not complete.
    OperationFailure,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::InvalidOperatorConfiguration => "invalid_operator_configuration",
            Self::InvalidGrantProvisioning => "invalid_grant_provisioning",
            Self::InvalidAuthorizationConfiguration => "invalid_authorization_configuration",
            Self::InvalidReceiptConfiguration => "invalid_receipt_configuration",
            Self::InvalidJournalPath => "invalid_journal_path",
            Self::InvalidReceiptOutputDirectory => "invalid_receipt_output_directory",
            Self::RequestRejected => "request_rejected",
            Self::OperationFailure => "operation_failure",
        };
        write!(formatter, "Kapsel application failure: {class}")
    }
}

impl Error for ApplicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must fail the response-bound test immediately"
)]
mod operator_tests {
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        thread,
    };

    use k8s_openapi::api::apps::v1::Deployment;
    use kube::Api;

    use super::*;

    const KUBERNETES_RESPONSE_BYTES_MAX: usize = 2 * 1024 * 1024;

    enum ResponseFraming {
        ContentLength,
        Chunked,
        CloseDelimited,
    }

    fn response_body(bytes: usize) -> Vec<u8> {
        let prefix = concat!(
            r#"{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"#,
            r#""name":"bounded","namespace":"demo","uid":"uid-1","resourceVersion":"1"}}"#
        );
        assert!(bytes >= prefix.len());
        let mut body = Vec::with_capacity(bytes);
        body.extend_from_slice(prefix.as_bytes());
        body.resize(bytes, b' ');
        body
    }

    fn response_server(
        body: Vec<u8>,
        framing: ResponseFraming,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            match framing {
                ResponseFraming::ContentLength => {
                    write!(
                        stream,
                        concat!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                            "content-length: {}\r\nconnection: close\r\n\r\n"
                        ),
                        body.len()
                    )
                    .unwrap();
                    let _ = stream.write_all(&body);
                },
                ResponseFraming::Chunked => {
                    stream
                        .write_all(
                            concat!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                                "transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    let _ = write!(stream, "{:x}\r\n", body.len());
                    let _ = stream.write_all(&body);
                    let _ = stream.write_all(b"\r\n0\r\n\r\n");
                },
                ResponseFraming::CloseDelimited => {
                    stream
                        .write_all(
                            concat!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                                "connection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    let _ = stream.write_all(&body);
                },
            }
        });
        (address, server)
    }

    async fn request_deployment(body_bytes: usize, framing: ResponseFraming) -> bool {
        let body = response_body(body_bytes);
        let (address, server) = response_server(body, framing);
        let kubeconfig = format!(
            concat!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n",
                "  cluster:\n    server: http://{}\ncontexts:\n- name: fixture\n",
                "  context:\n    cluster: fixture\n    user: fixture\n",
                "current-context: fixture\nusers:\n- name: fixture\n  user: {{}}\n"
            ),
            address
        );
        let client = load_operator_kubernetes_client(kubeconfig.as_bytes())
            .await
            .unwrap();
        let result = Api::<Deployment>::namespaced(client, "demo")
            .get("bounded")
            .await
            .is_ok();
        server.join().unwrap();
        result
    }

    #[test]
    fn fixed_receipt_path_validation_rejects_every_escape() {
        let directory = Path::new("/var/lib/kapsel/receipts");
        assert!(receipt_path_is_beneath(
            directory,
            Path::new("/var/lib/kapsel/receipts/operation.receipt.json")
        ));
        for path in [
            "/var/lib/kapsel/operation.receipt.json",
            "/var/lib/kapsel/receipts/nested/operation.receipt.json",
            "/var/lib/kapsel/receipts/../receipt.seed",
            "/etc/kapsel/receipt.seed",
            "/var/lib/kapsel/receipts",
        ] {
            assert!(!receipt_path_is_beneath(directory, Path::new(path)));
        }
    }

    #[tokio::test]
    async fn kubernetes_response_limit_accepts_exact_and_rejects_every_oversized_framing() {
        assert!(
            request_deployment(
                KUBERNETES_RESPONSE_BYTES_MAX,
                ResponseFraming::ContentLength
            )
            .await
        );
        assert!(
            !request_deployment(
                KUBERNETES_RESPONSE_BYTES_MAX + 1,
                ResponseFraming::ContentLength
            )
            .await
        );
        assert!(
            !request_deployment(KUBERNETES_RESPONSE_BYTES_MAX + 1, ResponseFraming::Chunked).await
        );
        assert!(
            !request_deployment(
                KUBERNETES_RESPONSE_BYTES_MAX + 1,
                ResponseFraming::CloseDelimited
            )
            .await
        );
    }
}
