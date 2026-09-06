//! Private durable representation for effect-gateway operations.
//!
//! This deep module owns row decoding, capacity enforcement, worker locking, snapshots, and guarded
//! transitions. Private children concentrate exact schema/migration and owner-private opening,
//! backup, and rollback-file behavior without creating a selectable storage interface.

mod opening;
mod schema;

use std::{
    fs::{File, TryLockError},
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::{
    kubernetes::{ApplyOutcome, ReceiverObservation, TargetIdentity, ValidatedTargetIdentity},
    receipt::{decode_frozen_receipt, publication, ReceiptStatement, RECEIPT_BYTES_MAX},
    validate_identity, AuthorizedRequest, FrozenReceipt, GatewayError, InputField, OperationResult,
    OperationState, ReceiptReference, ReceiptToPrepare, SetDeploymentImageRequest, TargetRejection,
    ValidatedRequest, WRITE_STRATEGY,
};

pub(crate) const OPERATION_COUNT_MAX: i64 = 10_000;

#[cfg(test)]
pub(crate) fn qualification_storage_limits() -> (usize, i32, u64) {
    (
        schema::PERSISTED_VALUE_BYTES_MAX,
        schema::PERSISTED_ROW_BYTES_MAX,
        opening::ROLLBACK_JOURNAL_BYTES_MAX,
    )
}

pub(crate) struct Journal {
    pub(crate) connection: Connection,
    worker_lock: File,
}

pub(crate) struct WorkerLock<'a> {
    file: &'a File,
}

#[cfg(test)]
pub(crate) struct OperationStateProjection {
    pub(crate) state: OperationState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct RequestFacts {
    approved_target: Option<super::ApprovedTarget>,
    preflight_target: Option<super::ApprovedTarget>,
    request: ValidatedRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Sha256Digest(String);

impl TryFrom<String> for Sha256Digest {
    type Error = GatewayError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            Ok(Self(value))
        } else {
            Err(GatewayError::InvalidPersistedState)
        }
    }
}

#[allow(
    dead_code,
    reason = "validated authorization provenance is retained by every authenticated phase"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct AuthorizationFacts {
    authorization_id: String,
    signer_key_id: String,
    grant_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplyResponseFacts {
    accepted: bool,
    requested_generation: Option<i64>,
    resource_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct AttemptFacts {
    target: ValidatedTargetIdentity,
    response: Option<ApplyResponseFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::gateway) struct ReceiverFacts {
    statement: ReceiptStatement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestedOperation {
    request: RequestFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedOperation {
    request: RequestFacts,
    authorization: AuthorizationFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NotAttemptedOperation {
    authorized: AuthorizedOperation,
    rejection: TargetRejection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyStartedOperation {
    authorized: AuthorizedOperation,
    attempt: AttemptFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiverObservedOperation {
    apply_started: ApplyStartedOperation,
    receiver: ReceiverFacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptPreparedOperation {
    receiver_observed: ReceiverObservedOperation,
    receipt: FrozenReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptWrittenOperation {
    receipt_prepared: ReceiptPreparedOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FinalizedOperation {
    receipt_written: ReceiptWrittenOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LoadedOperation {
    Requested(RequestedOperation),
    Authorized(AuthorizedOperation),
    NotAttempted(NotAttemptedOperation),
    ApplyStarted(ApplyStartedOperation),
    ReceiverObserved(ReceiverObservedOperation),
    ReceiptPrepared(ReceiptPreparedOperation),
    ReceiptWritten(ReceiptWrittenOperation),
    Finalized(FinalizedOperation),
}

impl RequestedOperation {
    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        &self.request.request
    }
}

impl AuthorizedOperation {
    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        &self.request.request
    }

    pub(in crate::gateway) fn approved_target(&self) -> Option<&super::ApprovedTarget> {
        self.request.approved_target.as_ref()
    }
}

impl ApplyStartedOperation {
    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        self.authorized.request()
    }

    pub(in crate::gateway) fn classification_outcome(&self) -> ApplyOutcome {
        ApplyOutcome {
            accepted: self
                .attempt
                .response
                .as_ref()
                .is_some_and(|response| response.accepted),
            requested_generation: self
                .attempt
                .response
                .as_ref()
                .and_then(|response| response.requested_generation),
            deployment_uid: Some(self.attempt.target.deployment_uid().to_owned()),
            resource_version: Some(self.attempt.response.as_ref().map_or_else(
                || self.attempt.target.resource_version().to_owned(),
                |response| response.resource_version.clone(),
            )),
        }
    }
}

impl ReceiverObservedOperation {
    pub(in crate::gateway) fn operation_id(&self) -> &str {
        self.apply_started.request().operation_id()
    }

    pub(in crate::gateway) fn statement(&self) -> &ReceiptStatement {
        &self.receiver.statement
    }
}

impl ReceiptPreparedOperation {
    pub(in crate::gateway) fn receipt(&self) -> &FrozenReceipt {
        &self.receipt
    }
}

impl ReceiptWrittenOperation {
    pub(in crate::gateway) fn receipt(&self) -> &FrozenReceipt {
        self.receipt_prepared.receipt()
    }
}

impl FinalizedOperation {
    pub(in crate::gateway) fn receipt(&self) -> &FrozenReceipt {
        self.receipt_written.receipt()
    }
}

impl LoadedOperation {
    pub(crate) fn state(&self) -> OperationState {
        match self {
            Self::Requested(_) => OperationState::Requested,
            Self::Authorized(_) => OperationState::Authorized,
            Self::NotAttempted(_) => OperationState::NotAttempted,
            Self::ApplyStarted(_) => OperationState::ApplyStarted,
            Self::ReceiverObserved(_) => OperationState::ReceiverObserved,
            Self::ReceiptPrepared(_) => OperationState::ReceiptPrepared,
            Self::ReceiptWritten(_) => OperationState::ReceiptWritten,
            Self::Finalized(_) => OperationState::Finalized,
        }
    }

    pub(in crate::gateway) fn request(&self) -> &ValidatedRequest {
        match self {
            Self::Requested(value) => &value.request.request,
            Self::Authorized(value) => &value.request.request,
            Self::NotAttempted(value) => value.authorized.request(),
            Self::ApplyStarted(value) => value.request(),
            Self::ReceiverObserved(value) => value.apply_started.request(),
            Self::ReceiptPrepared(value) => value.receiver_observed.apply_started.request(),
            Self::ReceiptWritten(value) => value
                .receipt_prepared
                .receiver_observed
                .apply_started
                .request(),
            Self::Finalized(value) => value
                .receipt_written
                .receipt_prepared
                .receiver_observed
                .apply_started
                .request(),
        }
    }

    fn request_facts(&self) -> &RequestFacts {
        match self {
            Self::Requested(v) => &v.request,
            Self::Authorized(v) => &v.request,
            Self::NotAttempted(v) => &v.authorized.request,
            Self::ApplyStarted(v) => &v.authorized.request,
            Self::ReceiverObserved(v) => &v.apply_started.authorized.request,
            Self::ReceiptPrepared(v) => &v.receiver_observed.apply_started.authorized.request,
            Self::ReceiptWritten(v) => {
                &v.receipt_prepared
                    .receiver_observed
                    .apply_started
                    .authorized
                    .request
            },
            Self::Finalized(v) => {
                &v.receipt_written
                    .receipt_prepared
                    .receiver_observed
                    .apply_started
                    .authorized
                    .request
            },
        }
    }

    pub(crate) fn targets(&self) -> super::OperationTargets {
        let request = self.request_facts();
        let attempt = match self {
            Self::ApplyStarted(v) => Some(&v.attempt),
            Self::ReceiverObserved(v) => Some(&v.apply_started.attempt),
            Self::ReceiptPrepared(v) => Some(&v.receiver_observed.apply_started.attempt),
            Self::ReceiptWritten(v) => {
                Some(&v.receipt_prepared.receiver_observed.apply_started.attempt)
            },
            Self::Finalized(v) => Some(
                &v.receipt_written
                    .receipt_prepared
                    .receiver_observed
                    .apply_started
                    .attempt,
            ),
            Self::Requested(_) | Self::Authorized(_) | Self::NotAttempted(_) => None,
        };
        let statement = match self {
            Self::ReceiverObserved(v) => Some(v.statement()),
            Self::ReceiptPrepared(v) => Some(v.receiver_observed.statement()),
            Self::ReceiptWritten(v) => Some(v.receipt_prepared.receiver_observed.statement()),
            Self::Finalized(v) => Some(
                v.receipt_written
                    .receipt_prepared
                    .receiver_observed
                    .statement(),
            ),
            _ => None,
        };
        super::OperationTargets {
            approved_target: request.approved_target.clone(),
            attempt_target: attempt.map(|v| super::ApprovedTarget {
                uid: v.target.deployment_uid().to_owned(),
                resource_version: v.target.resource_version().to_owned(),
            }),
            observed_target: statement.map_or_else(
                || {
                    request
                        .preflight_target
                        .as_ref()
                        .map(|v| super::ObservedTarget {
                            uid: Some(v.uid.clone()),
                            resource_version: Some(v.resource_version.clone()),
                        })
                },
                |statement| {
                    Some(super::ObservedTarget {
                        uid: statement.receiver_uid.clone(),
                        resource_version: statement.observed_resource_version.clone(),
                    })
                },
            ),
        }
    }

    pub(crate) fn result(&self) -> Option<OperationResult> {
        match self {
            Self::ReceiverObserved(value) => Some(value.receiver.statement.result),
            Self::ReceiptPrepared(value) => Some(value.receiver_observed.receiver.statement.result),
            Self::ReceiptWritten(value) => Some(
                value
                    .receipt_prepared
                    .receiver_observed
                    .receiver
                    .statement
                    .result,
            ),
            Self::Finalized(value) => Some(
                value
                    .receipt_written
                    .receipt_prepared
                    .receiver_observed
                    .receiver
                    .statement
                    .result,
            ),
            Self::Requested(_)
            | Self::Authorized(_)
            | Self::NotAttempted(_)
            | Self::ApplyStarted(_) => None,
        }
    }

    pub(crate) fn target_rejection(&self) -> Option<TargetRejection> {
        match self {
            Self::NotAttempted(value) => Some(value.rejection),
            _ => None,
        }
    }

    pub(in crate::gateway) fn frozen_receipt(&self) -> Option<&FrozenReceipt> {
        match self {
            Self::ReceiptPrepared(value) => Some(value.receipt()),
            Self::ReceiptWritten(value) => Some(value.receipt()),
            Self::Finalized(value) => Some(value.receipt()),
            _ => None,
        }
    }

    pub(crate) fn frozen_receipt_path(&self) -> Option<&Path> {
        self.frozen_receipt().map(|receipt| receipt.path.as_path())
    }

    pub(crate) fn receipt_reference(&self) -> Option<ReceiptReference> {
        match self {
            Self::Finalized(value) => Some(ReceiptReference {
                path: value.receipt().path.clone(),
                digest: value.receipt().digest.clone(),
            }),
            _ => None,
        }
    }
}

struct SnapshotRow {
    approved_uid: Option<String>,
    approved_resource_version: Option<String>,
    preflight_uid: Option<String>,
    preflight_resource_version: Option<String>,
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
    state: String,
    result: Option<String>,
    target_rejection: Option<String>,
    authorization_id: Option<String>,
    authorization_signer_key_id: Option<String>,
    authorization_grant_digest: Option<String>,
    write_strategy: Option<String>,
    apply_attempted: i64,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    apply_accepted: Option<i64>,
    requested_generation: Option<i64>,
    apply_resource_version: Option<String>,
    receiver_facts_present: bool,
    receipt_path: Option<String>,
    receipt_digest: Option<String>,
    receipt_bytes: Option<Vec<u8>>,
    receipt_key_id: Option<String>,
}

impl SnapshotRow {
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive hostile-row decoder keeps every phase/fact combination visible"
    )]
    fn into_operation(
        self,
        statement: Option<ReceiptStatement>,
    ) -> Result<LoadedOperation, GatewayError> {
        let state = OperationState::from_sql(&self.state)?;
        let apply_attempted = decode_sql_bool(self.apply_attempted)?;
        let apply_accepted = self.apply_accepted.map(decode_sql_bool).transpose()?;
        let approved_target = snapshot_target(self.approved_uid, self.approved_resource_version)?;
        let preflight_target =
            snapshot_target(self.preflight_uid, self.preflight_resource_version)?;
        if preflight_target.is_some()
            && matches!(
                state,
                OperationState::Requested | OperationState::Authorized
            )
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        let request = RequestFacts {
            approved_target,
            preflight_target,
            request: ValidatedRequest::try_from(&SetDeploymentImageRequest {
                operation_id: self.operation_id,
                namespace: self.namespace,
                deployment: self.deployment,
                container: self.container,
                immutable_image_digest: self.immutable_image_digest,
            })
            .map_err(|_| GatewayError::InvalidPersistedState)?,
        };
        let result = self
            .result
            .map(|value| OperationResult::from_sql(&value))
            .transpose()?;
        let rejection = self
            .target_rejection
            .map(|value| TargetRejection::from_sql(&value))
            .transpose()?;
        let authorization = validate_snapshot_authorization(
            self.authorization_id,
            self.authorization_signer_key_id,
            self.authorization_grant_digest,
        )?;
        let attempt = validate_snapshot_attempt_facts(
            state,
            self.write_strategy,
            self.target_uid,
            self.target_resource_version,
            apply_accepted,
            self.requested_generation,
            self.apply_resource_version,
        )?;
        if let Some(approved) = &request.approved_target {
            if authorization.is_none()
                || attempt.as_ref().is_some_and(|attempt| {
                    attempt.target.deployment_uid() != approved.uid
                        || attempt.target.resource_version() != approved.resource_version
                })
                || (attempt.is_some() && request.preflight_target.as_ref() != Some(approved))
            {
                return Err(GatewayError::InvalidPersistedState);
            }
        }
        if rejection == Some(TargetRejection::StaleApproval)
            && (request.approved_target.is_none()
                || request.preflight_target.is_none()
                || request.approved_target == request.preflight_target)
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if state == OperationState::NotAttempted
            && rejection != Some(TargetRejection::StaleApproval)
            && request.preflight_target.is_some()
        {
            return Err(GatewayError::InvalidPersistedState);
        }
        if statement.as_ref().map(|value| value.result) != result {
            return Err(GatewayError::InvalidPersistedState);
        }
        let receipt = snapshot_frozen_receipt(
            request.request.operation_id(),
            self.receipt_path,
            self.receipt_digest,
            self.receipt_bytes,
            self.receipt_key_id,
            statement.as_ref(),
        )?;
        let receiver = statement.map(|statement| ReceiverFacts { statement });

        match state {
            OperationState::Requested
                if !apply_attempted
                    && rejection.is_none()
                    && attempt.is_none()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::Requested(RequestedOperation { request }))
            },
            OperationState::Authorized
                if !apply_attempted
                    && authorization.is_some()
                    && rejection.is_none()
                    && attempt.is_none()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::Authorized(AuthorizedOperation {
                    request,
                    authorization: authorization.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::NotAttempted
                if !apply_attempted
                    && authorization.is_some()
                    && rejection.is_some()
                    && attempt.is_none()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::NotAttempted(NotAttemptedOperation {
                    authorized: AuthorizedOperation {
                        request,
                        authorization: authorization.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                    rejection: rejection.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::ApplyStarted
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_none()
                    && receiver.is_none()
                    && receipt.is_none()
                    && !self.receiver_facts_present =>
            {
                Ok(LoadedOperation::ApplyStarted(ApplyStartedOperation {
                    authorized: AuthorizedOperation {
                        request,
                        authorization: authorization.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                    attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::ReceiverObserved
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_some()
                    && receiver.is_some()
                    && receipt.is_none() =>
            {
                Ok(LoadedOperation::ReceiverObserved(
                    ReceiverObservedOperation {
                        apply_started: ApplyStartedOperation {
                            authorized: AuthorizedOperation {
                                request,
                                authorization: authorization
                                    .ok_or(GatewayError::InvalidPersistedState)?,
                            },
                            attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                        },
                        receiver: receiver.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                ))
            },
            OperationState::ReceiptPrepared
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_some()
                    && receiver.is_some()
                    && receipt.is_some() =>
            {
                Ok(LoadedOperation::ReceiptPrepared(ReceiptPreparedOperation {
                    receiver_observed: ReceiverObservedOperation {
                        apply_started: ApplyStartedOperation {
                            authorized: AuthorizedOperation {
                                request,
                                authorization: authorization
                                    .ok_or(GatewayError::InvalidPersistedState)?,
                            },
                            attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                        },
                        receiver: receiver.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                    receipt: receipt.ok_or(GatewayError::InvalidPersistedState)?,
                }))
            },
            OperationState::ReceiptWritten
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_some()
                    && receiver.is_some()
                    && receipt.is_some() =>
            {
                Ok(LoadedOperation::ReceiptWritten(ReceiptWrittenOperation {
                    receipt_prepared: ReceiptPreparedOperation {
                        receiver_observed: ReceiverObservedOperation {
                            apply_started: ApplyStartedOperation {
                                authorized: AuthorizedOperation {
                                    request,
                                    authorization: authorization
                                        .ok_or(GatewayError::InvalidPersistedState)?,
                                },
                                attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                            },
                            receiver: receiver.ok_or(GatewayError::InvalidPersistedState)?,
                        },
                        receipt: receipt.ok_or(GatewayError::InvalidPersistedState)?,
                    },
                }))
            },
            OperationState::Finalized
                if authorization.is_some()
                    && rejection.is_none()
                    && apply_attempted
                    && attempt.is_some()
                    && result.is_some()
                    && receiver.is_some()
                    && receipt.is_some() =>
            {
                Ok(LoadedOperation::Finalized(FinalizedOperation {
                    receipt_written: ReceiptWrittenOperation {
                        receipt_prepared: ReceiptPreparedOperation {
                            receiver_observed: ReceiverObservedOperation {
                                apply_started: ApplyStartedOperation {
                                    authorized: AuthorizedOperation {
                                        request,
                                        authorization: authorization
                                            .ok_or(GatewayError::InvalidPersistedState)?,
                                    },
                                    attempt: attempt.ok_or(GatewayError::InvalidPersistedState)?,
                                },
                                receiver: receiver.ok_or(GatewayError::InvalidPersistedState)?,
                            },
                            receipt: receipt.ok_or(GatewayError::InvalidPersistedState)?,
                        },
                    },
                }))
            },
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are one persisted fact group"
)]
fn validate_snapshot_attempt_facts(
    state: OperationState,
    write_strategy: Option<String>,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    apply_accepted: Option<bool>,
    requested_generation: Option<i64>,
    apply_resource_version: Option<String>,
) -> Result<Option<AttemptFacts>, GatewayError> {
    let target = match (write_strategy, target_uid, target_resource_version) {
        (Some(strategy), Some(deployment_uid), Some(resource_version))
            if strategy == WRITE_STRATEGY =>
        {
            Some(
                ValidatedTargetIdentity::try_from(TargetIdentity {
                    deployment_uid,
                    resource_version,
                })
                .map_err(|_| GatewayError::InvalidPersistedState)?,
            )
        },
        (None, None, None) => None,
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    let Some(target) = target else {
        if apply_accepted.is_none()
            && requested_generation.is_none()
            && apply_resource_version.is_none()
        {
            return Ok(None);
        }
        return Err(GatewayError::InvalidPersistedState);
    };
    let response = match (apply_accepted, apply_resource_version) {
        (None, None) if state != OperationState::ApplyStarted || requested_generation.is_none() => {
            None
        },
        (Some(accepted), Some(resource_version)) => {
            ApplyOutcome {
                accepted,
                requested_generation,
                deployment_uid: Some(target.deployment_uid().to_owned()),
                resource_version: Some(resource_version.clone()),
            }
            .validate()
            .map_err(|_| GatewayError::InvalidPersistedState)?;
            Some(ApplyResponseFacts {
                accepted,
                requested_generation,
                resource_version,
            })
        },
        _ => return Err(GatewayError::InvalidPersistedState),
    };
    Ok(Some(AttemptFacts { target, response }))
}

impl Drop for WorkerLock<'_> {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl OperationState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::NotAttempted => "not_attempted",
            Self::ApplyStarted => "apply_started",
            Self::ReceiverObserved => "receiver_observed",
            Self::ReceiptPrepared => "receipt_prepared",
            Self::ReceiptWritten => "receipt_written",
            Self::Finalized => "finalized",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "requested" => Ok(Self::Requested),
            "authorized" => Ok(Self::Authorized),
            "not_attempted" => Ok(Self::NotAttempted),
            "apply_started" => Ok(Self::ApplyStarted),
            "receiver_observed" => Ok(Self::ReceiverObserved),
            "receipt_prepared" => Ok(Self::ReceiptPrepared),
            "receipt_written" => Ok(Self::ReceiptWritten),
            "finalized" => Ok(Self::Finalized),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

impl TargetRejection {
    fn as_sql(self) -> &'static str {
        match self {
            Self::DeploymentNotFound => "deployment_not_found",
            Self::ContainerNotFound => "container_not_found",
            Self::InvalidTarget => "invalid_target",
            Self::StaleApproval => "stale_approval",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "deployment_not_found" => Ok(Self::DeploymentNotFound),
            "container_not_found" => Ok(Self::ContainerNotFound),
            "invalid_target" => Ok(Self::InvalidTarget),
            "stale_approval" => Ok(Self::StaleApproval),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

impl OperationResult {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn from_sql(value: &str) -> Result<Self, GatewayError> {
        match value {
            "SUCCEEDED" => Ok(Self::Succeeded),
            "FAILED" => Ok(Self::Failed),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(GatewayError::InvalidPersistedState),
        }
    }
}

impl Journal {
    pub(in crate::gateway) fn open(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        let opening::OpenedJournal {
            connection,
            worker_lock,
        } = opening::open_journal(path.as_ref())?;
        Ok(Self {
            connection,
            worker_lock,
        })
    }

    pub(in crate::gateway) fn try_lock_worker(
        &self,
    ) -> Result<Option<WorkerLock<'_>>, GatewayError> {
        match self.worker_lock.try_lock() {
            Ok(()) => Ok(Some(WorkerLock {
                file: &self.worker_lock,
            })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(GatewayError::WorkerLock(error)),
        }
    }

    pub(in crate::gateway) fn existing_submission(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<Option<OperationState>, GatewayError> {
        existing_submission_on(&self.connection, authorized)
    }

    pub(in crate::gateway) fn authorized_operation(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        self.authorized_operation_with(authorized, || {})
    }

    fn authorized_operation_with(
        &self,
        authorized: &AuthorizedRequest,
        after_ownership_read: impl FnOnce(),
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        if existing_submission_on(&transaction, authorized)?.is_none() {
            return Ok(None);
        }
        after_ownership_read();
        loaded_operation_on(&transaction, authorized.request().operation_id())
    }

    pub(in crate::gateway) fn insert_requested(
        &self,
        authorized: &AuthorizedRequest,
    ) -> Result<(), GatewayError> {
        let request = authorized.request();
        let authority = authorized.authorization();
        let approved = authority.authorization.approved_target.as_ref();
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(GatewayError::Database)?;
        let operation_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM kubernetes_image_operations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(GatewayError::Database)?;
        if operation_count >= OPERATION_COUNT_MAX {
            return Err(GatewayError::JournalFull);
        }
        transaction
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container,
                    immutable_image_digest, state, authorization_id,
                    authorization_signer_key_id, authorization_grant_digest,
                    approved_uid, approved_resource_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    request.operation_id(),
                    request.namespace(),
                    request.deployment(),
                    request.container(),
                    request.immutable_image_digest(),
                    OperationState::Requested.as_sql(),
                    authority.authorization.authorization_id,
                    authority.signer_key_id,
                    authority.grant_digest,
                    approved.map(|target| target.uid.as_str()),
                    approved.map(|target| target.resource_version.as_str()),
                ],
            )
            .map_err(GatewayError::Database)?;
        transaction.commit().map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn mark_authorized(
        &self,
        operation: &RequestedOperation,
        authorized: &AuthorizedRequest,
    ) -> Result<(), GatewayError> {
        if operation.request() != authorized.request()
            || existing_submission_on(&self.connection, authorized)?
                != Some(OperationState::Requested)
        {
            return Err(GatewayError::InvalidTransition);
        }
        let operation_id = operation.request().operation_id();
        let authorization = authorized.authorization();
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, authorization_id = ?2,
                     authorization_signer_key_id = ?3, authorization_grant_digest = ?4
                 WHERE operation_id = ?5 AND state = ?6",
                params![
                    OperationState::Authorized.as_sql(),
                    authorization.authorization.authorization_id,
                    authorization.signer_key_id,
                    authorization.grant_digest,
                    operation_id,
                    OperationState::Requested.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    #[cfg(test)]
    pub(in crate::gateway) fn state(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationState>, GatewayError> {
        self.connection
            .query_row(
                "SELECT state FROM kubernetes_image_operations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?
            .map(|state| OperationState::from_sql(&state))
            .transpose()
    }

    #[cfg(test)]
    pub(in crate::gateway) fn target_rejection(
        &self,
        operation_id: &str,
    ) -> Result<Option<TargetRejection>, GatewayError> {
        self.connection
            .query_row(
                "SELECT target_rejection
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2",
                params![operation_id, OperationState::NotAttempted.as_sql()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?
            .map(|value| TargetRejection::from_sql(&value))
            .transpose()
    }

    #[cfg(test)]
    pub(in crate::gateway) fn result(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationResult>, GatewayError> {
        self.connection
            .query_row(
                "SELECT result FROM kubernetes_image_operations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?
            .flatten()
            .map(|result| OperationResult::from_sql(&result))
            .transpose()
    }

    #[cfg(test)]
    pub(in crate::gateway) fn receipt_statement(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptStatement>, GatewayError> {
        receipt_statement_on(&self.connection, operation_id)
    }

    pub(in crate::gateway) fn prepare_receipt(
        &self,
        operation: &ReceiverObservedOperation,
        candidate: &ReceiptToPrepare,
    ) -> Result<(), GatewayError> {
        let receipt = candidate.receipt();
        if receipt.operation_id != operation.operation_id() {
            return Err(GatewayError::InvalidTransition);
        }
        let path = receipt
            .path
            .to_str()
            .ok_or(GatewayError::ReceiptPublication)?;
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, receipt_path = ?2, receipt_digest = ?3,
                     receipt_bytes = ?4, receipt_key_id = ?5
                 WHERE operation_id = ?6 AND state = ?7",
                params![
                    OperationState::ReceiptPrepared.as_sql(),
                    path,
                    receipt.digest,
                    receipt.bytes,
                    receipt.key_id,
                    receipt.operation_id,
                    OperationState::ReceiverObserved.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_receipt_written(
        &self,
        operation: &ReceiptPreparedOperation,
    ) -> Result<(), GatewayError> {
        let operation_id = operation.receipt().operation_id.as_str();
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1
                 WHERE operation_id = ?2 AND state = ?3
                       AND receipt_path IS NOT NULL AND receipt_digest IS NOT NULL
                       AND receipt_bytes IS NOT NULL AND receipt_key_id IS NOT NULL",
                params![
                    OperationState::ReceiptWritten.as_sql(),
                    operation_id,
                    OperationState::ReceiptPrepared.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_finalized(
        &self,
        operation: &ReceiptWrittenOperation,
    ) -> Result<(), GatewayError> {
        let operation_id = operation.receipt().operation_id.as_str();
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1
                 WHERE operation_id = ?2 AND state = ?3
                       AND receipt_path IS NOT NULL AND receipt_digest IS NOT NULL
                       AND receipt_bytes IS NOT NULL AND receipt_key_id IS NOT NULL",
                params![
                    OperationState::Finalized.as_sql(),
                    operation_id,
                    OperationState::ReceiptWritten.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    #[cfg(test)]
    pub(in crate::gateway) fn receipt_reference(
        &self,
        operation_id: &str,
    ) -> Result<Option<ReceiptReference>, GatewayError> {
        self.connection
            .query_row(
                "SELECT receipt_path, receipt_digest
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state IN (?2, ?3)
                       AND receipt_path IS NOT NULL AND receipt_digest IS NOT NULL",
                params![
                    operation_id,
                    OperationState::ReceiptWritten.as_sql(),
                    OperationState::Finalized.as_sql(),
                ],
                |row| {
                    Ok(ReceiptReference {
                        path: PathBuf::from(row.get::<_, String>(0)?),
                        digest: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(GatewayError::Database)
    }

    pub(in crate::gateway) fn next_executable_operation(
        &self,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let authorized = self.next_operation(OperationState::Authorized)?;
        let apply_started = self.next_operation(OperationState::ApplyStarted)?;
        Ok(authorized.or(apply_started))
    }

    #[cfg(test)]
    pub(in crate::gateway) fn next_receipt_finalization_operation(
        &self,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let receiver_observed = self.next_operation(OperationState::ReceiverObserved)?;
        let receipt_prepared = self.next_operation(OperationState::ReceiptPrepared)?;
        let receipt_written = self.next_operation(OperationState::ReceiptWritten)?;
        Ok(receiver_observed.or(receipt_prepared).or(receipt_written))
    }

    fn next_operation(
        &self,
        state: OperationState,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        let operation_id = transaction
            .query_row(
                "SELECT operation_id
                 FROM kubernetes_image_operations
                 WHERE state = ?1
                 ORDER BY CASE WHEN ?1 = 'authorized' THEN target_read_failures ELSE 0 END,
                          operation_id
                 LIMIT 1",
                [state.as_sql()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(GatewayError::Database)?;
        let Some(operation_id) = operation_id else {
            return Ok(None);
        };
        let operation = loaded_operation_on(&transaction, &operation_id)?
            .ok_or(GatewayError::InvalidPersistedState)?;
        if operation.state() != state {
            return Err(GatewayError::InvalidPersistedState);
        }
        Ok(Some(operation))
    }

    pub(in crate::gateway) fn operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<LoadedOperation>, GatewayError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(GatewayError::Database)?;
        loaded_operation_on(&transaction, operation_id)
    }

    #[cfg(test)]
    pub(in crate::gateway) fn operation_snapshot(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationStateProjection>, GatewayError> {
        self.operation(operation_id).map(|operation| {
            operation.map(|operation| OperationStateProjection {
                state: operation.state(),
            })
        })
    }

    pub(in crate::gateway) fn defer_target_retry(
        &self,
        operation: &AuthorizedOperation,
    ) -> Result<(), GatewayError> {
        let operation_id = operation.request().operation_id();
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET target_read_failures = target_read_failures + 1
                 WHERE operation_id = ?1 AND state = ?2
                       AND target_read_failures < 9223372036854775807",
                params![operation_id, OperationState::Authorized.as_sql()],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_not_attempted(
        &self,
        operation: &AuthorizedOperation,
        rejection: TargetRejection,
    ) -> Result<(), GatewayError> {
        let operation_id = operation.request().operation_id();
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, target_rejection = ?2, apply_attempted = 0
                 WHERE operation_id = ?3 AND state = ?4",
                params![
                    OperationState::NotAttempted.as_sql(),
                    rejection.as_sql(),
                    operation_id,
                    OperationState::Authorized.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn begin_attempt(
        &self,
        operation: &AuthorizedOperation,
        observed: ValidatedTargetIdentity,
    ) -> Result<Option<ValidatedTargetIdentity>, GatewayError> {
        let target = if let Some(approved) = operation.approved_target() {
            if observed.deployment_uid() != approved.uid
                || observed.resource_version() != approved.resource_version
            {
                self.mark_stale_approval(operation, &observed)?;
                return Ok(None);
            }
            ValidatedTargetIdentity::try_from(TargetIdentity {
                deployment_uid: approved.uid.clone(),
                resource_version: approved.resource_version.clone(),
            })
            .map_err(|_| GatewayError::InvalidPersistedState)?
        } else {
            observed
        };
        self.mark_apply_started(operation, &target)?;
        Ok(Some(target))
    }

    pub(in crate::gateway) fn mark_stale_approval(
        &self,
        operation: &AuthorizedOperation,
        observed: &ValidatedTargetIdentity,
    ) -> Result<(), GatewayError> {
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET state = 'not_attempted',
                target_rejection = 'stale_approval', apply_attempted = 0,
                preflight_uid = ?1, preflight_resource_version = ?2
             WHERE operation_id = ?3 AND state = 'authorized'",
                params![
                    observed.deployment_uid(),
                    observed.resource_version(),
                    operation.request().operation_id()
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn mark_apply_started(
        &self,
        operation: &AuthorizedOperation,
        target: &ValidatedTargetIdentity,
    ) -> Result<(), GatewayError> {
        let operation_id = operation.request().operation_id();
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, write_strategy = ?2, apply_attempted = 1,
                     target_uid = ?3, target_resource_version = ?4,
                     preflight_uid = ?3, preflight_resource_version = ?4
                 WHERE operation_id = ?5 AND state = ?6",
                params![
                    OperationState::ApplyStarted.as_sql(),
                    WRITE_STRATEGY,
                    target.deployment_uid(),
                    target.resource_version(),
                    operation_id,
                    OperationState::Authorized.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn record_apply_outcome(
        &self,
        operation: &ApplyStartedOperation,
        outcome: &ApplyOutcome,
    ) -> Result<(), GatewayError> {
        let operation_id = operation.request().operation_id();
        outcome.validate()?;
        let target_uid = self
            .connection
            .query_row(
                "SELECT target_uid
                 FROM kubernetes_image_operations
                 WHERE operation_id = ?1 AND state = ?2 AND apply_attempted = 1",
                params![operation_id, OperationState::ApplyStarted.as_sql()],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(GatewayError::Database)?;
        if target_uid.is_none()
            || outcome.deployment_uid.as_ref() != target_uid.as_ref()
            || outcome.resource_version.is_none()
        {
            return Err(GatewayError::InvalidKubernetesFact);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET apply_accepted = ?1, requested_generation = ?2,
                     apply_resource_version = ?3
                 WHERE operation_id = ?4 AND state = ?5 AND apply_attempted = 1",
                params![
                    outcome.accepted,
                    outcome.requested_generation,
                    outcome.resource_version,
                    operation_id,
                    OperationState::ApplyStarted.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }

    pub(in crate::gateway) fn freeze_observation(
        &self,
        operation: &ApplyStartedOperation,
        observation: &ReceiverObservation,
    ) -> Result<(), GatewayError> {
        observation.validate()?;
        let request = operation.request();
        let outcome = operation.classification_outcome();
        let result = observation.classify(request, &outcome);
        let requested_generation = observation.requested_generation(request, &outcome);
        let changed = self
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET state = ?1, receiver_uid = ?2, receiver_image = ?3,
                     receiver_operation_marker = ?4, current_generation = ?5,
                     observed_generation = ?6, receiver_resource_version = ?7,
                     desired_replicas = ?8, updated_replicas = ?9,
                     available_replicas = ?10, unavailable_replicas = ?11,
                     result = ?12, requested_generation = ?13,
                     rollout_condition_type = ?14, rollout_condition_status = ?15,
                     rollout_condition_reason = ?16
                 WHERE operation_id = ?17 AND state = ?18",
                params![
                    OperationState::ReceiverObserved.as_sql(),
                    observation.deployment_uid,
                    observation.image,
                    observation.operation_marker,
                    observation.current_generation,
                    observation.observed_generation,
                    observation.resource_version,
                    observation.desired_replicas,
                    observation.updated_replicas,
                    observation.available_replicas,
                    observation.unavailable_replicas,
                    result.as_sql(),
                    requested_generation,
                    observation.rollout_condition_type,
                    observation.rollout_condition_status,
                    observation.rollout_condition_reason,
                    request.operation_id(),
                    OperationState::ApplyStarted.as_sql(),
                ],
            )
            .map_err(GatewayError::Database)?;
        changed_one(changed)
    }
}

fn existing_submission_on(
    connection: &Connection,
    authorized: &AuthorizedRequest,
) -> Result<Option<OperationState>, GatewayError> {
    let request = authorized.request();
    let authorization = authorized.authorization();
    let existing = connection
        .query_row(
            "SELECT namespace, deployment, container, immutable_image_digest,
                    authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, state
             FROM kubernetes_image_operations
             WHERE operation_id = ?1",
            [request.operation_id()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(GatewayError::Database)?;
    let Some((
        namespace,
        deployment,
        container,
        image,
        authorization_id,
        authorization_signer_key_id,
        authorization_grant_digest,
        state,
    )) = existing
    else {
        return Ok(None);
    };
    if namespace != request.namespace()
        || deployment != request.deployment()
        || container != request.container()
        || image != request.immutable_image_digest()
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    let state = OperationState::from_sql(&state)?;
    if state == OperationState::Requested
        && authorization_id.is_none()
        && authorization.authorization.approved_target.is_some()
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    if (state != OperationState::Requested || authorization_id.is_some())
        && (authorization_id.as_deref()
            != Some(authorization.authorization.authorization_id.as_str())
            || authorization_signer_key_id.as_deref() != Some(authorization.signer_key_id.as_str())
            || authorization_grant_digest.as_deref() != Some(authorization.grant_digest.as_str()))
    {
        return Err(GatewayError::OperationIdentityConflict);
    }
    let loaded = loaded_operation_on(connection, request.operation_id())?
        .ok_or(GatewayError::InvalidPersistedState)?;
    if loaded.request_facts().approved_target != authorization.authorization.approved_target {
        return Err(GatewayError::OperationIdentityConflict);
    }
    if loaded.state() != state {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(Some(state))
}

fn snapshot_row_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<SnapshotRow>, GatewayError> {
    connection
        .query_row(
            "SELECT operation_id, namespace, deployment, container,
                    immutable_image_digest, state, result, target_rejection,
                    authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, write_strategy, apply_attempted,
                    target_uid, target_resource_version, apply_accepted,
                    requested_generation, apply_resource_version,
                    receiver_uid IS NOT NULL OR receiver_image IS NOT NULL
                        OR receiver_operation_marker IS NOT NULL
                        OR current_generation IS NOT NULL
                        OR observed_generation IS NOT NULL
                        OR receiver_resource_version IS NOT NULL
                        OR desired_replicas IS NOT NULL
                        OR updated_replicas IS NOT NULL
                        OR available_replicas IS NOT NULL
                        OR unavailable_replicas IS NOT NULL
                        OR rollout_condition_type IS NOT NULL
                        OR rollout_condition_status IS NOT NULL
                        OR rollout_condition_reason IS NOT NULL,
                    receipt_path, receipt_digest, receipt_bytes, receipt_key_id,
                    approved_uid, approved_resource_version,
                    preflight_uid, preflight_resource_version
             FROM kubernetes_image_operations
             WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok(SnapshotRow {
                    approved_uid: row.get(23)?,
                    approved_resource_version: row.get(24)?,
                    preflight_uid: row.get(25)?,
                    preflight_resource_version: row.get(26)?,
                    operation_id: row.get(0)?,
                    namespace: row.get(1)?,
                    deployment: row.get(2)?,
                    container: row.get(3)?,
                    immutable_image_digest: row.get(4)?,
                    state: row.get(5)?,
                    result: row.get(6)?,
                    target_rejection: row.get(7)?,
                    authorization_id: row.get(8)?,
                    authorization_signer_key_id: row.get(9)?,
                    authorization_grant_digest: row.get(10)?,
                    write_strategy: row.get(11)?,
                    apply_attempted: row.get(12)?,
                    target_uid: row.get(13)?,
                    target_resource_version: row.get(14)?,
                    apply_accepted: row.get(15)?,
                    requested_generation: row.get(16)?,
                    apply_resource_version: row.get(17)?,
                    receiver_facts_present: row.get(18)?,
                    receipt_path: row.get(19)?,
                    receipt_digest: row.get(20)?,
                    receipt_bytes: row.get(21)?,
                    receipt_key_id: row.get(22)?,
                })
            },
        )
        .optional()
        .map_err(GatewayError::Database)
}

fn receipt_statement_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<ReceiptStatement>, GatewayError> {
    connection
        .query_row(
            "SELECT operation_id, authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, namespace, deployment, container,
                    immutable_image_digest, write_strategy, target_uid,
                    target_resource_version, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, requested_generation,
                    observed_generation, receiver_resource_version, desired_replicas,
                    updated_replicas, available_replicas, unavailable_replicas,
                    rollout_condition_type, rollout_condition_status,
                    rollout_condition_reason, result, approved_uid, approved_resource_version
             FROM kubernetes_image_operations
             WHERE operation_id = ?1 AND state IN (?2, ?3, ?4, ?5)",
            params![
                operation_id,
                OperationState::ReceiverObserved.as_sql(),
                OperationState::ReceiptPrepared.as_sql(),
                OperationState::ReceiptWritten.as_sql(),
                OperationState::Finalized.as_sql(),
            ],
            ReceiptRow::from_sql,
        )
        .optional()
        .map_err(GatewayError::Database)?
        .map(ReceiptRow::into_statement)
        .transpose()
}

fn loaded_operation_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<LoadedOperation>, GatewayError> {
    let Some(row) = snapshot_row_on(connection, operation_id)? else {
        return Ok(None);
    };
    let statement = receipt_statement_on(connection, operation_id)?;
    row.into_operation(statement).map(Some)
}

fn snapshot_target(
    uid: Option<String>,
    resource_version: Option<String>,
) -> Result<Option<super::ApprovedTarget>, GatewayError> {
    match (uid, resource_version) {
        (None, None) => Ok(None),
        (Some(uid), Some(resource_version)) => {
            let target = super::ApprovedTarget {
                uid,
                resource_version,
            };
            if !target.is_valid() {
                return Err(GatewayError::InvalidPersistedState);
            }
            Ok(Some(target))
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn decode_sql_bool(value: i64) -> Result<bool, GatewayError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn validate_snapshot_authorization(
    authorization_id: Option<String>,
    signer_key_id: Option<String>,
    grant_digest: Option<String>,
) -> Result<Option<AuthorizationFacts>, GatewayError> {
    match (authorization_id, signer_key_id, grant_digest) {
        (None, None, None) => Ok(None),
        (Some(authorization_id), Some(signer_key_id), Some(grant_digest)) => {
            validate_identity(InputField::AuthorizationId, &authorization_id)
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            validate_identity(InputField::AuthorizationId, &signer_key_id)
                .map_err(|_| GatewayError::InvalidPersistedState)?;
            Ok(Some(AuthorizationFacts {
                authorization_id,
                signer_key_id,
                grant_digest: Sha256Digest::try_from(grant_digest)?,
            }))
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn snapshot_frozen_receipt(
    operation_id: &str,
    path: Option<String>,
    digest: Option<String>,
    bytes: Option<Vec<u8>>,
    key_id: Option<String>,
    statement: Option<&ReceiptStatement>,
) -> Result<Option<FrozenReceipt>, GatewayError> {
    match (path, digest, bytes, key_id) {
        (None, None, None, None) => Ok(None),
        (Some(path), Some(digest), Some(bytes), Some(key_id)) => {
            let receipt = validate_frozen_receipt(FrozenReceipt {
                operation_id: operation_id.to_owned(),
                path: PathBuf::from(path),
                digest,
                bytes,
                key_id,
            })?;
            let expected_statement = statement.ok_or(GatewayError::InvalidPersistedState)?;
            let (embedded_key_id, embedded_statement) =
                decode_frozen_receipt(&receipt.bytes).map_err(GatewayError::Receipt)?;
            if embedded_key_id != receipt.key_id || embedded_statement != *expected_statement {
                return Err(GatewayError::InvalidPersistedState);
            }
            Ok(Some(receipt))
        },
        _ => Err(GatewayError::InvalidPersistedState),
    }
}

fn validate_frozen_receipt(receipt: FrozenReceipt) -> Result<FrozenReceipt, GatewayError> {
    if receipt.bytes.len() > RECEIPT_BYTES_MAX
        || publication::receipt_digest_hex(&receipt.bytes) != receipt.digest
    {
        return Err(GatewayError::ReceiptDigestMismatch);
    }
    validate_identity(InputField::AuthorizationId, &receipt.key_id)
        .map_err(|_| GatewayError::InvalidPersistedState)?;
    let expected_name = publication::receipt_filename(&receipt.operation_id, &receipt.digest);
    if !receipt.path.is_absolute()
        || receipt.path.file_name() != Some(expected_name.as_ref())
        || receipt.path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(receipt)
}

struct ReceiptRow {
    approved_uid: Option<String>,
    approved_resource_version: Option<String>,
    operation_id: String,
    authorization_id: Option<String>,
    authorization_signer_key_id: Option<String>,
    authorization_grant_digest: Option<String>,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
    write_strategy: Option<String>,
    target_uid: Option<String>,
    target_resource_version: Option<String>,
    receiver_uid: Option<String>,
    observed_image: Option<String>,
    observed_operation_marker: Option<String>,
    current_generation: Option<i64>,
    requested_generation: Option<i64>,
    observed_generation: Option<i64>,
    observed_resource_version: Option<String>,
    desired_replicas: Option<i32>,
    updated_replicas: Option<i32>,
    available_replicas: Option<i32>,
    unavailable_replicas: Option<i32>,
    rollout_condition_type: Option<String>,
    rollout_condition_status: Option<String>,
    rollout_condition_reason: Option<String>,
    result: String,
}

impl ReceiptRow {
    fn from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            approved_uid: row.get(26)?,
            approved_resource_version: row.get(27)?,
            operation_id: row.get(0)?,
            authorization_id: row.get(1)?,
            authorization_signer_key_id: row.get(2)?,
            authorization_grant_digest: row.get(3)?,
            namespace: row.get(4)?,
            deployment: row.get(5)?,
            container: row.get(6)?,
            immutable_image_digest: row.get(7)?,
            write_strategy: row.get(8)?,
            target_uid: row.get(9)?,
            target_resource_version: row.get(10)?,
            receiver_uid: row.get(11)?,
            observed_image: row.get(12)?,
            observed_operation_marker: row.get(13)?,
            current_generation: row.get(14)?,
            requested_generation: row.get(15)?,
            observed_generation: row.get(16)?,
            observed_resource_version: row.get(17)?,
            desired_replicas: row.get(18)?,
            updated_replicas: row.get(19)?,
            available_replicas: row.get(20)?,
            unavailable_replicas: row.get(21)?,
            rollout_condition_type: row.get(22)?,
            rollout_condition_status: row.get(23)?,
            rollout_condition_reason: row.get(24)?,
            result: row.get(25)?,
        })
    }

    fn into_statement(self) -> Result<ReceiptStatement, GatewayError> {
        let statement = ReceiptStatement {
            approved_target: snapshot_target(self.approved_uid, self.approved_resource_version)?,
            operation_id: self.operation_id,
            authorization_id: self
                .authorization_id
                .ok_or(GatewayError::InvalidPersistedState)?,
            authorization_signer_key_id: self
                .authorization_signer_key_id
                .ok_or(GatewayError::InvalidPersistedState)?,
            authorization_grant_digest: self
                .authorization_grant_digest
                .ok_or(GatewayError::InvalidPersistedState)?,
            namespace: self.namespace,
            deployment: self.deployment,
            container: self.container,
            immutable_image_digest: self.immutable_image_digest,
            write_strategy: self
                .write_strategy
                .ok_or(GatewayError::InvalidPersistedState)?,
            target_uid: self.target_uid.ok_or(GatewayError::InvalidPersistedState)?,
            target_resource_version: self
                .target_resource_version
                .ok_or(GatewayError::InvalidPersistedState)?,
            receiver_uid: self.receiver_uid,
            observed_image: self.observed_image,
            observed_operation_marker: self.observed_operation_marker,
            current_generation: self.current_generation,
            requested_generation: self.requested_generation,
            observed_generation: self.observed_generation,
            observed_resource_version: self.observed_resource_version,
            desired_replicas: self.desired_replicas,
            updated_replicas: self.updated_replicas,
            available_replicas: self.available_replicas,
            unavailable_replicas: self.unavailable_replicas,
            rollout_condition_type: self.rollout_condition_type,
            rollout_condition_status: self.rollout_condition_status,
            rollout_condition_reason: self.rollout_condition_reason,
            result: OperationResult::from_sql(&self.result)?,
        };
        statement
            .validate()
            .map_err(|_| GatewayError::InvalidPersistedState)?;
        Ok(statement)
    }
}

fn changed_one(changed: usize) -> Result<(), GatewayError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(GatewayError::InvalidTransition)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::*;
    use crate::gateway::{
        sign_authorization_grant, verify_authorization_grant, ExactAuthorization,
    };

    fn journal(name: &str) -> (Journal, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "kapsel-journal-snapshot-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let journal = Journal::open(root.join("journal.sqlite3")).unwrap();
        (journal, root)
    }

    fn snapshot_statement() -> ReceiptStatement {
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        ReceiptStatement {
            approved_target: None,
            operation_id: "snapshot-op".into(),
            authorization_id: "snapshot-auth".into(),
            authorization_signer_key_id: "snapshot-signer".into(),
            authorization_grant_digest:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: image.into(),
            write_strategy: WRITE_STRATEGY.into(),
            target_uid: "target-uid".into(),
            target_resource_version: "target-rv".into(),
            receiver_uid: Some("target-uid".into()),
            observed_image: Some(image.into()),
            observed_operation_marker: Some("snapshot-op".into()),
            current_generation: Some(2),
            requested_generation: Some(2),
            observed_generation: Some(2),
            observed_resource_version: Some("receiver-rv".into()),
            desired_replicas: Some(1),
            updated_replicas: Some(1),
            available_replicas: Some(1),
            unavailable_replicas: Some(0),
            rollout_condition_type: Some("Available".into()),
            rollout_condition_status: Some("True".into()),
            rollout_condition_reason: Some("MinimumReplicasAvailable".into()),
            result: OperationResult::Succeeded,
        }
    }

    fn insert_snapshot_row(
        journal: &Journal,
        state: &str,
        result: Option<&str>,
        rejection: Option<&str>,
        receipt: bool,
    ) {
        let authorized = state != "requested";
        let attempted = matches!(
            state,
            "apply_started"
                | "receiver_observed"
                | "receipt_prepared"
                | "receipt_written"
                | "finalized"
        );
        let observed = matches!(
            state,
            "receiver_observed" | "receipt_prepared" | "receipt_written" | "finalized"
        );
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        let statement = snapshot_statement();
        let receipt_bytes =
            super::super::receipt::sign_statement(&statement, &[9_u8; 32], "snapshot-receipt-key")
                .unwrap();
        let receipt_digest = publication::receipt_digest_hex(&receipt_bytes);
        let receipt_path = format!(
            "/private/{}",
            publication::receipt_filename("snapshot-op", &receipt_digest)
        );
        journal
            .connection
            .execute(
                "INSERT INTO kubernetes_image_operations (
                    operation_id, namespace, deployment, container,
                    immutable_image_digest, state, result, target_rejection,
                    authorization_id, authorization_signer_key_id,
                    authorization_grant_digest, write_strategy, apply_attempted,
                    target_uid, target_resource_version, receiver_uid, receiver_image,
                    receiver_operation_marker, current_generation, requested_generation,
                    observed_generation, receiver_resource_version, desired_replicas,
                    updated_replicas, available_replicas, unavailable_replicas,
                    rollout_condition_type, rollout_condition_status,
                    rollout_condition_reason, receipt_path, receipt_digest,
                    receipt_bytes, receipt_key_id
                 ) VALUES (?1, 'demo', 'agent-api', 'api', ?2, ?3, ?4, ?5,
                           ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                           ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                           ?27, ?28, ?29, ?30)",
                params![
                    "snapshot-op",
                    image,
                    state,
                    result,
                    rejection,
                    authorized.then_some("snapshot-auth"),
                    authorized.then_some("snapshot-signer"),
                    authorized.then_some(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    ),
                    attempted.then_some(WRITE_STRATEGY),
                    attempted,
                    attempted.then_some("target-uid"),
                    attempted.then_some("target-rv"),
                    observed.then_some("target-uid"),
                    observed.then_some(image),
                    observed.then_some("snapshot-op"),
                    observed.then_some(2_i64),
                    observed.then_some(2_i64),
                    observed.then_some(2_i64),
                    observed.then_some("receiver-rv"),
                    observed.then_some(1_i32),
                    observed.then_some(1_i32),
                    observed.then_some(1_i32),
                    observed.then_some(0_i32),
                    observed.then_some("Available"),
                    observed.then_some("True"),
                    observed.then_some("MinimumReplicasAvailable"),
                    receipt.then_some(receipt_path),
                    receipt.then_some(receipt_digest),
                    receipt.then_some(receipt_bytes),
                    receipt.then_some("snapshot-receipt-key"),
                ],
            )
            .unwrap();
    }

    #[test]
    fn persisted_operation_decoder_builds_exact_variant_for_every_legal_phase() {
        for (state, result, rejection, receipt) in [
            ("requested", None, None, false),
            ("authorized", None, None, false),
            ("not_attempted", None, Some("deployment_not_found"), false),
            ("apply_started", None, None, false),
            ("receiver_observed", Some("SUCCEEDED"), None, false),
            ("receipt_prepared", Some("SUCCEEDED"), None, true),
            ("receipt_written", Some("SUCCEEDED"), None, true),
            ("finalized", Some("SUCCEEDED"), None, true),
        ] {
            let (journal, root) = journal(&format!("legal-{state}"));
            insert_snapshot_row(&journal, state, result, rejection, receipt);
            let operation = journal.operation("snapshot-op").unwrap().unwrap();
            let exact_variant = matches!(
                (state, &operation),
                ("requested", LoadedOperation::Requested(_))
                    | ("authorized", LoadedOperation::Authorized(_))
                    | ("not_attempted", LoadedOperation::NotAttempted(_))
                    | ("apply_started", LoadedOperation::ApplyStarted(_))
                    | ("receiver_observed", LoadedOperation::ReceiverObserved(_))
                    | ("receipt_prepared", LoadedOperation::ReceiptPrepared(_))
                    | ("receipt_written", LoadedOperation::ReceiptWritten(_))
                    | ("finalized", LoadedOperation::Finalized(_))
            );
            assert!(exact_variant, "{state}");
            assert_eq!(operation.request().operation_id(), "snapshot-op");
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_missing_required_phase_facts() {
        for (name, state, result, rejection, receipt, assignment) in [
            (
                "requested-invalid-request",
                "requested",
                None,
                None,
                false,
                "namespace = 'Uppercase'",
            ),
            (
                "authorized-missing-authorization",
                "authorized",
                None,
                None,
                false,
                "authorization_id = NULL",
            ),
            (
                "not-attempted-missing-rejection",
                "not_attempted",
                None,
                Some("deployment_not_found"),
                false,
                "target_rejection = NULL",
            ),
            (
                "apply-started-missing-attempt",
                "apply_started",
                None,
                None,
                false,
                "target_uid = NULL",
            ),
            (
                "receiver-observed-missing-result",
                "receiver_observed",
                Some("SUCCEEDED"),
                None,
                false,
                "result = NULL",
            ),
            (
                "receipt-prepared-missing-receipt",
                "receipt_prepared",
                Some("SUCCEEDED"),
                None,
                true,
                "receipt_path = NULL",
            ),
            (
                "receipt-written-missing-receipt",
                "receipt_written",
                Some("SUCCEEDED"),
                None,
                true,
                "receipt_digest = NULL",
            ),
            (
                "finalized-missing-receipt",
                "finalized",
                Some("SUCCEEDED"),
                None,
                true,
                "receipt_bytes = NULL",
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, state, result, rejection, receipt);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment} \
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();
            assert!(journal.operation("snapshot-op").is_err(), "{name}");
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_facts_before_their_phase() {
        for (name, state, result, rejection, assignment) in [
            (
                "attempt-before-apply",
                "authorized",
                None,
                None,
                concat!(
                    "write_strategy = 'conditional-strategic-merge-patch', ",
                    "apply_attempted = 1, target_uid = 'uid', ",
                    "target_resource_version = 'rv'"
                ),
            ),
            (
                "receiver-before-observed",
                "authorized",
                None,
                None,
                "receiver_uid = 'uid'",
            ),
            (
                "receipt-before-prepared",
                "receiver_observed",
                Some("SUCCEEDED"),
                None,
                "receipt_key_id = 'early-key'",
            ),
            (
                "rejection-and-receiver-result",
                "not_attempted",
                Some("UNKNOWN"),
                Some("deployment_not_found"),
                "receiver_uid = 'uid'",
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, state, result, rejection, false);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment} \
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();
            assert!(journal.operation("snapshot-op").is_err(), "{name}");
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_rejects_marker_only_pre_attempt_rows() {
        for (state, rejection) in [
            ("requested", None),
            ("authorized", None),
            ("not_attempted", Some("deployment_not_found")),
        ] {
            let (journal, root) = journal(&format!("marker-only-{state}"));
            insert_snapshot_row(&journal, state, None, rejection, false);
            journal
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations SET apply_attempted = 1
                     WHERE operation_id = ?1",
                    ["snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err(), "{state}");
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn queue_selection_rejects_malformed_later_phase_rows_before_advancing() {
        let (executable_journal, root) = journal("malformed-executable-queue");
        insert_snapshot_row(&executable_journal, "apply_started", None, None, false);
        executable_journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET operation_id = 'apply-op', target_uid = NULL
                 WHERE operation_id = 'snapshot-op'",
                [],
            )
            .unwrap();
        insert_snapshot_row(&executable_journal, "authorized", None, None, false);

        assert!(executable_journal.next_executable_operation().is_err());
        drop(executable_journal);
        fs::remove_dir_all(root).unwrap();

        let (journal, root) = journal("malformed-receipt-queue");
        insert_snapshot_row(&journal, "receipt_prepared", Some("SUCCEEDED"), None, true);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET operation_id = 'prepared-op', receipt_path = NULL
                 WHERE operation_id = 'snapshot-op'",
                [],
            )
            .unwrap();
        insert_snapshot_row(
            &journal,
            "receiver_observed",
            Some("SUCCEEDED"),
            None,
            false,
        );

        assert!(journal.next_receipt_finalization_operation().is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persisted_operation_decoder_rejects_noncanonical_write_strategy() {
        let (journal, root) = journal("noncanonical-write-strategy");
        insert_snapshot_row(&journal, "apply_started", None, None, false);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET write_strategy = 'banana'
                 WHERE operation_id = ?1",
                ["snapshot-op"],
            )
            .unwrap();

        assert!(journal.operation("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persisted_operation_decoder_rejects_nonbinary_boolean_columns() {
        for (name, assignment) in [
            ("attempt-positive", "apply_attempted = 2"),
            ("attempt-negative", "apply_attempted = -1"),
            (
                "accepted-positive",
                "apply_accepted = 2, apply_resource_version = 'apply-rv'",
            ),
            (
                "accepted-negative",
                "apply_accepted = -1, apply_resource_version = 'apply-rv'",
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, "apply_started", None, None, false);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment}
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err(), "{name}");
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn persisted_operation_decoder_requires_complete_apply_response_facts() {
        for accepted in [false, true] {
            let (journal, root) = journal(if accepted {
                "accepted-response-no-version"
            } else {
                "rejected-response-no-version"
            });
            insert_snapshot_row(&journal, "apply_started", None, None, false);
            journal
                .connection
                .execute(
                    "UPDATE kubernetes_image_operations
                     SET apply_accepted = ?1, requested_generation = 2
                     WHERE operation_id = ?2",
                    params![accepted, "snapshot-op"],
                )
                .unwrap();

            assert!(journal.operation("snapshot-op").is_err());
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("complete-rejected-response");
        insert_snapshot_row(&journal, "apply_started", None, None, false);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET apply_accepted = 0, apply_resource_version = 'apply-rv'
                 WHERE operation_id = ?1",
                ["snapshot-op"],
            )
            .unwrap();
        assert!(matches!(
            journal.operation("snapshot-op").unwrap(),
            Some(LoadedOperation::ApplyStarted(_))
        ));
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn record_apply_outcome_requires_complete_matching_response_identity() {
        let (journal, root) = journal("provider-response-identity");
        insert_snapshot_row(&journal, "apply_started", None, None, false);
        let loaded = journal.operation("snapshot-op").unwrap().unwrap();
        assert!(matches!(&loaded, LoadedOperation::ApplyStarted(_)));
        let LoadedOperation::ApplyStarted(operation) = loaded else {
            return;
        };
        for outcome in [
            ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: None,
                resource_version: Some("apply-rv".into()),
            },
            ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("target-uid".into()),
                resource_version: None,
            },
            ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("other-uid".into()),
                resource_version: Some("apply-rv".into()),
            },
        ] {
            assert!(matches!(
                journal.record_apply_outcome(&operation, &outcome),
                Err(GatewayError::InvalidKubernetesFact)
            ));
        }
        let persisted: (Option<bool>, Option<i64>, Option<String>) = journal
            .connection
            .query_row(
                "SELECT apply_accepted, requested_generation, apply_resource_version
                 FROM kubernetes_image_operations WHERE operation_id = ?1",
                ["snapshot-op"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(persisted, (None, None, None));

        journal
            .record_apply_outcome(
                &operation,
                &ApplyOutcome {
                    accepted: false,
                    requested_generation: None,
                    deployment_uid: Some("target-uid".into()),
                    resource_version: Some("apply-rv".into()),
                },
            )
            .unwrap();
        assert!(matches!(
            journal.operation("snapshot-op").unwrap(),
            Some(LoadedOperation::ApplyStarted(_))
        ));
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_operation_rejects_incoherent_public_facts() {
        for (name, state, result, rejection, receipt) in [
            ("finalized-no-result", "finalized", None, None, true),
            (
                "not-attempted-no-rejection",
                "not_attempted",
                None,
                None,
                false,
            ),
            (
                "active-with-terminal-facts",
                "authorized",
                Some("SUCCEEDED"),
                Some("deployment_not_found"),
                false,
            ),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, state, result, rejection, receipt);
            assert!(journal.operation("snapshot-op").is_err());
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn loaded_operation_requires_complete_valid_frozen_receipt_facts() {
        for (name, assignment) in [
            ("missing-path", "receipt_path = NULL"),
            ("missing-digest", "receipt_digest = NULL"),
            ("missing-bytes", "receipt_bytes = NULL"),
            ("missing-key", "receipt_key_id = NULL"),
            (
                "missing-tuple",
                "receipt_path = NULL, receipt_digest = NULL, receipt_bytes = NULL, \
                 receipt_key_id = NULL",
            ),
            ("bad-key", "receipt_key_id = 'bad key'"),
            ("bad-digest", "receipt_digest = '00'"),
            ("wrong-name", "receipt_path = '/private/wrong.receipt'"),
            ("relative-path", "receipt_path = 'relative.receipt'"),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
            let update = format!(
                "UPDATE kubernetes_image_operations SET {assignment} \
                 WHERE operation_id = ?1"
            );
            journal
                .connection
                .execute(&update, ["snapshot-op"])
                .unwrap();
            assert!(journal.operation("snapshot-op").is_err());
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("oversized-receipt");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET receipt_bytes = ?1 \
                 WHERE operation_id = ?2",
                params![vec![0_u8; RECEIPT_BYTES_MAX + 1], "snapshot-op"],
            )
            .unwrap();
        assert!(journal.operation("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_operation_binds_receiver_facts_and_receipt_envelope() {
        for (name, assignment) in [
            ("result-tamper", "result = 'FAILED'"),
            ("classifier-tamper", "available_replicas = 0"),
            ("key-tamper", "receipt_key_id = 'other-valid-key'"),
        ] {
            let (journal, root) = journal(name);
            insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
            journal
                .connection
                .execute(
                    &format!(
                        "UPDATE kubernetes_image_operations SET {assignment} \
                         WHERE operation_id = ?1"
                    ),
                    ["snapshot-op"],
                )
                .unwrap();
            assert!(journal.operation("snapshot-op").is_err());
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (journal, root) = journal("non-receipt-bytes");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        let bytes = b"not-a-receipt";
        let digest = publication::receipt_digest_hex(bytes);
        let path = format!(
            "/private/{}",
            publication::receipt_filename("snapshot-op", &digest)
        );
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET receipt_path = ?1, receipt_digest = ?2, receipt_bytes = ?3
                 WHERE operation_id = ?4",
                params![path, digest, bytes.as_slice(), "snapshot-op"],
            )
            .unwrap();
        assert!(journal.operation("snapshot-op").is_err());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authorized_snapshot_holds_one_sqlite_read_view() {
        let (journal, root) = journal("atomic-authorization");
        let request = SetDeploymentImageRequest {
            operation_id: "snapshot-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        };
        let authorization = ExactAuthorization {
            approved_target: None,
            authorization_id: "snapshot-auth".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        };
        let signed =
            sign_authorization_grant(&authorization, &[7_u8; 32], "snapshot-signer").unwrap();
        let verified = verify_authorization_grant(
            &signed,
            &super::super::AuthorizationTrust {
                key_id: "snapshot-signer".into(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            },
        )
        .unwrap();
        let authorized =
            AuthorizedRequest::bind(ValidatedRequest::try_from(&request).unwrap(), verified)
                .unwrap();
        journal.insert_requested(&authorized).unwrap();
        let other = Journal::open(root.join("journal.sqlite3")).unwrap();

        let snapshot = journal
            .authorized_operation_with(&authorized, || {
                let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations
                     SET state = 'authorized', authorization_id = 'other-auth',
                         authorization_signer_key_id = 'other-signer',
                         authorization_grant_digest = ?1
                     WHERE operation_id = ?2",
                    params!["0".repeat(64), "snapshot-op"],
                );
                assert!(result.is_err());
            })
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.state(), OperationState::Requested);

        drop(other);
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authorized_finalized_snapshot_freezes_receipt_and_ownership_together() {
        let (journal, root) = journal("atomic-finalized-receipt");
        insert_snapshot_row(&journal, "finalized", Some("SUCCEEDED"), None, true);
        let request = SetDeploymentImageRequest {
            operation_id: "snapshot-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        };
        let authorization = ExactAuthorization {
            approved_target: None,
            authorization_id: "snapshot-auth".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        };
        let signed =
            sign_authorization_grant(&authorization, &[7_u8; 32], "snapshot-signer").unwrap();
        let verified = verify_authorization_grant(
            &signed,
            &super::super::AuthorizationTrust {
                key_id: "snapshot-signer".into(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            },
        )
        .unwrap();
        let mut statement = snapshot_statement();
        statement.authorization_grant_digest = verified.grant_digest.clone();
        let receipt_bytes =
            super::super::receipt::sign_statement(&statement, &[9_u8; 32], "snapshot-receipt-key")
                .unwrap();
        let receipt_digest = publication::receipt_digest_hex(&receipt_bytes);
        let receipt_path = format!(
            "/private/{}",
            publication::receipt_filename("snapshot-op", &receipt_digest)
        );
        journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET authorization_grant_digest = ?1, receipt_path = ?2,
                     receipt_digest = ?3, receipt_bytes = ?4
                 WHERE operation_id = ?5",
                params![
                    verified.grant_digest,
                    receipt_path,
                    receipt_digest,
                    receipt_bytes,
                    "snapshot-op"
                ],
            )
            .unwrap();
        let authorized =
            AuthorizedRequest::bind(ValidatedRequest::try_from(&request).unwrap(), verified)
                .unwrap();
        let other = Journal::open(root.join("journal.sqlite3")).unwrap();

        let snapshot = journal
            .authorized_operation_with(&authorized, || {
                let result = other.connection.execute(
                    "UPDATE kubernetes_image_operations
                     SET authorization_id = 'other-auth', receipt_bytes = ?1
                     WHERE operation_id = ?2",
                    params![b"replacement".as_slice(), "snapshot-op"],
                );
                assert!(result.is_err());
            })
            .unwrap()
            .unwrap();
        let receipt = snapshot.frozen_receipt().unwrap();
        assert_ne!(receipt.bytes, b"replacement");
        assert_eq!(
            publication::receipt_digest_hex(&receipt.bytes),
            receipt.digest
        );

        drop(other);
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_operation_requires_state_local_authorization_and_attempt_facts() {
        for (name, state, assignment) in [
            (
                "authorized-no-auth",
                "authorized",
                "authorization_id = NULL",
            ),
            ("apply-no-marker", "apply_started", "apply_attempted = 0"),
            ("apply-no-target", "apply_started", "target_uid = NULL"),
            ("apply-empty-target", "apply_started", "target_uid = ''"),
            (
                "apply-partial-outcome",
                "apply_started",
                "requested_generation = 2",
            ),
            (
                "not-attempted-apply-fact",
                "not_attempted",
                "apply_accepted = 0",
            ),
            (
                "not-attempted-receiver-fact",
                "not_attempted",
                "receiver_uid = 'unexpected'",
            ),
            ("observed-no-result", "receiver_observed", "result = NULL"),
        ] {
            let (journal, root) = journal(name);
            let result = (state == "receiver_observed").then_some("SUCCEEDED");
            insert_snapshot_row(&journal, state, result, None, false);
            let update = format!(
                "UPDATE kubernetes_image_operations SET {assignment} \
                 WHERE operation_id = ?1"
            );
            journal
                .connection
                .execute(&update, ["snapshot-op"])
                .unwrap();
            assert!(journal.operation("snapshot-op").is_err(), "{name}");
            drop(journal);
            fs::remove_dir_all(root).unwrap();
        }

        let (oversized_journal, root) = journal("apply-oversized-target");
        insert_snapshot_row(&oversized_journal, "apply_started", None, None, false);
        oversized_journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations SET target_uid = ?1
                 WHERE operation_id = ?2",
                params!["x".repeat(129), "snapshot-op"],
            )
            .unwrap();
        assert!(oversized_journal.operation("snapshot-op").is_err());
        drop(oversized_journal);
        fs::remove_dir_all(root).unwrap();

        let (outcome_journal, root) = journal("apply-complete-outcome");
        insert_snapshot_row(&outcome_journal, "apply_started", None, None, false);
        outcome_journal
            .connection
            .execute(
                "UPDATE kubernetes_image_operations
                 SET apply_accepted = 1, requested_generation = 2,
                     apply_resource_version = 'apply-rv'
                 WHERE operation_id = ?1",
                ["snapshot-op"],
            )
            .unwrap();
        assert_eq!(
            outcome_journal
                .operation("snapshot-op")
                .unwrap()
                .unwrap()
                .state(),
            OperationState::ApplyStarted
        );
        drop(outcome_journal);
        fs::remove_dir_all(root).unwrap();
    }
}
