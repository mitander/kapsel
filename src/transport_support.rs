//! Private composition and domain projection shared by the CLI and MCP adapters.

use std::{fs::File, io::Read as _, path::Path};

use kapsel::{
    open_application_from_operator_document, Application, ApplicationError, OperationReport,
    OperationResult, OperationState, TargetRejection,
};
use rustix::fs::{openat, Mode, OFlags, CWD};

const JSON_BYTES_MAX: usize = 16 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FailureClass {
    OperatorConfiguration,
    RequestRejected,
    OperationFailure,
}

pub(crate) struct OperationProjection<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) state: &'static str,
    pub(crate) result: Option<&'static str>,
    pub(crate) target_rejection: Option<&'static str>,
    pub(crate) receipt_file: Option<&'a str>,
    pub(crate) receipt_sha256: Option<&'a str>,
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime, FailureClass> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FailureClass::OperationFailure)
}

pub(crate) async fn open_application(path: &Path) -> Result<Application, FailureClass> {
    let document = read_bounded(path, JSON_BYTES_MAX)?;
    open_application_from_operator_document(&document, |path, maximum| {
        read_bounded(path, maximum).map_err(|_| ApplicationError::InvalidOperatorConfiguration)
    })
    .await
    .map_err(|error| match error {
        ApplicationError::InvalidOperatorConfiguration
        | ApplicationError::InvalidAuthorizationConfiguration
        | ApplicationError::InvalidReceiptConfiguration
        | ApplicationError::InvalidJournalPath
        | ApplicationError::InvalidReceiptOutputDirectory
        | ApplicationError::InvalidGrantProvisioning => FailureClass::OperatorConfiguration,
        ApplicationError::RequestRejected | ApplicationError::OperationFailure => {
            FailureClass::OperationFailure
        },
    })
}

pub(crate) fn classify_application_operation(error: &ApplicationError) -> FailureClass {
    match error {
        ApplicationError::RequestRejected => FailureClass::RequestRejected,
        _ => FailureClass::OperationFailure,
    }
}

pub(crate) fn project_operation(
    report: &OperationReport,
) -> Result<OperationProjection<'_>, FailureClass> {
    let (receipt_file, receipt_sha256) = match &report.receipt {
        Some(receipt) => (
            Some(
                receipt
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(FailureClass::OperationFailure)?,
            ),
            Some(receipt.digest.as_str()),
        ),
        None => (None, None),
    };
    Ok(OperationProjection {
        operation_id: &report.operation_id,
        state: operation_state(report.state),
        result: report.result.map(operation_result),
        target_rejection: report.target_rejection.map(target_rejection),
        receipt_file,
        receipt_sha256,
    })
}

pub(crate) fn target_fields(targets: &kapsel::OperationTargets) -> String {
    let exact = |target: Option<&kapsel::ApprovedTarget>| {
        target.map(|target| {
        serde_json::json!({"uid": target.uid, "resource_version": target.resource_version})
    })
    };
    serde_json::json!({
        "approved_target": exact(targets.approved_target.as_ref()),
        "attempt_target": exact(targets.attempt_target.as_ref()),
        "observed_target": targets.observed_target.as_ref().map(|target| serde_json::json!({
            "uid": target.uid, "resource_version": target.resource_version,
        })),
    })
    .to_string()
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, FailureClass> {
    let descriptor = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| FailureClass::OperatorConfiguration)?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| FailureClass::OperatorConfiguration)?;
    if !metadata.is_file()
        || usize::try_from(metadata.len()).map_or(true, |length| length > maximum)
    {
        return Err(FailureClass::OperatorConfiguration);
    }
    let capacity = maximum
        .checked_add(1)
        .ok_or(FailureClass::OperatorConfiguration)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(u64::try_from(capacity).map_err(|_| FailureClass::OperatorConfiguration)?)
        .read_to_end(&mut bytes)
        .map_err(|_| FailureClass::OperatorConfiguration)?;
    if bytes.len() > maximum {
        return Err(FailureClass::OperatorConfiguration);
    }
    Ok(bytes)
}

const fn operation_state(value: OperationState) -> &'static str {
    match value {
        OperationState::Requested => "REQUESTED",
        OperationState::Authorized => "AUTHORIZED",
        OperationState::NotAttempted => "NOT_ATTEMPTED",
        OperationState::ApplyStarted => "APPLY_STARTED",
        OperationState::ReceiverObserved => "RECEIVER_OBSERVED",
        OperationState::ReceiptPrepared => "RECEIPT_PREPARED",
        OperationState::ReceiptWritten => "RECEIPT_WRITTEN",
        OperationState::Finalized => "FINALIZED",
    }
}

const fn operation_result(value: OperationResult) -> &'static str {
    match value {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

const fn target_rejection(value: TargetRejection) -> &'static str {
    match value {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
        TargetRejection::StaleApproval => "STALE_APPROVAL",
    }
}
