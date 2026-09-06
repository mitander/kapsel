//! Kapsel effect gateway for one authorized Kubernetes Deployment image change.
//!
//! The [`Application`] composition root separates request-only [`AgentRequest`] from operator-owned
//! authorization, Kubernetes authority, signing material, and paths. The private deep gateway owns
//! the effect-gateway request, exact authorization, durable lifecycle, Kubernetes interaction,
//! recovery, and prototype receipt. This crate exposes no generic capability or provider contract.
//!
//! The current `v0.1.1` artifact and adopted v0.2 beta expose no supported external Rust API. They
//! make no production-readiness, exactly-once, causation, Kubernetes-truth, complete-capture, or
//! witnessing claim.

mod application;
mod gateway;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod recovery_policy_tests;
#[cfg(test)]
mod simulation_tests;

pub use application::{
    open_application_from_fixed_operator_document, open_application_from_operator_document,
    provision_exact_grant, provision_snapshot_grant, validate_service_operator_inputs,
    AgentRequest, Application, ApplicationError, GrantProvisioning, OperationReport,
    OperatorConfiguration, SetDeploymentImageReceipt, SetDeploymentImageStatus,
    ValidatedServiceOperatorInputs,
};
pub use gateway::{
    inspect_receipt, ApprovedTarget, AuthorizationTrust, ExactAuthorization, InspectionLimits,
    InspectionReport, InspectionStatus, ObservedTarget, OperationResult, OperationState,
    OperationTargets, ReceiptError, ReceiptReference, ReceiptStatement, ReceiptTrust,
    SetDeploymentImageRequest, TargetRejection,
};
#[cfg(test)]
use gateway::{
    test_deployment_patch_document, TestApplyOutcome as ApplyOutcome,
    TestKubernetesDeploymentImageAdapter as KubernetesDeploymentImageAdapter,
    TestReceiverObservation as ReceiverObservation, TestTargetIdentity as TargetIdentity,
};
#[cfg(test)]
use gateway::{DeploymentImageAdapter, Gateway, ReceiptSettings, TargetReadError};
#[cfg(test)]
use gateway::{FaultPoint, GatewayError};
