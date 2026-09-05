//! Concrete Kubernetes behavior and bounded receiver facts.

pub(in crate::gateway) mod adapter;
pub(in crate::gateway) mod facts;

#[cfg(test)]
pub(crate) use adapter::deployment_patch_document_for_test;
pub(crate) use adapter::KubernetesDeploymentImageAdapter;
pub(in crate::gateway) use facts::ValidatedTargetIdentity;
pub(crate) use facts::{ApplyOutcome, ReceiverObservation, TargetIdentity};
