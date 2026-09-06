//! Prototype-scoped effect-gateway receipt bytes and deterministic offline inspection.
//!
//! This module owns only the prototype-scoped receipt format. It does not define stable
//! cross-version bytes, a package format, generic trust, or a verifier profile.

#![allow(clippy::struct_field_names)]

use std::{error::Error, fmt};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub(in crate::gateway) mod publication;

use super::{
    kubernetes::facts::{ApplyOutcome, ReceiverObservation, KUBERNETES_FACT_BYTES_MAX},
    validate_dns_label, validate_dns_subdomain, validate_identity, validate_immutable_image,
    InputField, OperationResult, SetDeploymentImageRequest, ValidatedRequest, WRITE_STRATEGY,
};

const STATEMENT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-STATEMENT-V2\0";
const RECEIPT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-RECEIPT-V2\0";
const SNAPSHOT_STATEMENT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-STATEMENT-V3\0";
const SNAPSHOT_RECEIPT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-RECEIPT-V3\0";
const SNAPSHOT_PURPOSE: &str = "kapsel.kap0038.kubernetes-effect-receipt.v3";
const PURPOSE: &str = "kapsel.kap0038.kubernetes-effect-receipt.v2";
const NON_CLAIMS: &str = concat!(
    "no-exactly-once;no-causation;no-kubernetes-truth;",
    "no-complete-capture;no-witnessing;not-production"
);

pub(crate) const RECEIPT_BYTES_MAX: usize = 16 * 1024;
const STATEMENT_BYTES_MAX: usize = 8 * 1024;
const TRUST_BYTES_MAX: usize = 1024;
const TEXT_BYTES_MAX: usize = 512;

const _: () = assert!(TEXT_BYTES_MAX <= TRUST_BYTES_MAX);
const _: () = assert!(TEXT_BYTES_MAX <= STATEMENT_BYTES_MAX);
const _: () = assert!(STATEMENT_BYTES_MAX < RECEIPT_BYTES_MAX);

/// Read-only classifier inputs authenticated by a successfully parsed receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptStatement {
    pub(in crate::gateway) approved_target: Option<super::ApprovedTarget>,
    pub(in crate::gateway) operation_id: String,
    pub(in crate::gateway) authorization_id: String,
    pub(in crate::gateway) authorization_signer_key_id: String,
    pub(in crate::gateway) authorization_grant_digest: String,
    pub(in crate::gateway) namespace: String,
    pub(in crate::gateway) deployment: String,
    pub(in crate::gateway) container: String,
    pub(in crate::gateway) immutable_image_digest: String,
    pub(in crate::gateway) write_strategy: String,
    pub(in crate::gateway) target_uid: String,
    pub(in crate::gateway) target_resource_version: String,
    pub(in crate::gateway) receiver_uid: Option<String>,
    pub(in crate::gateway) observed_image: Option<String>,
    pub(in crate::gateway) observed_operation_marker: Option<String>,
    pub(in crate::gateway) current_generation: Option<i64>,
    pub(in crate::gateway) requested_generation: Option<i64>,
    pub(in crate::gateway) observed_generation: Option<i64>,
    pub(in crate::gateway) observed_resource_version: Option<String>,
    pub(in crate::gateway) desired_replicas: Option<i32>,
    pub(in crate::gateway) updated_replicas: Option<i32>,
    pub(in crate::gateway) available_replicas: Option<i32>,
    pub(in crate::gateway) unavailable_replicas: Option<i32>,
    pub(in crate::gateway) rollout_condition_type: Option<String>,
    pub(in crate::gateway) rollout_condition_status: Option<String>,
    pub(in crate::gateway) rollout_condition_reason: Option<String>,
    pub(in crate::gateway) result: OperationResult,
}

impl ReceiptStatement {
    /// Returns the signed approved object version, absent for legacy receipts.
    pub fn approved_target(&self) -> Option<&super::ApprovedTarget> {
        self.approved_target.as_ref()
    }

    /// Returns the stable local operation identity.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the exact authorization identity.
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    /// Returns the configured grant signing-key identity that authenticated the operation.
    pub fn authorization_signer_key_id(&self) -> &str {
        &self.authorization_signer_key_id
    }

    /// Returns the SHA-256 digest of the exact signed authorization grant bytes.
    pub fn authorization_grant_digest(&self) -> &str {
        &self.authorization_grant_digest
    }

    /// Returns the Kubernetes namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the Deployment name.
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    /// Returns the selected container name.
    pub fn container(&self) -> &str {
        &self.container
    }

    /// Returns the requested immutable image digest.
    pub fn immutable_image_digest(&self) -> &str {
        &self.immutable_image_digest
    }

    /// Returns the durable mutation strategy identity used for this operation.
    pub fn write_strategy(&self) -> &str {
        &self.write_strategy
    }

    /// Returns the Deployment UID validated before the mutation marker was committed.
    pub fn target_uid(&self) -> &str {
        &self.target_uid
    }

    /// Returns the resource version validated before the conditional write.
    pub fn target_resource_version(&self) -> &str {
        &self.target_resource_version
    }

    /// Returns the Deployment UID observed at `receiver_observed`, when known.
    pub fn receiver_uid(&self) -> Option<&str> {
        self.receiver_uid.as_deref()
    }

    /// Returns the observed image digest used by classification, when known.
    pub fn observed_image(&self) -> Option<&str> {
        self.observed_image.as_deref()
    }

    /// Returns the observed operation marker used by classification, when known.
    pub fn observed_operation_marker(&self) -> Option<&str> {
        self.observed_operation_marker.as_deref()
    }

    /// Returns the receiver's current generation, when known.
    pub fn current_generation(&self) -> Option<i64> {
        self.current_generation
    }

    /// Returns the requested generation frozen at observation, when known.
    pub fn requested_generation(&self) -> Option<i64> {
        self.requested_generation
    }

    /// Returns the receiver's observed generation, when known.
    pub fn observed_generation(&self) -> Option<i64> {
        self.observed_generation
    }

    /// Returns the receiver resource version, when known.
    pub fn observed_resource_version(&self) -> Option<&str> {
        self.observed_resource_version.as_deref()
    }

    /// Returns the desired replica count used by classification, when known.
    pub fn desired_replicas(&self) -> Option<i32> {
        self.desired_replicas
    }

    /// Returns the updated replica count used by classification, when known.
    pub fn updated_replicas(&self) -> Option<i32> {
        self.updated_replicas
    }

    /// Returns the available replica count used by classification, when known.
    pub fn available_replicas(&self) -> Option<i32> {
        self.available_replicas
    }

    /// Returns the unavailable replica count used by classification, when known.
    pub fn unavailable_replicas(&self) -> Option<i32> {
        self.unavailable_replicas
    }

    /// Returns the exact selected Kubernetes condition type, when known.
    pub fn rollout_condition_type(&self) -> Option<&str> {
        self.rollout_condition_type.as_deref()
    }

    /// Returns the exact selected Kubernetes condition status, when known.
    pub fn rollout_condition_status(&self) -> Option<&str> {
        self.rollout_condition_status.as_deref()
    }

    /// Returns the exact selected Kubernetes condition reason, when known.
    pub fn rollout_condition_reason(&self) -> Option<&str> {
        self.rollout_condition_reason.as_deref()
    }

    /// Returns the signed result after the inspector has recomputed the same classification.
    pub fn result(&self) -> OperationResult {
        self.result
    }

    /// Returns the fixed signed non-claims.
    #[allow(clippy::unused_self)]
    pub fn non_claims(&self) -> &'static str {
        NON_CLAIMS
    }

    #[allow(
        clippy::too_many_lines,
        reason = "fixed ordered receipt fields form one canonical codec"
    )]
    pub(super) fn encode(&self) -> Result<Vec<u8>, ReceiptError> {
        self.validate()?;
        let mut output = Vec::with_capacity(1536);
        output.extend_from_slice(if self.approved_target.is_some() {
            SNAPSHOT_STATEMENT_MAGIC
        } else {
            STATEMENT_MAGIC
        });
        for (tag, value) in [
            (1, self.operation_id.as_str()),
            (2, self.authorization_id.as_str()),
            (3, self.authorization_signer_key_id.as_str()),
            (4, self.authorization_grant_digest.as_str()),
            (5, self.namespace.as_str()),
            (6, self.deployment.as_str()),
            (7, self.container.as_str()),
            (8, self.immutable_image_digest.as_str()),
            (9, self.write_strategy.as_str()),
            (10, self.target_uid.as_str()),
            (11, self.target_resource_version.as_str()),
        ] {
            push_text(&mut output, tag, value, STATEMENT_BYTES_MAX)?;
        }
        push_optional_text(
            &mut output,
            12,
            self.receiver_uid.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push_optional_text(
            &mut output,
            13,
            self.observed_image.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push_optional_text(
            &mut output,
            14,
            self.observed_operation_marker.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push_i64(
            &mut output,
            15,
            self.current_generation,
            STATEMENT_BYTES_MAX,
        )?;
        push_i64(
            &mut output,
            16,
            self.requested_generation,
            STATEMENT_BYTES_MAX,
        )?;
        push_i64(
            &mut output,
            17,
            self.observed_generation,
            STATEMENT_BYTES_MAX,
        )?;
        push_optional_text(
            &mut output,
            18,
            self.observed_resource_version.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push_i32(&mut output, 19, self.desired_replicas, STATEMENT_BYTES_MAX)?;
        push_i32(&mut output, 20, self.updated_replicas, STATEMENT_BYTES_MAX)?;
        push_i32(
            &mut output,
            21,
            self.available_replicas,
            STATEMENT_BYTES_MAX,
        )?;
        push_i32(
            &mut output,
            22,
            self.unavailable_replicas,
            STATEMENT_BYTES_MAX,
        )?;
        push_optional_text(
            &mut output,
            23,
            self.rollout_condition_type.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push_optional_text(
            &mut output,
            24,
            self.rollout_condition_status.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push_optional_text(
            &mut output,
            25,
            self.rollout_condition_reason.as_deref(),
            STATEMENT_BYTES_MAX,
        )?;
        push(
            &mut output,
            26,
            self.result.as_receipt_bytes(),
            STATEMENT_BYTES_MAX,
        )?;
        push(&mut output, 27, NON_CLAIMS.as_bytes(), STATEMENT_BYTES_MAX)?;
        if let Some(approved) = &self.approved_target {
            push_text(&mut output, 28, &approved.uid, STATEMENT_BYTES_MAX)?;
            push_text(
                &mut output,
                29,
                &approved.resource_version,
                STATEMENT_BYTES_MAX,
            )?;
        }
        Ok(output)
    }

    fn parse(input: &[u8], limits: InspectionLimits) -> Result<Self, ReceiptError> {
        limits.validate()?;
        bounded(input, limits.statement_bytes_max)?;
        let snapshot = input.starts_with(SNAPSHOT_STATEMENT_MAGIC);
        let mut records = Records::new(
            input,
            if snapshot {
                SNAPSHOT_STATEMENT_MAGIC
            } else {
                STATEMENT_MAGIC
            },
            limits.text_bytes_max,
        )?;
        let mut statement = Self {
            approved_target: None,
            operation_id: records.text(1)?,
            authorization_id: records.text(2)?,
            authorization_signer_key_id: records.text(3)?,
            authorization_grant_digest: records.text(4)?,
            namespace: records.text(5)?,
            deployment: records.text(6)?,
            container: records.text(7)?,
            immutable_image_digest: records.text(8)?,
            write_strategy: records.text(9)?,
            target_uid: records.text(10)?,
            target_resource_version: records.text(11)?,
            receiver_uid: empty_as_none(records.text(12)?),
            observed_image: empty_as_none(records.text(13)?),
            observed_operation_marker: empty_as_none(records.text(14)?),
            current_generation: decode_generation(records.take(15)?)?,
            requested_generation: decode_generation(records.take(16)?)?,
            observed_generation: decode_generation(records.take(17)?)?,
            observed_resource_version: empty_as_none(records.text(18)?),
            desired_replicas: decode_replica_count(records.take(19)?)?,
            updated_replicas: decode_replica_count(records.take(20)?)?,
            available_replicas: decode_replica_count(records.take(21)?)?,
            unavailable_replicas: decode_replica_count(records.take(22)?)?,
            rollout_condition_type: empty_as_none(records.text(23)?),
            rollout_condition_status: empty_as_none(records.text(24)?),
            rollout_condition_reason: empty_as_none(records.text(25)?),
            result: OperationResult::from_receipt_bytes(records.take(26)?)?,
        };
        if records.take(27)? != NON_CLAIMS.as_bytes() {
            return Err(ReceiptError::InvalidValue);
        }
        if snapshot {
            statement.approved_target = Some(super::ApprovedTarget {
                uid: records.text(28)?,
                resource_version: records.text(29)?,
            });
        }
        records.finish()?;
        statement.validate()?;
        Ok(statement)
    }

    pub(in crate::gateway) fn validate(&self) -> Result<(), ReceiptError> {
        validate_identity(InputField::OperationId, &self.operation_id)
            .map_err(|_| ReceiptError::InvalidValue)?;
        for identity in [
            self.authorization_id.as_str(),
            self.authorization_signer_key_id.as_str(),
        ] {
            validate_identity(InputField::AuthorizationId, identity)
                .map_err(|_| ReceiptError::InvalidValue)?;
        }
        validate_digest(&self.authorization_grant_digest)?;
        if self.approved_target.as_ref().is_some_and(|target| {
            !target.is_valid()
                || target.uid != self.target_uid
                || target.resource_version != self.target_resource_version
        }) {
            return Err(ReceiptError::InvalidValue);
        }
        validate_dns_label(InputField::Namespace, &self.namespace)
            .map_err(|_| ReceiptError::InvalidValue)?;
        validate_dns_subdomain(InputField::Deployment, &self.deployment)
            .map_err(|_| ReceiptError::InvalidValue)?;
        validate_dns_label(InputField::Container, &self.container)
            .map_err(|_| ReceiptError::InvalidValue)?;
        validate_immutable_image(&self.immutable_image_digest)
            .map_err(|_| ReceiptError::InvalidValue)?;
        if self.write_strategy != WRITE_STRATEGY {
            return Err(ReceiptError::InvalidValue);
        }
        for value in [
            Some(self.target_uid.as_str()),
            Some(self.target_resource_version.as_str()),
            self.receiver_uid.as_deref(),
            self.observed_operation_marker.as_deref(),
            self.observed_resource_version.as_deref(),
            self.rollout_condition_type.as_deref(),
            self.rollout_condition_status.as_deref(),
            self.rollout_condition_reason.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_kubernetes_fact(value)?;
        }
        if let Some(image) = &self.observed_image {
            validate_immutable_image(image).map_err(|_| ReceiptError::InvalidValue)?;
        }
        let observation = self.receiver_observation();
        observation
            .validate()
            .map_err(|_| ReceiptError::InvalidValue)?;
        let request =
            ValidatedRequest::try_from(&self.request()).map_err(|_| ReceiptError::InvalidValue)?;
        if observation.classify(&request, &self.apply_outcome()) != self.result {
            return Err(ReceiptError::InvalidValue);
        }
        Ok(())
    }

    fn request(&self) -> SetDeploymentImageRequest {
        SetDeploymentImageRequest {
            operation_id: self.operation_id.clone(),
            namespace: self.namespace.clone(),
            deployment: self.deployment.clone(),
            container: self.container.clone(),
            immutable_image_digest: self.immutable_image_digest.clone(),
        }
    }

    fn apply_outcome(&self) -> ApplyOutcome {
        ApplyOutcome {
            accepted: false,
            requested_generation: self.requested_generation,
            deployment_uid: Some(self.target_uid.clone()),
            resource_version: Some(self.target_resource_version.clone()),
        }
    }

    fn receiver_observation(&self) -> ReceiverObservation {
        ReceiverObservation {
            deployment_uid: self.receiver_uid.clone(),
            resource_version: self.observed_resource_version.clone(),
            current_generation: self.current_generation,
            observed_generation: self.observed_generation,
            image: self.observed_image.clone(),
            operation_marker: self.observed_operation_marker.clone(),
            desired_replicas: self.desired_replicas,
            updated_replicas: self.updated_replicas,
            available_replicas: self.available_replicas,
            unavailable_replicas: self.unavailable_replicas,
            rollout_condition_type: self.rollout_condition_type.clone(),
            rollout_condition_status: self.rollout_condition_status.clone(),
            rollout_condition_reason: self.rollout_condition_reason.clone(),
        }
    }
}

/// Separately supplied trust input for the prototype receipt inspector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptTrust {
    /// Trusted signing key identity.
    pub key_id: String,
    /// Trusted Ed25519 verifying key bytes.
    pub public_key: [u8; 32],
    /// Accepted prototype signing purpose.
    pub accepted_purpose: String,
    /// Inclusive trust interval start in Unix seconds.
    pub not_before_unix_s: i64,
    /// Exclusive trust interval end in Unix seconds.
    pub not_after_unix_s: i64,
}

impl ReceiptTrust {
    /// Encodes separate trust as bounded prototype trust-document bytes.
    ///
    /// # Errors
    ///
    /// Returns a bounded receipt error when the key identity, public key, purpose, time interval,
    /// or encoded trust document violates the prototype contract.
    pub fn encode(&self) -> Result<Vec<u8>, ReceiptError> {
        kapsel_authority::encode_receipt_trust(&kapsel_authority::ReceiptTrustDocument {
            key_id: self.key_id.clone(),
            public_key: self.public_key,
            accepted_purpose: self.accepted_purpose.clone(),
            not_before_unix_s: self.not_before_unix_s,
            not_after_unix_s: self.not_after_unix_s,
        })
        .map_err(map_receipt_trust_error)
    }

    fn parse(input: &[u8], limits: InspectionLimits) -> Result<Self, ReceiptError> {
        limits.validate()?;
        let trust = kapsel_authority::parse_receipt_trust(
            input,
            kapsel_authority::ReceiptTrustLimits {
                trust_bytes_max: limits.trust_bytes_max,
                text_bytes_max: limits.text_bytes_max,
            },
        )
        .map_err(map_receipt_trust_error)?;
        Ok(Self {
            key_id: trust.key_id,
            public_key: trust.public_key,
            accepted_purpose: trust.accepted_purpose,
            not_before_unix_s: trust.not_before_unix_s,
            not_after_unix_s: trust.not_after_unix_s,
        })
    }
}

pub(crate) fn sign_statement(
    statement: &ReceiptStatement,
    seed: &[u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, ReceiptError> {
    validate_key_id(key_id)?;
    let statement_bytes = statement.encode()?;
    Ok(sign_statement_bytes(&statement_bytes, seed, key_id))
}

fn sign_statement_bytes(statement_bytes: &[u8], seed: &[u8; 32], key_id: &str) -> Vec<u8> {
    let signature = SigningKey::from_bytes(seed).sign(&signature_input(statement_bytes));
    let mut output = Vec::with_capacity(statement_bytes.len() + 160);
    output.extend_from_slice(if statement_bytes.starts_with(SNAPSHOT_STATEMENT_MAGIC) {
        SNAPSHOT_RECEIPT_MAGIC
    } else {
        RECEIPT_MAGIC
    });
    push(
        &mut output,
        1,
        statement_purpose(statement_bytes).as_bytes(),
        RECEIPT_BYTES_MAX,
    )
    .unwrap_or_else(|_| unreachable!("validated receipt purpose fits the receipt bound"));
    push_text(&mut output, 2, key_id, RECEIPT_BYTES_MAX)
        .unwrap_or_else(|_| unreachable!("validated receipt key ID fits the receipt bound"));
    push(&mut output, 3, statement_bytes, RECEIPT_BYTES_MAX)
        .unwrap_or_else(|_| unreachable!("validated statement fits the receipt bound"));
    push(&mut output, 4, &signature.to_bytes(), RECEIPT_BYTES_MAX)
        .unwrap_or_else(|_| unreachable!("fixed signature fits the receipt bound"));
    output
}

struct ReceiptEnvelope<'a> {
    accepted_purpose: String,
    key_id: String,
    statement_bytes: &'a [u8],
    statement: ReceiptStatement,
    signature: Signature,
}

fn parse_receipt_envelope(
    receipt: &[u8],
    limits: InspectionLimits,
) -> Result<ReceiptEnvelope<'_>, ReceiptError> {
    limits.validate()?;
    bounded(receipt, limits.receipt_bytes_max)?;
    let snapshot = receipt.starts_with(SNAPSHOT_RECEIPT_MAGIC);
    let mut records = Records::new(
        receipt,
        if snapshot {
            SNAPSHOT_RECEIPT_MAGIC
        } else {
            RECEIPT_MAGIC
        },
        limits.text_bytes_max,
    )?;
    let purpose = records.text(1)?;
    if purpose != if snapshot { SNAPSHOT_PURPOSE } else { PURPOSE } {
        return Err(ReceiptError::InvalidValue);
    }
    let key_id = records.text(2)?;
    validate_key_id(&key_id)?;
    let statement_bytes = records.take(3)?;
    let statement = ReceiptStatement::parse(statement_bytes, limits)?;
    if statement.approved_target.is_some() != snapshot {
        return Err(ReceiptError::InvalidValue);
    }
    let signature = Signature::from_bytes(&array(records.take(4)?)?);
    records.finish()?;
    Ok(ReceiptEnvelope {
        accepted_purpose: purpose,
        key_id,
        statement_bytes,
        statement,
        signature,
    })
}

pub(in crate::gateway) fn decode_frozen_receipt(
    receipt: &[u8],
) -> Result<(String, ReceiptStatement), ReceiptError> {
    let envelope = parse_receipt_envelope(receipt, InspectionLimits::default())?;
    Ok((envelope.key_id, envelope.statement))
}

/// Aggregate outcome of bounded offline inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionStatus {
    /// Receipt, statement, or trust structure was rejected.
    StructureRejected,
    /// Parsed bytes did not authenticate under the supplied key.
    SignatureRejected,
    /// The signature authenticated but supplied trust rejected key, purpose, or time.
    UntrustedSigner,
    /// The receipt authenticated under the explicitly supplied trust.
    Inspected,
}

/// Caller-selected inspection ceilings, each bounded by the receipt-format maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectionLimits {
    /// Maximum accepted receipt bytes.
    pub receipt_bytes_max: usize,
    /// Maximum accepted embedded statement bytes.
    pub statement_bytes_max: usize,
    /// Maximum accepted trust-document bytes.
    pub trust_bytes_max: usize,
    /// Maximum accepted individual text bytes.
    pub text_bytes_max: usize,
}

impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            receipt_bytes_max: RECEIPT_BYTES_MAX,
            statement_bytes_max: STATEMENT_BYTES_MAX,
            trust_bytes_max: TRUST_BYTES_MAX,
            text_bytes_max: TEXT_BYTES_MAX,
        }
    }
}

/// Bounded offline inspection report; status is the single acceptance source of truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectionReport {
    status: InspectionStatus,
    statement: Option<ReceiptStatement>,
}

impl InspectionReport {
    /// Returns the aggregate inspection status.
    pub fn status(&self) -> InspectionStatus {
        self.status
    }

    /// Returns authenticated statement facts for inspected or untrusted-signer reports.
    pub fn statement(&self) -> Option<&ReceiptStatement> {
        self.statement.as_ref()
    }

    /// Returns the fixed non-claims disclosed by inspected or untrusted-signer reports.
    pub fn non_claims(&self) -> Option<&'static str> {
        self.statement.as_ref().map(ReceiptStatement::non_claims)
    }
}

/// Inspects bounded receipt bytes offline under separate trust and explicit evaluation time.
///
/// This function performs no network, filesystem, environment, or ambient-clock access. An
/// `Inspected` result authenticates disclosed bytes only; it does not verify Kubernetes truth,
/// causation, completeness, witnessing, policy authorization, or production safety.
pub fn inspect_receipt(
    receipt: &[u8],
    trust: &[u8],
    evaluation_time_unix_s: i64,
    limits: InspectionLimits,
) -> InspectionReport {
    match inspect_inner(receipt, trust, evaluation_time_unix_s, limits) {
        Ok(statement) => InspectionReport {
            status: InspectionStatus::Inspected,
            statement: Some(statement),
        },
        Err(ReceiptError::BadSignature) => InspectionReport {
            status: InspectionStatus::SignatureRejected,
            statement: None,
        },
        Err(ReceiptError::UntrustedSigner(statement)) => InspectionReport {
            status: InspectionStatus::UntrustedSigner,
            statement: Some(*statement),
        },
        Err(_) => InspectionReport {
            status: InspectionStatus::StructureRejected,
            statement: None,
        },
    }
}

fn inspect_inner(
    receipt: &[u8],
    trust: &[u8],
    evaluation_time_unix_s: i64,
    limits: InspectionLimits,
) -> Result<ReceiptStatement, ReceiptError> {
    let envelope = parse_receipt_envelope(receipt, limits)?;
    let parsed_trust = ReceiptTrust::parse(trust, limits)?;

    let verifying_key = VerifyingKey::from_bytes(&parsed_trust.public_key)
        .map_err(|_| ReceiptError::InvalidValue)?;
    verifying_key
        .verify_strict(
            &signature_input(envelope.statement_bytes),
            &envelope.signature,
        )
        .map_err(|_| ReceiptError::BadSignature)?;

    let trust_matches_envelope = parsed_trust.key_id == envelope.key_id
        && parsed_trust.accepted_purpose == envelope.accepted_purpose;
    if !trust_matches_envelope
        || evaluation_time_unix_s < parsed_trust.not_before_unix_s
        || evaluation_time_unix_s >= parsed_trust.not_after_unix_s
    {
        return Err(ReceiptError::UntrustedSigner(Box::new(envelope.statement)));
    }
    Ok(envelope.statement)
}

impl InspectionLimits {
    fn validate(self) -> Result<(), ReceiptError> {
        if self.receipt_bytes_max == 0
            || self.receipt_bytes_max > RECEIPT_BYTES_MAX
            || self.statement_bytes_max == 0
            || self.statement_bytes_max > STATEMENT_BYTES_MAX
            || self.trust_bytes_max == 0
            || self.trust_bytes_max > TRUST_BYTES_MAX
            || self.text_bytes_max == 0
            || self.text_bytes_max > TEXT_BYTES_MAX
        {
            return Err(ReceiptError::LimitExceeded);
        }
        Ok(())
    }
}

/// Typed failure while constructing trust or processing hostile receipt bytes.
#[derive(Debug)]
pub enum ReceiptError {
    /// A caller-selected or document bound was exceeded.
    LimitExceeded,
    /// A bounded value violated its field grammar or semantic invariants.
    InvalidValue,
    /// Fixed record ordering or shape was invalid.
    InvalidRecord,
    /// Parsed signature bytes did not strictly authenticate.
    BadSignature,
    /// Authenticated bytes were rejected by separately supplied trust.
    UntrustedSigner(Box<ReceiptStatement>),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::LimitExceeded => "limit_exceeded",
            Self::InvalidValue => "invalid_value",
            Self::InvalidRecord => "invalid_record",
            Self::BadSignature => "bad_signature",
            Self::UntrustedSigner(_) => "untrusted_signer",
        };
        write!(formatter, "effect-gateway receipt failure: {class}")
    }
}

impl Error for ReceiptError {}

impl OperationResult {
    fn as_receipt_bytes(self) -> &'static [u8] {
        match self {
            Self::Succeeded => b"SUCCEEDED",
            Self::Failed => b"FAILED",
            Self::Unknown => b"UNKNOWN",
        }
    }

    fn from_receipt_bytes(value: &[u8]) -> Result<Self, ReceiptError> {
        match value {
            b"SUCCEEDED" => Ok(Self::Succeeded),
            b"FAILED" => Ok(Self::Failed),
            b"UNKNOWN" => Ok(Self::Unknown),
            _ => Err(ReceiptError::InvalidValue),
        }
    }
}

fn statement_purpose(statement: &[u8]) -> &'static str {
    if statement.starts_with(SNAPSHOT_STATEMENT_MAGIC) {
        SNAPSHOT_PURPOSE
    } else {
        PURPOSE
    }
}

fn signature_input(statement: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PURPOSE.len() + 1 + statement.len());
    input.extend_from_slice(statement_purpose(statement).as_bytes());
    input.push(0);
    input.extend_from_slice(statement);
    input
}

fn push_text(
    output: &mut Vec<u8>,
    tag: u8,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ReceiptError> {
    validate_text(value, false)?;
    push(output, tag, value.as_bytes(), maximum_bytes)
}

fn push_optional_text(
    output: &mut Vec<u8>,
    tag: u8,
    value: Option<&str>,
    maximum_bytes: usize,
) -> Result<(), ReceiptError> {
    if let Some(value) = value {
        validate_text(value, false)?;
        push(output, tag, value.as_bytes(), maximum_bytes)
    } else {
        push(output, tag, &[], maximum_bytes)
    }
}

fn push_i64(
    output: &mut Vec<u8>,
    tag: u8,
    value: Option<i64>,
    maximum_bytes: usize,
) -> Result<(), ReceiptError> {
    push(
        output,
        tag,
        &value.unwrap_or(-1).to_be_bytes(),
        maximum_bytes,
    )
}

fn push_i32(
    output: &mut Vec<u8>,
    tag: u8,
    value: Option<i32>,
    maximum_bytes: usize,
) -> Result<(), ReceiptError> {
    push(
        output,
        tag,
        &value.unwrap_or(-1).to_be_bytes(),
        maximum_bytes,
    )
}

fn push(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    maximum_bytes: usize,
) -> Result<(), ReceiptError> {
    let length = u32::try_from(value.len()).map_err(|_| ReceiptError::LimitExceeded)?;
    if output
        .len()
        .checked_add(5)
        .and_then(|length| length.checked_add(value.len()))
        .is_none_or(|length| length > maximum_bytes)
    {
        return Err(ReceiptError::LimitExceeded);
    }
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Records<'a> {
    input: &'a [u8],
    offset: usize,
    next_tag: u8,
    maximum_text_bytes: usize,
}

impl<'a> Records<'a> {
    fn new(input: &'a [u8], magic: &[u8], maximum_text_bytes: usize) -> Result<Self, ReceiptError> {
        if !input.starts_with(magic) {
            return Err(ReceiptError::InvalidRecord);
        }
        Ok(Self {
            input,
            offset: magic.len(),
            next_tag: 1,
            maximum_text_bytes,
        })
    }

    fn take(&mut self, expected_tag: u8) -> Result<&'a [u8], ReceiptError> {
        if expected_tag != self.next_tag {
            return Err(ReceiptError::InvalidRecord);
        }
        let header_end = self
            .offset
            .checked_add(5)
            .ok_or(ReceiptError::LimitExceeded)?;
        if header_end > self.input.len() {
            return Err(ReceiptError::InvalidRecord);
        }
        let tag = self.input[self.offset];
        if tag != expected_tag {
            return Err(ReceiptError::InvalidRecord);
        }
        let length = u32::from_be_bytes(array(&self.input[self.offset + 1..header_end])?);
        let length = usize::try_from(length).map_err(|_| ReceiptError::LimitExceeded)?;
        let value_end = header_end
            .checked_add(length)
            .ok_or(ReceiptError::LimitExceeded)?;
        if value_end > self.input.len() {
            return Err(ReceiptError::InvalidRecord);
        }
        self.offset = value_end;
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .ok_or(ReceiptError::InvalidRecord)?;
        Ok(&self.input[header_end..value_end])
    }

    fn text(&mut self, expected_tag: u8) -> Result<String, ReceiptError> {
        let bytes = self.take(expected_tag)?;
        if bytes.len() > self.maximum_text_bytes {
            return Err(ReceiptError::LimitExceeded);
        }
        if !bytes.is_ascii() {
            return Err(ReceiptError::InvalidValue);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| ReceiptError::InvalidValue)
    }

    fn finish(self) -> Result<(), ReceiptError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ReceiptError::InvalidRecord)
        }
    }
}

fn bounded(input: &[u8], maximum_bytes: usize) -> Result<(), ReceiptError> {
    if input.len() > maximum_bytes {
        Err(ReceiptError::LimitExceeded)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_key_id(value: &str) -> Result<(), ReceiptError> {
    if kapsel_authority::identity_is_valid(value) {
        Ok(())
    } else {
        Err(ReceiptError::InvalidValue)
    }
}

fn map_receipt_trust_error(error: kapsel_authority::ReceiptTrustError) -> ReceiptError {
    match error {
        kapsel_authority::ReceiptTrustError::LimitExceeded => ReceiptError::LimitExceeded,
        kapsel_authority::ReceiptTrustError::InvalidValue => ReceiptError::InvalidValue,
        kapsel_authority::ReceiptTrustError::InvalidRecord => ReceiptError::InvalidRecord,
    }
}

fn validate_digest(value: &str) -> Result<(), ReceiptError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReceiptError::InvalidValue);
    }
    Ok(())
}

fn validate_kubernetes_fact(value: &str) -> Result<(), ReceiptError> {
    if value.is_empty() || value.len() > KUBERNETES_FACT_BYTES_MAX || !value.is_ascii() {
        return Err(ReceiptError::InvalidValue);
    }
    Ok(())
}

fn validate_text(value: &str, allow_empty: bool) -> Result<(), ReceiptError> {
    if (!allow_empty && value.is_empty()) || value.len() > TEXT_BYTES_MAX || !value.is_ascii() {
        return Err(ReceiptError::InvalidValue);
    }
    Ok(())
}

fn decode_generation(value: &[u8]) -> Result<Option<i64>, ReceiptError> {
    let decoded = i64::from_be_bytes(array(value)?);
    match decoded {
        -1 => Ok(None),
        0.. => Ok(Some(decoded)),
        _ => Err(ReceiptError::InvalidValue),
    }
}

fn decode_replica_count(value: &[u8]) -> Result<Option<i32>, ReceiptError> {
    let decoded = i32::from_be_bytes(array(value)?);
    match decoded {
        -1 => Ok(None),
        0.. => Ok(Some(decoded)),
        _ => Err(ReceiptError::InvalidValue),
    }
}

fn empty_as_none(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn array<const N: usize>(input: &[u8]) -> Result<[u8; N], ReceiptError> {
    input.try_into().map_err(|_| ReceiptError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn statement() -> ReceiptStatement {
        ReceiptStatement {
            approved_target: None,
            operation_id: "op-001".into(),
            authorization_id: "auth-001".into(),
            authorization_signer_key_id: "kap0038-authorization-test-key".into(),
            authorization_grant_digest: "0".repeat(64),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
            write_strategy: WRITE_STRATEGY.into(),
            target_uid: "deployment-uid-1".into(),
            target_resource_version: "resource-version-0".into(),
            receiver_uid: Some("deployment-uid-1".into()),
            observed_image: Some(
                concat!(
                    "registry.example/example/agent-api@sha256:",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                )
                .into(),
            ),
            observed_operation_marker: Some("op-001".into()),
            current_generation: Some(2),
            requested_generation: Some(2),
            observed_generation: Some(2),
            observed_resource_version: Some("resource-version-2".into()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: Some("Progressing".into()),
            rollout_condition_status: Some("False".into()),
            rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
            result: OperationResult::Failed,
        }
    }

    fn trust(seed: &[u8; 32]) -> ReceiptTrust {
        ReceiptTrust {
            key_id: "kap0038-test-key".into(),
            public_key: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
            accepted_purpose: PURPOSE.into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
    }

    fn signed_fixture() -> (Vec<u8>, Vec<u8>) {
        let seed = [9_u8; 32];
        (
            sign_statement(&statement(), &seed, "kap0038-test-key").unwrap(),
            trust(&seed).encode().unwrap(),
        )
    }

    fn record_offset(input: &[u8], magic: &[u8], tag: u8) -> (usize, usize, usize) {
        let mut offset = magic.len();
        loop {
            let header_end = offset + 5;
            let length = u32::from_be_bytes(input[offset + 1..header_end].try_into().unwrap());
            let value_start = header_end;
            let value_end = value_start + usize::try_from(length).unwrap();
            if input[offset] == tag {
                return (offset, value_start, value_end);
            }
            offset = value_end;
        }
    }

    fn replace_record(input: &mut Vec<u8>, magic: &[u8], tag: u8, value: &[u8]) {
        let (header_start, value_start, value_end) = record_offset(input, magic, tag);
        input[header_start + 1..value_start]
            .copy_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        input.splice(value_start..value_end, value.iter().copied());
    }

    fn append_record(input: &mut Vec<u8>, tag: u8, value: &[u8]) {
        input.push(tag);
        input.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        input.extend_from_slice(value);
    }

    fn malformed_shapes(input: &[u8], magic: &[u8], last_tag: u8) -> Vec<Vec<u8>> {
        let mut duplicate = input.to_vec();
        append_record(&mut duplicate, last_tag, b"");
        let mut reordered = input.to_vec();
        reordered[magic.len()] = 2;
        let mut unknown = input.to_vec();
        let (last, _, _) = record_offset(&unknown, magic, last_tag);
        unknown[last] = last_tag + 1;
        let mut trailing = input.to_vec();
        trailing.push(b'x');
        let truncated = input[..input.len() - 1].to_vec();
        vec![duplicate, reordered, unknown, trailing, truncated]
    }

    #[test]
    fn all_document_shapes_reject_duplicate_reordered_unknown_trailing_and_truncated_records() {
        let limits = InspectionLimits::default();
        let statement = statement().encode().unwrap();
        for malformed in malformed_shapes(&statement, STATEMENT_MAGIC, 27) {
            assert!(ReceiptStatement::parse(&malformed, limits).is_err());
        }

        let (receipt, trust) = signed_fixture();
        for malformed in malformed_shapes(&receipt, RECEIPT_MAGIC, 4) {
            assert_eq!(
                inspect_receipt(&malformed, &trust, 150, limits).status(),
                InspectionStatus::StructureRejected
            );
        }
        for malformed in [
            trust[..trust.len() - 1].to_vec(),
            [trust.as_slice(), b"trailing"].concat(),
        ] {
            assert_eq!(
                inspect_receipt(&receipt, &malformed, 150, limits).status(),
                InspectionStatus::StructureRejected
            );
        }
    }

    #[test]
    fn caller_selected_inspection_limits_reject_lower_and_excessive_ceilings() {
        let (receipt, trust) = signed_fixture();
        let defaults = InspectionLimits::default();
        let cases = [
            InspectionLimits {
                receipt_bytes_max: receipt.len() - 1,
                ..defaults
            },
            InspectionLimits {
                statement_bytes_max: 1,
                ..defaults
            },
            InspectionLimits {
                trust_bytes_max: trust.len() - 1,
                ..defaults
            },
            InspectionLimits {
                text_bytes_max: 1,
                ..defaults
            },
            InspectionLimits {
                receipt_bytes_max: defaults.receipt_bytes_max + 1,
                ..defaults
            },
        ];

        for limits in cases {
            assert_eq!(
                inspect_receipt(&receipt, &trust, 150, limits).status(),
                InspectionStatus::StructureRejected
            );
        }
    }

    #[test]
    fn hostile_signed_statements_enforce_field_grammars_and_result_coherence() {
        let seed = [9_u8; 32];
        let trust = trust(&seed).encode().unwrap();
        let valid = statement().encode().unwrap();
        let invalid_values: &[(u8, &[u8])] = &[
            (1, b"../outside"),
            (2, b"bad key!"),
            (3, b"bad signer!"),
            (4, b"not-a-sha256-digest"),
            (5, b"Uppercase"),
            (6, b"bad..deployment"),
            (7, b"-api"),
            (8, b"registry.example/image:latest"),
            (10, &[b'u'; KUBERNETES_FACT_BYTES_MAX + 1]),
            (15, &(-2_i64).to_be_bytes()),
        ];
        for (tag, value) in invalid_values {
            let mut hostile = valid.clone();
            replace_record(&mut hostile, STATEMENT_MAGIC, *tag, value);
            let receipt = sign_statement_bytes(&hostile, &seed, "kap0038-test-key");
            assert_eq!(
                inspect_receipt(&receipt, &trust, 150, InspectionLimits::default()).status(),
                InspectionStatus::StructureRejected
            );
        }

        for (tag, value) in [
            (12, b"".as_slice()),
            (16, 3_i64.to_be_bytes().as_slice()),
            (17, 1_i64.to_be_bytes().as_slice()),
            (23, b"Available".as_slice()),
            (24, b"True".as_slice()),
            (25, b"Other".as_slice()),
            (26, b"SUCCEEDED".as_slice()),
        ] {
            let mut hostile = valid.clone();
            replace_record(&mut hostile, STATEMENT_MAGIC, tag, value);
            let receipt = sign_statement_bytes(&hostile, &seed, "kap0038-test-key");
            assert_eq!(
                inspect_receipt(&receipt, &trust, 150, InspectionLimits::default()).status(),
                InspectionStatus::StructureRejected
            );
        }
    }

    #[test]
    fn purpose_mismatch_is_untrusted_and_reports_non_claims() {
        let (receipt, _) = signed_fixture();
        let seed = [9_u8; 32];
        let mut wrong_trust = trust(&seed);
        wrong_trust.accepted_purpose = "kapsel.effect-gateway.wrong-purpose.v1".into();
        let report = inspect_receipt(
            &receipt,
            &wrong_trust.encode().unwrap(),
            150,
            InspectionLimits::default(),
        );
        assert_eq!(report.status(), InspectionStatus::UntrustedSigner);
        assert_eq!(report.non_claims(), Some(NON_CLAIMS));
    }

    #[test]
    fn strict_verification_rejects_real_small_order_key_and_signature() {
        let seed = [9_u8; 32];
        let statement = statement().encode().unwrap();
        let mut receipt = sign_statement_bytes(&statement, &seed, "kap0038-test-key");
        replace_record(
            &mut receipt,
            RECEIPT_MAGIC,
            4,
            &[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
        let weak_trust = ReceiptTrust {
            key_id: "kap0038-test-key".into(),
            public_key: [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            accepted_purpose: PURPOSE.into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap();
        assert_eq!(
            inspect_receipt(&receipt, &weak_trust, 150, InspectionLimits::default()).status(),
            InspectionStatus::SignatureRejected
        );
    }

    #[test]
    fn canonical_statement_receipt_and_trust_vectors_are_exact() {
        let seed = [9_u8; 32];
        let statement_bytes = statement().encode().unwrap();
        let receipt_bytes = sign_statement(&statement(), &seed, "kap0038-test-key").unwrap();
        let trust_bytes = trust(&seed).encode().unwrap();

        // Fixed independently reviewable vector snapshots are populated with exact encoded bytes.
        assert_eq!(
            hex(&statement_bytes),
            include_str!("../../../vectors/effect-gateway-statement.hex").trim()
        );
        assert_eq!(
            hex(&receipt_bytes),
            include_str!("../../../vectors/effect-gateway-receipt.hex").trim()
        );
        assert_eq!(
            hex(&trust_bytes),
            include_str!("../../../vectors/effect-gateway-trust.hex").trim()
        );
        assert_eq!(
            hex(&Sha256::digest(&receipt_bytes)),
            include_str!("../../../vectors/effect-gateway-receipt.sha256").trim()
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
