//! Fixed-purpose Kapsel authority formats and validation.
//!
//! This unpublished package owns the exact authorization-grant and receipt-trust codecs needed by
//! the root Kapsel package and its installer. It is not a generic authorization library, policy
//! interface, runtime package, or supported SDK.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const GRANT_STATEMENT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V1\0";
const SIGNED_GRANT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-GRANT-V1\0";
const SNAPSHOT_STATEMENT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V2\0";
const SNAPSHOT_GRANT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-GRANT-V2\0";
const SNAPSHOT_PURPOSE: &str = "kapsel.kap0038.kubernetes-set-deployment-image-grant.v2";
const GRANT_PURPOSE: &str = "kapsel.kap0038.kubernetes-set-deployment-image-grant.v1";
const RECEIPT_TRUST_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-TRUST-V2\0";
const RECEIPT_PURPOSE: &str = "kapsel.kap0038.kubernetes-effect-receipt.v2";
const SIGNED_GRANT_BYTES_MAX: usize = 4 * 1024;
const GRANT_STATEMENT_BYTES_MAX: usize = 2 * 1024;
const GRANT_TEXT_BYTES_MAX: usize = 512;
const RECEIPT_TRUST_BYTES_MAX: usize = 1024;
const RECEIPT_TEXT_BYTES_MAX: usize = 512;

const _: () = assert!(GRANT_TEXT_BYTES_MAX <= GRANT_STATEMENT_BYTES_MAX);
const _: () = assert!(GRANT_STATEMENT_BYTES_MAX < SIGNED_GRANT_BYTES_MAX);
const _: () = assert!(RECEIPT_TEXT_BYTES_MAX <= RECEIPT_TRUST_BYTES_MAX);

/// Exact owner-controlled statement embedded in a signed authorization grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactAuthorization {
    /// Operator-approved object version. None retains legacy name-bound grant semantics.
    pub approved_target: Option<ApprovedTarget>,
    /// Stable local identity for the authorization record.
    pub authorization_id: String,
    /// Exact authorized operation identity.
    pub operation_id: String,
    /// Exact authorized Kubernetes namespace.
    pub namespace: String,
    /// Exact authorized Deployment name.
    pub deployment: String,
    /// Exact authorized container name.
    pub container: String,
    /// Exact authorized immutable image reference.
    pub immutable_image_digest: String,
}

/// Exact Kubernetes object identity and opaque version approved by the operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedTarget {
    /// Deployment UID, 1–128 ASCII bytes.
    pub uid: String,
    /// Opaque resourceVersion, 1–128 ASCII bytes, compared only by equality.
    pub resource_version: String,
}

impl ApprovedTarget {
    /// Checks both opaque values without interpreting or normalizing them.
    pub fn is_valid(&self) -> bool {
        [&self.uid, &self.resource_version]
            .into_iter()
            .all(|value| !value.is_empty() && value.len() <= 128 && value.is_ascii())
    }
}

impl ExactAuthorization {
    fn validate(&self) -> Result<(), AuthorizationGrantError> {
        if self
            .approved_target
            .as_ref()
            .is_some_and(|target| !target.is_valid())
        {
            return Err(AuthorizationGrantError::Invalid);
        }
        for (field, valid) in [
            (
                AuthorizationInputField::AuthorizationId,
                identity_is_valid(&self.authorization_id),
            ),
            (
                AuthorizationInputField::OperationId,
                identity_is_valid(&self.operation_id),
            ),
            (
                AuthorizationInputField::Namespace,
                dns_label_is_valid(&self.namespace),
            ),
            (
                AuthorizationInputField::Deployment,
                dns_subdomain_is_valid(&self.deployment),
            ),
            (
                AuthorizationInputField::Container,
                dns_label_is_valid(&self.container),
            ),
            (
                AuthorizationInputField::ImmutableImageDigest,
                immutable_image_is_valid(&self.immutable_image_digest),
            ),
        ] {
            if !valid {
                return Err(AuthorizationGrantError::InvalidInput(field));
            }
        }
        Ok(())
    }
}

/// Owner-controlled trust for the fixed-purpose authorization-grant signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationTrust {
    /// Exact configured grant signing-key identity.
    pub key_id: String,
    /// Exact configured Ed25519 verifying key.
    pub public_key: [u8; 32],
}

impl AuthorizationTrust {
    fn validate(&self) -> Result<(), AuthorizationGrantError> {
        if !identity_is_valid(&self.key_id) {
            return Err(AuthorizationGrantError::Invalid);
        }
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| AuthorizationGrantError::Invalid)?;
        Ok(())
    }
}

/// Public identities derived from consistent Kapsel service operator inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedServiceOperatorInputs {
    /// Exact operation tuple authenticated by the authorization key.
    pub authorization: ExactAuthorization,
    /// Signing-key identity authenticated inside the exact authorization grant.
    pub authorization_signing_key_id: String,
    /// Receipt-signing key identity appointed by evaluator trust.
    pub receipt_signing_key_id: String,
}

/// Parsed public fields from a bounded receipt-trust document.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptTrustDocument {
    /// Trusted signing-key identity.
    pub key_id: String,
    /// Trusted Ed25519 verifying-key bytes.
    pub public_key: [u8; 32],
    /// Accepted receipt-signing purpose.
    pub accepted_purpose: String,
    /// Inclusive trust interval start in Unix seconds.
    pub not_before_unix_s: i64,
    /// Exclusive trust interval end in Unix seconds.
    pub not_after_unix_s: i64,
}

/// Caller-selected receipt-trust parsing bounds.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptTrustLimits {
    /// Maximum accepted trust-document bytes.
    pub trust_bytes_max: usize,
    /// Maximum accepted individual text bytes.
    pub text_bytes_max: usize,
}

impl Default for ReceiptTrustLimits {
    fn default() -> Self {
        Self {
            trust_bytes_max: RECEIPT_TRUST_BYTES_MAX,
            text_bytes_max: RECEIPT_TEXT_BYTES_MAX,
        }
    }
}

/// Exact bounded authorization field rejected before grant signing or acceptance.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationInputField {
    /// Authorization identity.
    AuthorizationId,
    /// Operation identity.
    OperationId,
    /// Kubernetes namespace.
    Namespace,
    /// Kubernetes Deployment name.
    Deployment,
    /// Kubernetes container name.
    Container,
    /// Immutable named image reference.
    ImmutableImageDigest,
}

/// Fixed-purpose authorization-grant failure class.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationGrantError {
    /// One exact authorization tuple field violated its shared grammar.
    InvalidInput(AuthorizationInputField),
    /// Grant bytes, trust, or key material were malformed.
    Invalid,
    /// The grant did not authenticate under the configured trust.
    Untrusted,
}

/// Fixed-purpose receipt-trust failure class.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptTrustError {
    /// A caller-selected or document bound was exceeded.
    LimitExceeded,
    /// A bounded value violated its field grammar or semantic invariants.
    InvalidValue,
    /// Fixed record ordering or shape was invalid.
    InvalidRecord,
}

/// Opaque service operator-input validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceOperatorInputsError {
    _private: (),
}

/// Produces canonical owner-signed bytes for one exact authorization grant.
///
/// # Errors
///
/// Returns a bounded error when the authorization tuple or signing-key identity is invalid.
#[doc(hidden)]
pub fn sign_authorization_grant(
    authorization: &ExactAuthorization,
    signing_seed: &[u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, AuthorizationGrantError> {
    authorization.validate()?;
    if !identity_is_valid(key_id) {
        return Err(AuthorizationGrantError::Invalid);
    }
    let statement = encode_statement(authorization)?;
    let signature = SigningKey::from_bytes(signing_seed).sign(&grant_signature_input(&statement));
    let mut output = Vec::with_capacity(statement.len() + 192);
    output.extend_from_slice(if authorization.approved_target.is_some() {
        SNAPSHOT_GRANT_MAGIC
    } else {
        SIGNED_GRANT_MAGIC
    });
    append_grant_record(
        &mut output,
        1,
        grant_purpose(&statement).as_bytes(),
        SIGNED_GRANT_BYTES_MAX,
    )?;
    append_grant_record(&mut output, 2, key_id.as_bytes(), SIGNED_GRANT_BYTES_MAX)?;
    append_grant_record(&mut output, 3, &statement, SIGNED_GRANT_BYTES_MAX)?;
    append_grant_record(
        &mut output,
        4,
        &signature.to_bytes(),
        SIGNED_GRANT_BYTES_MAX,
    )?;
    Ok(output)
}

/// Validates an explicitly configured authorization signer identity and key.
///
/// # Errors
///
/// Returns a bounded error when the identity or Ed25519 key is malformed.
#[doc(hidden)]
pub fn validate_authorization_trust(
    trust: &AuthorizationTrust,
) -> Result<(), AuthorizationGrantError> {
    trust.validate()
}

/// Verifies one grant under an explicitly configured signer identity and key.
///
/// # Errors
///
/// Returns a bounded error when the grant is malformed or does not authenticate.
#[doc(hidden)]
pub fn verify_authorization_grant(
    bytes: &[u8],
    trust: &AuthorizationTrust,
) -> Result<ValidatedAuthorizationGrant, AuthorizationGrantError> {
    trust.validate()?;
    if bytes.len() > SIGNED_GRANT_BYTES_MAX {
        return Err(AuthorizationGrantError::Invalid);
    }
    let snapshot = bytes.starts_with(SNAPSHOT_GRANT_MAGIC);
    let mut records = GrantRecords::new(
        bytes,
        if snapshot {
            SNAPSHOT_GRANT_MAGIC
        } else {
            SIGNED_GRANT_MAGIC
        },
    )?;
    if records.take_record(1)?
        != if snapshot {
            SNAPSHOT_PURPOSE
        } else {
            GRANT_PURPOSE
        }
        .as_bytes()
    {
        return Err(AuthorizationGrantError::Invalid);
    }
    let key_id = records.take_ascii_text(2)?;
    if !identity_is_valid(&key_id) {
        return Err(AuthorizationGrantError::Invalid);
    }
    let statement_bytes = records.take_record(3)?;
    if statement_bytes.len() > GRANT_STATEMENT_BYTES_MAX {
        return Err(AuthorizationGrantError::Invalid);
    }
    let signature_bytes: [u8; 64] = records
        .take_record(4)?
        .try_into()
        .map_err(|_| AuthorizationGrantError::Invalid)?;
    records.finish_exact()?;
    let authorization = parse_statement(statement_bytes)?;
    if authorization.approved_target.is_some() != snapshot {
        return Err(AuthorizationGrantError::Invalid);
    }
    if key_id != trust.key_id {
        return Err(AuthorizationGrantError::Untrusted);
    }
    let key = VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorizationGrantError::Invalid)?;
    key.verify_strict(
        &grant_signature_input(statement_bytes),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| AuthorizationGrantError::Untrusted)?;
    Ok(ValidatedAuthorizationGrant {
        authorization,
        signer_key_id: key_id,
        grant_digest: digest_hex(bytes),
    })
}

fn verify_authorization_grant_for_public_key(
    bytes: &[u8],
    public_key: &[u8; 32],
) -> Result<ValidatedAuthorizationGrant, AuthorizationGrantError> {
    if bytes.len() > SIGNED_GRANT_BYTES_MAX {
        return Err(AuthorizationGrantError::Invalid);
    }
    let snapshot = bytes.starts_with(SNAPSHOT_GRANT_MAGIC);
    let mut records = GrantRecords::new(
        bytes,
        if snapshot {
            SNAPSHOT_GRANT_MAGIC
        } else {
            SIGNED_GRANT_MAGIC
        },
    )?;
    if records.take_record(1)?
        != if snapshot {
            SNAPSHOT_PURPOSE
        } else {
            GRANT_PURPOSE
        }
        .as_bytes()
    {
        return Err(AuthorizationGrantError::Invalid);
    }
    let key_id = records.take_ascii_text(2)?;
    verify_authorization_grant(
        bytes,
        &AuthorizationTrust {
            key_id,
            public_key: *public_key,
        },
    )
}

/// Verified public authorization-grant facts used by the root gateway.
#[doc(hidden)]
pub struct ValidatedAuthorizationGrant {
    authorization: ExactAuthorization,
    signer_key_id: String,
    grant_digest: String,
}

impl ValidatedAuthorizationGrant {
    /// Consumes the verified grant into its public facts.
    #[doc(hidden)]
    pub fn into_parts(self) -> (ExactAuthorization, String, String) {
        (self.authorization, self.signer_key_id, self.grant_digest)
    }
}

/// Encodes a bounded receipt-trust document with canonical bytes.
///
/// # Errors
///
/// Returns the exact bounded trust error class for invalid fields or excessive output.
#[doc(hidden)]
pub fn encode_receipt_trust(trust: &ReceiptTrustDocument) -> Result<Vec<u8>, ReceiptTrustError> {
    validate_receipt_trust(trust)?;
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(RECEIPT_TRUST_MAGIC);
    push_trust_text(&mut output, 1, &trust.key_id, RECEIPT_TRUST_BYTES_MAX)?;
    push_trust(&mut output, 2, &trust.public_key, RECEIPT_TRUST_BYTES_MAX)?;
    push_trust_text(
        &mut output,
        3,
        &trust.accepted_purpose,
        RECEIPT_TRUST_BYTES_MAX,
    )?;
    push_trust(
        &mut output,
        4,
        &trust.not_before_unix_s.to_be_bytes(),
        RECEIPT_TRUST_BYTES_MAX,
    )?;
    push_trust(
        &mut output,
        5,
        &trust.not_after_unix_s.to_be_bytes(),
        RECEIPT_TRUST_BYTES_MAX,
    )?;
    Ok(output)
}

/// Parses a bounded receipt-trust document without ambient input.
///
/// # Errors
///
/// Returns the exact bounded trust error class for limits, shape, or field validation.
#[doc(hidden)]
pub fn parse_receipt_trust(
    input: &[u8],
    limits: ReceiptTrustLimits,
) -> Result<ReceiptTrustDocument, ReceiptTrustError> {
    validate_receipt_trust_limits(limits)?;
    if input.len() > limits.trust_bytes_max {
        return Err(ReceiptTrustError::LimitExceeded);
    }
    let mut records = TrustRecords::new(input, RECEIPT_TRUST_MAGIC, limits.text_bytes_max)?;
    let trust = ReceiptTrustDocument {
        key_id: records.text(1)?,
        public_key: records
            .take(2)?
            .try_into()
            .map_err(|_| ReceiptTrustError::InvalidValue)?,
        accepted_purpose: records.text(3)?,
        not_before_unix_s: i64::from_be_bytes(
            records
                .take(4)?
                .try_into()
                .map_err(|_| ReceiptTrustError::InvalidValue)?,
        ),
        not_after_unix_s: i64::from_be_bytes(
            records
                .take(5)?
                .try_into()
                .map_err(|_| ReceiptTrustError::InvalidValue)?,
        ),
    };
    records.finish()?;
    validate_receipt_trust(&trust)?;
    Ok(trust)
}

fn receipt_signing_key_id(
    seed: &[u8; 32],
    trust: &[u8],
    snapshot: bool,
) -> Result<String, ReceiptTrustError> {
    let trust = parse_receipt_trust(trust, ReceiptTrustLimits::default())?;
    if trust.accepted_purpose
        != if snapshot {
            "kapsel.kap0038.kubernetes-effect-receipt.v3"
        } else {
            RECEIPT_PURPOSE
        }
        || trust.public_key != SigningKey::from_bytes(seed).verifying_key().to_bytes()
    {
        return Err(ReceiptTrustError::InvalidValue);
    }
    Ok(trust.key_id)
}

/// Validates the grant, authorization key, receipt seed, and evaluator trust together.
///
/// The returned value contains only public identity and the function performs no filesystem,
/// network, environment, clock, or durable-state access.
///
/// # Errors
///
/// Returns a bounded class when the four inputs do not appoint one consistent authority.
pub fn validate_service_operator_inputs(
    signed_authorization_grant: &[u8],
    authorization_public_key: &[u8; 32],
    receipt_signing_seed: &[u8; 32],
    receipt_trust: &[u8],
) -> Result<ValidatedServiceOperatorInputs, ServiceOperatorInputsError> {
    let verified = verify_authorization_grant_for_public_key(
        signed_authorization_grant,
        authorization_public_key,
    )
    .map_err(|_| ServiceOperatorInputsError { _private: () })?;
    let receipt_signing_key_id = receipt_signing_key_id(
        receipt_signing_seed,
        receipt_trust,
        verified.authorization.approved_target.is_some(),
    )
    .map_err(|_| ServiceOperatorInputsError { _private: () })?;
    let (authorization, authorization_signing_key_id, _) = verified.into_parts();
    Ok(ValidatedServiceOperatorInputs {
        authorization,
        authorization_signing_key_id,
        receipt_signing_key_id,
    })
}

/// Returns whether a bounded operation or key identity uses the exact shared grammar.
#[doc(hidden)]
pub fn identity_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Returns whether a Kubernetes DNS label uses the exact shared grammar.
#[doc(hidden)]
pub fn dns_label_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .first()
            .is_some_and(|byte| is_ascii_lowercase_or_digit(*byte))
        && bytes
            .last()
            .is_some_and(|byte| is_ascii_lowercase_or_digit(*byte))
        && bytes
            .iter()
            .copied()
            .all(|byte| is_ascii_lowercase_or_digit(byte) || byte == b'-')
}

/// Returns whether a Kubernetes DNS subdomain uses the exact shared grammar.
#[doc(hidden)]
pub fn dns_subdomain_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(dns_label_is_valid)
}

/// Returns whether an immutable image reference uses the exact shared grammar.
#[doc(hidden)]
pub fn immutable_image_is_valid(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return false;
    }
    let Some((name, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    if name.contains('@') {
        return false;
    }
    let digest_is_lowercase_sha256 = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    digest_is_lowercase_sha256 && name.split('/').all(image_name_component_is_valid)
}

fn encode_statement(
    authorization: &ExactAuthorization,
) -> Result<Vec<u8>, AuthorizationGrantError> {
    let mut output = Vec::with_capacity(768);
    output.extend_from_slice(if authorization.approved_target.is_some() {
        SNAPSHOT_STATEMENT_MAGIC
    } else {
        GRANT_STATEMENT_MAGIC
    });
    for (tag, value) in [
        (1, authorization.authorization_id.as_str()),
        (2, authorization.operation_id.as_str()),
        (3, authorization.namespace.as_str()),
        (4, authorization.deployment.as_str()),
        (5, authorization.container.as_str()),
        (6, authorization.immutable_image_digest.as_str()),
    ] {
        append_grant_record(
            &mut output,
            tag,
            value.as_bytes(),
            GRANT_STATEMENT_BYTES_MAX,
        )?;
    }
    if let Some(target) = &authorization.approved_target {
        append_grant_record(
            &mut output,
            7,
            target.uid.as_bytes(),
            GRANT_STATEMENT_BYTES_MAX,
        )?;
        append_grant_record(
            &mut output,
            8,
            target.resource_version.as_bytes(),
            GRANT_STATEMENT_BYTES_MAX,
        )?;
    }
    Ok(output)
}

fn parse_statement(bytes: &[u8]) -> Result<ExactAuthorization, AuthorizationGrantError> {
    let snapshot = bytes.starts_with(SNAPSHOT_STATEMENT_MAGIC);
    let mut records = GrantRecords::new(
        bytes,
        if snapshot {
            SNAPSHOT_STATEMENT_MAGIC
        } else {
            GRANT_STATEMENT_MAGIC
        },
    )?;
    let authorization = ExactAuthorization {
        authorization_id: records.take_ascii_text(1)?,
        operation_id: records.take_ascii_text(2)?,
        namespace: records.take_ascii_text(3)?,
        deployment: records.take_ascii_text(4)?,
        container: records.take_ascii_text(5)?,
        immutable_image_digest: records.take_ascii_text(6)?,
        approved_target: if snapshot {
            Some(ApprovedTarget {
                uid: records.take_ascii_text(7)?,
                resource_version: records.take_ascii_text(8)?,
            })
        } else {
            None
        },
    };
    records.finish_exact()?;
    authorization.validate()?;
    Ok(authorization)
}

fn grant_purpose(statement: &[u8]) -> &'static str {
    if statement.starts_with(SNAPSHOT_STATEMENT_MAGIC) {
        SNAPSHOT_PURPOSE
    } else {
        GRANT_PURPOSE
    }
}

fn grant_signature_input(statement: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(GRANT_PURPOSE.len() + 1 + statement.len());
    input.extend_from_slice(grant_purpose(statement).as_bytes());
    input.push(0);
    input.extend_from_slice(statement);
    input
}

fn append_grant_record(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    maximum_bytes: usize,
) -> Result<(), AuthorizationGrantError> {
    let length = u32::try_from(value.len()).map_err(|_| AuthorizationGrantError::Invalid)?;
    if output
        .len()
        .checked_add(5)
        .and_then(|length| length.checked_add(value.len()))
        .is_none_or(|length| length > maximum_bytes)
    {
        return Err(AuthorizationGrantError::Invalid);
    }
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct GrantRecords<'a> {
    bytes: &'a [u8],
    offset: usize,
    next_tag: u8,
}

impl<'a> GrantRecords<'a> {
    fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, AuthorizationGrantError> {
        if !bytes.starts_with(magic) {
            return Err(AuthorizationGrantError::Invalid);
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
            next_tag: 1,
        })
    }

    fn take_record(&mut self, expected_tag: u8) -> Result<&'a [u8], AuthorizationGrantError> {
        if expected_tag != self.next_tag {
            return Err(AuthorizationGrantError::Invalid);
        }
        let header_end = self
            .offset
            .checked_add(5)
            .ok_or(AuthorizationGrantError::Invalid)?;
        if header_end > self.bytes.len() || self.bytes[self.offset] != expected_tag {
            return Err(AuthorizationGrantError::Invalid);
        }
        let length = u32::from_be_bytes(
            self.bytes[self.offset + 1..header_end]
                .try_into()
                .map_err(|_| AuthorizationGrantError::Invalid)?,
        );
        let length = usize::try_from(length).map_err(|_| AuthorizationGrantError::Invalid)?;
        let value_end = header_end
            .checked_add(length)
            .ok_or(AuthorizationGrantError::Invalid)?;
        if value_end > self.bytes.len() {
            return Err(AuthorizationGrantError::Invalid);
        }
        self.offset = value_end;
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .ok_or(AuthorizationGrantError::Invalid)?;
        Ok(&self.bytes[header_end..value_end])
    }

    fn take_ascii_text(&mut self, expected_tag: u8) -> Result<String, AuthorizationGrantError> {
        let value = self.take_record(expected_tag)?;
        if value.is_empty() || value.len() > GRANT_TEXT_BYTES_MAX || !value.is_ascii() {
            return Err(AuthorizationGrantError::Invalid);
        }
        String::from_utf8(value.to_vec()).map_err(|_| AuthorizationGrantError::Invalid)
    }

    fn finish_exact(self) -> Result<(), AuthorizationGrantError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AuthorizationGrantError::Invalid)
        }
    }
}

fn validate_receipt_trust(trust: &ReceiptTrustDocument) -> Result<(), ReceiptTrustError> {
    if !identity_is_valid(&trust.key_id)
        || !receipt_text_is_valid(&trust.accepted_purpose)
        || trust.not_before_unix_s >= trust.not_after_unix_s
    {
        return Err(ReceiptTrustError::InvalidValue);
    }
    Ok(())
}

fn validate_receipt_trust_limits(limits: ReceiptTrustLimits) -> Result<(), ReceiptTrustError> {
    if limits.trust_bytes_max == 0
        || limits.trust_bytes_max > RECEIPT_TRUST_BYTES_MAX
        || limits.text_bytes_max == 0
        || limits.text_bytes_max > RECEIPT_TEXT_BYTES_MAX
    {
        return Err(ReceiptTrustError::LimitExceeded);
    }
    Ok(())
}

fn receipt_text_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= RECEIPT_TEXT_BYTES_MAX && value.is_ascii()
}

fn push_trust_text(
    output: &mut Vec<u8>,
    tag: u8,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ReceiptTrustError> {
    if !receipt_text_is_valid(value) {
        return Err(ReceiptTrustError::InvalidValue);
    }
    push_trust(output, tag, value.as_bytes(), maximum_bytes)
}

fn push_trust(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    maximum_bytes: usize,
) -> Result<(), ReceiptTrustError> {
    let length = u32::try_from(value.len()).map_err(|_| ReceiptTrustError::LimitExceeded)?;
    if output
        .len()
        .checked_add(5)
        .and_then(|length| length.checked_add(value.len()))
        .is_none_or(|length| length > maximum_bytes)
    {
        return Err(ReceiptTrustError::LimitExceeded);
    }
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct TrustRecords<'a> {
    input: &'a [u8],
    offset: usize,
    next_tag: u8,
    maximum_text_bytes: usize,
}

impl<'a> TrustRecords<'a> {
    fn new(
        input: &'a [u8],
        magic: &[u8],
        maximum_text_bytes: usize,
    ) -> Result<Self, ReceiptTrustError> {
        if !input.starts_with(magic) {
            return Err(ReceiptTrustError::InvalidRecord);
        }
        Ok(Self {
            input,
            offset: magic.len(),
            next_tag: 1,
            maximum_text_bytes,
        })
    }

    fn take(&mut self, expected_tag: u8) -> Result<&'a [u8], ReceiptTrustError> {
        if expected_tag != self.next_tag {
            return Err(ReceiptTrustError::InvalidRecord);
        }
        let header_end = self
            .offset
            .checked_add(5)
            .ok_or(ReceiptTrustError::LimitExceeded)?;
        if header_end > self.input.len() || self.input[self.offset] != expected_tag {
            return Err(ReceiptTrustError::InvalidRecord);
        }
        let length = u32::from_be_bytes(
            self.input[self.offset + 1..header_end]
                .try_into()
                .map_err(|_| ReceiptTrustError::InvalidValue)?,
        );
        let length = usize::try_from(length).map_err(|_| ReceiptTrustError::LimitExceeded)?;
        let value_end = header_end
            .checked_add(length)
            .ok_or(ReceiptTrustError::LimitExceeded)?;
        if value_end > self.input.len() {
            return Err(ReceiptTrustError::InvalidRecord);
        }
        self.offset = value_end;
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .ok_or(ReceiptTrustError::InvalidRecord)?;
        Ok(&self.input[header_end..value_end])
    }

    fn text(&mut self, expected_tag: u8) -> Result<String, ReceiptTrustError> {
        let bytes = self.take(expected_tag)?;
        if bytes.len() > self.maximum_text_bytes {
            return Err(ReceiptTrustError::LimitExceeded);
        }
        if !bytes.is_ascii() {
            return Err(ReceiptTrustError::InvalidValue);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| ReceiptTrustError::InvalidValue)
    }

    fn finish(self) -> Result<(), ReceiptTrustError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ReceiptTrustError::InvalidRecord)
        }
    }
}

fn image_name_component_is_valid(component: &str) -> bool {
    let bytes = component.as_bytes();
    !bytes.is_empty()
        && bytes
            .first()
            .is_some_and(|byte| is_ascii_lowercase_or_digit(*byte))
        && bytes
            .last()
            .is_some_and(|byte| is_ascii_lowercase_or_digit(*byte))
        && bytes
            .iter()
            .copied()
            .all(|byte| is_ascii_lowercase_or_digit(byte) || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_ascii_lowercase_or_digit(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap_or_else(|_| unreachable!());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> ExactAuthorization {
        ExactAuthorization {
            approved_target: None,
            authorization_id: "auth-001".into(),
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

    fn authorization_trust(seed: &[u8; 32], key_id: &str) -> AuthorizationTrust {
        AuthorizationTrust {
            key_id: key_id.into(),
            public_key: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
        }
    }

    fn receipt_trust(seed: &[u8; 32], purpose: &str) -> ReceiptTrustDocument {
        ReceiptTrustDocument {
            key_id: "kap0038-test-key".into(),
            public_key: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
            accepted_purpose: purpose.into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
    }

    fn record_offset(input: &[u8], magic: &[u8], tag: u8) -> (usize, usize, usize) {
        let mut offset = magic.len();
        loop {
            let record_tag = input[offset];
            let length = u32::from_be_bytes(input[offset + 1..offset + 5].try_into().unwrap());
            let length = usize::try_from(length).unwrap();
            if record_tag == tag {
                return (offset, offset + 5, length);
            }
            offset += 5 + length;
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn snapshot_grant_authenticates_every_field_and_preserves_legacy() {
        let seed = [7_u8; 32];
        let trust = AuthorizationTrust {
            key_id: "owner-key".into(),
            public_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        };
        let mut approved = authorization();
        approved.approved_target = Some(ApprovedTarget {
            uid: "deployment-uid".into(),
            resource_version: "opaque:0007".into(),
        });
        let bytes = sign_authorization_grant(&approved, &seed, &trust.key_id).unwrap();
        assert_eq!(
            verify_authorization_grant(&bytes, &trust)
                .unwrap()
                .into_parts()
                .0,
            approved
        );
        let (_, start, len) = record_offset(&bytes, SNAPSHOT_GRANT_MAGIC, 3);
        for tag in 1..=8 {
            let (_, value, _) =
                record_offset(&bytes[start..start + len], SNAPSHOT_STATEMENT_MAGIC, tag);
            let mut tampered = bytes.clone();
            tampered[start + value] ^= 1;
            assert!(verify_authorization_grant(&tampered, &trust).is_err());
        }
        for value in [String::new(), "x".repeat(129), "é".into()] {
            approved.approved_target.as_mut().unwrap().resource_version = value;
            assert!(sign_authorization_grant(&approved, &seed, &trust.key_id).is_err());
        }
        approved.approved_target = Some(ApprovedTarget {
            uid: "u".repeat(128),
            resource_version: "v".repeat(128),
        });
        assert!(sign_authorization_grant(&approved, &seed, &trust.key_id).is_ok());
        let legacy = sign_authorization_grant(&authorization(), &seed, &trust.key_id).unwrap();
        assert!(verify_authorization_grant(&legacy, &trust)
            .unwrap()
            .into_parts()
            .0
            .approved_target
            .is_none());
        let mut mixed = bytes.clone();
        mixed[..SNAPSHOT_GRANT_MAGIC.len()].copy_from_slice(SIGNED_GRANT_MAGIC);
        assert!(verify_authorization_grant(&mixed, &trust).is_err());
        for hostile in [
            &bytes[..bytes.len() - 1],
            &[bytes.as_slice(), b"extra"].concat(),
        ] {
            assert!(verify_authorization_grant(hostile, &trust).is_err());
        }
    }

    #[test]
    fn canonical_grant_and_trust_vectors_are_byte_exact() {
        let authorization_seed = [7_u8; 32];
        let grant =
            sign_authorization_grant(&authorization(), &authorization_seed, "owner-key").unwrap();
        assert_eq!(
            hex(&grant),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vectors/effect-gateway-grant.hex"
            ))
            .trim()
        );

        let receipt_seed = [9_u8; 32];
        let trust = encode_receipt_trust(&receipt_trust(&receipt_seed, RECEIPT_PURPOSE)).unwrap();
        assert_eq!(
            hex(&trust),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vectors/effect-gateway-trust.hex"
            ))
            .trim()
        );
    }

    #[test]
    fn combined_validation_returns_only_exact_public_identity() {
        let authorization_seed = [7_u8; 32];
        let grant =
            sign_authorization_grant(&authorization(), &authorization_seed, "owner-key").unwrap();
        let receipt_seed = [9_u8; 32];
        let trust = encode_receipt_trust(&receipt_trust(&receipt_seed, RECEIPT_PURPOSE)).unwrap();

        let validated = validate_service_operator_inputs(
            &grant,
            &SigningKey::from_bytes(&authorization_seed)
                .verifying_key()
                .to_bytes(),
            &receipt_seed,
            &trust,
        )
        .unwrap();

        assert_eq!(validated.authorization, authorization());
        assert_eq!(validated.authorization_signing_key_id, "owner-key");
        assert_eq!(validated.receipt_signing_key_id, "kap0038-test-key");
    }

    #[test]
    fn hostile_grant_shapes_and_wrong_key_retain_error_classes() {
        let seed = [7_u8; 32];
        let bytes = sign_authorization_grant(&authorization(), &seed, "owner-key").unwrap();
        assert_eq!(
            verify_authorization_grant(&bytes, &authorization_trust(&[8_u8; 32], "owner-key"))
                .err(),
            Some(AuthorizationGrantError::Untrusted)
        );
        let (key_header, key_value, _) = record_offset(&bytes, SIGNED_GRANT_MAGIC, 2);
        let (statement_header, statement_value, statement_length) =
            record_offset(&bytes, SIGNED_GRANT_MAGIC, 3);
        let statement = &bytes[statement_value..statement_value + statement_length];
        let (statement_first_header, _, _) = record_offset(statement, GRANT_STATEMENT_MAGIC, 1);

        let mut duplicate = bytes.clone();
        duplicate[key_header] = 1;
        let mut reordered = bytes.clone();
        reordered[statement_header] = 2;
        let mut unknown = bytes.clone();
        unknown[key_header] = 9;
        let mut malformed_length = bytes.clone();
        malformed_length[key_header + 1..key_header + 5].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut non_ascii = bytes.clone();
        non_ascii[key_value] = 0xff;
        let mut nested_duplicate = bytes.clone();
        nested_duplicate[statement_value + statement_first_header] = 2;
        for hostile in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), b"trailing"].concat(),
            vec![0_u8; SIGNED_GRANT_BYTES_MAX + 1],
            duplicate,
            reordered,
            unknown,
            malformed_length,
            non_ascii,
            nested_duplicate,
        ] {
            assert_eq!(
                verify_authorization_grant(&hostile, &authorization_trust(&seed, "owner-key"))
                    .err(),
                Some(AuthorizationGrantError::Invalid)
            );
        }
    }

    #[test]
    fn hostile_trust_shapes_and_inconsistent_authority_fail_closed() {
        let authorization_seed = [7_u8; 32];
        let grant =
            sign_authorization_grant(&authorization(), &authorization_seed, "owner-key").unwrap();
        let authorization_key = SigningKey::from_bytes(&authorization_seed)
            .verifying_key()
            .to_bytes();
        let receipt_seed = [9_u8; 32];
        let trust = encode_receipt_trust(&receipt_trust(&receipt_seed, RECEIPT_PURPOSE)).unwrap();

        let (key_header, key_value, _) = record_offset(&trust, RECEIPT_TRUST_MAGIC, 1);
        let (last_header, _, _) = record_offset(&trust, RECEIPT_TRUST_MAGIC, 5);
        let mut duplicate = trust.clone();
        duplicate.push(5);
        duplicate.extend_from_slice(&0_u32.to_be_bytes());
        let mut reordered = trust.clone();
        reordered[key_header] = 2;
        let mut unknown = trust.clone();
        unknown[last_header] = 6;
        let mut malformed_length = trust.clone();
        malformed_length[key_header + 1..key_header + 5].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut non_ascii = trust.clone();
        non_ascii[key_value] = 0xff;
        assert_eq!(
            parse_receipt_trust(
                &vec![0_u8; RECEIPT_TRUST_BYTES_MAX + 1],
                ReceiptTrustLimits::default()
            )
            .err(),
            Some(ReceiptTrustError::LimitExceeded)
        );
        assert_eq!(
            parse_receipt_trust(
                &trust,
                ReceiptTrustLimits {
                    trust_bytes_max: RECEIPT_TRUST_BYTES_MAX,
                    text_bytes_max: 1,
                }
            )
            .err(),
            Some(ReceiptTrustError::LimitExceeded)
        );
        assert_eq!(
            parse_receipt_trust(&trust[..trust.len() - 1], ReceiptTrustLimits::default()).err(),
            Some(ReceiptTrustError::InvalidRecord)
        );
        assert_eq!(
            parse_receipt_trust(&non_ascii, ReceiptTrustLimits::default()).err(),
            Some(ReceiptTrustError::InvalidValue)
        );
        for hostile in [
            [trust.as_slice(), b"trailing"].concat(),
            duplicate,
            reordered,
            unknown,
            malformed_length,
        ] {
            assert!(parse_receipt_trust(&hostile, ReceiptTrustLimits::default()).is_err());
        }
        assert!(
            validate_service_operator_inputs(&grant, &authorization_key, &[10_u8; 32], &trust)
                .is_err()
        );
        let wrong_purpose =
            encode_receipt_trust(&receipt_trust(&receipt_seed, "wrong-purpose")).unwrap();
        assert!(validate_service_operator_inputs(
            &grant,
            &authorization_key,
            &receipt_seed,
            &wrong_purpose
        )
        .is_err());
    }
}
