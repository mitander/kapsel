//! Fixed-purpose signed authorization grants for the effect gateway.
//!
//! Canonical bytes and validation live in the unpublished service operator-input package so the
//! root gateway and installer consume one implementation. This private module preserves gateway
//! error classes and internal verified-fact ownership.

use kapsel_authority::{
    self as authority, AuthorizationGrantError, AuthorizationInputField,
    ValidatedAuthorizationGrant,
};
pub use kapsel_authority::{ApprovedTarget, AuthorizationTrust, ExactAuthorization};

use super::GatewayError;

pub(crate) struct VerifiedAuthorization {
    pub(crate) authorization: ExactAuthorization,
    pub(crate) signer_key_id: String,
    pub(crate) grant_digest: String,
}

pub(crate) fn sign_authorization_grant(
    authorization: &ExactAuthorization,
    signing_seed: &[u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, GatewayError> {
    authority::sign_authorization_grant(authorization, signing_seed, key_id)
        .map_err(map_authorization_error)
}

pub(crate) fn validate_authorization_trust(trust: &AuthorizationTrust) -> Result<(), GatewayError> {
    authority::validate_authorization_trust(trust).map_err(map_authorization_error)
}

pub(crate) fn verify_authorization_grant(
    bytes: &[u8],
    trust: &AuthorizationTrust,
) -> Result<VerifiedAuthorization, GatewayError> {
    authority::verify_authorization_grant(bytes, trust)
        .map(into_verified)
        .map_err(map_authorization_error)
}

fn into_verified(verified: ValidatedAuthorizationGrant) -> VerifiedAuthorization {
    let (authorization, signer_key_id, grant_digest) = verified.into_parts();
    VerifiedAuthorization {
        authorization,
        signer_key_id,
        grant_digest,
    }
}

fn map_authorization_error(error: AuthorizationGrantError) -> GatewayError {
    match error {
        AuthorizationGrantError::InvalidInput(field) => {
            GatewayError::InvalidInput(map_input_field(field))
        },
        AuthorizationGrantError::Invalid => GatewayError::InvalidAuthorizationGrant,
        AuthorizationGrantError::Untrusted => GatewayError::UntrustedAuthorizationGrant,
    }
}

fn map_input_field(field: AuthorizationInputField) -> super::InputField {
    match field {
        AuthorizationInputField::AuthorizationId => super::InputField::AuthorizationId,
        AuthorizationInputField::OperationId => super::InputField::OperationId,
        AuthorizationInputField::Namespace => super::InputField::Namespace,
        AuthorizationInputField::Deployment => super::InputField::Deployment,
        AuthorizationInputField::Container => super::InputField::Container,
        AuthorizationInputField::ImmutableImageDigest => super::InputField::ImmutableImageDigest,
    }
}
