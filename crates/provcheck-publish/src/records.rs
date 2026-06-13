//! `app.provcheck.signingKey` record CRUD.
//!
//! **Scaffold only in this commit.** Same pattern as
//! [`crate::session`] — public API is in place but bodies return
//! `RecordsError::NotImplemented` until Phase 3 sub-pass 3 wires
//! up the atrium-api calls.
//!
//! Implementation notes for sub-pass 3:
//!
//! - `com.atproto.repo.createRecord` for publish, with the record
//!   body serialised as `serde_json::Value` from
//!   [`provcheck_attestation_spec::SigningKeyRecord`]'s serde impl.
//! - `com.atproto.repo.listRecords` for list, paged 100 at a time.
//! - `com.atproto.repo.putRecord` for update (the revoke flow uses
//!   this with `validUntil` set to now).
//! - `com.atproto.repo.deleteRecord` for delete (sharp tool —
//!   prefer revoke-via-validUntil for the audit trail).

use std::fmt;

use provcheck_attestation_spec::SigningKeyRecord;
use serde::{Deserialize, Serialize};

use crate::session::AtprotoClient;

/// An atproto record URI, e.g.
/// `at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a`.
/// Newtype around `String` for type-level clarity at call sites
/// where mixing record-keys with at-uris would be a silent bug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtUri(pub String);

impl AtUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors from the records layer.
#[derive(Debug, thiserror::Error)]
pub enum RecordsError {
    /// Sub-pass 3 placeholder.
    #[error("not implemented: {0} — lands in Phase 3 sub-pass 3")]
    NotImplemented(&'static str),

    /// The PDS rejected the operation (record already exists,
    /// invalid record shape, etc.).
    #[error("PDS rejected operation: {0}")]
    PdsRejected(String),

    /// Network or transport-level failure.
    #[error("http: {0}")]
    Http(String),
}

/// Thin wrapper around an [`AtprotoClient`] that exposes the
/// record-CRUD surface. The wrapper lets us add stateful concerns
/// later (caching, optimistic local mirroring) without changing
/// the call sites.
pub struct RecordWriter<'a> {
    pub client: &'a AtprotoClient,
}

impl<'a> RecordWriter<'a> {
    pub fn new(client: &'a AtprotoClient) -> Self {
        Self { client }
    }

    /// Publish a new `app.provcheck.signingKey` record to the
    /// authenticated user's repo. Returns the at-uri of the
    /// created record.
    pub async fn publish_signing_key(
        &self,
        _record: &SigningKeyRecord,
    ) -> Result<AtUri, RecordsError> {
        Err(RecordsError::NotImplemented("publish_signing_key"))
    }

    /// List all `app.provcheck.signingKey` records under the
    /// authenticated user's DID. Returns (at-uri, record) pairs.
    /// Includes records that have a `validUntil` in the past — the
    /// caller decides whether to filter.
    pub async fn list_signing_keys(&self) -> Result<Vec<(AtUri, SigningKeyRecord)>, RecordsError> {
        Err(RecordsError::NotImplemented("list_signing_keys"))
    }

    /// Update an existing record at `rkey` to the new content.
    /// Used by the revoke flow (set `validUntil` to now and
    /// optionally `supersededBy` to a new record's at-uri).
    pub async fn update_signing_key(
        &self,
        _rkey: &str,
        _record: &SigningKeyRecord,
    ) -> Result<(), RecordsError> {
        Err(RecordsError::NotImplemented("update_signing_key"))
    }

    /// Delete the record at `rkey`. Sharp tool — prefer
    /// [`revoke_signing_key`](Self::revoke_signing_key) for the
    /// audit trail.
    pub async fn delete_signing_key(&self, _rkey: &str) -> Result<(), RecordsError> {
        Err(RecordsError::NotImplemented("delete_signing_key"))
    }

    /// Convenience: stamp `validUntil = now()` on the record and
    /// optionally set `supersededBy`. Used by `kit revoke` and
    /// `kit rotate`. The record stays in atproto history rather
    /// than being deleted — important for the audit story.
    pub async fn revoke_signing_key(
        &self,
        _rkey: &str,
        _superseded_by: Option<AtUri>,
    ) -> Result<(), RecordsError> {
        Err(RecordsError::NotImplemented("revoke_signing_key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_uri_round_trips_through_string() {
        let u = AtUri("at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a".into());
        assert_eq!(
            u.as_str(),
            "at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a"
        );
        assert_eq!(format!("{u}"), u.as_str());
    }

    #[test]
    fn at_uri_is_serializable() {
        // Wire-shape check so the JSON dispatch path (when sub-
        // pass 3 lands) sees the right format.
        let u = AtUri("at://x/y/z".into());
        let json = serde_json::to_string(&u).expect("ser");
        // Newtype struct serialises as the inner value.
        assert_eq!(json, "\"at://x/y/z\"");
    }
}
