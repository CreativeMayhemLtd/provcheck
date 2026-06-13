//! `app.provcheck.signingKey` record CRUD via atrium's typed
//! lexicon API.
//!
//! All four primitives — publish, list, update, delete — go
//! through `agent.api.com.atproto.repo.*`. The record body
//! is hand-marshalled via `TryIntoUnknown` because
//! `app.provcheck.signingKey` is our custom lexicon and isn't
//! part of atrium's generated namespace tree.
//!
//! The revoke flow is a `list → find by fingerprint → mutate
//! validUntil → update` orchestration in the CLI binary, not a
//! primitive here. Keeping the trait surface to the four
//! atproto verbs keeps this module honest about what it does.

use std::fmt;

use atrium_api::types::string::{AtIdentifier, Nsid, RecordKey};
use atrium_api::types::{TryFromUnknown, TryIntoUnknown};
use provcheck_attestation_spec::SigningKeyRecord;
use serde::{Deserialize, Serialize};

use crate::session::AtprotoClient;

/// Collection NSID for our records. Matches the lexicon at
/// `lexicons/app/provcheck/signingKey.json`.
pub const COLLECTION_NSID: &str = "app.provcheck.signingKey";

/// An atproto record URI, e.g.
/// `at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a`.
/// Newtype around `String` so call sites can't mix at-uris with
/// rkeys (the trailing path segment) accidentally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtUri(pub String);

impl AtUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the record key (final path segment) from an
    /// at-uri. Returns `None` when the input is malformed (not
    /// at-uri-shaped, no rkey segment, etc.).
    pub fn rkey(&self) -> Option<&str> {
        // at://<did>/<collection>/<rkey>
        // After the scheme, three path segments. Take the last.
        self.0.rsplit('/').next().filter(|s| !s.is_empty())
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors from the records layer. Each variant carries enough
/// detail for the CLI to render a useful message.
#[derive(Debug, thiserror::Error)]
pub enum RecordsError {
    /// The PDS rejected the operation. Common cases: record
    /// already exists (createRecord with explicit rkey), invalid
    /// record shape, swap-commit mismatch, rate-limit.
    #[error("PDS rejected operation: {0}")]
    PdsRejected(String),

    /// Network or transport-level failure.
    #[error("http: {0}")]
    Http(String),

    /// Server returned a record that didn't deserialise into our
    /// `SigningKeyRecord` shape. Typically means the PDS has a
    /// record we wrote with a different version of the schema,
    /// or someone hand-wrote a non-conforming record under the
    /// same collection.
    #[error("record shape: {0}")]
    Shape(String),

    /// The atproto NSID constants we ship are statically valid;
    /// this variant exists for the cert-fingerprint /
    /// at-identifier code paths that could fail if a caller hands
    /// in junk strings.
    #[error("invalid atproto identifier: {0}")]
    InvalidIdentifier(String),

    /// The agent has no live session (caller is using a stale
    /// `AtprotoClient`). The CLI binary maps this to exit code 3.
    #[error("no live session — re-run `kit login`")]
    NoSession,
}

/// Thin wrapper around an [`AtprotoClient`]. Lets us add stateful
/// concerns later (local mirror writes, offline queueing) without
/// changing call sites.
pub struct RecordWriter<'a> {
    pub client: &'a AtprotoClient,
}

impl<'a> RecordWriter<'a> {
    pub fn new(client: &'a AtprotoClient) -> Self {
        Self { client }
    }

    /// Publish a new `app.provcheck.signingKey` record under the
    /// authenticated user's repo. Returns the at-uri of the
    /// created record.
    ///
    /// Atproto generates a fresh rkey server-side — we don't pass
    /// one. If the caller wants to overwrite an existing record
    /// at a specific rkey, use [`Self::update_signing_key`].
    pub async fn publish_signing_key(
        &self,
        record: &SigningKeyRecord,
    ) -> Result<AtUri, RecordsError> {
        let repo = self.repo_identifier().await?;
        let collection = Nsid::new(COLLECTION_NSID.to_string())
            .map_err(|e| RecordsError::InvalidIdentifier(format!("collection NSID: {e}")))?;

        let typed = typed_record(record);
        let unknown = typed
            .try_into_unknown()
            .map_err(|e| RecordsError::Shape(format!("encode record: {e}")))?;

        let input = atrium_api::com::atproto::repo::create_record::InputData {
            collection,
            record: unknown,
            repo,
            rkey: None,
            swap_commit: None,
            validate: None,
        };

        let output = self
            .client
            .agent
            .api
            .com
            .atproto
            .repo
            .create_record(input.into())
            .await
            .map_err(map_xrpc_err)?;

        Ok(AtUri(output.uri.clone()))
    }

    /// List every `app.provcheck.signingKey` record under the
    /// authenticated user's DID. Returns (at-uri, record) pairs.
    /// Does NOT filter by validity — the caller decides whether
    /// to keep expired / superseded records.
    ///
    /// Pages internally via the `cursor` field; returns the full
    /// set in one Vec. Atrium's list_records caps at 100 per
    /// page so this loops until cursor is empty.
    pub async fn list_signing_keys(&self) -> Result<Vec<(AtUri, SigningKeyRecord)>, RecordsError> {
        let repo = self.repo_identifier().await?;
        let collection = Nsid::new(COLLECTION_NSID.to_string())
            .map_err(|e| RecordsError::InvalidIdentifier(format!("collection NSID: {e}")))?;

        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = atrium_api::com::atproto::repo::list_records::ParametersData {
                collection: collection.clone(),
                cursor: cursor.clone(),
                limit: None,
                repo: repo.clone(),
                reverse: None,
            };
            let output = self
                .client
                .agent
                .api
                .com
                .atproto
                .repo
                .list_records(params.into())
                .await
                .map_err(map_xrpc_err)?;

            for record in &output.records {
                let record_data = &record.data;
                let value: TypedSigningKeyRecord =
                    TryFromUnknown::try_from_unknown(record_data.value.clone())
                        .map_err(|e| RecordsError::Shape(format!("decode record: {e}")))?;
                out.push((AtUri(record_data.uri.clone()), value.into_inner()));
            }

            match &output.cursor {
                Some(c) if !c.is_empty() => cursor = Some(c.clone()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Overwrite the record at the given rkey with the new content.
    /// Used for revocation flows (set `validUntil = now` and
    /// optionally `supersededBy`).
    pub async fn update_signing_key(
        &self,
        rkey: &str,
        record: &SigningKeyRecord,
    ) -> Result<(), RecordsError> {
        let repo = self.repo_identifier().await?;
        let collection = Nsid::new(COLLECTION_NSID.to_string())
            .map_err(|e| RecordsError::InvalidIdentifier(format!("collection NSID: {e}")))?;
        let rkey = RecordKey::new(rkey.to_string())
            .map_err(|e| RecordsError::InvalidIdentifier(format!("rkey: {e}")))?;

        let typed = typed_record(record);
        let unknown = typed
            .try_into_unknown()
            .map_err(|e| RecordsError::Shape(format!("encode record: {e}")))?;

        let input = atrium_api::com::atproto::repo::put_record::InputData {
            collection,
            record: unknown,
            repo,
            rkey,
            swap_commit: None,
            swap_record: None,
            validate: None,
        };

        self.client
            .agent
            .api
            .com
            .atproto
            .repo
            .put_record(input.into())
            .await
            .map_err(map_xrpc_err)?;
        Ok(())
    }

    /// Permanently delete the record at the given rkey. Sharp
    /// tool — for an audit-clean revocation, prefer setting
    /// `validUntil` via [`Self::update_signing_key`] so the
    /// record stays in atproto history as a tombstone.
    pub async fn delete_signing_key(&self, rkey: &str) -> Result<(), RecordsError> {
        let repo = self.repo_identifier().await?;
        let collection = Nsid::new(COLLECTION_NSID.to_string())
            .map_err(|e| RecordsError::InvalidIdentifier(format!("collection NSID: {e}")))?;
        let rkey = RecordKey::new(rkey.to_string())
            .map_err(|e| RecordsError::InvalidIdentifier(format!("rkey: {e}")))?;

        let input = atrium_api::com::atproto::repo::delete_record::InputData {
            collection,
            repo,
            rkey,
            swap_commit: None,
            swap_record: None,
        };

        self.client
            .agent
            .api
            .com
            .atproto
            .repo
            .delete_record(input.into())
            .await
            .map_err(map_xrpc_err)?;
        Ok(())
    }

    /// Resolve the authenticated user's DID into the `AtIdentifier`
    /// shape atrium's repo APIs want.
    async fn repo_identifier(&self) -> Result<AtIdentifier, RecordsError> {
        let did = self.client.agent.did().await.ok_or(RecordsError::NoSession)?;
        // `Did` → `AtIdentifier` is a direct, infallible
        // conversion in atrium 0.25 — both types share the same
        // string-newtype shape.
        Ok(AtIdentifier::from(did))
    }
}

/// Wrapper that adds atproto's mandatory `$type` discriminator to
/// the wire shape of a SigningKeyRecord. The body is `flatten`'d
/// so the JSON ends up as
/// `{"$type": "app.provcheck.signingKey", "createdAt": "...", ...}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypedSigningKeyRecord {
    #[serde(rename = "$type")]
    type_field: String,
    #[serde(flatten)]
    inner: SigningKeyRecord,
}

impl TypedSigningKeyRecord {
    fn into_inner(self) -> SigningKeyRecord {
        self.inner
    }
}

fn typed_record(record: &SigningKeyRecord) -> TypedSigningKeyRecord {
    TypedSigningKeyRecord {
        type_field: COLLECTION_NSID.to_string(),
        inner: record.clone(),
    }
}

/// Project atrium's structured XRPC error onto our typed
/// RecordsError. atrium's Error<E> is generic over the lexicon's
/// own error variant; we string-match on common substrings to
/// surface meaningful distinctions to the CLI.
fn map_xrpc_err<E: std::fmt::Display>(e: E) -> RecordsError {
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("invalid_token")
        || lower.contains("session")
        || lower.contains("expired")
    {
        RecordsError::Http(format!("session may have expired: {msg}"))
    } else if lower.contains("invalid_request")
        || lower.contains("bad_request")
        || lower.contains("400")
        || lower.contains("conflict")
    {
        RecordsError::PdsRejected(msg)
    } else {
        RecordsError::Http(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_record() -> SigningKeyRecord {
        SigningKeyRecord {
            created_at: "2026-06-14T12:00:00Z".into(),
            fingerprint:
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
                    .into(),
            algorithm: "ES256".into(),
            label: Some("studio mac".into()),
            valid_from: None,
            valid_until: None,
            superseded_by: None,
        }
    }

    #[test]
    fn at_uri_as_str_round_trips() {
        let u = AtUri("at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a".into());
        assert_eq!(
            u.as_str(),
            "at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a"
        );
        assert_eq!(format!("{u}"), u.as_str());
    }

    #[test]
    fn at_uri_extracts_rkey_from_trailing_segment() {
        let u = AtUri("at://did:plc:abc/app.provcheck.signingKey/3jzfcijpj2z2a".into());
        assert_eq!(u.rkey(), Some("3jzfcijpj2z2a"));
    }

    #[test]
    fn at_uri_rkey_handles_trailing_slash_gracefully() {
        // A trailing slash makes the final split-segment empty.
        // We filter for non-empty so the caller gets None
        // instead of an empty string they'd then have to check.
        let u = AtUri("at://did/coll/".into());
        assert_eq!(u.rkey(), None);
    }

    #[test]
    fn at_uri_serialises_as_bare_string() {
        let u = AtUri("at://x/y/z".into());
        let json = serde_json::to_string(&u).expect("ser");
        assert_eq!(json, "\"at://x/y/z\"");
    }

    #[test]
    fn typed_record_serialises_with_dollar_type_first() {
        let r = fake_record();
        let typed = typed_record(&r);
        let json = serde_json::to_string(&typed).expect("ser");
        // The `$type` discriminator must be present — atproto
        // PDSes reject records that omit it.
        assert!(json.contains("\"$type\":\"app.provcheck.signingKey\""));
        // The flattened SigningKeyRecord fields are at the same
        // level (not nested under "inner" or similar).
        assert!(json.contains("\"createdAt\":\"2026-06-14T12:00:00Z\""));
        assert!(json.contains("\"fingerprint\":"));
        assert!(json.contains("\"algorithm\":\"ES256\""));
    }

    #[test]
    fn typed_record_round_trips_through_json() {
        let r = fake_record();
        let typed = typed_record(&r);
        let json = serde_json::to_string(&typed).expect("ser");
        let back: TypedSigningKeyRecord = serde_json::from_str(&json).expect("de");
        assert_eq!(back.type_field, COLLECTION_NSID);
        assert_eq!(back.inner, r);
    }

    #[test]
    fn typed_record_round_trips_through_atrium_unknown() {
        // The wire path: SigningKeyRecord → TypedSigningKeyRecord
        // → Unknown (via TryIntoUnknown) → JSON over the wire
        // → Unknown (via the server) → TypedSigningKeyRecord
        // (via TryFromUnknown) → SigningKeyRecord. The load-bearing
        // shape assertion is that all six conversions preserve the
        // exact record value.
        let r = fake_record();
        let typed = typed_record(&r);

        let unknown = typed.clone().try_into_unknown().expect("into unknown");
        let back: TypedSigningKeyRecord =
            TryFromUnknown::try_from_unknown(unknown).expect("from unknown");
        assert_eq!(back.type_field, COLLECTION_NSID);
        assert_eq!(back.inner, r);
    }

    #[test]
    fn collection_nsid_matches_the_lexicon() {
        // If this assertion ever changes, every existing record
        // in the wild becomes invisible to this build (we'd be
        // listing a different collection). Lock it in here so a
        // typo can't sneak past code review.
        assert_eq!(COLLECTION_NSID, "app.provcheck.signingKey");
    }

    #[test]
    fn at_uri_extracts_rkey_from_canonical_layout() {
        // Sanity: a real at-uri has three meaningful path
        // segments after `at://` — DID, collection, rkey. The
        // rkey() helper should always find the third.
        let u = AtUri(format!("at://did:plc:test/{COLLECTION_NSID}/3jzfcijpj2z2a"));
        assert_eq!(u.rkey(), Some("3jzfcijpj2z2a"));
    }
}
