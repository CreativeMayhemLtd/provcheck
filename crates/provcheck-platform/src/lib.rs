//! provcheck-platform — networking + storage layer for provcheck.
//!
//! `provcheck` itself stays strictly offline: it has no HTTP, no DID
//! resolver, no cache. This crate is where the network-aware features
//! live — currently DID-anchored attestation; in the future, key
//! distribution and ownership records (Phase 2).
//!
//! The verifier-stays-offline invariant becomes a *type-level*
//! guarantee because `provcheck` doesn't depend on this crate; only
//! callers that opt in (the CLI, the GUI, sibling tooling) link it.

pub mod attestation;
pub mod network;
pub mod storage;

pub use attestation::{
    AttestationConfig, AttestationOptions, check_attestation, fingerprint_leaf_cert,
    verify_with_attestation,
};
