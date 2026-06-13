//! In-process secret cache with TTL.
//!
//! Wraps the user-prompt-and-decrypt cost of [`KeyProvider::fetch`]
//! so a `kit sign A.wav && kit sign B.wav && kit sign C.wav` flow
//! within a single process prompts the user once instead of three
//! times — mirroring the ssh-agent UX.
//!
//! ## What's cached
//!
//! The cache key is the cert fingerprint (a `&str`, owned as
//! `String` internally). The cache value is the unwrapped private-
//! key PEM, held in a [`SecretString`] that zeroises on drop or
//! eviction.
//!
//! ## What isn't cached
//!
//! - **Across processes.** Each `kit` invocation gets a fresh
//!   cache. This is deliberate — keeping unwrapped secrets in a
//!   persistent daemon would defeat the at-rest encryption story.
//!   ssh-agent users opt into a long-lived agent process; we
//!   don't ship one because the v0.3.0 CLI flows don't justify
//!   the surface area.
//! - **Across user accounts on a shared machine.** The cache is
//!   per-process, so per-user by default.
//!
//! ## Time
//!
//! The cache takes a [`Clock`] at construction so tests can
//! advance time without `std::thread::sleep`. Production code
//! uses [`SystemClock`], which delegates to [`Instant::now`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};

/// Default TTL — fifteen minutes. The CLI binary can override at
/// construction time; an explicit `kit lock` invalidates entries
/// regardless of TTL.
pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);

/// Abstraction over "what time is it." Production uses
/// [`SystemClock`]; tests use [`ManualClock`] to advance time
/// without sleeping.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Instant;
}

/// Production clock — delegates to [`Instant::now`].
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Test clock — wraps an [`Instant`] tests can advance via
/// [`ManualClock::advance`]. Anchored to `Instant::now()` at
/// construction.
#[derive(Debug)]
pub struct ManualClock(Mutex<Instant>);

impl ManualClock {
    pub fn new() -> Self {
        Self(Mutex::new(Instant::now()))
    }
    /// Move the clock forward by `by`. Tests use this to simulate
    /// TTL expiry without `std::thread::sleep`.
    pub fn advance(&self, by: Duration) {
        let mut t = self.0.lock().expect("manual clock mutex poisoned");
        *t += by;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.0.lock().expect("manual clock mutex poisoned")
    }
}

/// One entry in the cache. The secret zeroises on drop; nothing
/// here implements `Serialize` / `Debug-prints-the-secret`.
struct CacheEntry {
    secret: SecretString,
    expires_at: Instant,
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheEntry")
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// In-process cache. Cheap to clone — the inner state is an
/// `Arc`. Thread-safe via [`RwLock`]: many threads can read
/// concurrently; writers (put / invalidate / clear) take an
/// exclusive lock.
#[derive(Clone)]
pub struct SecretCache {
    inner: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SecretCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .inner
            .read()
            .map(|m| m.len())
            .unwrap_or(0);
        f.debug_struct("SecretCache")
            .field("ttl", &self.ttl)
            .field("entries", &count)
            .field("clock", &self.clock)
            .finish()
    }
}

impl SecretCache {
    /// Build a cache with the given TTL and a production clock.
    pub fn new(ttl: Duration) -> Self {
        Self::with_clock(ttl, Arc::new(SystemClock))
    }

    /// Build a cache with an explicit clock. The CLI uses the
    /// default; tests pass a [`ManualClock`].
    pub fn with_clock(ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            clock,
        }
    }

    /// Get a cached secret if present and not expired. Side-effect-
    /// free on hit — does not reset the TTL on access. (Sliding-
    /// window TTLs would let an attacker who got a process snapshot
    /// keep the secret alive indefinitely.)
    pub fn get(&self, fingerprint: &str) -> Option<SecretString> {
        let now = self.clock.now();
        let map = self.inner.read().expect("secret cache rwlock poisoned");
        let entry = map.get(fingerprint)?;
        if entry.expires_at <= now {
            return None;
        }
        // Re-wrap the SecretString. The clone here is cheap (the
        // underlying inner is Arc'd inside secrecy) and gives the
        // caller an owned SecretString they can move out of the
        // cache's lifetime.
        Some(SecretString::from(entry.secret.expose_secret().to_string()))
    }

    /// Put a secret into the cache. Sets the entry's TTL deadline
    /// to `now + self.ttl`. Overwrites any existing entry for the
    /// same fingerprint.
    pub fn put(&self, fingerprint: String, secret: SecretString) {
        let expires_at = self.clock.now() + self.ttl;
        let mut map = self.inner.write().expect("secret cache rwlock poisoned");
        map.insert(fingerprint, CacheEntry { secret, expires_at });
    }

    /// Drop one entry. The `SecretString` zeroises on the way out.
    /// Called by `kit rotate` after the new key supersedes the old.
    pub fn invalidate(&self, fingerprint: &str) {
        let mut map = self.inner.write().expect("secret cache rwlock poisoned");
        map.remove(fingerprint);
    }

    /// Drop every entry. Called by `kit lock` and at process
    /// shutdown.
    pub fn clear(&self) {
        let mut map = self.inner.write().expect("secret cache rwlock poisoned");
        map.clear();
    }

    /// How many live (non-expired) entries are currently held.
    /// Used by `kit status` to surface "passphrase cached for N
    /// identities." Lazy: expired entries aren't proactively
    /// purged, just skipped here.
    pub fn live_count(&self) -> usize {
        let now = self.clock.now();
        let map = self.inner.read().expect("secret cache rwlock poisoned");
        map.values().filter(|e| e.expires_at > now).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "sha256:deadbeef";
    const FP2: &str = "sha256:cafebabe";

    fn manual_cache() -> (SecretCache, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        let cache = SecretCache::with_clock(Duration::from_secs(60), clock.clone());
        (cache, clock)
    }

    #[test]
    fn miss_returns_none() {
        let (cache, _) = manual_cache();
        assert!(cache.get(FP).is_none());
    }

    #[test]
    fn put_then_get_round_trips() {
        let (cache, _) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("the-key".to_string()));
        let got = cache.get(FP).expect("hit");
        assert_eq!(got.expose_secret(), "the-key");
    }

    #[test]
    fn entry_expires_after_ttl() {
        let (cache, clock) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("the-key".to_string()));
        // Just before TTL: still cached.
        clock.advance(Duration::from_secs(59));
        assert!(cache.get(FP).is_some());
        // Exactly at TTL: expired (strict-less-than semantics).
        clock.advance(Duration::from_secs(1));
        assert!(cache.get(FP).is_none());
    }

    #[test]
    fn get_does_not_extend_ttl() {
        // Sliding-window TTLs would let an attacker keep an entry
        // alive indefinitely. Confirm get() is read-only on the
        // expiry deadline.
        let (cache, clock) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("k".to_string()));
        clock.advance(Duration::from_secs(30));
        let _ = cache.get(FP);
        clock.advance(Duration::from_secs(31));
        assert!(cache.get(FP).is_none(), "TTL not extended by get()");
    }

    #[test]
    fn put_overwrites_existing_entry() {
        let (cache, _) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("v1".to_string()));
        cache.put(FP.to_string(), SecretString::from("v2".to_string()));
        let got = cache.get(FP).expect("hit");
        assert_eq!(got.expose_secret(), "v2");
    }

    #[test]
    fn put_resets_ttl_on_overwrite() {
        let (cache, clock) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("v1".to_string()));
        clock.advance(Duration::from_secs(45));
        cache.put(FP.to_string(), SecretString::from("v2".to_string()));
        // 30 sec after the second put: still cached (would have
        // expired if put() were idempotent on TTL).
        clock.advance(Duration::from_secs(30));
        assert!(cache.get(FP).is_some());
    }

    #[test]
    fn invalidate_drops_named_entry() {
        let (cache, _) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("a".to_string()));
        cache.put(FP2.to_string(), SecretString::from("b".to_string()));
        cache.invalidate(FP);
        assert!(cache.get(FP).is_none());
        assert!(cache.get(FP2).is_some(), "other entry untouched");
    }

    #[test]
    fn clear_drops_everything() {
        let (cache, _) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("a".to_string()));
        cache.put(FP2.to_string(), SecretString::from("b".to_string()));
        cache.clear();
        assert!(cache.get(FP).is_none());
        assert!(cache.get(FP2).is_none());
    }

    #[test]
    fn live_count_skips_expired_entries() {
        let (cache, clock) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("a".to_string()));
        assert_eq!(cache.live_count(), 1);
        cache.put(FP2.to_string(), SecretString::from("b".to_string()));
        assert_eq!(cache.live_count(), 2);
        clock.advance(Duration::from_secs(61));
        // Both expired; lazy-skipped by live_count.
        assert_eq!(cache.live_count(), 0);
    }

    #[test]
    fn debug_redacts_secret_content() {
        let (cache, _) = manual_cache();
        cache.put(FP.to_string(), SecretString::from("super-secret".to_string()));
        let debug = format!("{cache:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("entries: 1"));
    }

    #[test]
    fn cache_is_cheap_to_clone() {
        // Clone shares state: a put on the clone is visible
        // through the original. This is the property the CLI
        // binary relies on — pass the cache by clone wherever
        // needed without losing coherence.
        let (cache, _) = manual_cache();
        let cloned = cache.clone();
        cloned.put(FP.to_string(), SecretString::from("from-clone".to_string()));
        assert_eq!(
            cache.get(FP).expect("shared state").expose_secret(),
            "from-clone"
        );
    }

    #[test]
    fn system_clock_advances_with_wall_time() {
        // Sanity: the production clock is monotonic and actually
        // moves forward between two calls.
        let c = SystemClock;
        let t1 = c.now();
        let t2 = c.now();
        assert!(t2 >= t1);
    }
}
