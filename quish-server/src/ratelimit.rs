//! Per-IP DoS controls for the worker's accept path: a hard cap on concurrent
//! connections per source IP, and an exponential backoff applied before each
//! auth attempt from an IP with recent failures. In-memory, swept lazily.
//!
//! This is complementary to — not a replacement for — the auth registry's
//! constant-time failure floor: the floor hides *which* credential failed; the
//! backoff slows *repeated* guessing from one source.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Drop stale per-IP entries older than this (conns == 0) to bound the map.
const ENTRY_TTL: Duration = Duration::from_secs(600);

/// Tunables (constructed once at worker start).
pub struct RateLimiter {
    inner: Mutex<HashMap<IpAddr, Entry>>,
    max_conns_per_ip: usize,
    base_backoff: Duration,
    max_backoff: Duration,
}

struct Entry {
    conns: usize,
    fails: u32,
    last_seen: Instant,
}

impl Entry {
    fn new() -> Self {
        Self {
            conns: 0,
            fails: 0,
            last_seen: Instant::now(),
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(32, Duration::from_millis(200), Duration::from_secs(30))
    }
}

impl RateLimiter {
    pub fn new(max_conns_per_ip: usize, base_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_conns_per_ip,
            base_backoff,
            max_backoff,
        }
    }

    /// Admit a new connection from `ip`, or `None` if it is over the cap. The
    /// returned guard releases the slot on drop.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, e| e.conns > 0 || now.duration_since(e.last_seen) < ENTRY_TTL);

        let entry = map.entry(ip).or_insert_with(Entry::new);
        if entry.conns >= self.max_conns_per_ip {
            return None;
        }
        entry.conns += 1;
        entry.last_seen = now;
        Some(ConnGuard {
            limiter: self.clone(),
            ip,
        })
    }

    /// Backoff to wait before an auth attempt from `ip` (0 if no recent fails):
    /// `base * 2^(fails-1)`, capped at `max_backoff`.
    pub fn backoff(&self, ip: IpAddr) -> Duration {
        let map = self.inner.lock().unwrap();
        let fails = map.get(&ip).map(|e| e.fails).unwrap_or(0);
        if fails == 0 {
            return Duration::ZERO;
        }
        let shift = (fails - 1).min(16);
        self.base_backoff
            .saturating_mul(1u32 << shift)
            .min(self.max_backoff)
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(ip).or_insert_with(Entry::new);
        entry.fails = entry.fails.saturating_add(1);
        entry.last_seen = Instant::now();
    }

    pub fn record_success(&self, ip: IpAddr) {
        let mut map = self.inner.lock().unwrap();
        if let Some(entry) = map.get_mut(&ip) {
            entry.fails = 0;
            entry.last_seen = Instant::now();
        }
    }
}

/// Releases an IP's connection slot when dropped.
pub struct ConnGuard {
    limiter: Arc<RateLimiter>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut map = self.limiter.inner.lock().unwrap();
        if let Some(entry) = map.get_mut(&self.ip) {
            entry.conns = entry.conns.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[test]
    fn caps_concurrent_connections() {
        let rl = Arc::new(RateLimiter::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(1),
        ));
        let g1 = rl.admit(ip());
        let g2 = rl.admit(ip());
        assert!(g1.is_some() && g2.is_some());
        assert!(rl.admit(ip()).is_none(), "third over cap");
        drop(g1);
        assert!(rl.admit(ip()).is_some(), "slot freed on drop");
        drop(g2);
    }

    #[test]
    fn backoff_grows_then_resets() {
        let rl = Arc::new(RateLimiter::new(
            4,
            Duration::from_millis(100),
            Duration::from_secs(5),
        ));
        assert_eq!(rl.backoff(ip()), Duration::ZERO);
        rl.record_failure(ip());
        assert_eq!(rl.backoff(ip()), Duration::from_millis(100));
        rl.record_failure(ip());
        assert_eq!(rl.backoff(ip()), Duration::from_millis(200));
        rl.record_failure(ip());
        assert_eq!(rl.backoff(ip()), Duration::from_millis(400));
        rl.record_success(ip());
        assert_eq!(rl.backoff(ip()), Duration::ZERO);
    }

    #[test]
    fn backoff_capped() {
        let rl = Arc::new(RateLimiter::new(
            4,
            Duration::from_secs(1),
            Duration::from_secs(4),
        ));
        for _ in 0..10 {
            rl.record_failure(ip());
        }
        assert_eq!(rl.backoff(ip()), Duration::from_secs(4));
    }
}
