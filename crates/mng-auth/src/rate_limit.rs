use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_KEY_BYTES: usize = 256;
const MAX_TRACKED_KEYS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after: Duration,
}

/// In-memory sliding-window limiter for login attempts.
///
/// It is intentionally per-process: a restart clears the counters. That is
/// acceptable for a single-node deployment; a shared store is required before
/// running more than one `mngd` instance.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max_attempts: u32,
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        assert!(max_attempts > 0, "max_attempts must be positive");
        assert!(!window.is_zero(), "window must be positive");
        Self {
            window,
            max_attempts,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(&self, key: &str) -> Decision {
        self.try_acquire_at(key, Instant::now())
    }

    /// Count one attempt and report whether it is allowed. The attempt is
    /// recorded even when allowed, so concurrent requests cannot all pass the
    /// check before any of them records a failure.
    pub fn try_acquire_at(&self, key: &str, now: Instant) -> Decision {
        let key = normalize_key(key);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune_all(&mut entries, now, self.window);

        let attempts = entries.entry(key).or_default();
        if attempts.len() >= self.max_attempts as usize {
            let oldest = attempts.front().copied().unwrap_or(now);
            let elapsed = now.saturating_duration_since(oldest);
            let retry_after = self
                .window
                .saturating_sub(elapsed)
                .max(Duration::from_secs(1));
            return Decision {
                allowed: false,
                remaining: 0,
                retry_after,
            };
        }
        attempts.push_back(now);
        Decision {
            allowed: true,
            remaining: self.max_attempts.saturating_sub(attempts.len() as u32),
            retry_after: Duration::ZERO,
        }
    }

    /// Clear the bucket after a successful login.
    pub fn reset(&self, key: &str) {
        let key = normalize_key(key);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.remove(&key);
    }
}

fn normalize_key(key: &str) -> String {
    let trimmed = key.trim();
    if trimmed.len() <= MAX_KEY_BYTES {
        trimmed.to_owned()
    } else {
        // Keep memory bounded without pulling a hashing dependency into the
        // hot path; a prefix plus length is enough to separate callers.
        let prefix: String = trimmed.chars().take(MAX_KEY_BYTES).collect();
        format!("{prefix}:{}", trimmed.len())
    }
}

fn prune_all(entries: &mut HashMap<String, VecDeque<Instant>>, now: Instant, window: Duration) {
    for attempts in entries.values_mut() {
        while let Some(front) = attempts.front() {
            if now.saturating_duration_since(*front) >= window {
                attempts.pop_front();
            } else {
                break;
            }
        }
    }
    if entries.len() > MAX_TRACKED_KEYS {
        entries.retain(|_, attempts| !attempts.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_attempts_and_recovers_after_window() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let now = Instant::now();
        assert!(limiter.try_acquire_at("ip|alice", now).allowed);
        assert!(
            limiter
                .try_acquire_at("ip|alice", now + Duration::from_secs(1))
                .allowed
        );
        let third = limiter.try_acquire_at("ip|alice", now + Duration::from_secs(2));
        assert!(third.allowed);
        assert_eq!(third.remaining, 0);

        let blocked = limiter.try_acquire_at("ip|alice", now + Duration::from_secs(3));
        assert!(!blocked.allowed);
        assert!(blocked.retry_after >= Duration::from_secs(1));

        let later = now + Duration::from_secs(61);
        assert!(limiter.try_acquire_at("ip|alice", later).allowed);
    }

    #[test]
    fn buckets_are_isolated_and_reset_clears() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let now = Instant::now();
        assert!(limiter.try_acquire_at("a", now).allowed);
        assert!(!limiter.try_acquire_at("a", now).allowed);
        assert!(limiter.try_acquire_at("b", now).allowed);
        limiter.reset("a");
        assert!(limiter.try_acquire_at("a", now).allowed);
    }

    #[test]
    fn oversized_keys_are_bounded() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let key = "x".repeat(10_000);
        assert!(limiter.try_acquire(&key).allowed);
        assert!(!limiter.try_acquire(&key).allowed);
    }
}
