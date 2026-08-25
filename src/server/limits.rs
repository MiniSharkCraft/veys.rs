use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 4096;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
    connections: usize,
    last_seen: Instant,
}

#[derive(Debug, Default)]
pub struct AdmissionLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

static GLOBAL_LIMITER: OnceLock<AdmissionLimiter> = OnceLock::new();

pub fn global() -> &'static AdmissionLimiter {
    GLOBAL_LIMITER.get_or_init(AdmissionLimiter::default)
}

impl AdmissionLimiter {
    pub fn allow_request(&self, ip: IpAddr, rate: u32, burst: u32) -> bool {
        if rate == 0 || burst == 0 {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        evict_old(&mut buckets, now);
        if buckets.len() >= MAX_ENTRIES && !buckets.contains_key(&ip) {
            return false;
        }
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: burst as f64,
            updated: now,
            connections: 0,
            last_seen: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate as f64).min(burst as f64);
        bucket.updated = now;
        bucket.last_seen = now;
        if bucket.tokens < 1.0 {
            false
        } else {
            bucket.tokens -= 1.0;
            true
        }
    }

    pub fn try_connection(&self, ip: IpAddr, max: usize) -> bool {
        if max == 0 {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        evict_old(&mut buckets, now);
        if buckets.len() >= MAX_ENTRIES && !buckets.contains_key(&ip) {
            return false;
        }
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: 0.0,
            updated: now,
            connections: 0,
            last_seen: now,
        });
        if bucket.connections >= max {
            return false;
        }
        bucket.connections += 1;
        bucket.last_seen = now;
        true
    }

    pub fn release_connection(&self, ip: IpAddr) {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(bucket) = buckets.get_mut(&ip) {
            bucket.connections = bucket.connections.saturating_sub(1);
            bucket.last_seen = Instant::now();
        }
    }
}

fn evict_old(buckets: &mut HashMap<IpAddr, Bucket>, now: Instant) {
    buckets.retain(|_, bucket| {
        bucket.connections > 0 && now.duration_since(bucket.last_seen) < Duration::from_secs(300)
            || now.duration_since(bucket.last_seen) < Duration::from_secs(60)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn token_bucket_enforces_burst_and_recovers() {
        let limiter = AdmissionLimiter::default();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(limiter.allow_request(ip, 1, 2));
        assert!(limiter.allow_request(ip, 1, 2));
        assert!(!limiter.allow_request(ip, 1, 2));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(limiter.allow_request(ip, 1, 2));
    }

    #[test]
    fn ipv6_connection_limit_is_bounded() {
        let limiter = AdmissionLimiter::default();
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(limiter.try_connection(ip, 1));
        assert!(!limiter.try_connection(ip, 1));
        limiter.release_connection(ip);
        assert!(limiter.try_connection(ip, 1));
    }
}
