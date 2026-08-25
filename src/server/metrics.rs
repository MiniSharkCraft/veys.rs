use std::sync::atomic::{AtomicU64, Ordering};

static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUESTS_ACTIVE: AtomicU64 = AtomicU64::new(0);
static RESPONSE_BYTES: AtomicU64 = AtomicU64::new(0);
static STATUS_4XX: AtomicU64 = AtomicU64::new(0);
static STATUS_5XX: AtomicU64 = AtomicU64::new(0);
static PROXY_REQUESTS: AtomicU64 = AtomicU64::new(0);
static FASTCGI_REQUESTS: AtomicU64 = AtomicU64::new(0);

pub struct RequestGuard;

impl RequestGuard {
    pub fn begin() -> Self {
        REQUESTS_ACTIVE.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        REQUESTS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn record_response(status: u16, bytes: u64) {
    REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    RESPONSE_BYTES.fetch_add(bytes, Ordering::Relaxed);
    if (400..500).contains(&status) {
        STATUS_4XX.fetch_add(1, Ordering::Relaxed);
    } else if (500..600).contains(&status) {
        STATUS_5XX.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_proxy() {
    PROXY_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_fastcgi() {
    FASTCGI_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn render_prometheus() -> String {
    format!(
        "# TYPE veysrs_requests_total counter\nveysrs_requests_total {}\n# TYPE veysrs_requests_active gauge\nveysrs_requests_active {}\n# TYPE veysrs_response_bytes counter\nveysrs_response_bytes {}\n# TYPE veysrs_4xx_total counter\nveysrs_4xx_total {}\n# TYPE veysrs_5xx_total counter\nveysrs_5xx_total {}\n# TYPE veysrs_proxy_requests_total counter\nveysrs_proxy_requests_total {}\n# TYPE veysrs_fastcgi_requests_total counter\nveysrs_fastcgi_requests_total {}\n",
        REQUESTS_TOTAL.load(Ordering::Relaxed),
        REQUESTS_ACTIVE.load(Ordering::Relaxed),
        RESPONSE_BYTES.load(Ordering::Relaxed),
        STATUS_4XX.load(Ordering::Relaxed),
        STATUS_5XX.load(Ordering::Relaxed),
        PROXY_REQUESTS.load(Ordering::Relaxed),
        FASTCGI_REQUESTS.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_bounded_prometheus_metrics() {
        record_response(200, 10);
        record_response(404, 3);
        let output = render_prometheus();
        assert!(output.contains("veysrs_requests_total"));
        assert!(output.contains("veysrs_4xx_total"));
    }
}
