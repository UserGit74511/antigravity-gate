//! Overseas SNI reverse-proxy pool with health checks and failover.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct Endpoint {
    pub name: &'static str,
    pub addr: SocketAddr,
    pub provider: &'static str,
    failures: AtomicU32,
    benched_until: Mutex<Option<Instant>>,
    latency_ms: AtomicU64,
}

impl Endpoint {
    pub fn new(name: &'static str, addr: SocketAddr, provider: &'static str) -> Self {
        Self {
            name,
            addr,
            provider,
            failures: AtomicU32::new(0),
            benched_until: Mutex::new(None),
            latency_ms: AtomicU64::new(0),
        }
    }

    pub async fn is_benched(&self) -> bool {
        let mut guard = self.benched_until.lock().await;
        if let Some(until) = *guard {
            if Instant::now() < until {
                true
            } else {
                *guard = None;
                false
            }
        } else {
            false
        }
    }

    pub fn latency_ms(&self) -> u64 {
        self.latency_ms.load(Ordering::Relaxed)
    }

    pub async fn record_success(&self, latency: Duration) {
        self.failures.store(0, Ordering::Relaxed);
        let ms = (latency.as_millis() as u64).max(1);
        self.latency_ms.store(ms, Ordering::Relaxed);
        let mut guard = self.benched_until.lock().await;
        *guard = None;
    }

    pub async fn record_failure(&self) {
        let fails = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if fails >= 2 {
            // Backoff: 30s * 2^(fails - 2), capped at 600s
            let exponent = (fails - 2).min(5);
            let bench_secs = 30 * (1 << exponent);
            let until = Instant::now() + Duration::from_secs(bench_secs);
            let mut guard = self.benched_until.lock().await;
            *guard = Some(until);
            warn!(
                endpoint = self.name,
                provider = self.provider,
                addr = %self.addr,
                fails,
                bench_secs,
                "SNI reverse-proxy endpoint benched due to repeated failures"
            );
        }
    }
}

#[derive(Clone)]
pub struct SniPool {
    endpoints: Arc<Vec<Arc<Endpoint>>>,
    rr_counter: Arc<AtomicUsize>,
}

impl SniPool {
    pub fn new() -> Self {
        let endpoints = vec![
            Arc::new(Endpoint::new(
                "geohide-1",
                "193.233.112.67:443".parse().unwrap(),
                "geohide",
            )),
            Arc::new(Endpoint::new(
                "geohide-2",
                "193.233.112.68:443".parse().unwrap(),
                "geohide",
            )),
            Arc::new(Endpoint::new(
                "geohide-3",
                "193.233.112.88:443".parse().unwrap(),
                "geohide",
            )),
            Arc::new(Endpoint::new(
                "geohide-4",
                "159.194.200.33:443".parse().unwrap(),
                "geohide",
            )),
            Arc::new(Endpoint::new(
                "geohide-5",
                "37.230.192.51:443".parse().unwrap(),
                "geohide",
            )),
            Arc::new(Endpoint::new(
                "dns-ai-1",
                "191.44.41.215:443".parse().unwrap(),
                "dns-ai",
            )),
        ];

        Self {
            endpoints: Arc::new(endpoints),
            rr_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_endpoints(endpoints: Vec<Arc<Endpoint>>) -> Self {
        Self {
            endpoints: Arc::new(endpoints),
            rr_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn endpoints(&self) -> &[Arc<Endpoint>] {
        &self.endpoints
    }

    pub async fn active_healthy_count(&self) -> usize {
        let mut count = 0;
        for ep in self.endpoints.iter() {
            if !ep.is_benched().await {
                count += 1;
            }
        }
        count
    }

    pub async fn get_candidates(&self) -> Vec<Arc<Endpoint>> {
        let mut healthy = Vec::new();
        let mut benched = Vec::new();

        for ep in self.endpoints.iter() {
            if ep.is_benched().await {
                benched.push(ep.clone());
            } else {
                healthy.push(ep.clone());
            }
        }

        healthy.sort_by(|a, b| {
            let lat_a = a.latency_ms();
            let lat_b = b.latency_ms();
            match (lat_a == 0, lat_b == 0) {
                (false, false) => lat_a.cmp(&lat_b),
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                (true, true) => std::cmp::Ordering::Equal,
            }
        });

        if healthy.len() > 1 {
            let offset = self.rr_counter.fetch_add(1, Ordering::Relaxed);
            let top_lat = healthy[0].latency_ms();
            let tied_count = healthy
                .iter()
                .take_while(|ep| ep.latency_ms() == top_lat)
                .count();
            if tied_count > 1 {
                let rot = offset % tied_count;
                healthy[0..tied_count].rotate_left(rot);
            }
        }

        if healthy.is_empty() {
            warn!("All SNI endpoints are currently benched; trying all as fallback");
            if benched.len() > 1 {
                let offset = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let rot = offset % benched.len();
                benched.rotate_left(rot);
            }
        }
        healthy.extend(benched);
        healthy
    }

    pub async fn connect_with_failover(
        &self,
        connect_budget: Duration,
    ) -> io::Result<(TcpStream, Arc<Endpoint>)> {
        let candidates = self.get_candidates().await;

        for ep in candidates {
            debug!(endpoint = ep.name, addr = %ep.addr, "Attempting connection to SNI proxy");
            let start = Instant::now();

            match tokio::time::timeout(connect_budget, TcpStream::connect(ep.addr)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    let elapsed = start.elapsed();
                    ep.record_success(elapsed).await;
                    debug!(
                        endpoint = ep.name,
                        addr = %ep.addr,
                        latency_ms = elapsed.as_millis(),
                        "Successfully connected to SNI proxy"
                    );
                    return Ok((stream, ep));
                }
                Ok(Err(err)) => {
                    ep.record_failure().await;
                    warn!(
                        endpoint = ep.name,
                        addr = %ep.addr,
                        %err,
                        "Connection to SNI proxy failed; attempting failover"
                    );
                }
                Err(_) => {
                    ep.record_failure().await;
                    warn!(
                        endpoint = ep.name,
                        addr = %ep.addr,
                        timeout_ms = connect_budget.as_millis(),
                        "Connection to SNI proxy timed out; attempting failover"
                    );
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "All candidate SNI reverse-proxy endpoints failed to connect",
        ))
    }

    pub async fn probe_all(&self, timeout: Duration) {
        let mut handles = Vec::new();

        for ep in self.endpoints.iter() {
            let ep = ep.clone();
            handles.push(tokio::spawn(async move {
                let start = Instant::now();
                match tokio::time::timeout(timeout, TcpStream::connect(ep.addr)).await {
                    Ok(Ok(_stream)) => {
                        let elapsed = start.elapsed();
                        ep.record_success(elapsed).await;
                        debug!(
                            endpoint = ep.name,
                            latency_ms = elapsed.as_millis(),
                            "Health probe passed"
                        );
                    }
                    Ok(Err(_)) | Err(_) => {
                        ep.record_failure().await;
                        debug!(endpoint = ep.name, "Health probe failed");
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let healthy = self.active_healthy_count().await;
        let total = self.endpoints.len();
        info!(healthy, total, "Completed SNI proxy pool health probe");
    }
}

impl Default for SniPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_endpoint_benching_and_recovery() {
        let ep = Endpoint::new("test-node", "127.0.0.1:80".parse().unwrap(), "test");
        assert!(!ep.is_benched().await);
        assert_eq!(ep.latency_ms(), 0);

        ep.record_failure().await;
        assert!(!ep.is_benched().await);

        ep.record_failure().await;
        assert!(ep.is_benched().await);

        ep.record_success(Duration::from_millis(42)).await;
        assert!(!ep.is_benched().await);
        assert_eq!(ep.latency_ms(), 42);
    }

    #[tokio::test]
    async fn test_candidate_ordering_by_latency() {
        let ep1 = Arc::new(Endpoint::new(
            "node-1",
            "127.0.0.1:8001".parse().unwrap(),
            "t1",
        ));
        let ep2 = Arc::new(Endpoint::new(
            "node-2",
            "127.0.0.1:8002".parse().unwrap(),
            "t2",
        ));
        let ep3 = Arc::new(Endpoint::new(
            "node-3",
            "127.0.0.1:8003".parse().unwrap(),
            "t3",
        ));

        ep1.record_success(Duration::from_millis(150)).await;
        ep2.record_success(Duration::from_millis(25)).await;

        let pool = SniPool::with_endpoints(vec![ep1.clone(), ep2.clone(), ep3.clone()]);
        let candidates = pool.get_candidates().await;

        assert_eq!(candidates[0].name, "node-2");
        assert_eq!(candidates[1].name, "node-1");
        assert_eq!(candidates[2].name, "node-3");

        ep2.record_failure().await;
        ep2.record_failure().await;

        let candidates_after_bench = pool.get_candidates().await;
        assert_eq!(candidates_after_bench[0].name, "node-1");
        assert_eq!(candidates_after_bench[1].name, "node-3");
        assert_eq!(candidates_after_bench[2].name, "node-2");
    }

    #[tokio::test]
    async fn test_connect_with_failover() {
        let live_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live_listener.local_addr().unwrap();

        let dead_addr = "127.0.0.1:1".parse().unwrap();
        let ep_dead = Arc::new(Endpoint::new("dead-node", dead_addr, "dead"));
        let ep_live = Arc::new(Endpoint::new("live-node", live_addr, "live"));

        let pool = SniPool::with_endpoints(vec![ep_dead.clone(), ep_live.clone()]);

        tokio::spawn(async move {
            let _ = live_listener.accept().await;
        });

        let (stream, connected_ep) = pool
            .connect_with_failover(Duration::from_millis(500))
            .await
            .unwrap();

        assert_eq!(connected_ep.name, "live-node");
        drop(stream);
    }

    #[tokio::test]
    async fn test_sub_millisecond_latency_handling() {
        let ep = Endpoint::new("fast-node", "127.0.0.1:80".parse().unwrap(), "fast");
        ep.record_success(Duration::from_micros(200)).await;
        assert_eq!(ep.latency_ms(), 1);
    }

    #[tokio::test]
    async fn test_round_robin_tie_breaking() {
        let ep1 = Arc::new(Endpoint::new(
            "node-a",
            "127.0.0.1:8001".parse().unwrap(),
            "t1",
        ));
        let ep2 = Arc::new(Endpoint::new(
            "node-b",
            "127.0.0.1:8002".parse().unwrap(),
            "t2",
        ));

        let pool = SniPool::with_endpoints(vec![ep1.clone(), ep2.clone()]);
        let first = pool.get_candidates().await;
        let second = pool.get_candidates().await;

        assert_ne!(first[0].name, second[0].name);
    }

    #[tokio::test]
    async fn test_benched_round_robin_rotation() {
        let ep1 = Arc::new(Endpoint::new(
            "benched-a",
            "127.0.0.1:8001".parse().unwrap(),
            "t1",
        ));
        let ep2 = Arc::new(Endpoint::new(
            "benched-b",
            "127.0.0.1:8002".parse().unwrap(),
            "t2",
        ));

        ep1.record_failure().await;
        ep1.record_failure().await;
        ep2.record_failure().await;
        ep2.record_failure().await;

        let pool = SniPool::with_endpoints(vec![ep1.clone(), ep2.clone()]);
        let first = pool.get_candidates().await;
        let second = pool.get_candidates().await;

        assert_ne!(first[0].name, second[0].name);
    }
}
