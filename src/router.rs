//! Smart routing engine for developer AI traffic.

use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::pool::{Endpoint, SniPool};
use crate::upstream::{self, normalize_host, UpstreamConfig};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouteDecision {
    SniPool,
    Upstream(UpstreamConfig),
    Direct,
}

impl RouteDecision {
    pub fn label(&self) -> &'static str {
        match self {
            RouteDecision::SniPool => "SNI-Reverse-Proxy",
            RouteDecision::Upstream(_) => "Upstream-SOCKS5",
            RouteDecision::Direct => "Direct-Passthrough",
        }
    }
}

#[derive(Clone)]
pub struct Router {
    sni_pool: SniPool,
    upstream: Option<UpstreamConfig>,
    upstream_domains: Vec<String>,
}

impl Router {
    pub fn new(
        sni_pool: SniPool,
        upstream: Option<UpstreamConfig>,
        custom_upstream_domains: Vec<String>,
    ) -> Self {
        let mut upstream_domains = vec![
            "anthropic.com".to_string(),
            "claude.ai".to_string(),
            "claudeusercontent.com".to_string(),
            "openai.com".to_string(),
            "chatgpt.com".to_string(),
            "cursor.sh".to_string(),
            "cursorapi.com".to_string(),
            "cursor.com".to_string(),
            "cursor-cdn.com".to_string(),
            "oaistatic.com".to_string(),
            "oaiusercontent.com".to_string(),
        ];
        for d in custom_upstream_domains {
            let trimmed = d.trim().to_ascii_lowercase();
            if !trimmed.is_empty() && !upstream_domains.contains(&trimmed) {
                upstream_domains.push(trimmed);
            }
        }

        Self {
            sni_pool,
            upstream,
            upstream_domains,
        }
    }

    pub fn sni_pool(&self) -> &SniPool {
        &self.sni_pool
    }

    pub fn upstream(&self) -> Option<&UpstreamConfig> {
        self.upstream.as_ref()
    }

    pub fn decide(&self, host: &str, _port: u16) -> RouteDecision {
        let h = normalize_host(host);

        if Self::is_google_ai(&h) {
            return RouteDecision::SniPool;
        }

        if let Some(upstream_cfg) = &self.upstream {
            if self.is_upstream_target(&h) {
                return RouteDecision::Upstream(upstream_cfg.clone());
            }
        }

        RouteDecision::Direct
    }

    pub fn is_google_ai(host: &str) -> bool {
        let h = normalize_host(host);

        if h == "daily-cloudcode-pa.googleapis.com"
            || h == "cloudcode-pa.googleapis.com"
            || h == "generativelanguage.googleapis.com"
            || h == "alkalimakersuite-pa.googleapis.com"
            || h == "cloudaicompanion.googleapis.com"
            || h == "proactivebackend-pa.googleapis.com"
            || h == "gemini.google.com"
            || h.ends_with(".gemini.google.com")
            || h == "aistudio.google.com"
            || h.ends_with(".aistudio.google.com")
            || h == "makersuite.google.com"
            || h == "googleai.com"
            || h == "bard.google.com"
            || h == "ai.google.dev"
            || h.ends_with(".googleai.com")
            || h == "ai.google"
            || h.ends_with(".ai.google")
            || h == "gemini.google"
            || h.ends_with(".gemini.google")
            || h == "deepmind.google"
            || h.ends_with(".deepmind.google")
            || h == "notebooklm.google.com"
            || h == "notebooklm.google"
            || h.ends_with(".clients6.google.com")
            || h == "clients6.google.com"
        {
            return true;
        }

        if h.ends_with(".googleapis.com") || h == "googleapis.com" {
            return true;
        }

        false
    }

    pub fn is_upstream_target(&self, host: &str) -> bool {
        let h = normalize_host(host);

        for domain in &self.upstream_domains {
            if h == *domain || h.ends_with(&format!(".{domain}")) {
                return true;
            }
        }
        false
    }

    pub async fn connect_with_sni(
        &self,
        target_host: &str,
        sni_host: Option<&str>,
        port: u16,
    ) -> io::Result<(TcpStream, RouteDecision, Option<Arc<Endpoint>>)> {
        if let Some(sni) = sni_host {
            let sni_decision = self.decide(sni, port);
            if sni_decision != RouteDecision::Direct {
                return self.connect(sni, port).await;
            }
        }
        self.connect(target_host, port).await
    }

    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<(TcpStream, RouteDecision, Option<Arc<Endpoint>>)> {
        let clean_host = normalize_host(host);
        if clean_host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target host cannot be empty",
            ));
        }
        let decision = self.decide(&clean_host, port);
        debug!(host = %clean_host, port, route = decision.label(), "Routing connection");

        match decision {
            RouteDecision::SniPool => {
                let (stream, ep) = self
                    .sni_pool
                    .connect_with_failover(Duration::from_secs(3))
                    .await?;
                info!(
                    host = %clean_host,
                    port,
                    endpoint = ep.name,
                    provider = ep.provider,
                    proxy_addr = %ep.addr,
                    "Routed Google AI traffic via SNI reverse-proxy pool"
                );
                Ok((stream, RouteDecision::SniPool, Some(ep)))
            }
            RouteDecision::Upstream(ref cfg) => {
                let stream = upstream::connect_socks5_with_auth(
                    cfg.addr,
                    cfg.auth.as_ref(),
                    &clean_host,
                    port,
                    Duration::from_secs(10),
                )
                .await?;
                info!(
                    host = %clean_host,
                    port,
                    upstream = %cfg,
                    "Routed traffic via upstream SOCKS5 proxy"
                );
                Ok((stream, RouteDecision::Upstream(cfg.clone()), None))
            }
            RouteDecision::Direct => {
                let target = if clean_host.contains(':') && !clean_host.starts_with('[') {
                    format!("[{clean_host}]:{port}")
                } else {
                    format!("{clean_host}:{port}")
                };
                let stream =
                    tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&target))
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("Direct connection to {target} timed out"),
                            )
                        })??;
                let _ = stream.set_nodelay(true);
                debug!(host = %clean_host, port, "Direct connection established");
                Ok((stream, RouteDecision::Direct, None))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_google_ai_detection() {
        assert!(Router::is_google_ai("daily-cloudcode-pa.googleapis.com"));
        assert!(Router::is_google_ai(
            "daily-cloudcode-pa.googleapis.com:443"
        ));
        assert!(Router::is_google_ai("DAILY-CLOUDCODE-PA.GOOGLEAPIS.COM."));
        assert!(Router::is_google_ai("cloudcode-pa.googleapis.com"));
        assert!(Router::is_google_ai("generativelanguage.googleapis.com"));
        assert!(Router::is_google_ai(
            "generativelanguage.googleapis.com:8443"
        ));
        assert!(Router::is_google_ai(
            "sub.daily-cloudcode-pa.googleapis.com"
        ));
        assert!(Router::is_google_ai("cloudaicompanion.googleapis.com"));
        assert!(Router::is_google_ai("aistudio.google.com"));
        assert!(Router::is_google_ai("gemini.google.com"));
        assert!(Router::is_google_ai("api.googleai.com"));
        assert!(Router::is_google_ai("bard.google.com"));
        assert!(Router::is_google_ai("ai.google.dev"));
        assert!(Router::is_google_ai("ai.google"));
        assert!(Router::is_google_ai("gemini.google"));
        assert!(Router::is_google_ai("notebooklm.google.com"));
        assert!(Router::is_google_ai("alkali-pa.clients6.google.com"));
        assert!(Router::is_google_ai("cloudcode-pa.clients6.google.com"));

        assert!(!Router::is_google_ai("google.com"));
        assert!(!Router::is_google_ai("youtube.com"));
        assert!(!Router::is_google_ai("github.com"));
        assert!(!Router::is_google_ai("evil-googleapis.com"));
    }

    #[test]
    fn test_routing_decisions() {
        let pool = SniPool::new();
        let upstream = UpstreamConfig {
            addr: "127.0.0.1:2080".parse().unwrap(),
            auth: None,
        };
        let router = Router::new(
            pool,
            Some(upstream.clone()),
            vec!["custom-ai.org".to_string()],
        );

        assert_eq!(
            router.decide("daily-cloudcode-pa.googleapis.com", 443),
            RouteDecision::SniPool
        );
        assert_eq!(
            router.decide("daily-cloudcode-pa.googleapis.com:443", 443),
            RouteDecision::SniPool
        );
        assert_eq!(
            router.decide("generativelanguage.googleapis.com", 443),
            RouteDecision::SniPool
        );
        assert_eq!(
            router.decide("alkali-pa.clients6.google.com", 443),
            RouteDecision::SniPool
        );

        assert_eq!(
            router.decide("api.anthropic.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("api.anthropic.com:443", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("assets.claudeusercontent.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("download.cursor-cdn.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("api.openai.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("chatgpt.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("cursor.sh", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("cursor.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("api.cursorapi.com", 443),
            RouteDecision::Upstream(upstream.clone())
        );
        assert_eq!(
            router.decide("api.custom-ai.org", 443),
            RouteDecision::Upstream(upstream)
        );

        assert_eq!(router.decide("github.com", 443), RouteDecision::Direct);
        assert_eq!(router.decide("crates.io", 443), RouteDecision::Direct);
        assert_eq!(router.decide("[::1]:443", 443), RouteDecision::Direct);
    }

    #[tokio::test]
    async fn test_router_connect_direct() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let pool = SniPool::new();
        let router = Router::new(pool, None, vec![]);
        let (mut stream, decision, _) = router
            .connect(&local_addr.ip().to_string(), local_addr.port())
            .await
            .unwrap();

        assert_eq!(decision, RouteDecision::Direct);
        stream.write_all(b"ping").await.unwrap();
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");
    }
}
