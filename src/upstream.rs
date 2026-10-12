//! Upstream SOCKS5 client connector.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub addr: SocketAddr,
    pub auth: Option<(String, String)>,
}

impl std::fmt::Display for UpstreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr_str = match self.addr.ip() {
            std::net::IpAddr::V4(v4) => format!("{}:{}", v4, self.addr.port()),
            std::net::IpAddr::V6(v6) => format!("[{}]:{}", v6, self.addr.port()),
        };
        if let Some((user, _)) = &self.auth {
            write!(f, "socks5://{user}@{addr_str}")
        } else {
            write!(f, "socks5://{addr_str}")
        }
    }
}

/// Normalizes host string by trimming brackets, attached ports, and FQDN trailing dots.
/// Also normalizes IPv4-mapped IPv6 (::ffff:127.0.0.1) to pure IPv4.
pub fn normalize_host(host: &str) -> String {
    let s = host.trim();
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let host_inside = &s[1..end];
            let host_clean = host_inside.trim_end_matches('.');
            let lowered = host_clean.to_ascii_lowercase();
            if let Ok(ipv6) = lowered.parse::<Ipv6Addr>() {
                if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                    return ipv4.to_string();
                }
            }
            return lowered;
        }
    }

    let host_only = if let Some(pos) = s.rfind(':') {
        let port_part = &s[pos + 1..];
        let host_part = &s[..pos];
        if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
            if !host_part.contains(':') || host_part.parse::<Ipv6Addr>().is_ok() {
                host_part.trim_end_matches('.')
            } else {
                s.trim_end_matches('.')
            }
        } else {
            s.trim_end_matches('.')
        }
    } else {
        s.trim_end_matches('.')
    };

    let lowered = host_only.to_ascii_lowercase();
    if let Ok(ipv6) = lowered.parse::<Ipv6Addr>() {
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            return ipv4.to_string();
        }
    }
    lowered
}

/// Parses an upstream SOCKS5 proxy address and optional credentials from a string.
///
/// Supports formats:
/// - `socks5://127.0.0.1:1080`
/// - `socks5h://127.0.0.1:1080`
/// - `http://127.0.0.1:1080`
/// - `127.0.0.1:1080`
/// - `127.0.0.1` (defaults port to 1080)
/// - `localhost:1080`
/// - `localhost` (defaults port to 1080)
/// - `[::1]:1080`
/// - `::1:1080` (unbracketed IPv6 with port)
/// - `[::1]` or `::1` (defaults port to 1080)
/// - `socks5://user:pass@127.0.0.1:1080/`
/// - `socks5://user:pass@[::1]:1080`
/// - `socks5://user:pass@::1:1080`
pub fn parse_upstream_config(s: &str) -> Result<UpstreamConfig, String> {
    let mut cleaned = s.trim();
    if cleaned.is_empty() {
        return Err("Upstream address cannot be empty".to_string());
    }
    for prefix in &["socks5://", "socks5h://", "http://", "https://"] {
        if let Some(rest) = cleaned.strip_prefix(prefix) {
            cleaned = rest;
            break;
        }
    }
    if let Some(pos) = cleaned.find('/') {
        cleaned = &cleaned[..pos];
    }

    let mut auth = None;
    if let Some(pos) = cleaned.rfind('@') {
        let auth_str = &cleaned[..pos];
        cleaned = &cleaned[pos + 1..];
        if let Some(colon) = auth_str.find(':') {
            auth = Some((
                auth_str[..colon].to_string(),
                auth_str[colon + 1..].to_string(),
            ));
        } else {
            auth = Some((auth_str.to_string(), String::new()));
        }
    }

    let addr = if let Ok(addr) = cleaned.parse::<SocketAddr>() {
        addr
    } else if cleaned.starts_with('[') && cleaned.ends_with(']') {
        if let Ok(ipv6) = cleaned[1..cleaned.len() - 1].parse::<Ipv6Addr>() {
            SocketAddr::new(std::net::IpAddr::V6(ipv6), 1080)
        } else {
            return Err(format!("Invalid upstream address '{s}'"));
        }
    } else if let Ok(ipv4) = cleaned.parse::<Ipv4Addr>() {
        SocketAddr::new(std::net::IpAddr::V4(ipv4), 1080)
    } else if let Some(pos) = cleaned.rfind(':') {
        let host_part = &cleaned[..pos];
        let port_part = &cleaned[pos + 1..];
        if let Ok(port) = port_part.parse::<u16>() {
            if let Ok(ipv6) = host_part.parse::<Ipv6Addr>() {
                SocketAddr::new(std::net::IpAddr::V6(ipv6), port)
            } else if let Ok(ipv4) = host_part.parse::<Ipv4Addr>() {
                SocketAddr::new(std::net::IpAddr::V4(ipv4), port)
            } else if let Ok(mut addrs) = cleaned.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    addr
                } else if let Ok(ipv6) = cleaned.parse::<Ipv6Addr>() {
                    SocketAddr::new(std::net::IpAddr::V6(ipv6), 1080)
                } else {
                    return Err(format!("Could not resolve upstream address '{s}'"));
                }
            } else if let Ok(ipv6) = cleaned.parse::<Ipv6Addr>() {
                SocketAddr::new(std::net::IpAddr::V6(ipv6), 1080)
            } else {
                return Err(format!("Invalid upstream address '{s}'"));
            }
        } else if let Ok(ipv6) = cleaned.parse::<Ipv6Addr>() {
            SocketAddr::new(std::net::IpAddr::V6(ipv6), 1080)
        } else {
            return Err(format!("Invalid upstream address '{s}'"));
        }
    } else if let Ok(ipv6) = cleaned.parse::<Ipv6Addr>() {
        SocketAddr::new(std::net::IpAddr::V6(ipv6), 1080)
    } else {
        use std::net::ToSocketAddrs;
        format!("{cleaned}:1080")
            .to_socket_addrs()
            .map_err(|e| format!("Invalid upstream address '{s}': {e}"))?
            .next()
            .ok_or_else(|| format!("Could not resolve upstream address '{s}'"))?
    };

    Ok(UpstreamConfig { addr, auth })
}

pub fn parse_upstream_addr(s: &str) -> Result<SocketAddr, String> {
    parse_upstream_config(s).map(|c| c.addr)
}

/// Parses an inbound bind address string with a default port fallback.
///
/// Supports:
/// - `127.0.0.1:1080`
/// - `127.0.0.1` (uses default_port)
/// - `[::1]:1080`
/// - `::1:1080` (unbracketed IPv6 with port)
/// - `[::1]` or `::1` (uses default_port)
/// - `0.0.0.0:1080` or `0.0.0.0`
/// - `[::]:1080`, `::` or `[::]`
/// - `localhost:1080` or `localhost`
pub fn parse_bind_addr(s: &str, default_port: u16) -> Result<SocketAddr, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("Bind address cannot be empty".to_string());
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        if let Ok(ipv6) = trimmed[1..trimmed.len() - 1].parse::<Ipv6Addr>() {
            return Ok(SocketAddr::new(std::net::IpAddr::V6(ipv6), default_port));
        } else {
            return Err(format!("Invalid bind address '{s}'"));
        }
    }

    if let Ok(ipv4) = trimmed.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(std::net::IpAddr::V4(ipv4), default_port));
    }

    if let Some(pos) = trimmed.rfind(':') {
        let host_part = &trimmed[..pos];
        let port_part = &trimmed[pos + 1..];
        if let Ok(port) = port_part.parse::<u16>() {
            if let Ok(ipv6) = host_part.parse::<Ipv6Addr>() {
                return Ok(SocketAddr::new(std::net::IpAddr::V6(ipv6), port));
            } else if let Ok(ipv4) = host_part.parse::<Ipv4Addr>() {
                return Ok(SocketAddr::new(std::net::IpAddr::V4(ipv4), port));
            } else {
                use std::net::ToSocketAddrs;
                if let Ok(mut addrs) = trimmed.to_socket_addrs() {
                    if let Some(addr) = addrs.next() {
                        return Ok(addr);
                    }
                }
            }
        }
    }

    if let Ok(ipv6) = trimmed.parse::<Ipv6Addr>() {
        return Ok(SocketAddr::new(std::net::IpAddr::V6(ipv6), default_port));
    }

    use std::net::ToSocketAddrs;
    if let Ok(mut addrs) = format!("{trimmed}:{default_port}").to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr);
        }
    }

    Err(format!("Invalid bind address '{s}'"))
}

pub fn parse_bind_addr_socks5(s: &str) -> Result<SocketAddr, String> {
    parse_bind_addr(s, 1080)
}

pub fn parse_bind_addr_http(s: &str) -> Result<SocketAddr, String> {
    parse_bind_addr(s, 1081)
}

/// Connects to a target host and port through an upstream SOCKS5 proxy with optional authentication.
pub async fn connect_socks5_with_auth(
    upstream: SocketAddr,
    auth: Option<&(String, String)>,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let clean_host = normalize_host(target_host);
    if clean_host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target host cannot be empty for upstream SOCKS5",
        ));
    }

    tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(upstream).await?;
        let _ = stream.set_nodelay(true);
        debug!(
            upstream = %upstream,
            target = %clean_host,
            port = target_port,
            has_auth = auth.is_some(),
            "Initiating SOCKS5 handshake with upstream proxy"
        );

        if auth.is_some() {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut greeting_resp = [0u8; 2];
        stream.read_exact(&mut greeting_resp).await?;
        if greeting_resp[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SOCKS version in upstream greeting response",
            ));
        }

        match greeting_resp[1] {
            0x00 => {}
            0x02 => {
                // RFC 1929 username/password auth
                let (user, pass) = auth.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Upstream SOCKS5 proxy requires authentication, but no credentials were provided",
                    )
                })?;

                let user_bytes = user.as_bytes();
                let pass_bytes = pass.as_bytes();
                if user_bytes.len() > 255 || pass_bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Username or password exceeds 255 bytes limit for SOCKS5 RFC 1929",
                    ));
                }

                let mut auth_req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
                auth_req.push(0x01);
                auth_req.push(user_bytes.len() as u8);
                auth_req.extend_from_slice(user_bytes);
                auth_req.push(pass_bytes.len() as u8);
                auth_req.extend_from_slice(pass_bytes);

                stream.write_all(&auth_req).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "Upstream SOCKS5 authentication failed (status: 0x{:02x})",
                            auth_resp[1]
                        ),
                    ));
                }
            }
            0xff => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Upstream SOCKS5 proxy rejected authentication methods",
                ));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("Unsupported auth method chosen by upstream: 0x{other:02x}"),
                ));
            }
        }

        let mut req = Vec::with_capacity(7 + clean_host.len());
        req.push(0x05);
        req.push(0x01);
        req.push(0x00);

        if let Ok(ipv4) = clean_host.parse::<Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ipv4.octets());
        } else if let Ok(ipv6) = clean_host.parse::<Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ipv6.octets());
        } else {
            let host_bytes = clean_host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Target hostname exceeds 255 bytes limit for SOCKS5",
                ));
            }
            req.push(0x03);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
        }

        req.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut resp_header = [0u8; 4];
        stream.read_exact(&mut resp_header).await?;
        if resp_header[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SOCKS5 version in upstream response",
            ));
        }

        let rep = resp_header[1];
        if rep != 0x00 {
            let msg = match rep {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown SOCKS5 error",
            };
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Upstream proxy connection failed (0x{rep:02x}): {msg}"),
            ));
        }

        let atyp = resp_header[3];
        match atyp {
            0x01 => {
                let mut discard = [0u8; 6];
                stream.read_exact(&mut discard).await?;
            }
            0x04 => {
                let mut discard = [0u8; 18];
                stream.read_exact(&mut discard).await?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut discard = vec![0u8; domain_len + 2];
                stream.read_exact(&mut discard).await?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported address type from upstream: {atyp}"),
                ));
            }
        }

        debug!(upstream = %upstream, target = %clean_host, port = target_port, "Upstream SOCKS5 tunnel established");
        Ok(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Upstream SOCKS5 connection timed out"))?
}

pub async fn connect_socks5(
    upstream: SocketAddr,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    connect_socks5_with_auth(upstream, None, target_host, target_port, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host("EXAMPLE.COM."), "example.com");
        assert_eq!(normalize_host("[::1]:443"), "::1");
        assert_eq!(normalize_host("[::1]"), "::1");
        assert_eq!(normalize_host("::1"), "::1");
        assert_eq!(normalize_host("::1:443"), "::1");
        assert_eq!(normalize_host("127.0.0.1:1080"), "127.0.0.1");
        assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_host("2001:db8::1:8080"), "2001:db8::1");
        assert_eq!(normalize_host("[2001:db8::1:2]:8080"), "2001:db8::1:2");
        assert_eq!(normalize_host("[2001:db8::1:2]"), "2001:db8::1:2");
        assert_eq!(normalize_host("[fe80::1:80]:443"), "fe80::1:80");
        assert_eq!(normalize_host("[::1:5000]"), "::1:5000");
        assert_eq!(normalize_host("[::ffff:127.0.0.1]:8080"), "127.0.0.1");
        assert_eq!(normalize_host("::ffff:127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(normalize_host("::ffff:127.0.0.1"), "127.0.0.1");
        assert_eq!(
            normalize_host("daily-cloudcode-pa.googleapis.com:443"),
            "daily-cloudcode-pa.googleapis.com"
        );
    }

    #[test]
    fn test_parse_upstream_addr_formats() {
        assert_eq!(
            parse_upstream_addr("127.0.0.1:10808").unwrap(),
            "127.0.0.1:10808".parse().unwrap()
        );
        assert_eq!(
            parse_upstream_addr("socks5://127.0.0.1:10808").unwrap(),
            "127.0.0.1:10808".parse().unwrap()
        );
        assert_eq!(
            parse_upstream_addr("socks5h://127.0.0.1:10808").unwrap(),
            "127.0.0.1:10808".parse().unwrap()
        );
        assert_eq!(
            parse_upstream_addr("socks5://[::1]:10808").unwrap(),
            "[::1]:10808".parse().unwrap()
        );
        assert_eq!(
            parse_upstream_addr("socks5://::1:10808").unwrap(),
            "[::1]:10808".parse().unwrap()
        );
        assert_eq!(
            parse_upstream_addr("socks5://::1").unwrap(),
            "[::1]:1080".parse().unwrap()
        );
        assert_eq!(
            parse_upstream_addr("127.0.0.1").unwrap(),
            "127.0.0.1:1080".parse().unwrap()
        );
        let cfg = parse_upstream_config("socks5://user:pass@127.0.0.1:10808/").unwrap();
        assert_eq!(cfg.addr, "127.0.0.1:10808".parse().unwrap());
        assert_eq!(cfg.auth, Some(("user".to_string(), "pass".to_string())));
        assert_eq!(cfg.to_string(), "socks5://user@127.0.0.1:10808");

        let cfg_v6 = parse_upstream_config("socks5://user:pass@[::1]:10808/").unwrap();
        assert_eq!(cfg_v6.addr, "[::1]:10808".parse().unwrap());
        assert_eq!(cfg_v6.to_string(), "socks5://user@[::1]:10808");

        assert!(parse_upstream_addr("invalid-address-xyz:99999").is_err());
    }

    #[test]
    fn test_parse_bind_addr() {
        assert_eq!(
            parse_bind_addr_socks5("127.0.0.1:1080").unwrap(),
            "127.0.0.1:1080".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_socks5("127.0.0.1").unwrap(),
            "127.0.0.1:1080".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_socks5("[::1]:1080").unwrap(),
            "[::1]:1080".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_socks5("::1:1080").unwrap(),
            "[::1]:1080".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_socks5("::1").unwrap(),
            "[::1]:1080".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_socks5("[::1]").unwrap(),
            "[::1]:1080".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_http("127.0.0.1").unwrap(),
            "127.0.0.1:1081".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr_http("::1").unwrap(),
            "[::1]:1081".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn test_upstream_socks5_handshake_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req_header = [0u8; 4];
            stream.read_exact(&mut req_header).await.unwrap();
            assert_eq!(req_header[0], 0x05);
            assert_eq!(req_header[1], 0x01);
            assert_eq!(req_header[3], 0x03);

            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.unwrap();
            let mut domain = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(String::from_utf8(domain).unwrap(), "api.anthropic.com");

            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.unwrap();
            assert_eq!(u16::from_be_bytes(port_buf), 443);

            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            let mut echo_buf = [0u8; 4];
            stream.read_exact(&mut echo_buf).await.unwrap();
            assert_eq!(&echo_buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut client_stream = connect_socks5(
            upstream_addr,
            "api.anthropic.com:443",
            443,
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        client_stream.write_all(b"ping").await.unwrap();
        let mut resp = [0u8; 4];
        client_stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_upstream_socks5_rfc1929_auth_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);

            stream.write_all(&[0x05, 0x02]).await.unwrap();

            let mut ver_and_ulen = [0u8; 2];
            stream.read_exact(&mut ver_and_ulen).await.unwrap();
            assert_eq!(ver_and_ulen[0], 0x01);
            let ulen = ver_and_ulen[1] as usize;
            let mut user_buf = vec![0u8; ulen];
            stream.read_exact(&mut user_buf).await.unwrap();
            assert_eq!(String::from_utf8(user_buf).unwrap(), "testuser");

            let mut plen_buf = [0u8; 1];
            stream.read_exact(&mut plen_buf).await.unwrap();
            let plen = plen_buf[0] as usize;
            let mut pass_buf = vec![0u8; plen];
            stream.read_exact(&mut pass_buf).await.unwrap();
            assert_eq!(String::from_utf8(pass_buf).unwrap(), "testpass");

            stream.write_all(&[0x01, 0x00]).await.unwrap();

            let mut req_header = [0u8; 4];
            stream.read_exact(&mut req_header).await.unwrap();
            assert_eq!(req_header[1], 0x01);

            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            let mut discard = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut discard).await.unwrap();

            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let credentials = ("testuser".to_string(), "testpass".to_string());
        let stream = connect_socks5_with_auth(
            upstream_addr,
            Some(&credentials),
            "cursor.sh",
            443,
            Duration::from_secs(2),
        )
        .await;

        assert!(stream.is_ok());
    }

    #[tokio::test]
    async fn test_upstream_socks5_rfc1929_auth_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x02]).await.unwrap();

            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf).await.unwrap();

            stream.write_all(&[0x01, 0x01]).await.unwrap();
        });

        let credentials = ("wronguser".to_string(), "badpass".to_string());
        let res = connect_socks5_with_auth(
            upstream_addr,
            Some(&credentials),
            "cursor.sh",
            443,
            Duration::from_secs(2),
        )
        .await;

        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_upstream_socks5_auth_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            let _ = stream.read_exact(&mut greeting).await;
            let _ = stream.write_all(&[0x05, 0xff]).await;
        });

        let res = connect_socks5(upstream_addr, "cursor.sh", 443, Duration::from_secs(2)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_upstream_socks5_connection_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            let _ = stream.read_exact(&mut greeting).await;
            let _ = stream.write_all(&[0x05, 0x00]).await;

            let mut req = [0u8; 1024];
            let _ = stream.read(&mut req).await;
            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        });

        let res = connect_socks5(upstream_addr, "cursor.sh", 443, Duration::from_secs(2)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
    }
}
