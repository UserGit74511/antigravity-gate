//! Inbound HTTP CONNECT proxy listener.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::router::Router;
use crate::sni;
use crate::tunnel;

const HTTP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP_HEADER_SIZE: usize = 16384;
const MAX_TLS_RECORD_SIZE: usize = 18432;

fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some((pos + 4, 4))
    } else {
        buf.windows(2)
            .position(|w| w == b"\n\n")
            .map(|pos| (pos + 2, 2))
    }
}

pub async fn run_http_server(listener: TcpListener, router: Router) -> io::Result<()> {
    let local_addr = listener.local_addr()?;
    info!(addr = %local_addr, "HTTP CONNECT inbound proxy listening");

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let _ = stream.set_nodelay(true);
                debug!(client = %client_addr, "Accepted incoming HTTP proxy connection");
                let router_clone = router.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_http_client(stream, router_clone, client_addr).await {
                        debug!(client = %client_addr, %err, "HTTP proxy connection closed");
                    }
                });
            }
            Err(err) => {
                error!(%err, "Error accepting HTTP connection");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_http_client(
    mut stream: TcpStream,
    router: Router,
    client_addr: SocketAddr,
) -> io::Result<()> {
    let mut header_buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 512];

    let read_result = tokio::time::timeout(HTTP_HANDSHAKE_TIMEOUT, async {
        while find_header_end(&header_buf).is_none() {
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Client closed connection prematurely",
                ));
            }
            header_buf.extend_from_slice(&temp[..n]);
            if header_buf.len() > MAX_HTTP_HEADER_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP request headers too large",
                ));
            }
        }
        Ok(())
    })
    .await;

    match read_result {
        Ok(Ok(())) => {}
        Ok(Err(ref err)) if err.kind() == io::ErrorKind::InvalidData => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers too large",
            ));
        }
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            let _ = stream
                .write_all(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP header reading timed out",
            ));
        }
    }

    let (header_end, _delim_len) = find_header_end(&header_buf).unwrap();
    let mut initial_payload = header_buf[header_end..].to_vec();

    let header_str = String::from_utf8_lossy(&header_buf[..header_end]);
    let mut lines = header_str.lines();
    let request_line = match lines.find(|l| !l.trim().is_empty()) {
        Some(line) => line,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty HTTP request",
            ));
        }
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Malformed HTTP request line",
        ));
    }

    let method = parts[0];
    let uri = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(uri, 443);
        if host.is_empty() || port == 0 {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty or invalid host in CONNECT request",
            ));
        }

        let is_ip = host.parse::<std::net::IpAddr>().is_ok();
        let is_tls = port == 443 || port == 8443;

        let pipelined_sni =
            if !initial_payload.is_empty() && sni::is_tls_handshake(&initial_payload) {
                sni::parse_sni(&initial_payload)
            } else {
                None
            };

        if !is_ip || pipelined_sni.is_some() || !is_tls {
            let effective_sni = pipelined_sni.as_deref();
            let (remote_stream, decision, _ep) = match router
                .connect_with_sni(&host, effective_sni, port)
                .await
            {
                Ok(res) => res,
                Err(err) => {
                    warn!(
                        client = %client_addr,
                        target = %host,
                        sni = ?effective_sni,
                        port,
                        %err,
                        "Failed to connect to target from HTTP CONNECT"
                    );
                    let _ = stream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: antigravity-gate\r\nConnection: close\r\n\r\n")
                        .await;
                    let _ = stream.shutdown().await;
                    return Err(err);
                }
            };

            stream
                .write_all(
                    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: antigravity-gate\r\n\r\n",
                )
                .await?;

            debug!(
                client = %client_addr,
                target = %host,
                sni = ?effective_sni,
                port,
                route = decision.label(),
                "HTTP CONNECT tunnel active"
            );

            let payload_ref = if initial_payload.is_empty() {
                None
            } else {
                Some(initial_payload.as_slice())
            };
            tunnel::pipe_bidirectional(stream, remote_stream, payload_ref).await?;
        } else {
            // IP destination on TLS port: ack 200 OK to elicit ClientHello for SNI inspection
            stream
                .write_all(
                    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: antigravity-gate\r\n\r\n",
                )
                .await?;

            let mut temp = [0u8; 4096];
            let read_res =
                tokio::time::timeout(Duration::from_secs(5), stream.read(&mut temp)).await;
            if let Ok(Ok(n)) = read_res {
                if n > 0 {
                    initial_payload.extend_from_slice(&temp[..n]);
                }
            }

            if initial_payload.len() >= 5 && sni::is_tls_handshake(&initial_payload) {
                let record_len =
                    u16::from_be_bytes([initial_payload[3], initial_payload[4]]) as usize;
                let total_needed = (5 + record_len).min(MAX_TLS_RECORD_SIZE);
                let _ = tokio::time::timeout(Duration::from_secs(3), async {
                    while initial_payload.len() < total_needed {
                        match stream.read(&mut temp).await {
                            Ok(chunk) if chunk > 0 => {
                                initial_payload.extend_from_slice(&temp[..chunk]);
                            }
                            _ => break,
                        }
                    }
                })
                .await;
            }

            let sni_host = if !initial_payload.is_empty() && sni::is_tls_handshake(&initial_payload)
            {
                sni::parse_sni(&initial_payload)
            } else {
                None
            };

            if let Some(ref sni) = sni_host {
                debug!(
                    client = %client_addr,
                    original = %host,
                    sni = %sni,
                    "Extracted SNI from HTTP CONNECT stream"
                );
            }

            let (remote_stream, decision, _ep) = match router
                .connect_with_sni(&host, sni_host.as_deref(), port)
                .await
            {
                Ok(res) => res,
                Err(err) => {
                    warn!(
                        client = %client_addr,
                        target = %host,
                        sni = ?sni_host,
                        port,
                        %err,
                        "Failed to connect to target from HTTP CONNECT"
                    );
                    let _ = stream.shutdown().await;
                    return Err(err);
                }
            };

            debug!(
                client = %client_addr,
                target = %host,
                sni = ?sni_host,
                port,
                route = decision.label(),
                "HTTP CONNECT tunnel active"
            );

            let payload_ref = if initial_payload.is_empty() {
                None
            } else {
                Some(initial_payload.as_slice())
            };
            tunnel::pipe_bidirectional(stream, remote_stream, payload_ref).await?;
        }
    } else {
        let host_header = lines
            .find(|l| l.to_ascii_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().to_string());

        let target = if let Some(h) = host_header {
            h
        } else if let Some(stripped) = uri.strip_prefix("http://") {
            stripped.split('/').next().unwrap_or("").to_string()
        } else {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Missing Host header in HTTP request",
            ));
        };

        let (host, port) = parse_host_port(&target, 80);
        if host.is_empty() || port == 0 {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty or invalid host in HTTP request",
            ));
        }

        let (remote_stream, _decision, _ep) = match router.connect(&host, port).await {
            Ok(res) => res,
            Err(err) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
                return Err(err);
            }
        };

        let fwd_payload = if let Some(rest) = uri.strip_prefix("http://") {
            let path_start = rest.find('/').or_else(|| rest.find('?'));
            let path = match path_start {
                Some(i) if rest[i..].starts_with('?') => format!("/{}", &rest[i..]),
                Some(i) => rest[i..].to_string(),
                None => "/".to_string(),
            };
            let proto = parts.get(2).unwrap_or(&"HTTP/1.1");
            let new_req_line = format!("{method} {path} {proto}\r\n");
            let mut buf = Vec::new();
            buf.extend_from_slice(new_req_line.as_bytes());

            let first_line_end = header_buf[..header_end]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| p + 2)
                .or_else(|| {
                    header_buf[..header_end]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map(|p| p + 1)
                });
            if let Some(pos) = first_line_end {
                buf.extend_from_slice(&header_buf[pos..header_end]);
            }
            buf.extend_from_slice(&initial_payload);
            buf
        } else {
            header_buf
        };

        tunnel::pipe_bidirectional(stream, remote_stream, Some(&fwd_payload)).await?;
    }

    Ok(())
}

pub fn parse_host_port(target: &str, default_port: u16) -> (String, u16) {
    let s = target.trim();
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let host_part = &s[1..end];
            let rest = &s[end + 1..];
            if let Some(pos) = rest.find(':') {
                let port_str = &rest[pos + 1..];
                if let Ok(p) = port_str.parse::<u16>() {
                    return (host_part.to_string(), p);
                } else {
                    return (host_part.to_string(), 0);
                }
            }
            return (host_part.to_string(), default_port);
        }
    }
    if let Some(pos) = s.rfind(':') {
        let host_part = &s[..pos];
        let port_part = &s[pos + 1..];
        if !host_part.contains(':') {
            if let Ok(p) = port_part.parse::<u16>() {
                return (host_part.trim_end_matches('.').to_string(), p);
            } else {
                return (host_part.trim_end_matches('.').to_string(), 0);
            }
        } else if !port_part.is_empty()
            && port_part.chars().all(|c| c.is_ascii_digit())
            && host_part.parse::<std::net::Ipv6Addr>().is_ok()
        {
            if let Ok(p) = port_part.parse::<u16>() {
                return (host_part.to_string(), p);
            } else {
                return (host_part.to_string(), 0);
            }
        }
    }
    (s.trim_end_matches('.').to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::SniPool;
    use crate::sni::tests::build_client_hello;

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("daily-cloudcode-pa.googleapis.com:443", 443),
            ("daily-cloudcode-pa.googleapis.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("daily-cloudcode-pa.googleapis.com", 443),
            ("daily-cloudcode-pa.googleapis.com".to_string(), 443)
        );
        assert_eq!(parse_host_port("[::1]:8080", 80), ("::1".to_string(), 8080));
        assert_eq!(parse_host_port("[::1]", 80), ("::1".to_string(), 80));
        assert_eq!(parse_host_port("::1", 80), ("::1".to_string(), 80));
        assert_eq!(parse_host_port("::1:8080", 80), ("::1".to_string(), 8080));
        assert_eq!(
            parse_host_port("[2001:db8::1:2]:8080", 80),
            ("2001:db8::1:2".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("[2001:db8::1:2]", 80),
            ("2001:db8::1:2".to_string(), 80)
        );
        assert_eq!(
            parse_host_port("[::ffff:127.0.0.1]:8080", 80),
            ("::ffff:127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("::ffff:127.0.0.1:8080", 80),
            ("::ffff:127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("::ffff:127.0.0.1", 80),
            ("::ffff:127.0.0.1".to_string(), 80)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:1080", 1080),
            ("127.0.0.1".to_string(), 1080)
        );
        assert_eq!(
            parse_host_port("127.0.0.1", 1080),
            ("127.0.0.1".to_string(), 1080)
        );
        assert_eq!(parse_host_port("[::1]:99999", 443), ("::1".to_string(), 0));
        assert_eq!(
            parse_host_port("127.0.0.1:99999", 443),
            ("127.0.0.1".to_string(), 0)
        );
        assert_eq!(parse_host_port("[::1]:", 443), ("::1".to_string(), 0));
        assert_eq!(
            parse_host_port("127.0.0.1:", 443),
            ("127.0.0.1".to_string(), 0)
        );
    }

    #[tokio::test]
    async fn test_http_connect_tunnel() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"data");
            stream.write_all(b"resp").await.unwrap();
        });

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_http_server(http_listener, router).await;
        });

        let mut client = TcpStream::connect(http_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            echo_addr.port(),
            echo_addr.port()
        );
        client.write_all(connect_req.as_bytes()).await.unwrap();

        let mut resp_buf = [0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("200 Connection Established"));

        client.write_all(b"data").await.unwrap();
        let mut echo_reply = [0u8; 4];
        client.read_exact(&mut echo_reply).await.unwrap();
        assert_eq!(&echo_reply, b"resp");
    }

    #[tokio::test]
    async fn test_http_connect_pipelined_client_hello() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 512];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            assert!(sni::is_tls_handshake(&buf[..n]));
            stream.write_all(b"pipelined_ok").await.unwrap();
        });

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_http_server(http_listener, router).await;
        });

        let mut client = TcpStream::connect(http_addr).await.unwrap();
        let hello = build_client_hello("example.com");

        let mut combined = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            echo_addr.port(),
            echo_addr.port()
        )
        .into_bytes();
        combined.extend_from_slice(&hello);
        client.write_all(&combined).await.unwrap();

        let mut resp_buf = [0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("200 Connection Established"));

        let mut reply = [0u8; 12];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pipelined_ok");
    }

    #[tokio::test]
    async fn test_plain_http_proxy() {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            stream.write_all(reply).await.unwrap();
        });

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_http_server(http_listener, router).await;
        });

        let mut client = TcpStream::connect(http_addr).await.unwrap();
        let get_req = format!(
            "GET http://127.0.0.1:{}/test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            origin_addr.port(),
            origin_addr.port()
        );
        client.write_all(get_req.as_bytes()).await.unwrap();

        let mut resp = [0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.ends_with("OK"));
    }
}
