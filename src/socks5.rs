//! Inbound SOCKS5 proxy listener.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::router::Router;
use crate::sni;
use crate::tunnel;
use crate::upstream::normalize_host;

pub async fn run_socks5_server(listener: TcpListener, router: Router) -> io::Result<()> {
    let local_addr = listener.local_addr()?;
    info!(addr = %local_addr, "SOCKS5 inbound proxy listening");

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let _ = stream.set_nodelay(true);
                debug!(client = %client_addr, "Accepted incoming SOCKS5 connection");
                let router_clone = router.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_socks5_client(stream, router_clone, client_addr).await
                    {
                        debug!(client = %client_addr, %err, "SOCKS5 connection closed");
                    }
                });
            }
            Err(err) => {
                error!(%err, "Error accepting SOCKS5 connection");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TLS_RECORD_SIZE: usize = 18432;

async fn handle_socks5_client(
    mut stream: TcpStream,
    router: Router,
    client_addr: SocketAddr,
) -> io::Result<()> {
    let (_ver, methods) = tokio::time::timeout(SOCKS5_HANDSHAKE_TIMEOUT, async {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        let ver = header[0];
        let nmethods = header[1] as usize;

        if ver != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported SOCKS version: {ver}"),
            ));
        }

        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
        Ok((ver, methods))
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "SOCKS5 greeting handshake timed out",
        )
    })??;

    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "No acceptable authentication method",
        ));
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let (raw_target_host, target_port) = tokio::time::timeout(SOCKS5_HANDSHAKE_TIMEOUT, async {
        let mut req_header = [0u8; 4];
        stream.read_exact(&mut req_header).await?;
        let ver = req_header[0];
        let cmd = req_header[1];
        let atyp = req_header[3];

        if ver != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid version in request",
            ));
        }

        if cmd != 0x01 {
            match atyp {
                0x01 => {
                    let mut discard = [0u8; 6];
                    let _ = stream.read_exact(&mut discard).await;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    if stream.read_exact(&mut len).await.is_ok() {
                        let mut discard = vec![0u8; len[0] as usize + 2];
                        let _ = stream.read_exact(&mut discard).await;
                    }
                }
                0x04 => {
                    let mut discard = [0u8; 18];
                    let _ = stream.read_exact(&mut discard).await;
                }
                _ => {}
            }

            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported SOCKS5 command: {cmd}"),
            ));
        }

        let raw_host = match atyp {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                Ipv4Addr::from(octets).to_string()
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                if domain_len == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Zero length domain",
                    ));
                }
                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await?;
                String::from_utf8(domain_buf).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid UTF-8 in domain: {e}"),
                    )
                })?
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                Ipv6Addr::from(octets).to_string()
            }
            _ => {
                stream
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                let _ = stream.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported address type: {atyp}"),
                ));
            }
        };

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);
        Ok((raw_host, port))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 request reading timed out"))??;

    let target_host = normalize_host(&raw_target_host);
    if target_host.is_empty() || target_port == 0 {
        stream
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let _ = stream.shutdown().await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target host cannot be empty and port must be non-zero",
        ));
    }

    let is_ip = target_host.parse::<std::net::IpAddr>().is_ok();
    let is_tls = target_port == 443 || target_port == 8443;

    if !is_ip || !is_tls {
        let (remote_stream, decision, _ep) = match router.connect(&target_host, target_port).await {
            Ok(res) => res,
            Err(err) => {
                let rep = match err.kind() {
                    io::ErrorKind::ConnectionRefused => 0x05,
                    io::ErrorKind::TimedOut => 0x04,
                    io::ErrorKind::NotFound | io::ErrorKind::AddrNotAvailable => 0x04,
                    io::ErrorKind::PermissionDenied => 0x02,
                    _ => 0x01,
                };
                warn!(
                    client = %client_addr,
                    target = %target_host,
                    port = target_port,
                    rep,
                    %err,
                    "Failed to connect to destination from SOCKS5"
                );
                let _ = stream
                    .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = stream.shutdown().await;
                return Err(err);
            }
        };

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        debug!(
            client = %client_addr,
            target = %target_host,
            port = target_port,
            route = decision.label(),
            "SOCKS5 tunnel active"
        );

        tunnel::pipe_bidirectional(stream, remote_stream, None).await?;
    } else {
        // Direct IP on TLS port: ack success early so client emits ClientHello to inspect SNI
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let mut initial_payload = Vec::new();
        let mut temp = [0u8; 4096];
        let read_res = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut temp)).await;
        if let Ok(Ok(n)) = read_res {
            if n > 0 {
                initial_payload.extend_from_slice(&temp[..n]);
            }
        }

        if initial_payload.len() >= 5 && sni::is_tls_handshake(&initial_payload) {
            let record_len = u16::from_be_bytes([initial_payload[3], initial_payload[4]]) as usize;
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

        let sni_host = if !initial_payload.is_empty() && sni::is_tls_handshake(&initial_payload) {
            sni::parse_sni(&initial_payload)
        } else {
            None
        };

        if let Some(ref sni) = sni_host {
            debug!(
                client = %client_addr,
                original = %target_host,
                sni = %sni,
                "Extracted SNI from TLS ClientHello"
            );
        }

        let (remote_stream, decision, _ep) = match router
            .connect_with_sni(&target_host, sni_host.as_deref(), target_port)
            .await
        {
            Ok(res) => res,
            Err(err) => {
                warn!(
                    client = %client_addr,
                    target = %target_host,
                    sni = ?sni_host,
                    port = target_port,
                    %err,
                    "Failed to route connection"
                );
                let _ = stream.shutdown().await;
                return Err(err);
            }
        };

        debug!(
            client = %client_addr,
            target = %target_host,
            sni = ?sni_host,
            port = target_port,
            route = decision.label(),
            "SOCKS5 tunnel active"
        );

        let payload_ref = if initial_payload.is_empty() {
            None
        } else {
            Some(initial_payload.as_slice())
        };
        tunnel::pipe_bidirectional(stream, remote_stream, payload_ref).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::SniPool;
    use crate::sni::tests::build_client_hello;

    #[tokio::test]
    async fn test_socks5_unsupported_version() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_socks5_server(listener, router).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

        let mut resp = [0u8; 2];
        let res = client.read(&mut resp).await;
        assert!(res.is_err() || res.unwrap() == 0);
    }

    #[tokio::test]
    async fn test_socks5_unsupported_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_socks5_server(listener, router).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0xff]);
    }

    #[tokio::test]
    async fn test_socks5_unsupported_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_socks5_server(listener, router).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting_resp = [0u8; 2];
        client.read_exact(&mut greeting_resp).await.unwrap();
        assert_eq!(greeting_resp, [0x05, 0x00]);

        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();

        let mut cmd_resp = [0u8; 10];
        client.read_exact(&mut cmd_resp).await.unwrap();
        assert_eq!(cmd_resp[0], 0x05);
        assert_eq!(cmd_resp[1], 0x07);
    }

    #[tokio::test]
    async fn test_socks5_connect_domain_and_pipe() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.unwrap();
        });

        let socks5_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks5_addr = socks5_listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_socks5_server(socks5_listener, router).await;
        });

        let mut client = TcpStream::connect(socks5_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let domain = "127.0.0.1";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain.as_bytes());
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; 10];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 0x05);
        assert_eq!(resp[1], 0x00);

        client.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
    }

    #[tokio::test]
    async fn test_socks5_connect_with_tls_client_hello() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 512];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            assert!(sni::is_tls_handshake(&buf[..n]));
            stream.write_all(b"tls_ack").await.unwrap();
        });

        let socks5_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks5_addr = socks5_listener.local_addr().unwrap();
        let router = Router::new(SniPool::new(), None, vec![]);

        tokio::spawn(async move {
            let _ = run_socks5_server(socks5_listener, router).await;
        });

        let mut client = TcpStream::connect(socks5_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();

        let domain = "127.0.0.1";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain.as_bytes());
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; 10];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x00);

        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut ack = [0u8; 7];
        client.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"tls_ack");
    }
}
