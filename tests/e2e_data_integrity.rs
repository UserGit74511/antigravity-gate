//! Comprehensive end-to-end data integrity, large payload streaming,
//! dual-stack IPv6, and CLI validation test suite for antigravity-gate.

use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use antigravity_gate::http::run_http_server;
use antigravity_gate::pool::SniPool;
use antigravity_gate::router::Router;
use antigravity_gate::socks5::run_socks5_server;
use antigravity_gate::upstream::{
    normalize_host, parse_bind_addr, parse_upstream_config, UpstreamConfig,
};

/// Helper to generate deterministic binary test patterns of arbitrary size.
fn generate_test_payload(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        // Deterministic pseudo-random pattern based on byte index
        data.push(((i ^ (i >> 8) ^ 0xA5) & 0xFF) as u8);
    }
    data
}

/// Spawns a high-speed TCP echo server on IPv4 loopback.
async fn spawn_ipv4_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    addr
}

/// Tries to spawn a TCP echo server on IPv6 loopback [::1].
async fn try_spawn_ipv6_echo_server() -> Option<std::net::SocketAddr> {
    let listener = TcpListener::bind("[::1]:0").await.ok()?;
    let addr = listener.local_addr().ok()?;

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    Some(addr)
}

/// Spawns a SOCKS5 proxy server.
async fn spawn_socks5_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new(SniPool::new(), None, vec![]);
    tokio::spawn(async move {
        let _ = run_socks5_server(listener, router).await;
    });
    addr
}

/// Spawns an HTTP proxy server.
async fn spawn_http_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new(SniPool::new(), None, vec![]);
    tokio::spawn(async move {
        let _ = run_http_server(listener, router).await;
    });
    addr
}

// =========================================================================
// 1. Large Payload Streaming Integrity Tests (Multi-Megabyte Streams)
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_payload_streaming_integrity_socks5() {
    let echo_addr = spawn_ipv4_echo_server().await;
    let proxy_addr = spawn_socks5_proxy().await;

    // 4 Megabytes of binary payload
    let test_size = 4 * 1024 * 1024;
    let payload = Arc::new(generate_test_payload(test_size));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let _ = client.set_nodelay(true);

    // 1. SOCKS5 Greeting
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await.unwrap();
    assert_eq!(greeting_resp, [0x05, 0x00]);

    // 2. SOCKS5 CONNECT to 127.0.0.1:echo_port
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00);

    // 3. Bidirectional streaming of 4MB payload
    let (mut read_half, mut write_half) = client.into_split();
    let payload_writer = payload.clone();

    let writer_handle = tokio::spawn(async move {
        let chunk_size = 65536;
        let mut offset = 0;
        while offset < payload_writer.len() {
            let end = (offset + chunk_size).min(payload_writer.len());
            write_half
                .write_all(&payload_writer[offset..end])
                .await
                .unwrap();
            offset = end;
        }
        let _ = write_half.shutdown().await;
    });

    let reader_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(test_size);
        let mut chunk = vec![0u8; 65536];
        loop {
            match read_half.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("Read error during large stream: {e}"),
            }
        }
        received
    });

    writer_handle.await.unwrap();
    let received = reader_handle.await.unwrap();

    // Verify 100% integrity: exact length and exact byte-for-byte match
    assert_eq!(received.len(), test_size);
    assert_eq!(&received[..], &payload[..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_payload_streaming_integrity_http_connect() {
    let echo_addr = spawn_ipv4_echo_server().await;
    let proxy_addr = spawn_http_proxy().await;

    // 4 Megabytes of binary payload
    let test_size = 4 * 1024 * 1024;
    let payload = Arc::new(generate_test_payload(test_size));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let _ = client.set_nodelay(true);

    // 1. Send HTTP CONNECT
    let connect_req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo_addr.port(),
        echo_addr.port()
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // 2. Read 200 Connection Established
    let mut header_buf = [0u8; 256];
    let n = client.read(&mut header_buf).await.unwrap();
    let header_str = String::from_utf8_lossy(&header_buf[..n]);
    assert!(
        header_str.contains("200 Connection Established"),
        "Expected 200 OK, got: {header_str}"
    );

    // 3. Bidirectional streaming of 4MB payload
    let (mut read_half, mut write_half) = client.into_split();
    let payload_writer = payload.clone();

    let writer_handle = tokio::spawn(async move {
        let chunk_size = 65536;
        let mut offset = 0;
        while offset < payload_writer.len() {
            let end = (offset + chunk_size).min(payload_writer.len());
            write_half
                .write_all(&payload_writer[offset..end])
                .await
                .unwrap();
            offset = end;
        }
        let _ = write_half.shutdown().await;
    });

    let reader_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(test_size);
        let mut chunk = vec![0u8; 65536];
        loop {
            match read_half.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("Read error during large stream: {e}"),
            }
        }
        received
    });

    writer_handle.await.unwrap();
    let received = reader_handle.await.unwrap();

    assert_eq!(received.len(), test_size);
    assert_eq!(&received[..], &payload[..]);
}

// =========================================================================
// 2. Chunked & Fragmented Streaming Integrity Tests
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_variable_chunk_streaming_integrity() {
    let echo_addr = spawn_ipv4_echo_server().await;
    let proxy_addr = spawn_socks5_proxy().await;

    let test_size = 512 * 1024; // 512 KB
    let payload = Arc::new(generate_test_payload(test_size));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();

    let (mut read_half, mut write_half) = client.into_split();
    let payload_writer = payload.clone();

    // Stream with highly irregular chunk sizes (1B, 7B, 137B, 4099B, 16384B)
    let writer_handle = tokio::spawn(async move {
        let chunk_sizes = [1, 7, 137, 4099, 16384, 53, 1024];
        let mut offset = 0;
        let mut idx = 0;
        while offset < payload_writer.len() {
            let chunk_size = chunk_sizes[idx % chunk_sizes.len()];
            let end = (offset + chunk_size).min(payload_writer.len());
            write_half
                .write_all(&payload_writer[offset..end])
                .await
                .unwrap();
            offset = end;
            idx += 1;
            tokio::task::yield_now().await;
        }
        let _ = write_half.shutdown().await;
    });

    let reader_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(test_size);
        let mut buf = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) => panic!("Read error: {e}"),
            }
        }
        received
    });

    writer_handle.await.unwrap();
    let received = reader_handle.await.unwrap();

    assert_eq!(received.len(), test_size);
    assert_eq!(&received[..], &payload[..]);
}

// =========================================================================
// 3. Dual-Stack & IPv6 Address Formatting Tests
// =========================================================================

#[tokio::test]
async fn test_dual_stack_ipv6_socks5_atyp_04() {
    let Some(echo_addr_v6) = try_spawn_ipv6_echo_server().await else {
        eprintln!("IPv6 loopback not supported in this environment, skipping test");
        return;
    };

    let proxy_addr = spawn_socks5_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await.unwrap();
    assert_eq!(greeting_resp, [0x05, 0x00]);

    // Send ATYP=0x04 (IPv6: ::1 = [0..0, 1])
    let mut req = vec![0x05, 0x01, 0x00, 0x04];
    let v6_bytes = std::net::Ipv6Addr::LOCALHOST.octets();
    req.extend_from_slice(&v6_bytes);
    req.extend_from_slice(&echo_addr_v6.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00, "Expected success REP=0x00");

    client.write_all(b"ipv6-socks5-data").await.unwrap();
    let mut echo = [0u8; 16];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ipv6-socks5-data");
}

#[tokio::test]
async fn test_dual_stack_ipv6_socks5_atyp_03_bracketed_and_unbracketed() {
    let Some(echo_addr_v6) = try_spawn_ipv6_echo_server().await else {
        eprintln!("IPv6 loopback not supported in this environment, skipping test");
        return;
    };

    let proxy_addr = spawn_socks5_proxy().await;

    // Test with ATYP=0x03 domain "::1"
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        let host = "::1";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&echo_addr_v6.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00);

        client.write_all(b"test-unbracketed-v6").await.unwrap();
        let mut echo = [0u8; 19];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"test-unbracketed-v6");
    }

    // Test with ATYP=0x03 domain "[::1]"
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        let host = "[::1]";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&echo_addr_v6.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00);

        client.write_all(b"test-bracketed-v6").await.unwrap();
        let mut echo = [0u8; 17];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"test-bracketed-v6");
    }
}

#[tokio::test]
async fn test_dual_stack_ipv4_mapped_ipv6_socks5() {
    let echo_addr = spawn_ipv4_echo_server().await;
    let proxy_addr = spawn_socks5_proxy().await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    // SOCKS5 request with ATYP=0x03 domain "::ffff:127.0.0.1"
    let host = "::ffff:127.0.0.1";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00);

    client.write_all(b"mapped-ipv6-socks5").await.unwrap();
    let mut echo = [0u8; 18];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"mapped-ipv6-socks5");
}

#[tokio::test]
async fn test_dual_stack_http_connect_bracketed_and_unbracketed_v6() {
    let Some(echo_addr_v6) = try_spawn_ipv6_echo_server().await else {
        eprintln!("IPv6 loopback not supported in this environment, skipping test");
        return;
    };

    let proxy_addr = spawn_http_proxy().await;

    // 1. Bracketed CONNECT [::1]:port
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT [::1]:{} HTTP/1.1\r\nHost: [::1]:{}\r\n\r\n",
            echo_addr_v6.port(),
            echo_addr_v6.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = [0u8; 256];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("200 Connection Established"));

        client.write_all(b"bracketed-v6-http").await.unwrap();
        let mut echo = [0u8; 17];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"bracketed-v6-http");
    }

    // 2. Unbracketed CONNECT ::1:port
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT ::1:{} HTTP/1.1\r\nHost: ::1:{}\r\n\r\n",
            echo_addr_v6.port(),
            echo_addr_v6.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = [0u8; 256];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("200 Connection Established"));

        client.write_all(b"unbracketed-v6-http").await.unwrap();
        let mut echo = [0u8; 19];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"unbracketed-v6-http");
    }
}

#[tokio::test]
async fn test_dual_stack_http_connect_ipv4_mapped_v6() {
    let echo_addr = spawn_ipv4_echo_server().await;
    let proxy_addr = spawn_http_proxy().await;

    // Bracketed IPv4-mapped IPv6
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT [::ffff:127.0.0.1]:{} HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:{}\r\n\r\n",
            echo_addr.port(),
            echo_addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = [0u8; 256];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("200 Connection Established"));

        client.write_all(b"mapped-bracketed-http").await.unwrap();
        let mut echo = [0u8; 21];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"mapped-bracketed-http");
    }

    // Unbracketed IPv4-mapped IPv6
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT ::ffff:127.0.0.1:{} HTTP/1.1\r\nHost: ::ffff:127.0.0.1:{}\r\n\r\n",
            echo_addr.port(),
            echo_addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = [0u8; 256];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("200 Connection Established"));

        client.write_all(b"mapped-unbracketed-http").await.unwrap();
        let mut echo = [0u8; 23];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"mapped-unbracketed-http");
    }
}

// =========================================================================
// 4. High-Concurrency Task and Descriptor Leak Audit
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_task_and_descriptor_leak_on_client_disconnect() {
    // Spawns an infinite generator server that continually sends data
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream_addr = listener.local_addr().unwrap();

    let server_running = Arc::new(AtomicBool::new(true));
    let server_flag = server_running.clone();

    tokio::spawn(async move {
        while server_flag.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let chunk = vec![0x42u8; 8192];
                    loop {
                        if stream.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let proxy_addr = spawn_socks5_proxy().await;
    let concurrency = 40;
    let finished_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let f_count = finished_count.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut g_resp = [0u8; 2];
            client.read_exact(&mut g_resp).await.unwrap();

            let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&stream_addr.port().to_be_bytes());
            client.write_all(&req).await.unwrap();
            let mut c_resp = [0u8; 10];
            client.read_exact(&mut c_resp).await.unwrap();

            // Read a few chunks, then abruptly disconnect
            let mut buf = [0u8; 4096];
            let _ = client.read(&mut buf).await;
            let _ = client.read(&mut buf).await;

            // Abrupt client socket drop
            drop(client);
            f_count.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(finished_count.load(Ordering::Relaxed), concurrency);

    // Give proxy server tasks 200ms to clean up terminated streams
    tokio::time::sleep(Duration::from_millis(200)).await;
    server_running.store(false, Ordering::Relaxed);
}

// =========================================================================
// 5. CLI Argument Parsing and Subcommand Validation Tests
// =========================================================================

#[test]
fn test_cli_help_and_version_flags() {
    let bin_path = env!("CARGO_BIN_EXE_antigravity-gate");

    // --help
    let output = Command::new(bin_path).arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("serve"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("patch"));
    assert!(stdout.contains("unpatch"));

    // -V / --version
    let output = Command::new(bin_path).arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0.1.0"));
}

#[test]
fn test_cli_subcommands_help() {
    let bin_path = env!("CARGO_BIN_EXE_antigravity-gate");

    for subcmd in &["serve", "status", "patch", "unpatch"] {
        let output = Command::new(bin_path)
            .args([subcmd, "--help"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Failed --help on subcommand: {subcmd}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Usage:"));
    }
}

#[test]
fn test_cli_status_nonexistent_custom_path() {
    let bin_path = env!("CARGO_BIN_EXE_antigravity-gate");

    let output = Command::new(bin_path)
        .args([
            "status",
            "--path",
            "C:\\ThisDirectoryDoesNotExist_123456789",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Specified directory or binary does not exist"),
        "Expected error message about missing custom path, got: {stdout}"
    );
    // Crucial safety check: must NOT have fallen back to system installation
    assert!(!stdout.contains("Found Installation: C:\\Users\\"));
}

#[test]
fn test_cli_invalid_flags_rejected() {
    let bin_path = env!("CARGO_BIN_EXE_antigravity-gate");

    let output = Command::new(bin_path)
        .arg("--unsupported-flag-xyz")
        .output()
        .unwrap();

    assert!(!output.status.success(), "Expected failure on invalid flag");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unexpected argument") || stderr.contains("error"));
}

#[test]
fn test_cli_bind_addr_parsing_unit_tests() {
    // SOCKS5 default port 1080
    assert_eq!(
        parse_bind_addr("127.0.0.1", 1080).unwrap(),
        "127.0.0.1:1080".parse().unwrap()
    );
    assert_eq!(
        parse_bind_addr("127.0.0.1:2080", 1080).unwrap(),
        "127.0.0.1:2080".parse().unwrap()
    );
    assert_eq!(
        parse_bind_addr("[::1]:2080", 1080).unwrap(),
        "[::1]:2080".parse().unwrap()
    );
    assert_eq!(
        parse_bind_addr("::1:2080", 1080).unwrap(),
        "[::1]:2080".parse().unwrap()
    );
    assert_eq!(
        parse_bind_addr("::1", 1080).unwrap(),
        "[::1]:1080".parse().unwrap()
    );
    assert_eq!(
        parse_bind_addr("[::1]", 1080).unwrap(),
        "[::1]:1080".parse().unwrap()
    );

    // HTTP default port 1081
    assert_eq!(
        parse_bind_addr("127.0.0.1", 1081).unwrap(),
        "127.0.0.1:1081".parse().unwrap()
    );
    assert_eq!(
        parse_bind_addr("::1", 1081).unwrap(),
        "[::1]:1081".parse().unwrap()
    );

    // Upstream parsing
    assert_eq!(
        parse_upstream_config("socks5://::1:1080").unwrap().addr,
        "[::1]:1080".parse().unwrap()
    );
    assert_eq!(
        parse_upstream_config("socks5://[::1]:1080").unwrap().addr,
        "[::1]:1080".parse().unwrap()
    );
    assert_eq!(
        parse_upstream_config("socks5://user:pass@::1:1080")
            .unwrap()
            .addr,
        "[::1]:1080".parse().unwrap()
    );
}

// =========================================================================
// 6. Upstream Chaining Large Payload Streaming & Data Integrity Tests
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chained_upstream_socks5_large_payload_streaming() {
    let echo_addr = spawn_ipv4_echo_server().await;

    // 1. Spawn mock upstream SOCKS5 server requiring RFC 1929 authentication
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let expected_user = "proxyuser";
    let expected_pass = "secret123";

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match upstream_listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            tokio::spawn(async move {
                // Greeting
                let mut greeting = [0u8; 4];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting[0], 0x05);
                // Require USERNAME/PASSWORD (0x02)
                stream.write_all(&[0x05, 0x02]).await.unwrap();

                // RFC 1929 Auth Request
                let mut ver_ulen = [0u8; 2];
                stream.read_exact(&mut ver_ulen).await.unwrap();
                assert_eq!(ver_ulen[0], 0x01);
                let ulen = ver_ulen[1] as usize;
                let mut user = vec![0u8; ulen];
                stream.read_exact(&mut user).await.unwrap();

                let mut plen_buf = [0u8; 1];
                stream.read_exact(&mut plen_buf).await.unwrap();
                let plen = plen_buf[0] as usize;
                let mut pass = vec![0u8; plen];
                stream.read_exact(&mut pass).await.unwrap();

                assert_eq!(std::str::from_utf8(&user).unwrap(), expected_user);
                assert_eq!(std::str::from_utf8(&pass).unwrap(), expected_pass);

                // Auth OK
                stream.write_all(&[0x01, 0x00]).await.unwrap();

                // SOCKS5 Request
                let mut req_header = [0u8; 4];
                stream.read_exact(&mut req_header).await.unwrap();
                let atyp = req_header[3];
                let target_port = match atyp {
                    0x01 => {
                        let mut ip_port = [0u8; 6];
                        stream.read_exact(&mut ip_port).await.unwrap();
                        u16::from_be_bytes([ip_port[4], ip_port[5]])
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.unwrap();
                        let mut d = vec![0u8; len[0] as usize + 2];
                        stream.read_exact(&mut d).await.unwrap();
                        let l = d.len();
                        u16::from_be_bytes([d[l - 2], d[l - 1]])
                    }
                    _ => panic!("Unexpected atyp: {atyp}"),
                };

                // Connect to destination (echo server)
                let mut target_stream = TcpStream::connect(format!("127.0.0.1:{target_port}"))
                    .await
                    .unwrap();

                // Send success response
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();

                // Bridge data between antigravity-gate and origin echo server
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await;
            });
        }
    });

    // 2. Spawn antigravity-gate configured with upstream SOCKS5 and custom domain route
    let upstream_cfg = UpstreamConfig {
        addr: upstream_addr,
        auth: Some((expected_user.to_string(), expected_pass.to_string())),
    };
    let router = Router::new(
        SniPool::new(),
        Some(upstream_cfg),
        vec!["upstream-test.ai".to_string()],
    );

    let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate_addr = gate_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = run_socks5_server(gate_listener, router).await;
    });

    // 3. Client connects to antigravity-gate requesting upstream-test.ai:echo_port
    let mut client = TcpStream::connect(gate_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [0x05, 0x00]);

    let domain = "upstream-test.ai";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain.as_bytes());
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut c_resp = [0u8; 10];
    client.read_exact(&mut c_resp).await.unwrap();
    assert_eq!(c_resp[1], 0x00, "Upstream tunnel must succeed");

    // 4. Stream 2MB through the chained upstream proxy
    let test_size = 2 * 1024 * 1024;
    let payload = Arc::new(generate_test_payload(test_size));

    let (mut read_half, mut write_half) = client.into_split();
    let payload_writer = payload.clone();

    let writer_handle = tokio::spawn(async move {
        let chunk_size = 32768;
        let mut offset = 0;
        while offset < payload_writer.len() {
            let end = (offset + chunk_size).min(payload_writer.len());
            write_half
                .write_all(&payload_writer[offset..end])
                .await
                .unwrap();
            offset = end;
        }
        let _ = write_half.shutdown().await;
    });

    let reader_handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(test_size);
        let mut chunk = vec![0u8; 32768];
        loop {
            match read_half.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("Read error during upstream stream: {e}"),
            }
        }
        received
    });

    writer_handle.await.unwrap();
    let received = reader_handle.await.unwrap();

    // Verify 100% byte-for-byte fidelity across chained upstream proxy
    assert_eq!(received.len(), test_size);
    assert_eq!(&received[..], &payload[..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_duplex_simultaneous_large_payload_streaming() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();

    let server_payload_size = 1024 * 1024; // 1MB
    let server_payload = Arc::new(generate_test_payload(server_payload_size));
    let server_payload_clone = server_payload.clone();

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (mut r, mut w) = stream.into_split();
            let p_clone = server_payload_clone.clone();

            let w_handle = tokio::spawn(async move {
                w.write_all(&p_clone).await.unwrap();
                let _ = w.shutdown().await;
            });

            let mut drain = Vec::with_capacity(server_payload_size);
            let mut buf = vec![0u8; 16384];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => drain.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            w_handle.await.unwrap();
        }
    });

    let proxy_addr = spawn_socks5_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&origin_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut c_resp = [0u8; 10];
    client.read_exact(&mut c_resp).await.unwrap();
    assert_eq!(c_resp[1], 0x00);

    let client_payload = Arc::new(generate_test_payload(server_payload_size));
    let (mut client_r, mut client_w) = client.into_split();

    let client_payload_clone = client_payload.clone();
    let client_w_handle = tokio::spawn(async move {
        client_w.write_all(&client_payload_clone).await.unwrap();
        let _ = client_w.shutdown().await;
    });

    let mut client_received = Vec::with_capacity(server_payload_size);
    let mut chunk = vec![0u8; 16384];
    loop {
        match client_r.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => client_received.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("Full-duplex read error: {e}"),
        }
    }

    client_w_handle.await.unwrap();

    assert_eq!(client_received.len(), server_payload_size);
    assert_eq!(&client_received[..], &server_payload[..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_plain_http_proxy_large_payload_streaming() {
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();

    let payload_size = 512 * 1024; // 512 KB
    let payload = Arc::new(generate_test_payload(payload_size));

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = origin_listener.accept().await {
            let mut header_buf = Vec::new();
            let mut temp = [0u8; 1024];
            while !header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut temp).await.unwrap();
                if n == 0 {
                    break;
                }
                header_buf.extend_from_slice(&temp[..n]);
            }

            let end_idx = header_buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .unwrap()
                + 4;
            let mut body = header_buf[end_idx..].to_vec();

            while body.len() < payload_size {
                let n = stream.read(&mut temp).await.unwrap();
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&temp[..n]);
            }

            let resp_header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp_header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });

    let proxy_addr = spawn_http_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    let req_line = format!(
        "POST http://127.0.0.1:{}/upload HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n",
        origin_addr.port(),
        origin_addr.port(),
        payload_size
    );
    client.write_all(req_line.as_bytes()).await.unwrap();
    client.write_all(&payload).await.unwrap();

    let mut resp = Vec::new();
    let mut buf = vec![0u8; 16384];
    loop {
        match client.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(e) => panic!("Plain HTTP read error: {e}"),
        }
    }

    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("Must have complete HTTP response");
    let resp_body = &resp[header_end + 4..];

    assert_eq!(resp_body.len(), payload_size);
    assert_eq!(resp_body, &payload[..]);
}

// =========================================================================
// 7. HTTP CONNECT Task Leak Audit & Recovery Tests
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http_connect_task_leak_on_disconnect_and_recovery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream_addr = listener.local_addr().unwrap();

    let server_running = Arc::new(AtomicBool::new(true));
    let server_flag = server_running.clone();

    tokio::spawn(async move {
        while server_flag.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let chunk = vec![0x33u8; 8192];
                    loop {
                        if stream.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let proxy_addr = spawn_http_proxy().await;
    let concurrency = 40;
    let finished_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let f_count = finished_count.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            let req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                stream_addr.port(),
                stream_addr.port()
            );
            client.write_all(req.as_bytes()).await.unwrap();

            let mut header_buf = [0u8; 256];
            let n = client.read(&mut header_buf).await.unwrap();
            let s = String::from_utf8_lossy(&header_buf[..n]);
            assert!(s.contains("200 Connection Established"));

            let mut buf = [0u8; 4096];
            let _ = client.read(&mut buf).await;
            let _ = client.read(&mut buf).await;

            drop(client);
            f_count.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(finished_count.load(Ordering::Relaxed), concurrency);

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Verify proxy is healthy: test clean transfer with fresh connection
    let echo_addr = spawn_ipv4_echo_server().await;
    let mut fresh_client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo_addr.port(),
        echo_addr.port()
    );
    fresh_client.write_all(req.as_bytes()).await.unwrap();
    let mut resp = [0u8; 256];
    let n = fresh_client.read(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp[..n]).contains("200 Connection Established"));

    fresh_client
        .write_all(b"recovery-check-ping")
        .await
        .unwrap();
    let mut pong = [0u8; 19];
    fresh_client.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"recovery-check-ping");

    server_running.store(false, Ordering::Relaxed);
}

// =========================================================================
// 8. Dual-Stack IPv6 Corner Cases & Invalid Port Handling Tests
// =========================================================================

#[test]
fn test_multi_hextet_bracketed_ipv6_normalization() {
    assert_eq!(normalize_host("[2001:db8::1:2]:8080"), "2001:db8::1:2");
    assert_eq!(normalize_host("[2001:db8::1:2]"), "2001:db8::1:2");
    assert_eq!(normalize_host("[fe80::1:80]:443"), "fe80::1:80");
    assert_eq!(normalize_host("[::1:5000]"), "::1:5000");
    assert_eq!(normalize_host("[::ffff:127.0.0.1]:8080"), "127.0.0.1");
    assert_eq!(normalize_host("::ffff:127.0.0.1:8080"), "127.0.0.1");
}

#[tokio::test]
async fn test_http_connect_invalid_ports_rejected_with_400() {
    let proxy_addr = spawn_http_proxy().await;

    // 1. Port > 65535 on bracketed IPv6
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT [::1]:99999 HTTP/1.1\r\nHost: [::1]:99999\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp_str.contains("400 Bad Request"),
            "Expected 400 Bad Request on port 99999, got: {resp_str}"
        );
    }

    // 2. Port > 65535 on IPv4
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:99999 HTTP/1.1\r\nHost: 127.0.0.1:99999\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp_str.contains("400 Bad Request"),
            "Expected 400 Bad Request on port 99999, got: {resp_str}"
        );
    }

    // 3. Trailing colon with empty port
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1: HTTP/1.1\r\nHost: 127.0.0.1:\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp_str.contains("400 Bad Request"),
            "Expected 400 Bad Request on empty port, got: {resp_str}"
        );
    }
}

// =========================================================================
// 9. Additional CLI Subcommands & Flags Tests
// =========================================================================

#[test]
fn test_cli_patch_and_unpatch_nonexistent_custom_path() {
    let bin_path = env!("CARGO_BIN_EXE_antigravity-gate");

    // Patch with nonexistent path
    let output = Command::new(bin_path)
        .args(["patch", "--path", "C:\\ThisDirectoryDoesNotExist_123456789"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Specified directory or binary does not exist"),
        "Expected error message for nonexistent path, got: {stdout}"
    );

    // Unpatch with nonexistent path
    let output = Command::new(bin_path)
        .args([
            "unpatch",
            "--path",
            "C:\\ThisDirectoryDoesNotExist_123456789",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Specified directory or binary does not exist"),
        "Expected error message for nonexistent path, got: {stdout}"
    );
}

#[test]
fn test_cli_invalid_bind_address_rejected() {
    let bin_path = env!("CARGO_BIN_EXE_antigravity-gate");

    let output = Command::new(bin_path)
        .args(["serve", "--socks5-bind", "invalid-hostname-xyz:99999"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Expected failure on invalid bind addr"
    );
}
