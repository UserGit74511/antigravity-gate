//! Fuzzing and malformed input test suite for antigravity-gate.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use antigravity_gate::http::run_http_server;
use antigravity_gate::pool::SniPool;
use antigravity_gate::router::Router;
use antigravity_gate::sni::{is_tls_handshake, parse_sni};
use antigravity_gate::socks5::run_socks5_server;

/// Helper to spin up a local SOCKS5 server instance.
async fn spawn_test_socks5_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new(SniPool::new(), None, vec![]);
    tokio::spawn(async move {
        let _ = run_socks5_server(listener, router).await;
    });
    addr
}

/// Helper to spin up a local HTTP proxy instance.
async fn spawn_test_http_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new(SniPool::new(), None, vec![]);
    tokio::spawn(async move {
        let _ = run_http_server(listener, router).await;
    });
    addr
}

#[tokio::test]
async fn test_socks5_garbage_handshake() {
    let server_addr = spawn_test_socks5_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // Send garbage binary bytes
    client
        .write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02])
        .await
        .unwrap();

    let mut buf = [0u8; 16];
    let res = client.read(&mut buf).await;
    // Server must reject garbage gracefully (EOF or error)
    assert!(res.is_err() || res.unwrap() == 0);
}

#[tokio::test]
async fn test_socks5_truncated_handshakes() {
    let server_addr = spawn_test_socks5_server().await;

    // Test truncated greeting: send only 1 byte (VER=5) then close
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(&[0x05]).await.unwrap();
        drop(client);
    }

    // Test truncated methods: send VER=5, NMETHODS=2, but only 1 method byte then close
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(&[0x05, 0x02, 0x00]).await.unwrap();
        drop(client);
    }

    // Test truncated request header: complete greeting, then send 2 bytes of request then close
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        client.write_all(&[0x05, 0x01]).await.unwrap(); // incomplete request
        drop(client);
    }
}

#[tokio::test]
async fn test_socks5_unsupported_commands_and_atyp() {
    let server_addr = spawn_test_socks5_server().await;

    // 1. Unsupported command BIND (0x02)
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // CMD=0x02 (BIND), RSV=0x00, ATYP=0x01 (IPv4: 127.0.0.1:80)
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut cmd_resp = [0u8; 10];
        client.read_exact(&mut cmd_resp).await.unwrap();
        // REP should be 0x07 (Command not supported)
        assert_eq!(cmd_resp[1], 0x07);
    }

    // 2. Unsupported address type (0x02 or 0xFF)
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // CMD=0x01 (CONNECT), RSV=0x00, ATYP=0xFF (invalid)
        client.write_all(&[0x05, 0x01, 0x00, 0xFF]).await.unwrap();
        let mut cmd_resp = [0u8; 10];
        client.read_exact(&mut cmd_resp).await.unwrap();
        // REP should be 0x08 (Address type not supported)
        assert_eq!(cmd_resp[1], 0x08);
    }
}

#[tokio::test]
async fn test_socks5_zero_length_domain() {
    let server_addr = spawn_test_socks5_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    // ATYP=0x03, domain len=0
    client
        .write_all(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xbb])
        .await
        .unwrap();
    let mut cmd_resp = [0u8; 10];
    let res = client.read(&mut cmd_resp).await;
    assert!(res.is_err() || res.unwrap() == 0);
}

#[tokio::test]
async fn test_http_oversized_headers_rejected() {
    let server_addr = spawn_test_http_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // Send headers exceeding 16KB limit
    let huge_header = "X-Padding: ".to_string() + &"A".repeat(17000) + "\r\n\r\n";
    let req = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{huge_header}");
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = [0u8; 512];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("431 Request Header Fields Too Large"));
}

#[tokio::test]
async fn test_http_malformed_request_line() {
    let server_addr = spawn_test_http_server().await;

    // 1. Single token request line
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client.write_all(b"JUST_ONE_TOKEN\r\n\r\n").await.unwrap();
        let mut resp = [0u8; 256];
        let n = client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400 Bad Request"));
    }

    // 2. Binary junk
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client
            .write_all(&[0xDE, 0xAD, 0xBE, 0xEF, b'\r', b'\n', b'\r', b'\n'])
            .await
            .unwrap();
        let mut resp = [0u8; 256];
        let n = client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400 Bad Request"));
    }

    // 3. Missing host header in relative GET
    {
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        client
            .write_all(b"GET /index.html HTTP/1.1\r\nUser-Agent: test\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 256];
        let n = client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400 Bad Request"));
    }
}

#[tokio::test]
async fn test_http_connect_empty_host() {
    let server_addr = spawn_test_http_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // CONNECT with empty target host
    client
        .write_all(b"CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n")
        .await
        .unwrap();
    let mut resp = [0u8; 256];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("400 Bad Request"));
}

#[tokio::test]
async fn test_slowloris_handshake_timeout() {
    let server_addr = spawn_test_http_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // Send 1 byte of HTTP request and do not send anything else
    client.write_all(b"G").await.unwrap();

    // Handshake timeout is 5s, wait for server to close with 408 Request Timeout
    let mut resp = [0u8; 256];
    let read_result = tokio::time::timeout(Duration::from_secs(7), client.read(&mut resp)).await;

    assert!(
        read_result.is_ok(),
        "Server should timeout stalled client within 5s"
    );
    let n = read_result.unwrap().unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("408 Request Timeout"));
}

#[tokio::test]
async fn test_fuzz_sni_parser_arbitrary_byte_sequences() {
    // Generate pseudo-random permutations of TLS headers and ensure zero panics
    for len in 0..128 {
        let mut buf = vec![0x16, 0x03, 0x01];
        buf.extend(vec![0xAA; len]);
        let _ = is_tls_handshake(&buf);
        let _ = parse_sni(&buf);
    }

    // Non-TLS content types (0x15 Alert, 0x17 Application Data)
    let alert_record = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32];
    assert!(!is_tls_handshake(&alert_record));
    assert_eq!(parse_sni(&alert_record), None);
}

#[tokio::test]
async fn test_socks5_connection_refused_returns_rep_05() {
    let server_addr = spawn_test_socks5_server().await;

    // Pick an unused port by binding and immediately dropping listener
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await.unwrap();
    assert_eq!(greeting_resp, [0x05, 0x00]);

    // CONNECT to the closed port
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&dead_port.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();
    // REP must be 0x05 (Connection Refused), NOT 0x00 (Success)
    assert_eq!(connect_resp[0], 0x05);
    assert_eq!(connect_resp[1], 0x05);
}

#[tokio::test]
async fn test_socks5_zero_port_rejected() {
    let server_addr = spawn_test_socks5_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await.unwrap();

    // CONNECT to port 0
    let req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0];
    client.write_all(&req).await.unwrap();

    let mut resp = [0u8; 10];
    let res = client.read(&mut resp).await;
    // Server must reject port 0 with error response or disconnect
    if let Ok(n) = res {
        if n >= 2 {
            assert_ne!(resp[1], 0x00, "Port 0 must not succeed");
        }
    }
}

#[tokio::test]
async fn test_http_connect_connection_refused_returns_502() {
    let server_addr = spawn_test_http_server().await;

    // Pick an unused port
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let req =
        format!("CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\nHost: 127.0.0.1:{dead_port}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = [0u8; 512];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    // Must return 502 Bad Gateway, NOT 200 Connection Established
    assert!(
        resp_str.contains("502 Bad Gateway"),
        "Expected 502 Bad Gateway on closed port, got: {resp_str}"
    );
}

#[tokio::test]
async fn test_http_connect_zero_port_rejected() {
    let server_addr = spawn_test_http_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();
    client
        .write_all(b"CONNECT 127.0.0.1:0 HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n")
        .await
        .unwrap();

    let mut resp = [0u8; 256];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("400 Bad Request"));
}

#[tokio::test]
async fn test_http_bare_lf_headers_succeeds() {
    // Spin up an origin HTTP server
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nbare_lf")
            .await
            .unwrap();
    });

    let server_addr = spawn_test_http_server().await;
    let mut client = TcpStream::connect(server_addr).await.unwrap();

    // Send HTTP request with bare \n\n instead of \r\n\r\n
    let bare_lf_req = format!(
        "GET http://127.0.0.1:{}/test HTTP/1.1\nHost: 127.0.0.1:{}\n\n",
        origin_addr.port(),
        origin_addr.port()
    );
    client.write_all(bare_lf_req.as_bytes()).await.unwrap();

    let mut resp = [0u8; 512];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("200 OK"));
    assert!(resp_str.contains("bare_lf"));
}
