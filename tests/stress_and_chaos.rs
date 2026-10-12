//! Concurrency, stress, and chaos network tests for antigravity-gate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use antigravity_gate::http::run_http_server;
use antigravity_gate::pool::SniPool;
use antigravity_gate::router::Router;
use antigravity_gate::socks5::run_socks5_server;

/// Spawns a high-performance echo server for stress testing.
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_extreme_concurrency_socks5() {
    let echo_addr = spawn_echo_server().await;
    let proxy_addr = spawn_socks5_proxy().await;

    let concurrency = 100;
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(concurrency);

    for i in 0..concurrency {
        let s_count = success_count.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();

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

            // 3. Send payload & read back
            let payload = format!("worker-socks5-{i}-data-payload-chunk");
            client.write_all(payload.as_bytes()).await.unwrap();

            let mut echo_buf = vec![0u8; payload.len()];
            client.read_exact(&mut echo_buf).await.unwrap();
            assert_eq!(echo_buf, payload.as_bytes());

            s_count.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(success_count.load(Ordering::Relaxed), concurrency);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_extreme_concurrency_http_connect() {
    let echo_addr = spawn_echo_server().await;
    let proxy_addr = spawn_http_proxy().await;

    let concurrency = 100;
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(concurrency);

    for i in 0..concurrency {
        let s_count = success_count.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();

            // 1. HTTP CONNECT request
            let req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                echo_addr.port(),
                echo_addr.port()
            );
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp_buf = [0u8; 1024];
            let n = client.read(&mut resp_buf).await.unwrap();
            let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
            assert!(resp_str.contains("200 Connection Established"));

            // 2. Stream data
            let payload = format!("worker-http-connect-{i}-data-payload-chunk");
            client.write_all(payload.as_bytes()).await.unwrap();

            let mut echo_buf = vec![0u8; payload.len()];
            client.read_exact(&mut echo_buf).await.unwrap();
            assert_eq!(echo_buf, payload.as_bytes());

            s_count.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(success_count.load(Ordering::Relaxed), concurrency);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chaos_client_abrupt_disconnects() {
    let echo_addr = spawn_echo_server().await;
    let proxy_addr = spawn_socks5_proxy().await;

    let concurrency = 50;
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut greeting_resp = [0u8; 2];
            client.read_exact(&mut greeting_resp).await.unwrap();

            let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&echo_addr.port().to_be_bytes());
            client.write_all(&req).await.unwrap();

            let mut connect_resp = [0u8; 10];
            client.read_exact(&mut connect_resp).await.unwrap();

            // Send partial data then abruptly drop/RST client socket
            client.write_all(b"partial-data").await.unwrap();
            drop(client);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    // Verify proxy is still healthy after 50 abrupt client disconnects
    let mut test_client = TcpStream::connect(proxy_addr).await.unwrap();
    test_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    test_client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rapid_connection_burst_and_resource_cleanup() {
    let echo_addr = spawn_echo_server().await;
    let proxy_addr = spawn_http_proxy().await;

    // Burst 150 rapid connections that connect, write 1 byte, and abort immediately
    let burst_count = 150;
    let mut handles = Vec::with_capacity(burst_count);

    for _ in 0..burst_count {
        handles.push(tokio::spawn(async move {
            if let Ok(mut client) = TcpStream::connect(proxy_addr).await {
                let _ = client.write_all(b"X").await;
                drop(client);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    // Allow tokio runtime to reap closed tasks
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify proxy continues to serve valid requests normally
    let mut healthy_client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo_addr.port(),
        echo_addr.port()
    );
    healthy_client.write_all(req.as_bytes()).await.unwrap();
    let mut resp = [0u8; 512];
    let n = healthy_client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("200 Connection Established"));
}

#[tokio::test]
async fn test_plain_http_proxy_with_query_string() {
    // Spin up an HTTP server that echoes the received request line
    let http_echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_echo_addr = http_echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = http_echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let req_str = String::from_utf8_lossy(&buf[..n]);
        // Send back HTTP 200 with the request line in body
        let body = req_str.lines().next().unwrap_or("").to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let proxy_addr = spawn_http_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // Absolute URI with query string: http://127.0.0.1:PORT/search?query=antigravity
    let abs_req = format!(
        "GET http://127.0.0.1:{}/search?query=antigravity HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        http_echo_addr.port(),
        http_echo_addr.port()
    );
    client.write_all(abs_req.as_bytes()).await.unwrap();

    let mut resp = [0u8; 1024];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("200 OK"));
    // Verify that the query string was preserved during URL rewrite!
    assert!(resp_str.contains("GET /search?query=antigravity HTTP/1.1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chaos_remote_server_abrupt_rst() {
    // Spin up a server that accepts a connection and immediately closes/drops it
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = dead_listener.accept().await {
            // Abruptly drop socket immediately upon connection
            drop(stream);
        }
    });

    let proxy_addr = spawn_socks5_proxy().await;

    // Client connects to the abrupt server through SOCKS5
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&dead_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();

    // Now write payload into the dead tunnel; should gracefully terminate without panic
    let _ = client.write_all(b"payload-to-dead-server").await;
    let mut read_buf = [0u8; 128];
    let res = client.read(&mut read_buf).await;
    // Client sees EOF or connection reset cleanly
    assert!(res.is_err() || res.unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chaos_half_close_streaming() {
    // Server reads request until EOF, then replies
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = server_listener.accept().await.unwrap();
        let mut full_body = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break, // EOF reached on read half
                Ok(n) => full_body.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        assert_eq!(&full_body, b"full-client-payload-before-half-close");
        stream
            .write_all(b"server-response-after-half-close")
            .await
            .unwrap();
    });

    let proxy_addr = spawn_socks5_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&server_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();

    // Send payload then shutdown writing half (TCP FIN)
    client
        .write_all(b"full-client-payload-before-half-close")
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    // Read response from server
    let mut reply = [0u8; 32];
    let n = client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..n], b"server-response-after-half-close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mixed_traffic_storm() {
    let echo_addr = spawn_echo_server().await;
    let socks5_addr = spawn_socks5_proxy().await;
    let http_addr = spawn_http_proxy().await;

    let valid_socks5_success = Arc::new(AtomicUsize::new(0));
    let valid_http_success = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    // 25 valid SOCKS5 clients
    for i in 0..25 {
        let sc = valid_socks5_success.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(socks5_addr).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut g = [0u8; 2];
            client.read_exact(&mut g).await.unwrap();

            let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&echo_addr.port().to_be_bytes());
            client.write_all(&req).await.unwrap();

            let mut cr = [0u8; 10];
            client.read_exact(&mut cr).await.unwrap();

            let data = format!("storm-socks5-{i}");
            client.write_all(data.as_bytes()).await.unwrap();
            let mut echo = vec![0u8; data.len()];
            client.read_exact(&mut echo).await.unwrap();
            assert_eq!(echo, data.as_bytes());
            sc.fetch_add(1, Ordering::Relaxed);
        }));
    }

    // 25 valid HTTP CONNECT clients
    for i in 0..25 {
        let hc = valid_http_success.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let req = format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                echo_addr.port(),
                echo_addr.port()
            );
            client.write_all(req.as_bytes()).await.unwrap();
            let mut buf = [0u8; 512];
            let n = client.read(&mut buf).await.unwrap();
            let s = String::from_utf8_lossy(&buf[..n]);
            assert!(s.contains("200 Connection Established"));

            let data = format!("storm-http-{i}");
            client.write_all(data.as_bytes()).await.unwrap();
            let mut echo = vec![0u8; data.len()];
            client.read_exact(&mut echo).await.unwrap();
            assert_eq!(echo, data.as_bytes());
            hc.fetch_add(1, Ordering::Relaxed);
        }));
    }

    // 25 garbage attackers sending random noise to both proxies
    for _ in 0..25 {
        handles.push(tokio::spawn(async move {
            if let Ok(mut c) = TcpStream::connect(socks5_addr).await {
                let _ = c.write_all(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).await;
            }
            if let Ok(mut c) = TcpStream::connect(http_addr).await {
                let _ = c.write_all(b"RANDOM_JUNK_NOT_HTTP\r\n\r\n").await;
            }
        }));
    }

    // 25 slowloris / partial disconnect clients
    for _ in 0..25 {
        handles.push(tokio::spawn(async move {
            if let Ok(mut c) = TcpStream::connect(http_addr).await {
                let _ = c.write_all(b"G").await;
                // Abruptly drop
                drop(c);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    // Assert that 100% of all valid clients succeeded despite chaos storm
    assert_eq!(valid_socks5_success.load(Ordering::Relaxed), 25);
    assert_eq!(valid_http_success.load(Ordering::Relaxed), 25);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chaos_high_concurrency_closed_port_error_fidelity() {
    let socks5_addr = spawn_socks5_proxy().await;
    let http_addr = spawn_http_proxy().await;

    // Pick an unused port
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let socks5_error_count = Arc::new(AtomicUsize::new(0));
    let http_error_count = Arc::new(AtomicUsize::new(0));
    let count = 30;
    let mut handles = Vec::with_capacity(count * 2);

    for _ in 0..count {
        let sc = socks5_error_count.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(socks5_addr).await.unwrap();
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut g = [0u8; 2];
            client.read_exact(&mut g).await.unwrap();

            let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&dead_port.to_be_bytes());
            client.write_all(&req).await.unwrap();

            let mut cr = [0u8; 10];
            client.read_exact(&mut cr).await.unwrap();
            if cr[1] == 0x05 {
                sc.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for _ in 0..count {
        let hc = http_error_count.clone();
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(http_addr).await.unwrap();
            let req = format!(
                "CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\nHost: 127.0.0.1:{dead_port}\r\n\r\n"
            );
            client.write_all(req.as_bytes()).await.unwrap();

            let mut buf = [0u8; 512];
            let n = client.read(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp.contains("502 Bad Gateway") {
                hc.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(socks5_error_count.load(Ordering::Relaxed), count);
    assert_eq!(http_error_count.load(Ordering::Relaxed), count);
}
