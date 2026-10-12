//! Bidirectional raw byte streaming tunnel.

use std::io;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

pub async fn pipe_bidirectional(
    mut client: TcpStream,
    mut remote: TcpStream,
    initial_payload: Option<&[u8]>,
) -> io::Result<(u64, u64)> {
    let initial_len = initial_payload.map(|d| d.len() as u64).unwrap_or(0);
    if let Some(data) = initial_payload {
        if !data.is_empty() {
            if let Err(e) = remote.write_all(data).await {
                let _ = client.shutdown().await;
                let _ = remote.shutdown().await;
                return Err(e);
            }
        }
    }

    let res = copy_bidirectional(&mut client, &mut remote).await;
    let _ = client.shutdown().await;
    let _ = remote.shutdown().await;

    let (from_client, from_remote) = res?;
    let total_from_client = from_client + initial_len;
    debug!(
        bytes_sent = total_from_client,
        bytes_received = from_remote,
        "Tunnel closed"
    );

    Ok((total_from_client, from_remote))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_pipe_bidirectional_with_initial_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 10];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"prefixtest");
            stream.write_all(b"responseok").await.unwrap();
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let pipe_handle = tokio::spawn(async move {
            let (client_stream, _) = client_listener.accept().await.unwrap();
            let remote_stream = TcpStream::connect(addr).await.unwrap();
            pipe_bidirectional(client_stream, remote_stream, Some(b"prefix"))
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client.write_all(b"test").await.unwrap();
        let mut resp = [0u8; 10];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"responseok");

        drop(client);
        let (sent, recv) = pipe_handle.await.unwrap();
        assert_eq!(sent, 10);
        assert_eq!(recv, 10);
    }
}
