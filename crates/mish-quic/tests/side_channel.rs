//! The reliable **side-channel** primitive over a real QUIC connection: a
//! bidirectional stream carrying length-prefixed request/response messages,
//! alongside (and independent of) the unreliable datagram path. This is the
//! plumbing that scrollback, large clipboard, and port-forwarding build on.

use std::time::Duration;

use mish_quic::transport;
use mish_ssp::framing::{read_message, write_message, MAX_MESSAGE_LEN};

/// A server that answers one side-channel request by echoing it back, framed.
async fn echo_server(server_ep: quinn::Endpoint) {
    let t = transport::accept(&server_ep).await.unwrap();
    loop {
        let (mut send, mut recv) = match t.accept_side_channel().await {
            Ok(s) => s,
            Err(_) => break,
        };
        // Serve each accepted stream concurrently (here, trivially inline).
        let req = read_message(&mut recv, MAX_MESSAGE_LEN)
            .await
            .unwrap()
            .expect("a framed request");
        let mut resp = b"echo:".to_vec();
        resp.extend_from_slice(&req);
        write_message(&mut send, &resp).await.unwrap();
        send.finish().unwrap();
    }
}

#[tokio::test]
async fn side_channel_round_trips_over_quic() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let server_task = tokio::spawn(echo_server(server_ep));

    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();

    // Open a reliable side-channel and round-trip a request/response.
    let (mut send, mut recv) = t.open_side_channel().await.unwrap();
    write_message(&mut send, b"history?").await.unwrap();
    send.finish().unwrap();

    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        read_message(&mut recv, MAX_MESSAGE_LEN),
    )
    .await
    .expect("a timely response")
    .unwrap()
    .expect("a framed response");
    assert_eq!(resp, b"echo:history?");

    server_task.abort();
}

/// The whole point of a *reliable* side-channel: deliver a payload far larger
/// than a single QUIC datagram, intact and in order (the datagram path would
/// have to fragment + heal it; the stream just works).
#[tokio::test]
async fn side_channel_carries_large_payload() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let server_task = tokio::spawn(echo_server(server_ep));

    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();

    // 256 KiB — orders of magnitude past the ~1200-byte datagram limit.
    let big: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let (mut send, mut recv) = t.open_side_channel().await.unwrap();
    write_message(&mut send, &big).await.unwrap();
    send.finish().unwrap();

    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        read_message(&mut recv, MAX_MESSAGE_LEN),
    )
    .await
    .expect("a timely response")
    .unwrap()
    .expect("a framed response");
    assert_eq!(resp.len(), big.len() + 5);
    assert_eq!(&resp[..5], b"echo:");
    assert_eq!(&resp[5..], &big[..]);

    server_task.abort();
}
