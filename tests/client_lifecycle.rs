//! The provider drives the real client, in real time, against a loopback TCP
//! listener that records each handshake request and then hangs up. No
//! WebSocket is established: the tests check what reaches the handshake, and
//! that a cancelled attempt reaches none (AUTH-03, AUTH-04).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use useceleris_client::{
    CelerisError, Channel, ChannelState, Client, ClientOptions, CredentialProvider, ProviderError,
};
use useceleris_server::{
    ChannelScope, Claims, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
    credential_provider,
};

fn scoped_claims() -> Claims {
    Claims::new(
        ChannelScope::Restricted(vec!["room-1".to_owned()]),
        SegmentPermissions::Restricted(vec![SegmentClaim {
            segment_id: "messages".to_owned(),
            read: true,
            write: false,
        }]),
    )
} // end fn scoped_claims

/// A signer with a fixed clock that counts its reads.
fn counting_signer() -> (Signer, Arc<AtomicU64>) {
    let reads = Arc::new(AtomicU64::new(0));
    let clock_reads = Arc::clone(&reads);

    let signer = Signer::new(SignerOptions {
        client_id: "synthetic-client".to_owned(),
        signing_secret: "synthetic-secret".to_owned(),
        clock: Some(Arc::new(move || {
            clock_reads.fetch_add(1, Ordering::SeqCst);

            UNIX_EPOCH + Duration::from_millis(123_456_789)
        })),
    })
    .unwrap();

    (signer, reads)
} // end fn counting_signer

/// Accepts connections, sends the request line of each handshake, and hangs
/// up.
async fn handshake_recorder() -> (u16, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];

            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                }
            }

            let text = String::from_utf8_lossy(&request);
            let request_line = text.lines().next().unwrap_or_default().to_owned();
            let _ = sender.send(request_line);
        }
    });

    (port, receiver)
} // end fn handshake_recorder

fn channel(port: u16, provider: CredentialProvider) -> Channel {
    let client = Client::new(ClientOptions {
        base_url: Some(format!("ws://127.0.0.1:{port}")),
        allow_insecure_loopback: true,
        connect_timeout: Some(Duration::from_secs(5)),
        ..ClientOptions::new(provider)
    })
    .unwrap();

    client.channel("room-1").unwrap()
} // end fn channel

/// Encodes a query value as an HTML form does, as the client does.
fn form_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            b' ' => "+".to_owned(),
            other => format!("%{other:02X}"),
        })
        .collect()
} // end fn form_encode

/// A provider whose claims signal when they start and then never finish.
fn pending_provider(signer: Signer, entered: Arc<Notify>) -> CredentialProvider {
    credential_provider(signer, move |_request| {
        let entered = Arc::clone(&entered);

        async move {
            entered.notify_one();

            std::future::pending().await
        }
    })
} // end fn pending_provider

#[tokio::test]
async fn the_signed_credentials_reach_the_handshake_encoded_once() {
    let (port, mut handshakes) = handshake_recorder().await;
    let (signer, _reads) = counting_signer();
    let expected = signer.sign(&scoped_claims()).unwrap();
    let channel = channel(
        port,
        credential_provider(signer, |_request| async { Ok(scoped_claims()) }),
    );

    let outcome = channel.connect().await;

    assert!(
        matches!(outcome, Err(CelerisError::Transport(_))),
        "{outcome:?}"
    );

    let request_line = handshakes.recv().await.unwrap();

    assert_eq!(
        request_line,
        format!(
            "GET /channel/room-1?payload={}&signature={} HTTP/1.1",
            form_encode(&expected.payload),
            form_encode(&expected.signature)
        )
    );

    channel.close().await;
} // end fn the_signed_credentials_reach_the_handshake_encoded_once

#[tokio::test]
async fn close_during_claims_cancels_without_signing_or_a_handshake() {
    let (port, mut handshakes) = handshake_recorder().await;
    let (signer, reads) = counting_signer();
    let entered = Arc::new(Notify::new());
    let channel = channel(port, pending_provider(signer, Arc::clone(&entered)));

    let connecting = tokio::spawn({
        let channel = channel.clone();

        async move { channel.connect().await }
    });

    entered.notified().await;
    channel.close().await;

    let outcome = connecting.await.unwrap();

    assert!(
        matches!(outcome, Err(CelerisError::Cancelled(_))),
        "{outcome:?}"
    );
    assert_eq!(channel.state(), ChannelState::Closed);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert!(handshakes.try_recv().is_err(), "a handshake started");
} // end fn close_during_claims_cancels_without_signing_or_a_handshake

#[tokio::test]
async fn a_dropped_connect_during_claims_fails_without_signing_or_a_handshake() {
    let (port, mut handshakes) = handshake_recorder().await;
    let (signer, reads) = counting_signer();
    let entered = Arc::new(Notify::new());
    let channel = channel(port, pending_provider(signer, Arc::clone(&entered)));

    tokio::select! {
        _ = channel.connect() => panic!("connect finished"),
        () = entered.notified() => {}
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(channel.state(), ChannelState::Failed);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert!(handshakes.try_recv().is_err(), "a handshake started");

    channel.close().await;
} // end fn a_dropped_connect_during_claims_fails_without_signing_or_a_handshake

#[tokio::test]
async fn a_claims_failure_surfaces_only_a_fixed_safe_error() {
    let (port, mut handshakes) = handshake_recorder().await;
    let (signer, reads) = counting_signer();
    let channel = channel(
        port,
        credential_provider(signer, |_request| async {
            Err::<Claims, ProviderError>("synthetic-secret claims failure".into())
        }),
    );

    let outcome = channel.connect().await;

    match &outcome {
        Err(CelerisError::Transport(message)) => {
            assert!(!message.contains("synthetic-secret"), "{message}");
        }
        other => panic!("got {other:?}"),
    }

    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert!(handshakes.try_recv().is_err(), "a handshake started");

    channel.close().await;
} // end fn a_claims_failure_surfaces_only_a_fixed_safe_error
