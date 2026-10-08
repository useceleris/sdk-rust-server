//! Configuration and helpers that the live suites share.

use std::fs;
use std::future::Future;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use useceleris_client::{
    CelerisError, Channel, Client, ClientOptions, CredentialRequest, ProviderError, ServerErrorType,
};
use useceleris_server::{
    ChannelScope, Claims, SegmentPermissions, Signer, SignerOptions, credential_provider,
};

static CHANNEL_COUNTER: AtomicU64 = AtomicU64::new(0);

static REACHABLE: OnceLock<()> = OnceLock::new();

/// Reads one setting: the environment first, then the crate's `.env` file. It
/// fails when the setting is missing, and never shows a value.
pub fn setting(name: &str) -> String {
    if let Ok(value) = std::env::var(name) {
        return value;
    }

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let text = fs::read_to_string(path).unwrap_or_default();

    for line in text.lines() {
        let line = line.trim();

        if line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=')
            && key.trim() == name
        {
            let value = value.trim().trim_matches(['\'', '"']);

            if !value.is_empty() {
                return value.to_owned();
            }
        }
    }

    panic!(
        "{name} is not set. Put CELERIS_WS_URL, CELERIS_CLIENT_ID and CELERIS_SIGNING_SECRET in the crate's .env file (git ignores it) or in the environment."
    );
} // end fn setting

/// The realtime URL, after one check that the stack is reachable.
pub fn websocket_url() -> String {
    let url = setting("CELERIS_WS_URL");

    REACHABLE.get_or_init(|| {
        let (secure, rest) = match url.split_once("://") {
            Some(("wss", rest)) => (true, rest),
            Some(("ws", rest)) => (false, rest),
            _ => panic!("CELERIS_WS_URL is not a ws:// or wss:// URL."),
        };

        let host = rest.split('/').next().unwrap_or_default();
        let address = if host.contains(':') && !host.ends_with(']') {
            host.to_owned()
        } else {
            format!("{host}:{}", if secure { 443 } else { 80 })
        };

        let reachable = address.to_socket_addrs().ok().and_then(|mut addresses| {
            addresses.find(|socket_address| {
                TcpStream::connect_timeout(socket_address, Duration::from_secs(5)).is_ok()
            })
        });

        assert!(
            reachable.is_some(),
            "The realtime service at {host} is not reachable. Start the stack, or point CELERIS_WS_URL elsewhere."
        );
    });

    url
} // end fn websocket_url

/// The qualification credentials. A test can change them.
pub fn signer_options() -> SignerOptions {
    SignerOptions {
        client_id: setting("CELERIS_CLIENT_ID"),
        signing_secret: setting("CELERIS_SIGNING_SECRET"),
        clock: None,
    }
} // end fn signer_options

pub fn unique_channel_reference(label: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let count = CHANNEL_COUNTER.fetch_add(1, Ordering::SeqCst);

    format!("rustqual-server-{label}-{now}-{count}")
} // end fn unique_channel_reference

/// Claims that grant every segment of one channel.
pub fn all_permission_claims(reference: &str) -> Claims {
    Claims::new(
        ChannelScope::Restricted(vec![reference.to_owned()]),
        SegmentPermissions::All {
            read: true,
            write: true,
        },
    )
} // end fn all_permission_claims

pub fn client_for(provider: useceleris_client::CredentialProvider) -> Client {
    Client::new(ClientOptions {
        base_url: Some(websocket_url()),
        allow_insecure_loopback: true,
        ..ClientOptions::new(provider)
    })
    .unwrap()
} // end fn client_for

pub fn qualification_client<ClaimsFor, Decided>(options: SignerOptions, claims: ClaimsFor) -> Client
where
    ClaimsFor: Fn(CredentialRequest) -> Decided + Send + Sync + 'static,
    Decided: Future<Output = Result<Claims, ProviderError>> + Send + 'static,
{
    let signer = Signer::new(options).unwrap();

    client_for(credential_provider(signer, claims))
} // end fn qualification_client

/// A claims function that always gives the same claims.
pub fn fixed_claims(
    claims: Claims,
) -> impl Fn(CredentialRequest) -> std::future::Ready<Result<Claims, ProviderError>>
+ Send
+ Sync
+ 'static {
    move |_request| std::future::ready(Ok(claims.clone()))
} // end fn fixed_claims

pub async fn connected_channel(reference: &str, claims: Claims) -> Channel {
    let client = qualification_client(signer_options(), fixed_claims(claims));
    let channel = client.channel(reference).unwrap();

    channel.connect().await.unwrap();

    channel
} // end fn connected_channel

/// Waits for the first value that matches, or fails after the timeout.
pub async fn receive_matching<Value>(
    receiver: &mut mpsc::UnboundedReceiver<Value>,
    predicate: impl Fn(&Value) -> bool,
    description: &str,
    timeout: Duration,
) -> Value {
    let waiting = async {
        loop {
            let value = receiver
                .recv()
                .await
                .expect("the listener stays registered");

            if predicate(&value) {
                return value;
            }
        }
    };

    tokio::time::timeout(timeout, waiting)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {description}"))
} // end fn receive_matching

/// Sends the channel's errors to a receiver.
pub fn errors(channel: &Channel) -> mpsc::UnboundedReceiver<CelerisError> {
    let (sender, receiver) = mpsc::unbounded_channel();

    channel.events().on_error(move |error| {
        let _ = sender.send(error.clone());
    });

    receiver
} // end fn errors

pub fn is_server_error(error: &CelerisError, error_type: &ServerErrorType) -> bool {
    matches!(error, CelerisError::Server(server_error) if &server_error.error_type == error_type)
} // end fn is_server_error
