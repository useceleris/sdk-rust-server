//! A trusted backend process that signs its own credentials and connects to
//! realtime through the client. Use this pattern for a backend worker, not
//! for a browser. The signing secret never leaves this process.
//!
//! Run it with `CELERIS_WS_URL`, `CELERIS_CLIENT_ID` and
//! `CELERIS_SIGNING_SECRET` set:
//!
//! ```sh
//! cargo run --example quickstart
//! ```

use std::env;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use useceleris_client::{Client, ClientOptions, CredentialReason, CredentialRequest, text_payload};
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentPermissions, Signer, SignerOptions, credential_provider,
};

/// Decides the claims for each connection attempt. The claims are
/// authoritative: nothing in the request makes them wider.
pub fn claims_for(request: CredentialRequest) -> Claims {
    let mut claims = Claims {
        reference: Some("server-quickstart".to_owned()),
        // This connection receives its own publishes.
        allow_echo: true,
        ..Claims::new(
            ChannelScope::Restricted(vec![request.channel_reference]),
            SegmentPermissions::All {
                read: true,
                write: true,
            },
        )
    };

    // On a reconnect, catch up on what the outage missed.
    if let CredentialReason::Reconnect {
        replay_lookback, ..
    } = request.reason
    {
        claims.replay = Replay::Lookback(replay_lookback);
    }

    claims
} // end fn claims_for

/// Connects, publishes one job and counts the deliveries that come back.
pub async fn run(
    websocket_url: String,
    signer: Signer,
) -> Result<usize, Box<dyn Error + Send + Sync>> {
    let provider = credential_provider(signer, |request| async move { Ok(claims_for(request)) });

    let client = Client::new(ClientOptions {
        base_url: Some(websocket_url),
        // A local ws:// stack. Production uses the built-in wss:// endpoint.
        allow_insecure_loopback: true,
        ..ClientOptions::new(provider)
    })?;

    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let channel = client.channel(&format!("server-quickstart-{started}"))?;

    channel.connect().await?;

    let jobs = channel.segment("jobs")?;
    let delivered = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&delivered);

    jobs.on_message(move |_payload, _metadata| {
        counter.fetch_add(1, Ordering::SeqCst);
    });

    let subscription = jobs.subscribe()?;

    tokio::time::sleep(Duration::from_secs(1)).await;
    jobs.publish(text_payload("job-1 done")).await?;

    for _ in 0..60 {
        if delivered.load(Ordering::SeqCst) > 0 {
            break;
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    subscription.cancel();
    channel.close().await;

    Ok(delivered.load(Ordering::SeqCst))
} // end fn run

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let signer = Signer::new(SignerOptions {
        client_id: env::var("CELERIS_CLIENT_ID")?,
        signing_secret: env::var("CELERIS_SIGNING_SECRET")?,
        clock: None,
    })?;

    let delivered = run(env::var("CELERIS_WS_URL")?, signer).await?;

    println!("example: ok delivered={delivered}");

    Ok(())
} // end fn main
