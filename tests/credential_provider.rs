//! The bridge to the client's credential provider: fresh claims and a fresh
//! timestamp per attempt (D-001, AUTH-03), errors returned unchanged, and a
//! dropped attempt that signs nothing (AUTH-04).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::Notify;
use useceleris_client::{
    CelerisError, CredentialReason, CredentialRequest, Credentials, ProviderError,
};
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
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

/// A signer whose clock counts its reads, so a test can tell if it signed.
fn counting_signer() -> (Signer, Arc<AtomicU64>) {
    let reads = Arc::new(AtomicU64::new(0));
    let clock_reads = Arc::clone(&reads);

    let signer = Signer::new(SignerOptions {
        client_id: "synthetic-client".to_owned(),
        signing_secret: "synthetic-secret".to_owned(),
        clock: Some(Arc::new(move || -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_000 + clock_reads.fetch_add(1, Ordering::SeqCst))
        })),
    })
    .unwrap();

    (signer, reads)
} // end fn counting_signer

fn initial(channel_reference: &str) -> CredentialRequest {
    CredentialRequest {
        channel_reference: channel_reference.to_owned(),
        reason: CredentialReason::Initial,
    }
} // end fn initial

fn reconnect(channel_reference: &str, replay_lookback: Duration) -> CredentialRequest {
    CredentialRequest {
        channel_reference: channel_reference.to_owned(),
        reason: CredentialReason::Reconnect {
            disconnected_at: UNIX_EPOCH + Duration::from_secs(1),
            replay_lookback,
        },
    }
} // end fn reconnect

fn decoded_payload(credentials: &Credentials) -> String {
    String::from_utf8(STANDARD.decode(&credentials.payload).unwrap()).unwrap()
} // end fn decoded_payload

#[derive(Debug)]
struct SyntheticFailure;

impl fmt::Display for SyntheticFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("synthetic claims failure")
    } // end method fmt
} // end impl Display for SyntheticFailure

impl std::error::Error for SyntheticFailure {}

#[tokio::test]
async fn the_provider_calls_claims_and_signs_afresh_each_attempt() {
    let (signer, reads) = counting_signer();
    let calls = Arc::new(AtomicU64::new(0));
    let claims_calls = Arc::clone(&calls);

    let provider = credential_provider(signer, move |_request| {
        claims_calls.fetch_add(1, Ordering::SeqCst);

        async { Ok(scoped_claims()) }
    });

    let first = provider.provide(initial("room-1")).await.unwrap();
    let second = provider.provide(initial("room-1")).await.unwrap();

    assert_ne!(first, second);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
} // end fn the_provider_calls_claims_and_signs_afresh_each_attempt

#[tokio::test]
async fn claims_decide_replay_from_the_reconnect_request() {
    let (signer, _reads) = counting_signer();

    let provider = credential_provider(signer, |request: CredentialRequest| async move {
        let mut claims = scoped_claims();

        if let CredentialReason::Reconnect {
            replay_lookback, ..
        } = request.reason
        {
            claims.replay = Replay::Lookback(replay_lookback.min(Duration::from_secs(30)));
        }

        Ok(claims)
    });

    let cases = [
        (initial("room-1"), r#""replay":false"#),
        (
            reconnect("room-1", Duration::from_millis(6_500)),
            r#""replay":6500"#,
        ),
        (
            reconnect("room-1", Duration::from_secs(3_600)),
            r#""replay":30000"#,
        ),
    ];

    for (request, expected) in cases {
        let credentials = provider.provide(request).await.unwrap();
        let payload = decoded_payload(&credentials);

        assert!(payload.contains(expected), "{payload}");
    }
} // end fn claims_decide_replay_from_the_reconnect_request

#[tokio::test(start_paused = true)]
async fn a_dropped_attempt_never_signs() {
    let (signer, reads) = counting_signer();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let claims_entered = Arc::clone(&entered);
    let claims_release = Arc::clone(&release);

    let provider = credential_provider(signer, move |_request| {
        let entered = Arc::clone(&claims_entered);
        let release = Arc::clone(&claims_release);

        async move {
            entered.notify_one();
            release.notified().await;

            Ok(scoped_claims())
        }
    });

    let attempt = tokio::time::timeout(Duration::from_secs(1), provider.provide(initial("room-1")));
    let (outcome, ()) = tokio::join!(attempt, entered.notified());

    assert!(outcome.is_err(), "the attempt finished");

    release.notify_waiters();
    tokio::task::yield_now().await;

    assert_eq!(reads.load(Ordering::SeqCst), 0);
} // end fn a_dropped_attempt_never_signs

#[tokio::test]
async fn a_claims_error_passes_through_unchanged_without_signing() {
    let (signer, reads) = counting_signer();

    let provider = credential_provider(signer, |_request| async {
        Err::<Claims, ProviderError>(Box::new(SyntheticFailure))
    });

    let error = provider.provide(initial("room-1")).await.unwrap_err();

    assert!(
        error.downcast_ref::<SyntheticFailure>().is_some(),
        "{error}"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
} // end fn a_claims_error_passes_through_unchanged_without_signing

#[tokio::test]
async fn request_fields_never_widen_the_claims() {
    let (signer, _reads) = counting_signer();
    let provider = credential_provider(signer, |_request| async { Ok(scoped_claims()) });

    let credentials = provider
        .provide(reconnect("admin-room", Duration::from_secs(3_600)))
        .await
        .unwrap();

    let payload = decoded_payload(&credentials);

    assert!(!payload.contains("admin-room"), "{payload}");
    assert!(
        payload.contains(r#""channel_references":["room-1"]"#),
        "{payload}"
    );
    assert!(payload.contains(r#""replay":false"#), "{payload}");
} // end fn request_fields_never_widen_the_claims

#[tokio::test]
async fn invalid_claims_from_the_callback_give_the_signers_error() {
    let (signer, reads) = counting_signer();

    let provider = credential_provider(signer, |_request| async {
        Ok(Claims::new(
            ChannelScope::Restricted(Vec::new()),
            SegmentPermissions::Restricted(Vec::new()),
        ))
    });

    let error = provider.provide(initial("room-1")).await.unwrap_err();

    assert_eq!(
        error.downcast_ref::<CelerisError>(),
        Some(&CelerisError::Configuration(
            "Invalid claims. channels: Must list at least one channel reference.".to_owned()
        ))
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
} // end fn invalid_claims_from_the_callback_give_the_signers_error

#[tokio::test]
async fn providers_share_no_credential_state() {
    let (signer, _reads) = counting_signer();
    let first = credential_provider(signer.clone(), |_request| async { Ok(scoped_claims()) });
    let second = credential_provider(signer, |_request| async { Ok(scoped_claims()) });

    let from_first = first.provide(initial("room-1")).await.unwrap();
    let from_second = second.provide(initial("room-1")).await.unwrap();
    let from_clone = first.clone().provide(initial("room-1")).await.unwrap();

    assert_ne!(from_first, from_second);
    assert_ne!(from_second, from_clone);
} // end fn providers_share_no_credential_state
