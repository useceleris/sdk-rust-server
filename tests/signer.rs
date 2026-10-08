//! The signer: fresh timestamps (D-001), option validation, and the clock's
//! range (AUTH-01).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use useceleris_client::CelerisError;
use useceleris_server::{
    ChannelScope, Claims, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
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

fn options(clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> SignerOptions {
    SignerOptions {
        client_id: "synthetic-client".to_owned(),
        signing_secret: "synthetic-secret".to_owned(),
        clock: Some(Arc::new(clock)),
    }
} // end fn options

fn at(milliseconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(milliseconds)
} // end fn at

fn configuration_message(error: CelerisError) -> String {
    match error {
        CelerisError::Configuration(message) => message,
        other => panic!("got {other:?}, want a configuration error"),
    }
} // end fn configuration_message

#[test]
fn signing_uses_a_fresh_timestamp_each_time() {
    let timestamp = Arc::new(AtomicU64::new(123_456_789));
    let clock_timestamp = Arc::clone(&timestamp);
    let signer = Signer::new(options(move || {
        at(clock_timestamp.fetch_add(1, Ordering::SeqCst))
    }))
    .unwrap();

    let first = signer.sign(&scoped_claims()).unwrap();
    let second = signer.sign(&scoped_claims()).unwrap();

    assert_ne!(first, second);
    assert_eq!(timestamp.load(Ordering::SeqCst), 123_456_791);

    let echo = Claims {
        allow_echo: true,
        ..scoped_claims()
    };

    assert_ne!(signer.sign(&echo).unwrap(), second);
} // end fn signing_uses_a_fresh_timestamp_each_time

#[test]
fn a_changed_secret_or_client_id_signs_differently() {
    let reference = Signer::new(options(|| at(5))).unwrap();
    let base = reference.sign(&scoped_claims()).unwrap();

    let other_secret = Signer::new(SignerOptions {
        signing_secret: "other-secret".to_owned(),
        ..options(|| at(5))
    })
    .unwrap();

    let other_client = Signer::new(SignerOptions {
        client_id: "other-client".to_owned(),
        ..options(|| at(5))
    })
    .unwrap();

    let secret_signed = other_secret.sign(&scoped_claims()).unwrap();
    let client_signed = other_client.sign(&scoped_claims()).unwrap();

    assert_eq!(secret_signed.payload, base.payload);
    assert_ne!(secret_signed.signature, base.signature);
    assert_eq!(client_signed.payload, base.payload);
    assert_ne!(client_signed.signature, base.signature);
} // end fn a_changed_secret_or_client_id_signs_differently

#[test]
fn signer_options_are_validated() {
    let cases = [
        (
            "",
            "",
            "Invalid signer options. client_id: Must not be empty. signing_secret: Must not be empty.",
        ),
        (
            "a:b",
            "s",
            "Invalid signer options. client_id: Must not contain a colon, CR or LF.",
        ),
        (
            "a\r",
            "s",
            "Invalid signer options. client_id: Must not contain a colon, CR or LF.",
        ),
        (
            "a\n",
            "s",
            "Invalid signer options. client_id: Must not contain a colon, CR or LF.",
        ),
        (
            "synthetic-secret:",
            "",
            "Invalid signer options. client_id: Must not contain a colon, CR or LF. signing_secret: Must not be empty.",
        ),
    ];

    for (client_id, signing_secret, expected) in cases {
        let error = Signer::new(SignerOptions {
            client_id: client_id.to_owned(),
            signing_secret: signing_secret.to_owned(),
            clock: None,
        })
        .unwrap_err();

        let message = configuration_message(error);

        assert_eq!(message, expected);
        assert!(!message.contains("synthetic-secret"));
    }
} // end fn signer_options_are_validated

#[test]
fn every_non_empty_secret_and_well_formed_client_id_is_accepted() {
    for (client_id, signing_secret) in [("c", "s"), ("client-雪", "secret-雪 :\r\n")] {
        let signer = Signer::new(SignerOptions {
            client_id: client_id.to_owned(),
            signing_secret: signing_secret.to_owned(),
            clock: None,
        });

        assert!(signer.is_ok(), "{client_id:?} refused");
    }
} // end fn every_non_empty_secret_and_well_formed_client_id_is_accepted

#[test]
fn invalid_claims_are_refused_before_the_clock_is_read() {
    let reads = Arc::new(AtomicU64::new(0));
    let clock_reads = Arc::clone(&reads);
    let signer = Signer::new(options(move || {
        clock_reads.fetch_add(1, Ordering::SeqCst);

        at(1)
    }))
    .unwrap();

    let error = signer
        .sign(&Claims::new(
            ChannelScope::Restricted(Vec::new()),
            SegmentPermissions::All {
                read: true,
                write: true,
            },
        ))
        .unwrap_err();

    assert_eq!(
        configuration_message(error),
        "Invalid claims. channels: Must list at least one channel reference."
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
} // end fn invalid_claims_are_refused_before_the_clock_is_read

#[test]
fn a_clock_outside_the_servers_range_is_refused() {
    let moments = [
        UNIX_EPOCH,
        UNIX_EPOCH + Duration::from_micros(999),
        UNIX_EPOCH - Duration::from_millis(5),
        at(253_402_300_800_000),
        UNIX_EPOCH + Duration::from_secs(18_446_744_073_709_552),
    ];

    for moment in moments {
        let error = Signer::new(options(move || moment))
            .unwrap()
            .sign(&scoped_claims())
            .unwrap_err();

        assert_eq!(
            configuration_message(error),
            "Invalid timestamp from clock. Must be between 1 and 253402300799999 milliseconds."
        );
    }

    for milliseconds in [1, 253_402_300_799_999] {
        let signer = Signer::new(options(move || at(milliseconds))).unwrap();

        assert!(
            signer.sign(&scoped_claims()).is_ok(),
            "{milliseconds} refused"
        );
    }
} // end fn a_clock_outside_the_servers_range_is_refused

#[test]
fn the_signer_defaults_to_the_wall_clock() {
    let signer = Signer::new(SignerOptions {
        clock: None,
        ..options(|| at(1))
    })
    .unwrap();

    let credentials = signer.sign(&scoped_claims()).unwrap();

    assert!(!credentials.payload.is_empty());
    assert!(!credentials.signature.is_empty());
} // end fn the_signer_defaults_to_the_wall_clock

#[test]
fn caller_changes_after_construction_change_nothing() {
    let claims = scoped_claims();
    let mut caller_options = options(|| at(123_456_789));
    let signer = Signer::new(caller_options.clone()).unwrap();
    let before = signer.sign(&claims).unwrap();

    caller_options.signing_secret = "changed".to_owned();
    caller_options.client_id = "changed".to_owned();

    assert_eq!(signer.sign(&claims).unwrap(), before);
    assert_eq!(signer.clone().sign(&claims).unwrap(), before);
} // end fn caller_changes_after_construction_change_nothing

#[test]
fn a_signer_can_be_shared_between_threads() {
    fn assert_shareable<Value: Clone + Send + Sync + 'static>() {}

    assert_shareable::<Signer>();
    assert_shareable::<SignerOptions>();

    let signer = Signer::new(options(|| at(42))).unwrap();
    let expected = signer.sign(&scoped_claims()).unwrap();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let signer = signer.clone();

            std::thread::spawn(move || signer.sign(&scoped_claims()).unwrap())
        })
        .collect();

    for handle in handles {
        assert_eq!(handle.join().unwrap(), expected);
    }
} // end fn a_signer_can_be_shared_between_threads
