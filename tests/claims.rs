//! AUTH-02: explicit scoped permissions, unrestricted access only by opt-in,
//! the empty allow-list refused, and the replay and echo defaults. Also every
//! validation rule, with its exact message.
//!
//! `Claims` has no default and its channels and permissions are not optional,
//! so the reference's "Required" rules cannot fail in Rust: the compiler
//! refuses claims without them. A `Duration` cannot be negative, so a lookback
//! below zero cannot be written either.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use useceleris_client::CelerisError;
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
};

fn signer() -> Signer {
    Signer::new(SignerOptions {
        client_id: "synthetic-client".to_owned(),
        signing_secret: "synthetic-secret".to_owned(),
        clock: Some(Arc::new(|| UNIX_EPOCH + Duration::from_millis(123_456_789))),
    })
    .unwrap()
} // end fn signer

fn signed_payload(claims: &Claims) -> String {
    let credentials = signer().sign(claims).unwrap();
    let decoded = STANDARD.decode(credentials.payload).unwrap();

    String::from_utf8(decoded).unwrap()
} // end fn signed_payload

fn refusal(claims: &Claims) -> String {
    match signer().sign(claims) {
        Err(CelerisError::Configuration(message)) => message,
        other => panic!("got {other:?}, want a configuration error"),
    }
} // end fn refusal

fn all_permissions() -> SegmentPermissions {
    SegmentPermissions::All {
        read: true,
        write: true,
    }
} // end fn all_permissions

fn channels(references: &[&str]) -> ChannelScope {
    ChannelScope::Restricted(references.iter().map(|text| text.to_string()).collect())
} // end fn channels

fn segment(segment_id: &str, read: bool, write: bool) -> SegmentClaim {
    SegmentClaim {
        segment_id: segment_id.to_owned(),
        read,
        write,
    }
} // end fn segment

#[test]
fn claims_new_gives_no_reference_no_replay_and_no_echo() {
    let claims = Claims::new(channels(&["room-1"]), all_permissions());

    assert_eq!(claims.reference, None);
    assert_eq!(claims.replay, Replay::None);
    assert!(!claims.allow_echo);
} // end fn claims_new_gives_no_reference_no_replay_and_no_echo

#[test]
fn a_deny_all_token_is_signed_with_explicit_defaults() {
    let claims = Claims::new(
        channels(&["room-1"]),
        SegmentPermissions::Restricted(Vec::new()),
    );

    assert_eq!(
        signed_payload(&claims),
        r#"{"timestamp":123456789,"channel_references":["room-1"],"token_permission":[],"replay":false,"allow_echo":false}"#
    );
} // end fn a_deny_all_token_is_signed_with_explicit_defaults

#[test]
fn unrestricted_access_is_signed_only_when_chosen() {
    let restricted = signed_payload(&Claims::new(
        channels(&["room-1"]),
        SegmentPermissions::Restricted(vec![segment("chat", true, false)]),
    ));

    assert!(restricted.contains(r#""channel_references":["room-1"]"#));
    assert!(
        restricted
            .contains(r#""token_permission":[{"segment_id":"chat","read":true,"write":false}]"#)
    );

    let unrestricted = signed_payload(&Claims::new(ChannelScope::All, all_permissions()));

    assert!(unrestricted.contains(r#""channel_references":null"#));
    assert!(unrestricted.contains(r#""token_permission":{"read":true,"write":true}"#));
} // end fn unrestricted_access_is_signed_only_when_chosen

#[test]
fn replay_and_echo_are_signed_as_chosen() {
    let cases = [
        (Replay::None, false, r#""replay":false,"allow_echo":false"#),
        (Replay::Backlog, true, r#""replay":true,"allow_echo":true"#),
        (
            Replay::Lookback(Duration::ZERO),
            false,
            r#""replay":0,"allow_echo":false"#,
        ),
        (
            Replay::Lookback(Duration::from_millis(6_500)),
            false,
            r#""replay":6500,"allow_echo":false"#,
        ),
    ];

    for (replay, allow_echo, expected) in cases {
        let payload = signed_payload(&Claims {
            replay,
            allow_echo,
            ..Claims::new(ChannelScope::All, all_permissions())
        });

        assert!(payload.ends_with(&format!("{expected}}}")), "{payload}");
    }
} // end fn replay_and_echo_are_signed_as_chosen

#[test]
fn claims_are_validated() {
    let cases = [
        (
            Claims::new(channels(&[]), all_permissions()),
            "Invalid claims. channels: Must list at least one channel reference.",
        ),
        (
            Claims::new(channels(&["a", "a"]), all_permissions()),
            "Invalid claims. channels: Must not repeat a channel reference.",
        ),
        (
            Claims::new(channels(&["ok", ""]), all_permissions()),
            "Invalid claims. channels[1]: Must not be empty.",
        ),
        (
            Claims::new(channels(&["x:y"]), all_permissions()),
            "Invalid claims. channels[0]: Must contain only ASCII letters, digits, hyphens (-) or underscores (_).",
        ),
        (
            Claims::new(channels(&["é"]), all_permissions()),
            "Invalid claims. channels[0]: Must contain only ASCII letters, digits, hyphens (-) or underscores (_).",
        ),
        (
            Claims::new(channels(&[&"x".repeat(256)]), all_permissions()),
            "Invalid claims. channels[0]: Must be at most 255 characters.",
        ),
        (
            Claims::new(
                ChannelScope::All,
                SegmentPermissions::Restricted(vec![segment("a\n", false, false)]),
            ),
            "Invalid claims. permissions[0].segment_id: Must not contain CR or LF.",
        ),
        (
            Claims::new(
                ChannelScope::All,
                SegmentPermissions::Restricted(vec![segment("a\r", false, false)]),
            ),
            "Invalid claims. permissions[0].segment_id: Must not contain CR or LF.",
        ),
        (
            Claims::new(
                ChannelScope::All,
                SegmentPermissions::Restricted(vec![segment("", false, false)]),
            ),
            "Invalid claims. permissions[0].segment_id: Must not be empty.",
        ),
        (
            Claims::new(
                ChannelScope::All,
                SegmentPermissions::Restricted(vec![
                    segment("s", true, false),
                    segment("s", false, true),
                ]),
            ),
            "Invalid claims. permissions: Must not repeat a segment ID.",
        ),
        (
            Claims {
                reference: Some("user:123".to_owned()),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. reference: Must not contain a colon, CR or LF.",
        ),
        (
            Claims {
                reference: Some("user\r".to_owned()),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. reference: Must not contain a colon, CR or LF.",
        ),
        (
            Claims {
                reference: Some("user\n".to_owned()),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. reference: Must not contain a colon, CR or LF.",
        ),
        (
            Claims {
                reference: Some(String::new()),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. reference: Must not be empty.",
        ),
        (
            Claims {
                replay: Replay::Lookback(Duration::from_millis(4_294_967_296)),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. replay: Lookback must be between 0 and 4294967295 milliseconds.",
        ),
        (
            Claims {
                replay: Replay::Lookback(Duration::from_micros(1_500)),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. replay: Lookback must be whole milliseconds.",
        ),
        (
            Claims {
                replay: Replay::Lookback(Duration::from_nanos(4_294_967_295_000_001)),
                ..Claims::new(ChannelScope::All, all_permissions())
            },
            "Invalid claims. replay: Lookback must be between 0 and 4294967295 milliseconds.",
        ),
    ];

    for (claims, expected) in cases {
        assert_eq!(refusal(&claims), expected);
    }
} // end fn claims_are_validated

#[test]
fn every_failure_is_named_in_order_without_its_value() {
    let claims = Claims {
        reference: Some("synthetic-reference:".to_owned()),
        replay: Replay::Lookback(Duration::from_nanos(1)),
        ..Claims::new(
            channels(&["synthetic-channel:", "synthetic-channel:", "ok", "ok"]),
            SegmentPermissions::Restricted(vec![
                segment("synthetic\nsegment", true, true),
                segment("", true, true),
            ]),
        )
    };

    let message = refusal(&claims);

    assert_eq!(
        message,
        "Invalid claims. \
         channels[0]: Must contain only ASCII letters, digits, hyphens (-) or underscores (_). \
         channels[1]: Must contain only ASCII letters, digits, hyphens (-) or underscores (_). \
         channels: Must not repeat a channel reference. \
         permissions[0].segment_id: Must not contain CR or LF. \
         permissions[1].segment_id: Must not be empty. \
         reference: Must not contain a colon, CR or LF. \
         replay: Lookback must be whole milliseconds."
    );
    assert!(!message.contains("synthetic"));
} // end fn every_failure_is_named_in_order_without_its_value

#[test]
fn valid_claims_across_their_range() {
    let valid = [
        Claims::new(
            channels(&["aZ09-_", &"x".repeat(255), "x"]),
            SegmentPermissions::Restricted(Vec::new()),
        ),
        Claims::new(
            ChannelScope::All,
            SegmentPermissions::Restricted(vec![segment(
                "s:with:colons 😀 \u{0} \t",
                false,
                false,
            )]),
        ),
        Claims {
            reference: Some("身分 😀".to_owned()),
            replay: Replay::Lookback(Duration::ZERO),
            ..Claims::new(
                ChannelScope::All,
                SegmentPermissions::All {
                    read: false,
                    write: false,
                },
            )
        },
        Claims {
            replay: Replay::Lookback(Duration::from_millis(4_294_967_295)),
            ..Claims::new(
                ChannelScope::All,
                SegmentPermissions::All {
                    read: true,
                    write: false,
                },
            )
        },
        Claims {
            replay: Replay::Backlog,
            allow_echo: true,
            ..Claims::new(
                ChannelScope::All,
                SegmentPermissions::All {
                    read: false,
                    write: true,
                },
            )
        },
    ];

    for (index, claims) in valid.iter().enumerate() {
        assert!(signer().sign(claims).is_ok(), "claims {index} refused");
    }
} // end fn valid_claims_across_their_range

#[test]
fn duplicate_segments_are_refused_not_merged() {
    let message = refusal(&Claims::new(
        ChannelScope::All,
        SegmentPermissions::Restricted(vec![
            segment("chat", true, false),
            segment("chat", false, true),
            segment("chat", true, true),
        ]),
    ));

    assert_eq!(
        message,
        "Invalid claims. permissions: Must not repeat a segment ID. permissions: Must not repeat a segment ID."
    );
} // end fn duplicate_segments_are_refused_not_merged
