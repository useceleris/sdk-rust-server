//! AUTH-01: fixed-clock signing vectors. Independent implementations produced
//! every expected payload and signature, and they are copied unchanged:
//! `testdata/shared-signing-vectors.json` holds the reference SDK's shared
//! vectors (Python's json, base64, hmac and hashlib, and the escapes vector
//! from the JavaScript reference signer), and
//! `testdata/reference-signing-vectors.json` holds the vectors that the
//! JavaScript reference signer generated.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::Value;
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
};

fn vectors(file: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(file);
    let text = fs::read_to_string(path).expect("the vectors file is readable");
    let parsed: Value = serde_json::from_str(&text).expect("the vectors file is JSON");

    parsed.as_array().expect("the vectors are a list").clone()
} // end fn vectors

fn text(value: &Value) -> String {
    value.as_str().expect("a JSON string").to_owned()
} // end fn text

/// Reads the reference's claims shape.
fn claims(vector: &Value) -> Claims {
    let channels = match vector["channels"]["kind"].as_str() {
        Some("restricted") => ChannelScope::Restricted(
            vector["channels"]["references"]
                .as_array()
                .expect("a list of references")
                .iter()
                .map(text)
                .collect(),
        ),
        _ => ChannelScope::All,
    };

    let permissions = match vector["permissions"]["kind"].as_str() {
        Some("all") => SegmentPermissions::All {
            read: vector["permissions"]["read"] == true,
            write: vector["permissions"]["write"] == true,
        },
        _ => SegmentPermissions::Restricted(
            vector["permissions"]["segments"]
                .as_array()
                .expect("a list of segments")
                .iter()
                .map(|segment| SegmentClaim {
                    segment_id: text(&segment["segmentId"]),
                    read: segment["read"] == true,
                    write: segment["write"] == true,
                })
                .collect(),
        ),
    };

    let replay = match &vector["replay"] {
        Value::Bool(true) => Replay::Backlog,
        Value::Object(lookback) => Replay::Lookback(Duration::from_millis(
            lookback["lookbackMs"].as_u64().expect("whole milliseconds"),
        )),
        _ => Replay::None,
    };

    Claims {
        reference: vector["reference"].as_str().map(str::to_owned),
        replay,
        allow_echo: vector["allowEcho"] == true,
        ..Claims::new(channels, permissions)
    }
} // end fn claims

#[test]
fn signs_every_independent_vector_byte_for_byte() {
    let mut all = vectors("shared-signing-vectors.json");
    all.extend(vectors("reference-signing-vectors.json"));

    assert_eq!(all.len(), 24);

    for vector in &all {
        let name = text(&vector["name"]);
        let timestamp = vector["timestamp"].as_u64().expect("a timestamp");

        let signer = Signer::new(SignerOptions {
            client_id: text(&vector["clientId"]),
            signing_secret: text(&vector["signingSecret"]),
            clock: Some(Arc::new(move || {
                UNIX_EPOCH + Duration::from_millis(timestamp)
            })),
        })
        .unwrap_or_else(|error| panic!("{name}: {error}"));

        let credentials = signer
            .sign(&claims(&vector["claims"]))
            .unwrap_or_else(|error| panic!("{name}: {error}"));

        assert_eq!(
            credentials.payload,
            text(&vector["expected"]["payload"]),
            "{name}: payload"
        );
        assert_eq!(
            credentials.signature,
            text(&vector["expected"]["signature"]),
            "{name}: signature"
        );
    }
} // end fn signs_every_independent_vector_byte_for_byte
