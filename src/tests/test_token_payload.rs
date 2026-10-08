use std::time::Duration;

use crate::claims::{ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions};
use crate::token_payload::{token_payload, write_json_string};

fn quoted(text: &str) -> String {
    let mut buffer = String::new();
    write_json_string(&mut buffer, text);

    buffer
} // end fn quoted

// AUTH-01: the exact payload bytes, key order included.
#[test]
fn writes_the_token_payload_layout() {
    let cases = [
        (
            Claims::new(
                ChannelScope::Restricted(vec!["room-1".to_owned()]),
                SegmentPermissions::Restricted(Vec::new()),
            ),
            r#"{"timestamp":5,"channel_references":["room-1"],"token_permission":[],"replay":false,"allow_echo":false}"#,
        ),
        (
            Claims {
                reference: Some("<u&>".to_owned()),
                replay: Replay::Backlog,
                allow_echo: true,
                ..Claims::new(
                    ChannelScope::All,
                    SegmentPermissions::All {
                        read: true,
                        write: false,
                    },
                )
            },
            r#"{"timestamp":5,"reference":"<u&>","channel_references":null,"token_permission":{"read":true,"write":false},"replay":true,"allow_echo":true}"#,
        ),
        (
            Claims {
                replay: Replay::Lookback(Duration::ZERO),
                ..Claims::new(
                    ChannelScope::All,
                    SegmentPermissions::Restricted(vec![SegmentClaim {
                        segment_id: "a".to_owned(),
                        read: false,
                        write: true,
                    }]),
                )
            },
            r#"{"timestamp":5,"channel_references":null,"token_permission":[{"segment_id":"a","read":false,"write":true}],"replay":0,"allow_echo":false}"#,
        ),
        (
            Claims {
                replay: Replay::Lookback(Duration::from_millis(4_294_967_295)),
                ..Claims::new(
                    ChannelScope::Restricted(vec!["a".to_owned(), "b".to_owned()]),
                    SegmentPermissions::Restricted(vec![
                        SegmentClaim {
                            segment_id: "x".to_owned(),
                            read: true,
                            write: true,
                        },
                        SegmentClaim {
                            segment_id: "y".to_owned(),
                            read: false,
                            write: false,
                        },
                    ]),
                )
            },
            r#"{"timestamp":5,"channel_references":["a","b"],"token_permission":[{"segment_id":"x","read":true,"write":true},{"segment_id":"y","read":false,"write":false}],"replay":4294967295,"allow_echo":false}"#,
        ),
    ];

    for (claims, expected) in cases {
        assert_eq!(token_payload(5, &claims), expected);
    }
} // end fn writes_the_token_payload_layout

// Written by hand from the JSON.stringify algorithm, never by this code.
#[test]
fn escapes_exactly_as_json_stringify_does() {
    let controls = [
        "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
        "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r", "\\u000e", "\\u000f", "\\u0010", "\\u0011",
        "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017", "\\u0018", "\\u0019",
        "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
    ];

    for (code, escape) in controls.iter().enumerate() {
        let character = char::from(u8::try_from(code).unwrap());

        assert_eq!(quoted(&character.to_string()), format!("\"{escape}\""));
    }

    assert_eq!(quoted(""), r#""""#);
    assert_eq!(quoted("\"\\/"), r#""\"\\/""#);
    assert_eq!(
        quoted("</script>&\u{7f}\u{85}\u{2028}\u{2029}\u{feff}😀雪"),
        "\"</script>&\u{7f}\u{85}\u{2028}\u{2029}\u{feff}😀雪\""
    );
} // end fn escapes_exactly_as_json_stringify_does

// Every quoted text decodes back to itself, and only the quote, the backslash
// and the control characters grow.
#[test]
fn quoted_text_decodes_back_to_itself() {
    let samples = (0u32..0x3000)
        .chain([
            0xd7ff, 0xe000, 0xfeff, 0xfffd, 0xffff, 0x1_0000, 0x1_f600, 0x10_ffff,
        ])
        .filter_map(char::from_u32);

    for character in samples {
        let text = format!("a{character}b");
        let quoted_text = quoted(&text);
        let decoded: String = serde_json::from_str(&quoted_text).unwrap();

        assert_eq!(decoded, text);

        let escaped = character < ' ' || character == '"' || character == '\\';

        if !escaped {
            assert_eq!(quoted_text.len(), text.len() + 2, "{character:?} grew");
        }
    }
} // end fn quoted_text_decodes_back_to_itself
