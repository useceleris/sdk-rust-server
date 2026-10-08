use crate::claims::{ChannelScope, Claims, Replay, SegmentPermissions};

/// Writes the token payload exactly as the reference signer's
/// `JSON.stringify` does, with the same key order, so that the same claims
/// sign to the same bytes in every SDK.
pub(crate) fn token_payload(timestamp: u128, claims: &Claims) -> String {
    let mut buffer = format!("{{\"timestamp\":{timestamp}");

    if let Some(reference) = &claims.reference {
        buffer.push_str(",\"reference\":");
        write_json_string(&mut buffer, reference);
    }

    buffer.push_str(",\"channel_references\":");

    match &claims.channels {
        ChannelScope::All => buffer.push_str("null"),
        ChannelScope::Restricted(references) => {
            buffer.push('[');

            for (index, reference) in references.iter().enumerate() {
                if index > 0 {
                    buffer.push(',');
                }

                write_json_string(&mut buffer, reference);
            }

            buffer.push(']');
        }
    }

    buffer.push_str(",\"token_permission\":");

    match &claims.permissions {
        SegmentPermissions::All { read, write } => {
            buffer.push_str(&format!("{{\"read\":{read},\"write\":{write}}}"));
        }
        SegmentPermissions::Restricted(segments) => {
            buffer.push('[');

            for (index, segment) in segments.iter().enumerate() {
                if index > 0 {
                    buffer.push(',');
                }

                buffer.push_str("{\"segment_id\":");
                write_json_string(&mut buffer, &segment.segment_id);
                buffer.push_str(&format!(
                    ",\"read\":{},\"write\":{}}}",
                    segment.read, segment.write
                ));
            }

            buffer.push(']');
        }
    }

    buffer.push_str(",\"replay\":");

    match claims.replay {
        Replay::None => buffer.push_str("false"),
        Replay::Backlog => buffer.push_str("true"),
        Replay::Lookback(lookback) => buffer.push_str(&lookback.as_millis().to_string()),
    }

    buffer.push_str(&format!(",\"allow_echo\":{}}}", claims.allow_echo));

    buffer
} // end fn token_payload

/// Quotes text as `JSON.stringify` does. It escapes the quote, the backslash
/// and the control characters below U+0020, and writes all other characters
/// as they are, `<`, `>`, `&`, U+2028 and U+2029 included.
pub(crate) fn write_json_string(buffer: &mut String, text: &str) {
    const HEXADECIMAL: &[u8; 16] = b"0123456789abcdef";

    buffer.push('"');

    for character in text.chars() {
        match character {
            '"' => buffer.push_str("\\\""),
            '\\' => buffer.push_str("\\\\"),
            '\u{8}' => buffer.push_str("\\b"),
            '\u{c}' => buffer.push_str("\\f"),
            '\n' => buffer.push_str("\\n"),
            '\r' => buffer.push_str("\\r"),
            '\t' => buffer.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let code = control as usize;

                buffer.push_str("\\u00");
                buffer.push(HEXADECIMAL[code >> 4] as char);
                buffer.push(HEXADECIMAL[code & 0xf] as char);
            }
            other => buffer.push(other),
        }
    }

    buffer.push('"');
} // end fn write_json_string
