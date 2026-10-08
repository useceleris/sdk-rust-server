//! The credential endpoint that each browser or mobile application needs. It
//! does not use a web framework: your framework finds the user, reads a small
//! request body, and calls `credential_response`. The endpoint decides the
//! claims on the server. It never trusts a permission that the client asks
//! for.
//!
//! Run it with `CELERIS_CLIENT_ID` and `CELERIS_SIGNING_SECRET` set:
//!
//! ```sh
//! cargo run --example credential_endpoint
//! ```
//!
//! It sends three demonstration requests and prints only their HTTP status.

use std::env;
use std::time::Duration;

use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
};

/// The user that your authentication found.
pub struct User {
    pub id: String,
    pub rooms: Vec<String>,
    pub moderator: bool,
} // end struct User

/// Stands in for YOUR authentication: a session cookie, a bearer token or the
/// user of your framework. The user never comes from the request body.
pub fn authenticate(authorization: &str) -> Option<User> {
    if authorization != "Bearer demo-session" {
        return None;
    }

    Some(User {
        id: "user-8317".to_owned(),
        rooms: vec!["room-42".to_owned()],
        moderator: false,
    })
} // end fn authenticate

/// Gives the HTTP status and the JSON body for one credential request.
pub fn credential_response(
    signer: &Signer,
    user: Option<&User>,
    channel_reference: &str,
    replay_lookback_milliseconds: i64,
) -> (u16, String) {
    let Some(user) = user else {
        return (401, r#"{"error":"unauthenticated"}"#.to_owned());
    };

    // Authorize the requested channel against what the user can access.
    if !user.rooms.iter().any(|room| room == channel_reference) {
        return (403, r#"{"error":"forbidden"}"#.to_owned());
    }

    // An application policy: catch up on thirty seconds at most.
    let lookback = replay_lookback_milliseconds.clamp(0, 30_000).unsigned_abs();

    let claims = Claims {
        reference: Some(user.id.clone()),
        replay: Replay::Lookback(Duration::from_millis(lookback)),
        ..Claims::new(
            ChannelScope::Restricted(vec![channel_reference.to_owned()]),
            SegmentPermissions::Restricted(vec![
                SegmentClaim {
                    segment_id: "chat".to_owned(),
                    read: true,
                    write: user.moderator,
                },
                SegmentClaim {
                    segment_id: "presence".to_owned(),
                    read: true,
                    write: false,
                },
            ]),
        )
    };

    // Sign again for each request.
    match signer.sign(&claims) {
        // Base64 text needs no JSON escapes.
        Ok(credentials) => (
            200,
            format!(
                r#"{{"payload":"{}","signature":"{}"}}"#,
                credentials.payload, credentials.signature
            ),
        ),
        Err(_) => (500, r#"{"error":"signing failed"}"#.to_owned()),
    }
} // end fn credential_response

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Signer::new(SignerOptions {
        client_id: env::var("CELERIS_CLIENT_ID")?,
        signing_secret: env::var("CELERIS_SIGNING_SECRET")?,
        clock: None,
    })?;

    let requests = [
        ("unauthenticated", "Bearer wrong", "room-42"),
        ("forbidden", "Bearer demo-session", "other-room"),
        ("authorized", "Bearer demo-session", "room-42"),
    ];

    for (label, authorization, channel_reference) in requests {
        let user = authenticate(authorization);
        let (status, _body) = credential_response(&signer, user.as_ref(), channel_reference, 0);

        // The body holds credentials. Do not print or log it.
        println!("example: {label} status={status}");
    }

    Ok(())
} // end fn main
