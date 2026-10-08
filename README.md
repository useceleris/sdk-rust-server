# Celeris Rust server

[![Documentation](https://docs.rs/useceleris-server/badge.svg)](https://docs.rs/useceleris-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/useceleris/sdk-rust-server/blob/main/LICENSE)

This crate signs Celeris credentials on a trusted server. Your server authenticates its user. It decides what the user can do, and it signs those claims. Clients connect with the result through [useceleris-client](https://crates.io/crates/useceleris-client) or a different Celeris SDK.

## How it fits

1. Your application asks your credential endpoint for credentials.
2. The endpoint authenticates the user, decides the claims, and signs them with this crate.
3. The application connects with the credentials. It never sees the signing secret.

A trusted backend that connects to realtime itself does not need the endpoint. It signs its own credentials. Refer to [A backend that connects to realtime](#a-backend-that-connects-to-realtime).

## Install

```toml
[dependencies]
useceleris-client = "0.1"
useceleris-server = "0.1"
```

The crate needs Rust 1.88 or newer. It uses the client crate for `Credentials`, `CredentialProvider` and `CelerisError`. The client crate never uses this crate. Signing uses the RustCrypto `hmac` and `sha2` crates and the `base64` crate.

## Sign credentials

```rust,no_run
use std::time::Duration;

use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the values from trusted configuration, never from code.
    let signer = Signer::new(SignerOptions {
        client_id: std::env::var("CELERIS_CLIENT_ID")?,
        signing_secret: std::env::var("CELERIS_SIGNING_SECRET")?,
        clock: None,
    })?;

    // The claims that your server decided for a user that it authenticated.
    let credentials = signer.sign(&Claims {
        reference: Some("user-8317".to_owned()),
        replay: Replay::Lookback(Duration::from_secs(30)),
        ..Claims::new(
            ChannelScope::Restricted(vec!["room-42".to_owned()]),
            SegmentPermissions::Restricted(vec![SegmentClaim {
                segment_id: "chat".to_owned(),
                read: true,
                write: true,
            }]),
        )
    })?;

    // Return credentials.payload and credentials.signature from your endpoint.
    let _ = credentials;

    Ok(())
}
```

`sign` is synchronous. It uses the current time as the timestamp. Sign again for each request. Do not cache, reuse or backdate credentials. A `Signer` is cheap to clone, and you can share it between threads.

## Claims

Authenticate and authorize the user before you choose their claims. Never sign permissions that a client asked for. `Claims` has no default, so you must choose the channels and the permissions. Unrestricted access is always an explicit choice.

| Field         | Values                                                                                                       | `Claims::new` gives |
| ------------- | ------------------------------------------------------------------------------------------------------------ | ------------------- |
| `channels`    | `ChannelScope::All`, or `ChannelScope::Restricted(references)`: 1 to 255 ASCII letters, digits, `-` or `_`   | (required)          |
| `permissions` | `SegmentPermissions::All { read, write }`, or `SegmentPermissions::Restricted(segments)`. No segments gives no access | (required) |
| `reference`   | The identity that peers see in deliveries and presence. It must not be empty and must not contain a colon, CR or LF | `None`        |
| `replay`      | `Replay::None`, `Replay::Backlog` for all the history that the server keeps, or `Replay::Lookback(duration)` in whole milliseconds, 0 to 4294967295 | `Replay::None` |
| `allow_echo`  | If `true`, a connection receives its own publishes                                                           | `false`             |

The server replays history each time the connection joins a segment. `Replay::Lookback(Duration::ZERO)` is different from `Replay::None`: it replays nothing older than the join.

## A credential endpoint

Each browser or mobile application needs a credential endpoint. This function, from [examples/credential_endpoint.rs](https://github.com/useceleris/sdk-rust-server/blob/main/examples/credential_endpoint.rs), does not need a web framework. It authorizes the channel, decides the claims, and signs them:

```rust
use std::time::Duration;

use useceleris_server::{ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer};

/// The user that your authentication found.
pub struct User {
    pub id: String,
    pub rooms: Vec<String>,
    pub moderator: bool,
}

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
}
```

Your web framework finds the user from its session, reads a small request body, and calls the function. The user never comes from the request body. Limit the size of the request body, and set a deadline for the request headers.

## A backend that connects to realtime

`credential_provider` changes a signer into the client's `CredentialProvider`, for a trusted server that connects itself. For each connection attempt, it calls your claims function again and signs with a new timestamp. Nothing in the request makes the claims wider.

```rust,no_run
use useceleris_client::{Client, ClientOptions, CredentialReason};
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentPermissions, Signer, SignerOptions, credential_provider,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Signer::new(SignerOptions {
        client_id: std::env::var("CELERIS_CLIENT_ID")?,
        signing_secret: std::env::var("CELERIS_SIGNING_SECRET")?,
        clock: None,
    })?;

    let provider = credential_provider(signer, |request| async move {
        let mut claims = Claims::new(
            ChannelScope::Restricted(vec![request.channel_reference]),
            SegmentPermissions::All {
                read: true,
                write: true,
            },
        );

        // On a reconnect, catch up on what the outage missed.
        if let CredentialReason::Reconnect {
            replay_lookback, ..
        } = request.reason
        {
            claims.replay = Replay::Lookback(replay_lookback);
        }

        Ok(claims)
    });

    let client = Client::new(ClientOptions::new(provider))?;
    let _ = client;

    Ok(())
}
```

[examples/quickstart.rs](https://github.com/useceleris/sdk-rust-server/blob/main/examples/quickstart.rs) shows the full flow as a program. If the claims function fails or gives invalid claims, `Channel::connect` gives a general `CelerisError::Transport`. To see which rule failed, sign the claims directly with `Signer::sign`.

## Errors

Invalid options or claims give `CelerisError::Configuration`. The message names each field and rule that failed, but never the value:

```rust
use useceleris_client::CelerisError;
use useceleris_server::{ChannelScope, Claims, SegmentPermissions, Signer, SignerOptions};

let signer = Signer::new(SignerOptions {
    client_id: "synthetic-client".to_owned(),
    signing_secret: "synthetic-secret".to_owned(),
    clock: None,
})
.unwrap();

let error = signer
    .sign(&Claims {
        reference: Some("user:8317".to_owned()),
        ..Claims::new(
            ChannelScope::Restricted(vec!["room-42".to_owned(), "room-42".to_owned()]),
            SegmentPermissions::All {
                read: true,
                write: false,
            },
        )
    })
    .unwrap_err();

assert_eq!(
    error,
    CelerisError::Configuration(
        "Invalid claims. channels: Must not repeat a channel reference. \
         reference: Must not contain a colon, CR or LF."
            .to_owned()
    )
);
```

Rust text is always valid UTF-8, so the signed bytes are always the text that you gave. For the same claims, the signed bytes are equal to the bytes of the JavaScript reference signer. Shared signing vectors prove this.

## Keeping the secret

The signing secret is the trust boundary. Keep it on trusted servers. Never ship the secret, or this crate, in an application. A `Signer` keeps the secret only inside its HMAC state. `Debug` shows `SignerOptions`, `Signer` and `Credentials` as redacted. The crate does not print or log.

## Versioning

Releases follow semantic versioning. Before version 1.0.0, a minor release can change the API.

## More documentation

- [Crate reference](https://docs.rs/useceleris-server)
- [Authentication](https://useceleris.com/docs/getting-started/authentication), for how credentials work in all SDKs

## Development

`make check` runs rustfmt, clippy, the unit and integration tests, and the documentation build. The tests include the signing vectors, the layout and surface checks, and every Rust snippet in this README. `make live` runs the acceptance suites against a real Celeris stack. They read `CELERIS_WS_URL`, `CELERIS_CLIENT_ID` and `CELERIS_SIGNING_SECRET` from the environment or from a `.env` file that git ignores.

Read [CONVENTIONS.md](https://github.com/useceleris/sdk-rust-server/blob/main/CONVENTIONS.md) before you contribute. Read [SECURITY.md](https://github.com/useceleris/sdk-rust-server/blob/main/SECURITY.md) before you report a vulnerability.

## License

[Apache 2.0](https://github.com/useceleris/sdk-rust-server/blob/main/LICENSE).
