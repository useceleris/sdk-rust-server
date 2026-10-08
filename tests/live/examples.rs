//! The examples against the real stack.

use std::time::Duration;

use useceleris_client::{
    CelerisError, ChannelState, CredentialProvider, Credentials, ServerErrorType,
};
use useceleris_server::Signer;

use crate::credential_endpoint::{authenticate, credential_response};
use crate::quickstart::run;
use crate::support::{
    client_for, errors, is_server_error, receive_matching, signer_options, websocket_url,
};

#[tokio::test]
async fn runs_the_quickstart() {
    let signer = Signer::new(signer_options()).unwrap();
    let delivered = run(websocket_url(), signer).await.unwrap();

    assert!(delivered >= 1, "delivered {delivered}");
} // end fn runs_the_quickstart

// The endpoint authenticates and authorizes on the server, and its credentials
// drive a real connection: the demonstration user reads "chat" but cannot
// write to it.
#[tokio::test]
async fn mints_credentials_through_the_endpoint_and_connects_with_them() {
    let signer = Signer::new(signer_options()).unwrap();
    let demo_user = authenticate("Bearer demo-session");

    let (unauthenticated, _) =
        credential_response(&signer, authenticate("Bearer wrong").as_ref(), "room-42", 0);
    let (forbidden, _) = credential_response(&signer, demo_user.as_ref(), "other-room", 0);

    // The endpoint's policy clamps a lookback that the client asks for. It
    // does not refuse it.
    let (clamped, _) = credential_response(&signer, demo_user.as_ref(), "room-42", -1);

    assert_eq!((unauthenticated, forbidden, clamped), (401, 403, 200));

    let (status, body) = credential_response(&signer, demo_user.as_ref(), "room-42", 0);

    assert_eq!(status, 200);

    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let credentials = Credentials {
        payload: parsed["payload"].as_str().unwrap().to_owned(),
        signature: parsed["signature"].as_str().unwrap().to_owned(),
    };

    let provider = CredentialProvider::new(move |_request| {
        let credentials = credentials.clone();

        async move { Ok(credentials) }
    });

    let reader = client_for(provider).channel("room-42").unwrap();

    reader.connect().await.unwrap();

    let chat = reader.segment("chat").unwrap();
    let _subscription = chat.subscribe().unwrap();
    let mut failures = errors(&reader);

    tokio::time::sleep(Duration::from_millis(1_500)).await;
    chat.publish(b"should be denied").await.unwrap();

    receive_matching(
        &mut failures,
        |error: &CelerisError| is_server_error(error, &ServerErrorType::PermissionDeniedError),
        "the PermissionDeniedError frame",
        Duration::from_secs(15),
    )
    .await;

    assert_eq!(reader.state(), ChannelState::Connected);

    reader.close().await;
} // end fn mints_credentials_through_the_endpoint_and_connects_with_them
