//! Server-signed credentials against the real stack: authentication, the
//! signed scope, echo, replay and presence (AUTH-02, AUTH-03).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc;
use useceleris_client::{
    CelerisError, ChannelState, CredentialReason, CredentialRequest, ServerErrorResource,
    ServerErrorType,
};
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, SignerOptions,
};

use crate::support::{
    all_permission_claims, connected_channel, errors, fixed_claims, is_server_error,
    qualification_client, receive_matching, signer_options, unique_channel_reference,
};

const SETTLE: Duration = Duration::from_millis(1_500);

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test]
async fn connects_with_server_signed_credentials() {
    let reference = unique_channel_reference("auth");
    let client = qualification_client(
        signer_options(),
        fixed_claims(all_permission_claims(&reference)),
    );
    let channel = client.channel(&reference).unwrap();
    let (sender, mut notices) = mpsc::unbounded_channel();

    channel.events().on_notice(move |notice| {
        let _ = sender.send(String::from_utf8_lossy(&notice.payload).into_owned());
    });

    channel.connect().await.unwrap();

    let greeting = receive_matching(&mut notices, |_| true, "the greeting", DELIVERY_TIMEOUT).await;

    assert!(greeting.contains("Successfully connected"), "{greeting}");

    channel.close().await;
} // end fn connects_with_server_signed_credentials

// DEV-02: a refused handshake is a transport failure.
#[tokio::test]
async fn rejects_a_wrong_secret_and_an_unknown_client_as_transport() {
    let reference = unique_channel_reference("reject");
    let wrong_secret = SignerOptions {
        signing_secret: "wrong-signing-secret".to_owned(),
        ..signer_options()
    };

    let unknown_client = SignerOptions {
        client_id: "rustqual-unknown".to_owned(),
        ..signer_options()
    };

    for options in [wrong_secret, unknown_client] {
        let client = qualification_client(options, fixed_claims(all_permission_claims(&reference)));
        let channel = client.channel(&reference).unwrap();
        let outcome = channel.connect().await;

        match &outcome {
            Err(CelerisError::Transport(message)) => {
                assert!(!message.contains("wrong-signing-secret"), "{message}");
            }
            other => panic!("got {other:?}"),
        }

        assert_eq!(channel.state(), ChannelState::Failed);
        channel.close().await;
    }
} // end fn rejects_a_wrong_secret_and_an_unknown_client_as_transport

// D-001: the server accepts a signed timestamp that is at most 60 seconds old
// and not in the future.
#[tokio::test]
async fn rejects_timestamps_outside_the_sixty_second_window() {
    let reference = unique_channel_reference("window");

    let shifted = |offset: Duration, ahead: bool| SignerOptions {
        clock: Some(Arc::new(move || {
            if ahead {
                SystemTime::now() + offset
            } else {
                SystemTime::now() - offset
            }
        })),
        ..signer_options()
    };

    for options in [
        shifted(Duration::from_secs(61), false),
        shifted(Duration::from_secs(59 * 60), false),
        shifted(Duration::from_secs(5 * 60), true),
    ] {
        let client = qualification_client(options, fixed_claims(all_permission_claims(&reference)));
        let channel = client.channel(&reference).unwrap();
        let outcome = channel.connect().await;

        assert!(
            matches!(outcome, Err(CelerisError::Transport(_))),
            "{outcome:?}"
        );
        channel.close().await;
    }

    let client = qualification_client(
        shifted(Duration::from_secs(30), false),
        fixed_claims(all_permission_claims(&reference)),
    );
    let recent = client.channel(&reference).unwrap();

    recent.connect().await.unwrap();
    recent.close().await;
} // end fn rejects_timestamps_outside_the_sixty_second_window

#[tokio::test]
async fn enforces_the_tokens_channel_restriction() {
    let allowed = unique_channel_reference("scope-allowed");
    let client = qualification_client(
        signer_options(),
        fixed_claims(all_permission_claims(&allowed)),
    );
    let denied = client
        .channel(&unique_channel_reference("scope-denied"))
        .unwrap();
    let outcome = denied.connect().await;

    assert!(
        matches!(outcome, Err(CelerisError::Transport(_))),
        "{outcome:?}"
    );
    denied.close().await;

    let channel = connected_channel(&allowed, all_permission_claims(&allowed)).await;

    channel.close().await;
} // end fn enforces_the_tokens_channel_restriction

/// The message id is the caller's own, so this suite does not depend on how the
/// client generates ids; the client's own suite checks those.
#[tokio::test]
async fn round_trips_a_payload_with_its_id_and_no_self_echo() {
    let reference = unique_channel_reference("msg");
    let publisher = connected_channel(&reference, all_permission_claims(&reference)).await;
    let receiver = connected_channel(&reference, all_permission_claims(&reference)).await;
    let (echo_sender, mut echoes) = mpsc::unbounded_channel();
    let (delivery_sender, mut deliveries) = mpsc::unbounded_channel();

    let publisher_chat = publisher.segment("chat").unwrap();
    let receiver_chat = receiver.segment("chat").unwrap();

    publisher_chat.on_message(move |_payload, metadata| {
        let _ = echo_sender.send(metadata.message_id.clone());
    });

    receiver_chat.on_message(move |payload, metadata| {
        let _ = delivery_sender.send((payload.to_vec(), metadata.message_id.clone()));
    });

    let _publisher_subscription = publisher_chat.subscribe().unwrap();
    let _receiver_subscription = receiver_chat.subscribe().unwrap();

    tokio::time::sleep(SETTLE).await;
    let sent_id = format!("{reference}_hello");

    publisher_chat
        .publish_with_message_id("hello-서버".as_bytes(), &sent_id)
        .await
        .unwrap();

    let (payload, message_id) = receive_matching(
        &mut deliveries,
        |_| true,
        "the cross-connection delivery",
        DELIVERY_TIMEOUT,
    )
    .await;

    assert_eq!(payload, "hello-서버".as_bytes());
    assert_eq!(message_id, sent_id);

    let echo = tokio::time::timeout(SETTLE, echoes.recv()).await;

    assert!(echo.is_err(), "the publisher received its own publish");

    publisher.close().await;
    receiver.close().await;
} // end fn round_trips_a_payload_with_its_id_and_no_self_echo

#[tokio::test]
async fn echoes_to_the_publisher_when_claims_allow_echo() {
    let reference = unique_channel_reference("echo");
    let claims = Claims {
        allow_echo: true,
        ..all_permission_claims(&reference)
    };

    let channel = connected_channel(&reference, claims).await;
    let chat = channel.segment("chat").unwrap();
    let (sender, mut deliveries) = mpsc::unbounded_channel();

    chat.on_message(move |payload, _metadata| {
        let _ = sender.send(payload.to_vec());
    });

    let _subscription = chat.subscribe().unwrap();

    tokio::time::sleep(SETTLE).await;
    chat.publish(b"self").await.unwrap();

    receive_matching(
        &mut deliveries,
        |payload| payload == b"self",
        "the echoed publish",
        DELIVERY_TIMEOUT,
    )
    .await;

    channel.close().await;
} // end fn echoes_to_the_publisher_when_claims_allow_echo

#[tokio::test]
async fn denies_a_read_only_restricted_segments_publish() {
    let reference = unique_channel_reference("perm");
    let read_only = connected_channel(
        &reference,
        Claims::new(
            ChannelScope::Restricted(vec![reference.clone()]),
            SegmentPermissions::Restricted(vec![SegmentClaim {
                segment_id: "chat".to_owned(),
                read: true,
                write: false,
            }]),
        ),
    )
    .await;
    let mut failures = errors(&read_only);

    // The publish completes locally. The denial arrives later and names the
    // segment.
    read_only
        .segment("chat")
        .unwrap()
        .publish(b"denied")
        .await
        .unwrap();

    let denial = receive_matching(
        &mut failures,
        |error| is_server_error(error, &ServerErrorType::PermissionDeniedError),
        "the PermissionDeniedError frame",
        DELIVERY_TIMEOUT,
    )
    .await;

    let CelerisError::Server(server_error) = denial else {
        unreachable!("the predicate matched a server error");
    };

    assert_eq!(server_error.sub_type.as_deref(), Some("PUB"));
    assert_eq!(
        server_error.resource,
        ServerErrorResource::Text("chat".to_owned())
    );
    assert_eq!(read_only.state(), ChannelState::Connected);

    read_only.close().await;
} // end fn denies_a_read_only_restricted_segments_publish

#[tokio::test]
async fn replays_recent_messages_through_reconnect_claims() {
    let reference = unique_channel_reference("replay");
    let claims = all_permission_claims(&reference);
    let publisher = connected_channel(&reference, claims.clone()).await;
    let live_receiver = connected_channel(&reference, claims.clone()).await;
    let (live_sender, mut live_deliveries) = mpsc::unbounded_channel();
    let live_history = live_receiver.segment("history").unwrap();

    live_history.on_message(move |payload, metadata| {
        let _ = live_sender.send((payload.to_vec(), metadata.message_id.clone()));
    });

    let _live_subscription = live_history.subscribe().unwrap();

    tokio::time::sleep(SETTLE).await;

    for body in ["one", "two", "three"] {
        publisher
            .segment("history")
            .unwrap()
            .publish(body.as_bytes())
            .await
            .unwrap();
    }

    let mut live_ids = HashMap::new();

    while live_ids.len() < 3 {
        let (payload, message_id) = receive_matching(
            &mut live_deliveries,
            |_| true,
            "the three live deliveries",
            Duration::from_secs(20),
        )
        .await;

        live_ids.insert(payload, message_id);
    }

    live_receiver.close().await;

    // The claims function applies the request's replay lookback, or a minute
    // on a first connect.
    let replaying = move |request: CredentialRequest| {
        let mut replay = claims.clone();

        replay.replay = match request.reason {
            CredentialReason::Reconnect {
                replay_lookback, ..
            } => Replay::Lookback(replay_lookback),
            CredentialReason::Initial => Replay::Lookback(Duration::from_secs(60)),
        };

        std::future::ready(Ok(replay))
    };

    let client = qualification_client(signer_options(), replaying);
    let replay_receiver = client.channel(&reference).unwrap();

    replay_receiver.connect().await.unwrap();

    let mut replayed = HashMap::new();
    let (replay_sender, mut replay_deliveries) = mpsc::unbounded_channel();
    let history = replay_receiver.segment("history").unwrap();

    history.on_message(move |payload, metadata| {
        let _ = replay_sender.send((payload.to_vec(), metadata.message_id.clone()));
    });

    let _replay_subscription = history.subscribe().unwrap();

    while replayed.len() < 3 {
        let (payload, message_id) = receive_matching(
            &mut replay_deliveries,
            |_| true,
            "the replayed history",
            Duration::from_secs(25),
        )
        .await;

        replayed.insert(payload, message_id);
    }

    assert_eq!(replayed, live_ids);

    publisher.close().await;
    replay_receiver.close().await;
} // end fn replays_recent_messages_through_reconnect_claims

#[tokio::test]
async fn surfaces_presence_for_a_server_signed_reference() {
    let reference = unique_channel_reference("presence");
    let claims = all_permission_claims(&reference);
    let watcher = connected_channel(&reference, claims.clone()).await;
    let watched = watcher.segment("chat").unwrap();
    let (sender, mut events) = mpsc::unbounded_channel();

    watched.on_presence(move |event| {
        let _ = sender.send(event.clone());
    });

    let _presence = watched.subscribe_presence().unwrap();

    tokio::time::sleep(SETTLE).await;

    let actor_claims = Claims {
        reference: Some("rustqual-server-actor".to_owned()),
        ..claims
    };

    let actor = connected_channel(&reference, actor_claims).await;
    let _membership = actor.segment("chat").unwrap().subscribe().unwrap();

    let join = receive_matching(
        &mut events,
        |event| event.joined && event.token_reference == "rustqual-server-actor",
        "the actor's presence join",
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(join.segment_id, "chat");
    assert!(!join.connection_id.is_empty());

    let page = watched.presence_list(1, 10).await.unwrap();

    assert!(page.total >= 1, "{page:?}");
    assert!(
        page.connections
            .iter()
            .any(|connection| connection.token_reference == "rustqual-server-actor"),
        "{page:?}"
    );

    actor.close().await;
    watcher.close().await;
} // end fn surfaces_presence_for_a_server_signed_reference
