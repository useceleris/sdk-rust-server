//! The public surface, written down once. Each public item is used here, so a
//! change to the surface fails to compile or fails this test. Every item
//! traces to the server surface in the specifications repository (AUTH-01,
//! AUTH-02, D-001).

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use useceleris_client::{
    CelerisError, CredentialProvider, CredentialRequest, Credentials, ProviderError,
};
use useceleris_server::{
    ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions, Signer, SignerOptions,
    credential_provider,
};

#[test]
fn the_public_surface_is_pinned() {
    let clock: Option<Arc<dyn Fn() -> SystemTime + Send + Sync>> = Some(Arc::new(SystemTime::now));

    let options = SignerOptions {
        client_id: "synthetic-client".to_owned(),
        signing_secret: "synthetic-secret".to_owned(),
        clock,
    };

    let new: fn(SignerOptions) -> Result<Signer, CelerisError> = Signer::new;
    let signer = new(options).unwrap();
    let sign: fn(&Signer, &Claims) -> Result<Credentials, CelerisError> = Signer::sign;

    let channels = [
        ChannelScope::All,
        ChannelScope::Restricted(vec!["room-1".to_owned()]),
    ];

    let permissions = [
        SegmentPermissions::All {
            read: true,
            write: false,
        },
        SegmentPermissions::Restricted(vec![SegmentClaim {
            segment_id: "chat".to_owned(),
            read: true,
            write: true,
        }]),
    ];

    let replays = [
        Replay::None,
        Replay::Backlog,
        Replay::Lookback(Duration::from_millis(1)),
    ];

    for (channel_scope, segment_permissions) in channels.into_iter().zip(permissions) {
        for replay in replays {
            let claims = Claims {
                channels: channel_scope.clone(),
                permissions: segment_permissions.clone(),
                reference: Some("user-1".to_owned()),
                replay,
                allow_echo: true,
            };

            assert!(sign(&signer, &claims).is_ok());
        }
    }

    let new_claims: fn(ChannelScope, SegmentPermissions) -> Claims = Claims::new;
    let _ = new_claims;

    fn bridge<ClaimsFor, Decided>(signer: Signer, claims: ClaimsFor) -> CredentialProvider
    where
        ClaimsFor: Fn(CredentialRequest) -> Decided + Send + Sync + 'static,
        Decided: Future<Output = Result<Claims, ProviderError>> + Send + 'static,
    {
        credential_provider(signer, claims)
    } // end fn bridge

    let _provider = bridge(signer, |_request| async {
        Ok(Claims::new(
            ChannelScope::All,
            SegmentPermissions::Restricted(Vec::new()),
        ))
    });
} // end fn the_public_surface_is_pinned

#[test]
fn the_public_types_implement_their_traits() {
    fn assert_value<Value: Clone + std::fmt::Debug + PartialEq + Eq + Send + Sync + 'static>() {}

    fn assert_handle<Value: Clone + std::fmt::Debug + Send + Sync + 'static>() {}

    assert_value::<Claims>();
    assert_value::<ChannelScope>();
    assert_value::<SegmentPermissions>();
    assert_value::<SegmentClaim>();
    assert_value::<Replay>();
    assert_handle::<Signer>();
    assert_handle::<SignerOptions>();

    let replay: Replay = Replay::Backlog;
    let copied = replay;

    assert_eq!(replay, copied);
} // end fn the_public_types_implement_their_traits
