//! AUTH-05: no secret and no credential value reaches a log or an error.
//! `Debug` shows the signer options, the signer, the credentials and the
//! provider as redacted, also inside the caller's own types.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use useceleris_client::Credentials;
use useceleris_server::{
    ChannelScope, Claims, SegmentPermissions, Signer, SignerOptions, credential_provider,
};

#[derive(Debug)]
#[allow(dead_code)]
struct Holder {
    options: SignerOptions,
    signer: Signer,
    signers: Vec<Signer>,
    credentials: Credentials,
} // end struct Holder

#[test]
fn debug_never_shows_the_secret_or_the_credentials() {
    let options = SignerOptions {
        client_id: "synthetic-client".to_owned(),
        signing_secret: "synthetic-secret".to_owned(),
        clock: Some(Arc::new(|| UNIX_EPOCH + Duration::from_millis(5))),
    };

    let signer = Signer::new(options.clone()).unwrap();
    let credentials = signer
        .sign(&Claims::new(
            ChannelScope::All,
            SegmentPermissions::All {
                read: true,
                write: true,
            },
        ))
        .unwrap();

    let provider = credential_provider(signer.clone(), |_request| async {
        Ok(Claims::new(
            ChannelScope::All,
            SegmentPermissions::Restricted(Vec::new()),
        ))
    });

    let holder = Holder {
        options: options.clone(),
        signer: signer.clone(),
        signers: vec![signer.clone()],
        credentials: credentials.clone(),
    };

    let printed = [
        format!("{options:?}"),
        format!("{options:#?}"),
        format!("{signer:?}"),
        format!("{signer:#?}"),
        format!("{credentials:?}"),
        format!("{provider:?}"),
        format!("{holder:?}"),
        format!("{holder:#?}"),
    ];

    let forbidden = [
        "synthetic-secret",
        "synthetic-client",
        credentials.payload.as_str(),
        credentials.signature.as_str(),
    ];

    for text in &printed {
        for value in forbidden {
            assert!(!text.contains(value), "{text} shows a value");
        }
    }

    assert_eq!(printed[0], "SignerOptions { redacted }");
    assert_eq!(printed[2], "Signer { redacted }");
} // end fn debug_never_shows_the_secret_or_the_credentials
