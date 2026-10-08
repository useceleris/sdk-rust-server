use std::future::Future;
use std::sync::Arc;

use useceleris_client::{CredentialProvider, CredentialRequest, ProviderError};

use crate::claims::Claims;
use crate::signer::Signer;

/// Makes a [`CredentialProvider`] for a trusted server that connects to
/// realtime itself.
///
/// For every connection attempt, the provider calls `claims` again and signs
/// the result with a new timestamp. The claims are authoritative: nothing in
/// the request, which the client makes, can make them wider. An error from
/// `claims` is returned unchanged, and the client reports it as
/// [`CelerisError::Transport`](useceleris_client::CelerisError::Transport).
/// Invalid claims give the error of [`Signer::sign`].
///
/// When the client drops the provider's future, for example because the
/// channel closed, nothing is signed.
pub fn credential_provider<ClaimsFor, Decided>(
    signer: Signer,
    claims: ClaimsFor,
) -> CredentialProvider
where
    ClaimsFor: Fn(CredentialRequest) -> Decided + Send + Sync + 'static,
    Decided: Future<Output = Result<Claims, ProviderError>> + Send + 'static,
{
    let signer = Arc::new(signer);

    CredentialProvider::new(move |request| {
        let decided = claims(request);
        let signer = Arc::clone(&signer);

        async move {
            let claims = decided.await?;

            Ok(signer.sign(&claims)?)
        }
    })
} // end fn credential_provider
