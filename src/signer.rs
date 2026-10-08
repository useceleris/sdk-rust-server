use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use useceleris_client::{CelerisError, Credentials};

use crate::claims::Claims;
use crate::constants::MAXIMUM_TIMESTAMP;
use crate::token_payload::token_payload;
use crate::validation::{validate_claims, validate_signer_options};

/// Configures a [`Signer`].
///
/// The options hold the signing secret, so `Debug` shows them as redacted.
#[derive(Clone)]
pub struct SignerOptions {
    /// Your application's client id. It must not be empty and must not
    /// contain a colon, CR or LF.
    pub client_id: String,

    /// Your application's signing secret. It must not be empty. Keep it on
    /// trusted servers only.
    pub signing_secret: String,

    /// Gives the time at which credentials are signed. `None` uses
    /// [`SystemTime::now`].
    pub clock: Option<Arc<dyn Fn() -> SystemTime + Send + Sync>>,
} // end struct SignerOptions

impl fmt::Debug for SignerOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignerOptions { redacted }")
    } // end method fmt
} // end impl Debug for SignerOptions

/// Signs credentials on a trusted server.
///
/// The signer keeps the signing secret only inside its HMAC state, and `Debug`
/// shows the signer as redacted. It is cheap to clone and safe to share
/// between threads.
#[derive(Clone)]
pub struct Signer {
    client_id: String,
    keyed_hash: Hmac<Sha512>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
} // end struct Signer

impl Signer {
    /// Validates the options and makes a signer. It fails with
    /// [`CelerisError::Configuration`], which names each field and rule that
    /// failed, but never a value.
    pub fn new(options: SignerOptions) -> Result<Signer, CelerisError> {
        validate_signer_options(&options.client_id, &options.signing_secret)?;

        let keyed_hash = Hmac::<Sha512>::new_from_slice(options.signing_secret.as_bytes())
            .map_err(|_| {
                CelerisError::Configuration(
                    "Invalid signer options. signing_secret: Must be a usable HMAC key.".to_owned(),
                )
            })?;

        let clock = options.clock.unwrap_or_else(|| Arc::new(SystemTime::now));

        Ok(Signer {
            client_id: options.client_id,
            keyed_hash,
            clock,
        })
    } // end fn new

    /// Signs credentials for `claims`, with the current time as the
    /// timestamp. Sign again for every connection attempt. Never cache,
    /// reuse or backdate credentials (D-001).
    ///
    /// It fails with [`CelerisError::Configuration`] for invalid claims, and
    /// names each field and rule that failed. It also fails when the clock
    /// gives a time outside 1 to 253402300799999 milliseconds after the Unix
    /// epoch.
    pub fn sign(&self, claims: &Claims) -> Result<Credentials, CelerisError> {
        validate_claims(claims)?;

        let timestamp = (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);

        if !(1..=MAXIMUM_TIMESTAMP).contains(&timestamp) {
            return Err(CelerisError::Configuration(
                "Invalid timestamp from clock. Must be between 1 and 253402300799999 milliseconds."
                    .to_owned(),
            ));
        }

        let payload = STANDARD.encode(token_payload(timestamp, claims));

        // The digest covers the encoded payload text, as the server checks it.
        let mut keyed_hash = self.keyed_hash.clone();
        keyed_hash.update(payload.as_bytes());

        let digest = hexadecimal(&keyed_hash.finalize().into_bytes());
        let signature = STANDARD.encode(format!("{}:{digest}", self.client_id));

        Ok(Credentials { payload, signature })
    } // end method sign
} // end impl Signer

impl fmt::Debug for Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Signer { redacted }")
    } // end method fmt
} // end impl Debug for Signer

/// Writes bytes as lowercase hexadecimal.
pub(crate) fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut text = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }

    text
} // end fn hexadecimal
