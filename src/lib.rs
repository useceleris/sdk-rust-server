#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod claims;
mod constants;
mod credential_provider;
mod signer;
mod token_payload;
mod validation;

#[cfg(test)]
mod tests;

pub use claims::{ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions};
pub use credential_provider::credential_provider;
pub use signer::{Signer, SignerOptions};
