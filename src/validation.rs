//! Rust text is always valid UTF-8, so the signed bytes are always exactly the
//! text that the caller passed (D-003). Where the reference refuses unpaired
//! surrogates, only the empty-text rules remain.

use std::collections::HashSet;

use useceleris_client::CelerisError;

use crate::claims::{ChannelScope, Claims, Replay, SegmentClaim, SegmentPermissions};
use crate::constants::{MAXIMUM_CHANNEL_REFERENCE_LENGTH, MAXIMUM_REPLAY_LOOKBACK};

pub(crate) fn validate_signer_options(
    client_id: &str,
    signing_secret: &str,
) -> Result<(), CelerisError> {
    let mut failures = Vec::new();

    if let Some(rule) = colon_free_identifier_rule(client_id) {
        failures.push(failure("client_id", rule));
    }

    if signing_secret.is_empty() {
        failures.push(failure("signing_secret", "Must not be empty"));
    }

    configuration_result("signer options", failures)
} // end fn validate_signer_options

pub(crate) fn validate_claims(claims: &Claims) -> Result<(), CelerisError> {
    let mut failures = Vec::new();

    if let ChannelScope::Restricted(references) = &claims.channels {
        failures.extend(channel_reference_failures(references));
    }

    if let SegmentPermissions::Restricted(segments) = &claims.permissions {
        failures.extend(segment_failures(segments));
    }

    if let Some(reference) = &claims.reference
        && let Some(rule) = colon_free_identifier_rule(reference)
    {
        failures.push(failure("reference", rule));
    }

    if let Replay::Lookback(lookback) = claims.replay {
        if lookback > MAXIMUM_REPLAY_LOOKBACK {
            failures.push(failure(
                "replay",
                "Lookback must be between 0 and 4294967295 milliseconds",
            ));
        } else if lookback.subsec_nanos() % 1_000_000 != 0 {
            failures.push(failure("replay", "Lookback must be whole milliseconds"));
        }
    }

    configuration_result("claims", failures)
} // end fn validate_claims

fn channel_reference_failures(references: &[String]) -> Vec<String> {
    if references.is_empty() {
        return vec![failure(
            "channels",
            "Must list at least one channel reference",
        )];
    }

    let mut failures = Vec::new();
    let mut seen = HashSet::new();

    for (index, reference) in references.iter().enumerate() {
        if let Some(rule) = channel_reference_rule(reference) {
            failures.push(failure(&format!("channels[{index}]"), rule));
        } else if seen.contains(reference.as_str()) {
            failures.push(failure("channels", "Must not repeat a channel reference"));
        }

        seen.insert(reference.as_str());
    }

    failures
} // end fn channel_reference_failures

fn segment_failures(segments: &[SegmentClaim]) -> Vec<String> {
    let mut failures = Vec::new();
    let mut seen = HashSet::new();

    for (index, segment) in segments.iter().enumerate() {
        let segment_id = segment.segment_id.as_str();

        if let Some(rule) = segment_id_rule(segment_id) {
            failures.push(failure(&format!("permissions[{index}].segment_id"), rule));
        } else if seen.contains(segment_id) {
            failures.push(failure("permissions", "Must not repeat a segment ID"));
        }

        seen.insert(segment_id);
    }

    failures
} // end fn segment_failures

fn segment_id_rule(segment_id: &str) -> Option<&'static str> {
    if segment_id.is_empty() {
        return Some("Must not be empty");
    }

    if segment_id.contains(['\r', '\n']) {
        return Some("Must not contain CR or LF");
    }

    None
} // end fn segment_id_rule

fn colon_free_identifier_rule(identifier: &str) -> Option<&'static str> {
    if identifier.is_empty() {
        return Some("Must not be empty");
    }

    if identifier.contains([':', '\r', '\n']) {
        return Some("Must not contain a colon, CR or LF");
    }

    None
} // end fn colon_free_identifier_rule

pub(crate) fn channel_reference_rule(reference: &str) -> Option<&'static str> {
    if reference.is_empty() {
        return Some("Must not be empty");
    }

    if reference.len() > MAXIMUM_CHANNEL_REFERENCE_LENGTH {
        return Some("Must be at most 255 characters");
    }

    let permitted = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';

    if !reference.bytes().all(permitted) {
        return Some("Must contain only ASCII letters, digits, hyphens (-) or underscores (_)");
    }

    None
} // end fn channel_reference_rule

/// Describes one failed field and the rule that it broke, never its value.
fn failure(path: &str, rule: &str) -> String {
    format!("{path}: {rule}.")
} // end fn failure

/// Names every failure: "Invalid claims. channels: Must not repeat a channel
/// reference."
fn configuration_result(subject: &str, failures: Vec<String>) -> Result<(), CelerisError> {
    if failures.is_empty() {
        return Ok(());
    }

    Err(CelerisError::Configuration(format!(
        "Invalid {subject}. {}",
        failures.join(" ")
    )))
} // end fn configuration_result
