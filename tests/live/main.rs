//! The acceptance suites, run against a real Celeris stack with `make live`.
//!
//! They read `CELERIS_WS_URL`, `CELERIS_CLIENT_ID` and
//! `CELERIS_SIGNING_SECRET` from the environment, or else from the crate's
//! `.env` file. Real environment variables take precedence. Missing
//! configuration or an unreachable stack fails the run. It never skips.

mod examples;
mod qualification;
mod support;

#[path = "../../examples/credential_endpoint.rs"]
#[allow(dead_code)]
mod credential_endpoint;

#[path = "../../examples/quickstart.rs"]
#[allow(dead_code)]
mod quickstart;
