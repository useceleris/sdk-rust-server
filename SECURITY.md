# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's [Security Advisories](https://github.com/useceleris/sdk-rust-server/security/advisories/new) on this repository. Only you and the maintainer can see the report. We can then prepare a fix before anything is disclosed.

Give the information that we need to make the problem occur again: the affected version, the Rust version, and the smallest example that shows the problem. A suggested fix is welcome, but it is not necessary.

You will get an acknowledgement in a few days. We will tell you what we found, what we will do, and when we expect a fix. We will give you credit when the fix is published, unless you do not want it.

## Supported versions

Fixes go into the latest release. There is no long-term support branch.

## Scope

In scope: anything in this crate that signs credentials that grant more than the claims, any leak of the signing secret or of credentials to a place that they must not reach, and any input that can crash or corrupt an application that uses the crate.

Out of scope: the Celeris service itself, which you report through the same channel on its own repository, and findings that need an attacker who already has the signing secret. That secret is the trust boundary. If an attacker has it, all trust is lost, by design.

## What this crate promises

This is the server crate. It holds the signing secret, so use it on trusted servers only. A `Signer` keeps the secret only inside its HMAC state. `Debug` shows `SignerOptions` and `Signer` as redacted. The crate does not print or log, and it forbids unsafe code. Validation errors name the field and the rule that failed, but never the value. Rust text is always valid UTF-8, so the signed bytes are always the text that the caller gave. The output is equal to the output of the JavaScript reference signer, byte for byte.
