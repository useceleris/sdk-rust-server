# Conventions

Simplicity and maintainability are paramount. These rules apply to every change. The surface contract is in the specifications repository. The JavaScript server package is the reference implementation that this crate mirrors.

## Names

Use full domain words: `channel_reference_failures`, `token_payload`, `signing_secret`, `credential_provider`. Do not use abbreviations or single-letter names, except in tight loops. A name says what the thing is. A comment states only a constraint that the code cannot show.

## Simplicity over abstraction

Solve the problem with the simplest structure that stays readable. Do not add registries, factories, builders, traits for one type or wrapper layers. Prefer a function to a type, and a method on an existing type to a new type.

The only seam is `SignerOptions::clock`, so that tests fix the timestamp.

## Signing

- `token_payload` writes the token payload by hand. It writes the keys in the reference order and escapes text exactly as `JSON.stringify` does. Never use a JSON library for the payload: their escapes can differ.
- The digest is HMAC-SHA512 of the base64 payload text, keyed with the signing secret. The signature is base64 of the client id, a colon and the lowercase hexadecimal digest.
- Rust text is always valid UTF-8, so the signed bytes are always the text that the caller gave (D-003). Where the reference refuses unpaired surrogates, only the rules for empty text remain.
- `Claims` has no default, and its channels and permissions are not optional. Unrestricted access is never granted by omission (AUTH-02).
- Sign again for each attempt, with a new timestamp (D-001). Never cache or backdate credentials.

## Maintainability

- Every fixed value is in `src/constants.rs`, as a `pub(crate)` constant in `SCREAMING_SNAKE_CASE`. Validation rules stay beside the code that uses them.
- Only `src/lib.rs` re-exports. Every other module imports from the module that defines the item.
- Delete code in the same change that makes it unnecessary.
- Every public item traces to a requirement or a recorded decision in the specifications repository. The public surface is pinned in one test, `tests/surface.rs`.
- Errors are `CelerisError::Configuration`. The message names every field that failed, with its snake_case path, and the rule that it broke. Never put a value, the secret or a cause into a message.
- The runtime dependencies are `useceleris-client`, `hmac`, `sha2` and `base64`. A test pins this list.

## Tests

- Unit tests of crate-private behaviour are in `src/tests/test_<topic>.rs`. No source file contains tests.
- Integration tests are in `tests/`, one file per topic. The live suites are in `tests/live/` (one binary, one module per topic) and run only with `make live`.
- Independent implementations produce the golden vectors. The code under test never produces them.
- An assertion must fail when nothing happens.

## Layout

rustfmt owns formatting, with its defaults. Two more rules apply, and `tests/layout.rs` enforces them on every Rust file of the crate:

- A statement or item that ends with a closing brace on a line of its own (a block, a closure, a struct literal) is followed by a blank line before the next statement or item. A `use` declaration is exempt.
- Every function, method, struct, enum, trait and impl block whose body spans several lines ends with a marker that names it: `} // end fn name`, `} // end method name` (a function with a `self` receiver), `} // end struct Name`, `} // end enum Name`, `} // end trait Name`, `} // end impl Name` or `} // end impl Trait for Name`.

`make check` must pass.

## Writing

Write documentation and comments in ASD-STE100 Simplified Technical English: short sentences, the active voice, one instruction per sentence, and approved words. Technical names such as `sign` and `claims` are permitted.
