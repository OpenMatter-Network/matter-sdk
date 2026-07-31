//! Splitting a secret URI into phrase, derivation junctions, and password.
//!
//! # Why this is hand-rolled
//!
//! `subxt_signer::SecretUri` does exactly this, but it does it with `regex` —
//! and `regex` is a non-optional dependency of `subxt-signer` that no feature
//! flag removes. Measured against the wasm artifact this package ships:
//!
//! | build | `matter_vault_wasm_bg.wasm` | vs. baseline |
//! |---|---|---|
//! | no key layer | 1,962,582 B | — |
//! | + sr25519 signing only | 2,047,892 B | +85 KB |
//! | + `SecretUri` (pulls `regex`) | 2,811,681 B | +849 KB |
//! | + this module instead | 2,120,572 B | **+158 KB** |
//!
//! 90% of the cost of key ingestion in the browser was the URI parser, so the
//! splitting moved here and `regex` left the graph, recovering 691 KB.
//! **Only the splitting.**
//! Junction interpretation and every derivation step still call
//! `subxt_signer::DeriveJunction` / `Keypair::derive` / `Keypair::from_phrase`
//! verbatim — this module must never contain cryptography.
//!
//! # Why this cannot silently drift
//!
//! A splitter that disagrees with the ecosystem derives the wrong account, which
//! is a silent, expensive failure. `tests/suri_equivalence.rs` therefore asserts
//! — over a corpus of accepted and rejected inputs — that this module agrees
//! with `SecretUri::from_str` on every field. That test keeps `subxt-signer`'s
//! full parser as the oracle while keeping it out of the shipped artifact,
//! because a dev-dependency does not link into a `cdylib`.
//!
//! The grammar being replicated, from `sp_core::crypto::SECRET_PHRASE_REGEX`:
//!
//! ```text
//! ^(?P<phrase>[\d\w ]+)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$
//!
//!   foo bar wibble //hard/soft ///password
//!   ^^^^^^^^^^^^^^ ^^^^^^^^^^^    ^^^^^^^^
//!     phrase           path       password
//! ```

use subxt_signer::DeriveJunction;

use crate::error::{KeyError, Result};

/// The separator introducing the optional password. Also the reason a password
/// cannot be confused with a junction: `//?[^/]+` requires a non-`/` immediately
/// after the slashes, so `///` can never begin a junction.
const PASSWORD_SEPARATOR: &str = "///";

/// A secret URI split into its three parts. Borrows from the input, so nothing
/// is copied and no owned `String` of key material is created.
#[derive(Debug)]
pub(crate) struct Suri<'a> {
    /// The BIP39 mnemonic or `0x` mini-secret. Empty if the input had none.
    pub phrase: &'a str,
    /// Derivation junctions, in application order.
    pub junctions: Vec<DeriveJunction>,
    /// The `///password` suffix, if present. Applied to mnemonics only —
    /// a hex phrase ignores it, matching upstream.
    pub password: Option<&'a str>,
}

/// Split `input` into phrase, junctions, and password.
///
/// Rejects anything the upstream grammar rejects, with a static description.
pub(crate) fn split(input: &str) -> Result<Suri<'_>> {
    // The password runs to the end of the string (`.*$`), so the first `///`
    // starts it.
    let (head, password) = match input.find(PASSWORD_SEPARATOR) {
        Some(at) => (&input[..at], Some(&input[at + PASSWORD_SEPARATOR.len()..])),
        None => (input, None),
    };

    // The phrase cannot contain `/`, and the path must start with one, so the
    // first `/` is the boundary.
    let (phrase, path) = match head.find('/') {
        Some(at) => (&head[..at], &head[at..]),
        None => (head, ""),
    };

    if !is_valid_phrase(phrase) {
        return Err(KeyError::Malformed {
            detail: "phrase may contain only letters, digits, underscores, and spaces",
        });
    }

    Ok(Suri {
        phrase,
        junctions: parse_junctions(path)?,
        password,
    })
}

/// The `[\d\w ]*` phrase class. `\w` is Unicode-aware in the upstream regex, so
/// this uses `char::is_alphanumeric` rather than an ASCII test; the equivalence
/// test covers the boundary.
fn is_valid_phrase(phrase: &str) -> bool {
    phrase
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == ' ')
}

/// Parse `(//?[^/]+)*` into junctions.
///
/// Each junction is a `/`, an optional second `/` marking it *hard*, then at
/// least one non-`/` character. The token handed to [`DeriveJunction::from`]
/// keeps the hard marker, exactly as the upstream junction regex captures it.
fn parse_junctions(path: &str) -> Result<Vec<DeriveJunction>> {
    const MALFORMED: KeyError = KeyError::Malformed {
        detail: "derivation path must be a sequence of `/soft` or `//hard` segments",
    };

    let mut junctions = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // `/` and the segment separator are ASCII, so byte indexing stays on
        // char boundaries.
        if bytes[i] != b'/' {
            return Err(MALFORMED);
        }
        let token_start = i;
        i += 1;
        if i < bytes.len() && bytes[i] == b'/' {
            i += 1;
        }

        let code_start = i;
        while i < bytes.len() && bytes[i] != b'/' {
            i += 1;
        }
        if i == code_start {
            // `[^/]+` needs at least one character: a trailing `/` or `//` is
            // not a junction, and upstream rejects the whole URI for it.
            return Err(MALFORMED);
        }

        // Skip the leading `/` of the segment; keep the second one if hard, so
        // `DeriveJunction::from` sees `/hard` or `soft` as the regex would.
        junctions.push(DeriveJunction::from(&path[token_start + 1..i]));
    }

    Ok(junctions)
}
