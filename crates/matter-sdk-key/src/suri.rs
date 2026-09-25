//! Splitting a secret URI into phrase, derivation junctions, and password.
//!
//! Replaces `subxt_signer::SecretUri`, whose `regex` dependency adds ~690 KB to
//! the wasm artifact. Only the splitting lives here; all derivation goes through
//! `subxt_signer`. This module must never contain cryptography.
//!
//! A disagreement with upstream derives the wrong account silently.
//! `tests/suri_equivalence.rs` checks every field against `SecretUri::from_str`.
//!
//! Grammar, from `sp_core::crypto::SECRET_PHRASE_REGEX`:
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

/// Introduces the password. Never begins a junction: `//?[^/]+` needs a non-`/`
/// after at most two slashes.
const PASSWORD_SEPARATOR: &str = "///";

/// A secret URI split into its parts. Borrows the input so no owned copy of key
/// material is created.
#[derive(Debug)]
pub(crate) struct Suri<'a> {
    /// The BIP39 mnemonic or `0x` mini-secret. Empty if the input had none.
    pub phrase: &'a str,
    pub junctions: Vec<DeriveJunction>,
    /// The `///password` suffix. Applies to mnemonics only.
    pub password: Option<&'a str>,
}

/// Split `input` into phrase, junctions, and password. Rejects exactly what the
/// upstream grammar rejects.
pub(crate) fn split(input: &str) -> Result<Suri<'_>> {
    // The first `///` starts the password, which runs to the end.
    let (head, password) = match input.find(PASSWORD_SEPARATOR) {
        Some(at) => (&input[..at], Some(&input[at + PASSWORD_SEPARATOR.len()..])),
        None => (input, None),
    };

    // The phrase has no `/`, so the first `/` starts the path.
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

/// The `[\d\w ]*` phrase class. Upstream `\w` is Unicode-aware, hence
/// `is_alphanumeric` rather than an ASCII test.
fn is_valid_phrase(phrase: &str) -> bool {
    phrase
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == ' ')
}

/// Parse `(//?[^/]+)*` into junctions. The token passed to
/// [`DeriveJunction::from`] keeps the hard marker (`/hard`), as upstream does.
fn parse_junctions(path: &str) -> Result<Vec<DeriveJunction>> {
    const MALFORMED: KeyError = KeyError::Malformed {
        detail: "derivation path must be a sequence of `/soft` or `//hard` segments",
    };

    let mut junctions = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // `/` is ASCII, so byte indexing stays on char boundaries.
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
            // Empty segment (e.g. trailing `/`): upstream rejects the whole URI.
            return Err(MALFORMED);
        }

        junctions.push(DeriveJunction::from(&path[token_start + 1..i]));
    }

    Ok(junctions)
}
