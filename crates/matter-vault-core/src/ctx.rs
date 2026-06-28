//! Process-wide BGV CRT context.
//!
//! The RLWE/BGV operations all need a `CrtContext`, whose construction parses a
//! large embedded parameter table (~30 ms). Build it once and share it, exactly
//! as the reference wasm encryptor does, so repeated seal/open calls don't pay
//! the cost each time.

use matter_crypto::bgv::params::SecureCipher;
use matter_crypto::bgv::poly::CrtContext;
use once_cell::sync::OnceCell;

/// Cached context; initialised on first [`ensure`] call.
static CTX: OnceCell<CrtContext<SecureCipher>> = OnceCell::new();

/// Returns the process-wide [`CrtContext`], building it on first access.
pub(crate) fn ensure() -> &'static CrtContext<SecureCipher> {
    CTX.get_or_init(CrtContext::gen)
}
