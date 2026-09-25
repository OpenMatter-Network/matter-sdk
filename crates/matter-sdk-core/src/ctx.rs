//! Process-wide BGV `CrtContext`, built once (~30 ms) and shared.

use matter_crypto::bgv::params::SecureCipher;
use matter_crypto::bgv::poly::CrtContext;
use once_cell::sync::OnceCell;

static CTX: OnceCell<CrtContext<SecureCipher>> = OnceCell::new();

/// Returns the process-wide [`CrtContext`], building it on first access.
pub(crate) fn ensure() -> &'static CrtContext<SecureCipher> {
    CTX.get_or_init(CrtContext::gen)
}
