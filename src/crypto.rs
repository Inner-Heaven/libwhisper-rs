//! This module is mostly reexports of sodiumoxide.

use errors::{WhisperResult, WhisperError};
use sodiumoxide;
use sodiumoxide::crypto::box_::gen_keypair;

pub use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
/// A keypair. This is just a helper type.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Public key.
    pub public_key: PublicKey,
    /// Secret key.
    pub secret_key: SecretKey,
}
impl KeyPair {
    /// Generate new keypair using libsodium.
    #[inline]
    pub fn new() -> KeyPair {
        let (public_key, secret_key) = gen_keypair();
        KeyPair {
            secret_key: secret_key,
            public_key: public_key,
        }
    }
}

/// In order to make libsodium threadsafe you must call this function before using any of it's andom number generation functions.
/// It's safe to call this method more than once and from more than one thread.
pub fn init() -> WhisperResult<()> {
  if sodiumoxide::init() {
    Ok(())
  } else {
    Err(WhisperError::InitializationFailed)
  }
}