//! This module contain error type returned by this library.

use std::result::Result;

quick_error! {
    #[derive(Debug)]
    /// Error kinds returns by this library.
    pub enum WhisperError {
        /// Public key failed validation.
        InvalidPublicKey {
          description("Public key failed validation.")
        }
    }
}

/// Result type used by this library.
pub type WhisperResult<T> = Result<T, WhisperError>;