//! This module contain error type returned by this library.

use std::result::Result;

quick_error! {
    #[derive(Debug)]
    /// Error kinds returns by this library.
    pub enum WhisperError {
        /// Server sent invalid payload for Ready frame.
        InvalidReadyFrame {
            description("Server sent invalid payload for Ready frame.")
        }
        /// Client sent invalid payload for Hello frame.
        InvalidHelloFrame {
            description("Client sent invalid payload for Hello frame.")
        }
        /// Public key failed validation.
        InvalidPublicKey {
          description("Public key failed validation.")
        }
        /// Decryption of payload failed.
        DecryptionFailed {}
        /// Server sent invalid Welcome frame.
        InvalidWelcomeFrame {}
        /// Client sent invalid Initiate frame.
        InvalidInitiateFrame {}
        /// Not having enough bytes to decode frame.
        IncompleteFrame {}
        /// Either restarting a handshake or forgetting to do handshake at all.
        InvalidSessionState {}
        /// Enough bytes to decode, but bytes make no sense.
        BadFrame {}
        /// Trying to use expired session.
        ExpiredSession {}
        /// Initialization of libsodium failed.
        /// This might happen when machine just booted and doesn't have enough entropy.
        InitializationFailed {}
    }
}

/// Result type used by this library.
pub type WhisperResult<T> = Result<T, WhisperError>;
