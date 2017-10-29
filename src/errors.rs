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
        /// Trying to use session before handshake is done or restarting handshake with the same keypair.
        InvalidSessionState {}
        /// Enough bytes to decode, but bytes make no sense.
        BadFrame {}
        /// Trying to use expired session.
        ExpiredSession {}
    }
}

/// Result type used by this library.
pub type WhisperResult<T> = Result<T, WhisperError>;
