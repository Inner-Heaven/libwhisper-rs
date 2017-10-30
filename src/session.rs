//! This module handles Session (singular) management. The session is
//! responsible for Frame generation and encryption.
//!
//! ### Client session vs Server session
//! Only different between ClientSession and ServerSession is that Client
//! doesn't know about server's session key at the beginning, while Server key
//! doesn't know about client's identity key.
//!
//! This handshake is heavily based on CurveCP and CurveZMQ.
//! ### Handshake
//! This is a very rough explanation. detailed one is coming later.
//!
//! 1. Client sends Hello frame to server
//! 2. Server replies with Welcome frame
//! 3. Client replies with Initiate frame
//! 4. Server verifies that client is allowed to talk to this server and
//! replies with Ready or Terminate frame
//!
//! ### Messages
//! The protocol allows bi-directorial message exchange. However,
//! implementation of that is not part of the protocol.

use chrono::{DateTime, Duration};
use chrono::offset::Utc;

use errors::WhisperResult;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{Nonce, PrecomputedKey, PublicKey, SecretKey};

/// Array of null bytes used in Hello package. Needs to be bigger than Welcome
/// frame to prevent amplification attacks. Maybe, 256 is too much...who knows?
pub static NULL_BYTES: [u8; 256] = [b'\x00'; 256];
/// Payload "server" side supposed to send to client when.
pub static READY_PAYLOAD: &'static [u8; 16] = b"My body is ready";

/// How much time client and server have to agree on shared secret.
pub static HANDSHAKE_DURATION: i64 = 3;
/// How much time one shared secret can last. In case you're wondering those
/// are Fibonacci numbers.
pub static SESSION_DURATION: i64 = 55;

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
        let (public_key, secret_key) = box_::gen_keypair();
        KeyPair {
            secret_key: secret_key,
            public_key: public_key,
        }
    }
}

/// Enum representing session state.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum SessionState {
    /// Session has been created, but handshake isn't initiated yet.
    Fresh,
    /// This state means that handshake has started.
    Initiated,
    /// This state means that session is established and messages can be sent
    /// both ways.
    Ready,
    /// This state means that session established, but can't be used at the
    /// time.
    Error,
}

/// Server-side session.
#[derive(Debug, Clone)]
pub struct ServerSession {
    expire_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    local_session_keypair: KeyPair,
    local_identity_keypair: KeyPair,
    remote_session_key: PublicKey,
    remote_identity_key: Option<PublicKey>,
    state: SessionState,
}
impl ServerSession {
    fn new(local_identity_keypair: &KeyPair, remote_session_key: &PublicKey) -> ServerSession {
        let now = Utc::now();
        ServerSession {
            expire_at: now + Duration::minutes(HANDSHAKE_DURATION),
            created_at: now,
            local_session_keypair: KeyPair::new(),
            local_identity_keypair:
                local_identity_keypair.clone(),
            remote_session_key: remote_session_key.clone(),
            remote_identity_key: None,
            state: SessionState::Fresh,
        }
    }
}

/// Client-side session.
#[derive(Debug, Clone)]
pub struct ClientSession {
    expire_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    local_session_keypair: KeyPair,
    local_identity_keypair: KeyPair,
    remote_session_key: Option<PublicKey>,
    remote_identity_key: PublicKey,
    state: SessionState,
}
impl ClientSession {
    /// Create new session. This method is private because it will create
    /// session with a few missing values.
    #[inline]
    fn new(local_identity_keypair: &KeyPair, remote_identity_key: &PublicKey) -> ClientSession {
        let now = Utc::now();
        ClientSession {
            expire_at: now + Duration::minutes(HANDSHAKE_DURATION),
            created_at: now,
            local_session_keypair: KeyPair::new(),
            local_identity_keypair:
                local_identity_keypair.clone(),
            remote_session_key: None,
            remote_identity_key: remote_identity_key.clone(),
            state: SessionState::Fresh,
        }
    }
}

/// Common session functions that apply to all session types.
trait Session {
    /// Returns true if session is expired.
    fn is_expired(&self) -> bool;
    /// Returns local long term public key.
    fn local_identity(&self) -> PublicKey;
    /// Returns session state.
    fn session_state(&self) -> SessionState;
    /// Returns session id. This should always be client short term public key.
    fn id(&self) -> PublicKey;
}

impl Session for ClientSession {
    fn is_expired(&self) -> bool { self.expire_at > Utc::now() }
    fn local_identity(&self) -> PublicKey { self.local_identity_keypair.public_key }

    fn session_state(&self) -> SessionState { self.state }
    fn id(&self) -> PublicKey { self.local_session_keypair.public_key }
}

impl Session for ServerSession {
    fn is_expired(&self) -> bool { self.expire_at > Utc::now() }
    fn local_identity(&self) -> PublicKey { self.local_identity_keypair.public_key }

    fn session_state(&self) -> SessionState { self.state }
    fn id(&self) -> PublicKey { self.remote_session_key }
}


/// This structure represent session that completed handshake.
///
/// Only way to create is to have ClientSession and ServerSession agree on
/// shared secret a.k.a. session_key a.k.a. PrecomputedKey.
/// ServerSession turns into EstablishedSession by verifying Initiate frame.
/// ClientSession turns into EstablishedSession by verifying Ready frame.
pub struct EstablishedSession {
    expire_at: DateTime<Utc>,
    established_at: DateTime<Utc>,
    local_intentity_key: PublicKey,
    remote_identity_key: PublicKey,
    session_key: PrecomputedKey,
}
