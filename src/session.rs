#![deny(missing_docs)]

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
use rand::thread_rng;
use secp256k1::Secp256k1;
use secp256k1::key::{PublicKey, SecretKey};
use std::rc::Rc;

/// Array of null bytes used in Hello package. Needs to be bigger than Welcome
/// frame to prevent amplification attacks. Maybe, 256 is too much, subject to
/// change.
pub static NULL_BYTES: [u8; 256] = [b'\x00'; 256];
/// Payload "server" side supposed to send to client when.
pub static READY_PAYLOAD: &'static [u8; 16] = b"My body is ready";

/// Secp256k1 keypair. This is just a helper type.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Public key.
    pub public_key: PublicKey,
    /// Secret key.
    pub secret_key: SecretKey,
}
impl KeyPair {
    /// Generate new keypair using thread-local random number generator. This
    /// function does unwrapping because the only reason for this to fail is to
    /// pass ctx without singing flag.
    #[inline]
    pub fn new(ctx: &Secp256k1) -> KeyPair {
        let (secret_key, public_key) = ctx.generate_keypair(&mut thread_rng())
            .expect("Failed to generate keypair");
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
    local_identity_keypair: Rc<KeyPair>,
    remote_session_key: PublicKey,
    remote_identity_key: Option<PublicKey>,
    state: SessionState,
    ctx: Secp256k1,
}
impl ServerSession {
    fn new(local_identity_keypair: Rc<KeyPair>,
           remote_session_key: PublicKey,
           ctx: Secp256k1)
           -> ServerSession {
        let now = Utc::now();
        ServerSession {
            expire_at: now + Duration::minutes(34),
            created_at: now,
            local_session_keypair: KeyPair::new(&ctx),
            local_identity_keypair: Rc::clone(&local_identity_keypair),
            remote_session_key: remote_session_key,
            remote_identity_key: None,
            state: SessionState::Fresh,
            ctx: ctx,
        }
    }
}

/// Client-side session.
#[derive(Debug, Clone)]
pub struct ClientSession {
    expire_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    local_session_keypair: KeyPair,
    local_identity_keypair: Rc<KeyPair>,
    remote_session_key: Option<PublicKey>,
    remote_identity_key: PublicKey,
    state: SessionState,
    ctx: Secp256k1,
}
impl ClientSession {
    /// Create new session. This method is private because it will create
    /// session with a few missing values.
    #[inline]
    fn new(local_identity_keypair: Rc<KeyPair>,
           remote_identity_key: PublicKey,
           ctx: Secp256k1)
           -> ClientSession {
        let now = Utc::now();
        ClientSession {
            expire_at: now + Duration::minutes(34),
            created_at: now,
            local_session_keypair: KeyPair::new(&ctx),
            local_identity_keypair: Rc::clone(&local_identity_keypair),
            remote_session_key: None,
            remote_identity_key: remote_identity_key,
            state: SessionState::Fresh,
            ctx: ctx,
        }
    }
}

trait Session {
    fn is_expired(&self) -> bool;
    fn local_identity(&self) -> PublicKey;
    fn session_state(&self) -> SessionState;
}

impl Session for ClientSession {
    fn is_expired(&self) -> bool {
        self.expire_at > Utc::now()
    }
    fn local_identity(&self) -> PublicKey {
        self.local_identity_keypair.public_key
    }

    fn session_state(&self) -> SessionState {
        self.state
    }
}

impl Session for ServerSession {
    fn is_expired(&self) -> bool {
        self.expire_at > Utc::now()
    }
    fn local_identity(&self) -> PublicKey {
        self.local_identity_keypair.public_key
    }

    fn session_state(&self) -> SessionState {
        self.state
    }
}
