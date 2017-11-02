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

use bytes::Bytes;
use chrono::{DateTime, Duration};
use chrono::offset::Utc;
use errors::{WhisperError, WhisperResult};

use frame::{Frame, FrameKind};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{Nonce, PrecomputedKey, PublicKey, SecretKey};

/// Array of null bytes used in Hello package. Needs to be bigger than Welcome
/// frame to prevent amplification attacks. Maybe, 256 is too much...who knows?
pub static NULL_BYTES: [u8; 256] = [b'\x00'; 256];
/// Payload "server" side supposed to send to client when.
pub static READY_PAYLOAD: &'static [u8; 16] = b"My body is ready";

/// How much time client and server have to agree on shared secret.
pub static HANDSHAKE_DURATION: i64 = 3;
/// How much time one shared secret can last.
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
    /// Server side session.
    pub fn new(local_identity_keypair: KeyPair, remote_session_key: PublicKey) -> ServerSession {
        let now = Utc::now();
        ServerSession {
            expire_at: now + Duration::minutes(HANDSHAKE_DURATION),
            created_at: now,
            local_session_keypair: KeyPair::new(),
            local_identity_keypair:
                local_identity_keypair,
            remote_session_key: remote_session_key,
            remote_identity_key: None,
            state: SessionState::Fresh,
        }
    }
    /// Helper to make a Welcome frame, a reply to Hello frame. Server worflow.
    pub fn make_welcome(&mut self, hello: &Frame) -> WhisperResult<Frame> {
        if self.state != SessionState::Fresh || hello.kind != FrameKind::Hello {
            return Err(WhisperError::InvalidSessionState);
        }
        // Verify content of the box
        if let Ok(payload) = box_::open(&hello.payload,
                                     &hello.nonce,
                                     &hello.id,
                                     &self.local_identity_keypair.secret_key)
        {
            // We're not going to verify that box content itself, but will verify it's
            // length since
            // that is what matters the most.
            if payload.len() != 256 {
                self.state = SessionState::Error;
                return Err(WhisperError::InvalidHelloFrame);
            }

            self.state = SessionState::Initiated;

            let nonce = box_::gen_nonce();
            let welcome_box = box_::seal(self.local_session_keypair.public_key.as_ref(),
                                         &nonce,
                                         &hello.id,
                                         &self.local_identity_keypair.secret_key);

            let welcome_frame = Frame {
                // Server uses client id in reply.
                id: hello.id,
                nonce: nonce,
                kind: FrameKind::Welcome,
                payload: welcome_box.into(),
            };
            Ok(welcome_frame)
        } else {
            self.state = SessionState::Error;
            Err(WhisperError::DecryptionFailed)
        }
    }
    /// A helper to extract client's permamanet public key from initiate frame
    /// in order to
    /// authenticate client. Authentication happens in another place.
    pub fn validate_initiate(&self, initiate: &Frame) -> WhisperResult<PublicKey> {
        if let Ok(initiate_payload) =
            box_::open(&initiate.payload,
                       &initiate.nonce,
                       &self.remote_session_key,
                       &self.local_session_keypair.secret_key)
        {
            // TODO: change to != with proper size
            if initiate_payload.len() < 60 {
                return Err(WhisperError::InvalidInitiateFrame);
            }
            // unwrapping here because they only panic when input is shorter than needed.
            let pk = PublicKey::from_slice(&initiate_payload[0..32])
                .expect("Failed to slice pk from payload");
            let v_nonce = Nonce::from_slice(&initiate_payload[32..56])
                .expect("Failed to slice nonce from payload");
            let v_box = &initiate_payload[56..initiate_payload.len()];

            if let Ok(vouch_payload) =
                box_::open(v_box, &v_nonce, &pk, &self.local_session_keypair.secret_key)
            {
                let v_pk = PublicKey::from_slice(&vouch_payload).expect("Wrong Size Key!!!");
                if vouch_payload.len() == 32 || v_pk == self.remote_session_key {
                    return Ok(pk);
                }
            }
        }
        Err(WhisperError::InvalidInitiateFrame)
    }

    /// Helper to make a Ready frame, a reply to Initiate frame. Server
    /// workflow.
    pub fn make_ready(&mut self,
                      initiate: &Frame,
                      client_identity_key: &PublicKey)
                      -> WhisperResult<(EstablishedSession, Frame)> {
        if self.state != SessionState::Initiated || initiate.kind != FrameKind::Initiate {
            return Err(WhisperError::InvalidSessionState);
        }

        // If client spend more than 3 minutes to come up with initiate - fuck him.
        let duration_since = Utc::now().signed_duration_since(self.created_at);
        if duration_since > Duration::minutes(HANDSHAKE_DURATION) {
            return Err(WhisperError::ExpiredSession);
        }
        self.state = SessionState::Ready;
        self.remote_identity_key = Some(*client_identity_key);

        let session = EstablishedSession::new(self.remote_session_key.clone(),
                                              self.local_session_keypair.clone());
        let (nonce, payload) = session.seal_msg(READY_PAYLOAD);
        let frame = Frame {
            id: initiate.id,
            nonce: nonce,
            kind: FrameKind::Ready,
            payload: payload,
        };
        Ok((session, frame))
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
    pub fn new(local_identity_keypair: KeyPair, remote_identity_key: PublicKey) -> ClientSession {
        let now = Utc::now();
        ClientSession {
            expire_at: now + Duration::minutes(HANDSHAKE_DURATION),
            created_at: now,
            local_session_keypair: KeyPair::new(),
            local_identity_keypair:
                local_identity_keypair,
            remote_session_key: None,
            remote_identity_key: remote_identity_key,
            state: SessionState::Fresh,
        }
    }
    /// Helper to make Hello frame. Client workflow.
    pub fn make_hello(&mut self) -> Frame {
        self.state = SessionState::Initiated;
        let nonce = box_::gen_nonce();
        let payload = box_::seal(&NULL_BYTES,
                                 &nonce,
                                 &self.remote_identity_key,
                                 &self.local_session_keypair.secret_key);
        Frame {
            id: self.local_session_keypair.public_key,
            nonce: nonce,
            kind: FrameKind::Hello,
            payload: payload.into(),
        }
    }

    /// Helper to make am Initiate frame, a reply to Welcome frame. Client
    /// workflow.
    pub fn make_initiate(&mut self, welcome: &Frame) -> WhisperResult<Frame> {
        if self.state != SessionState::Initiated || welcome.kind != FrameKind::Welcome {
            return Err(WhisperError::InvalidSessionState);
        }
        // Try to obtain server short public key from the box.
        if let Ok(server_pk) = box_::open(&welcome.payload,
                                       &welcome.nonce,
                                       &self.remote_identity_key,
                                       &self.local_session_keypair.secret_key)
        {
            if let Some(key) = PublicKey::from_slice(&server_pk) {
                self.remote_session_key = Some(key);
                let mut initiate_box = Vec::with_capacity(104);
                initiate_box.extend_from_slice(&self.local_identity_keypair.public_key.0);
                initiate_box.extend(self.make_vouch());
                let nonce = box_::gen_nonce();
                let payload = box_::seal(&initiate_box,
                                         &nonce,
                                         &self.remote_session_key.expect("Shit is on fire yo"),
                                         &self.local_session_keypair.secret_key);
                let frame = Frame {
                    id: welcome.id,
                    nonce: nonce,
                    kind: FrameKind::Initiate,
                    payload: payload.into(),
                };
                Ok(frame)
            } else {
                self.state = SessionState::Error;

                return Err(WhisperError::InvalidWelcomeFrame);
            }
        } else {
            self.state = SessionState::Error;
            return Err(WhisperError::DecryptionFailed);
        }
    }
    /// Verify that reply to initiate frame is correct ready frame. Changes
    /// session state if so.
    pub fn read_ready(&mut self, ready: &Frame) -> WhisperResult<EstablishedSession> {
        if self.state != SessionState::Initiated || ready.kind != FrameKind::Ready {
            return Err(WhisperError::InvalidSessionState);
        }
        // This can never fail when used properly.
        let session = EstablishedSession::new(self.remote_session_key.unwrap().clone(),
                                              self.local_session_keypair.clone());
        let msg = session.read_msg(ready)?;
        if msg.as_ref() == READY_PAYLOAD {
            self.state = SessionState::Ready;
            Ok(session)
        } else {
            Err(WhisperError::InvalidReadyFrame)
        }
    }
    // Helper to make a vouch
    fn make_vouch(&self) -> Vec<u8> {
        let nonce = box_::gen_nonce();
        let our_sk = &self.local_identity_keypair.secret_key;
        let pk = &self.local_session_keypair.public_key;
        let vouch_box = box_::seal(&pk.0,
                                   &nonce,
                                   &self.remote_session_key.expect("Shit is on fire yo"),
                                   our_sk);

        let mut vouch = Vec::with_capacity(72);
        vouch.extend_from_slice(&nonce.0);
        vouch.extend(vouch_box);
        vouch
    }
}

/// This structure represent session that completed handshake.
///
/// Only way to create is to have ClientSession and ServerSession agree on
/// shared secret a.k.a. session_key a.k.a. PrecomputedKey.
/// ServerSession turns into EstablishedSession by verifying Initiate frame.
/// ClientSession turns into EstablishedSession by verifying Ready frame.
pub struct EstablishedSession {
    id: PublicKey,
    expire_at: DateTime<Utc>,
    session_secret: PrecomputedKey,
}

impl EstablishedSession {
    /// Create EstablishSession by precomputing shared secret. Don't use this
    /// directly.
    pub fn new(remote_session_key: PublicKey,
               local_session_keypair: KeyPair)
               -> EstablishedSession {
        let now = Utc::now();
        let our_precomputed_key = box_::precompute(&remote_session_key,
                                                   &local_session_keypair.secret_key);
        EstablishedSession {
            id: local_session_keypair.public_key,
            expire_at: now + Duration::minutes(SESSION_DURATION),
            session_secret: our_precomputed_key,
        }
    }
    fn seal_msg(&self, data: &[u8]) -> (Nonce, Bytes) {
        let nonce = box_::gen_nonce();
        let payload = box_::seal_precomputed(data, &nonce, &self.session_secret);
        (nonce, payload.into())
    }

    /// Method use to open payload.
    pub fn read_msg(&self, frame: &Frame) -> WhisperResult<Bytes> {
        if let Ok(msg) = box_::open_precomputed(&frame.payload, &frame.nonce, &self.session_secret) {
            Ok(msg.into())
        } else {
            Err(WhisperError::DecryptionFailed)
        }
    }

    fn make_message(&self, data: &[u8], kind: FrameKind) -> WhisperResult<Frame> {
        if self.is_expired() {
            return Err(WhisperError::ExpiredSession);
        }
        let (nonce, payload) = self.seal_msg(data);
        let frame = Frame {
            id: self.id(),
            nonce: nonce,
            kind: kind,
            payload: payload,
        };
        Ok(frame)
    }

    /// Method used to create new requests.
    pub fn make_request(&self, data: &[u8]) -> WhisperResult<Frame> {
        self.make_message(data, FrameKind::Request)
    }

    /// Method used to create new responses.
    pub fn make_response(&self, data: &[u8]) -> WhisperResult<Frame> {
        self.make_message(data, FrameKind::Response)
    }

    /// Method used to create new notifications.
    pub fn make_notification(&self, data: &[u8]) -> WhisperResult<Frame> {
        self.make_message(data, FrameKind::Notification)
    }
}

/// Common session functions that apply to all session types.
trait Session {
    /// Returns true if session is expired.
    fn is_expired(&self) -> bool;
    /// Returns session state.
    fn session_state(&self) -> SessionState;
    /// Returns session id. This should always be client short term public key.
    fn id(&self) -> PublicKey;
}

impl Session for ClientSession {
    fn is_expired(&self) -> bool { self.expire_at < Utc::now() }
    fn session_state(&self) -> SessionState { self.state }
    fn id(&self) -> PublicKey { self.local_session_keypair.public_key }
}

impl Session for ServerSession {
    fn is_expired(&self) -> bool { self.expire_at < Utc::now() }
    fn session_state(&self) -> SessionState { self.state }
    fn id(&self) -> PublicKey { self.remote_session_key }
}

impl Session for EstablishedSession {
    fn is_expired(&self) -> bool { self.expire_at < Utc::now() }
    fn session_state(&self) -> SessionState { SessionState::Ready }
    fn id(&self) -> PublicKey { self.id }
}

#[cfg(test)]
mod test {
    use frame::FrameKind;
    use session::{ClientSession, EstablishedSession, KeyPair, ServerSession, Session, SessionState};

    /// Helper to create two established sessions.
    fn handshake() -> (EstablishedSession, EstablishedSession) {
        let client_identity_keypair = KeyPair::new();
        let server_identity_keypair = KeyPair::new();
        let mut client_session =
            ClientSession::new(client_identity_keypair.clone(),
                               server_identity_keypair.public_key.clone());
        let mut server_session = ServerSession::new(server_identity_keypair, client_session.id().clone());
        let hello_frame = client_session.make_hello();
        let welcome_frame =
            server_session.make_welcome(&hello_frame)
                          .expect("Failed to create welcome!");
        let initiate_frame =
            client_session.make_initiate(&welcome_frame)
                          .expect("Failed to create initiate!");
        let client_identity_key =
            server_session.validate_initiate(&initiate_frame)
                          .expect("Failed to unpack PublicKey");
        let (server_established_session, ready_frame) =
            server_session.make_ready(&initiate_frame, &client_identity_key)
                          .expect("Failed to create ready!");
        let client_established_session =
            client_session.read_ready(&ready_frame)
                          .expect("Failed to read ready frame!");
        (client_established_session, server_established_session)
    }

    #[test]
    fn test_expire_client() {
        let local = KeyPair::new();
        let remote = KeyPair::new();

        let client_session = ClientSession::new(local, remote.public_key.clone());
        assert!(!client_session.is_expired());
    }

    #[test]
    fn test_expire_server() {
        let local = KeyPair::new();
        let remote = KeyPair::new();

        let server_session = ServerSession::new(local, remote.public_key.clone());
        assert!(!server_session.is_expired());
    }

    #[test]
    fn test_successful_hashshake() {
        let client_identity_keypair = KeyPair::new();
        let server_identity_keypair = KeyPair::new();

        let mut client_session =
            ClientSession::new(client_identity_keypair.clone(),
                               server_identity_keypair.public_key.clone());
        let mut server_session = ServerSession::new(server_identity_keypair.clone(), client_session.id().clone());
        assert_eq!(client_session.state, SessionState::Fresh);
        assert_eq!(server_session.state, SessionState::Fresh);
        assert_eq!(client_session.id(), server_session.id());

        let hello_frame = client_session.make_hello();
        assert_eq!(hello_frame.kind, FrameKind::Hello);
        assert_eq!(client_session.state, SessionState::Initiated);

        let welcome_frame =
            server_session.make_welcome(&hello_frame)
                          .expect("Failed to create welcome!");
        assert_eq!(server_session.state, SessionState::Initiated);

        let initiate_frame =
            client_session.make_initiate(&welcome_frame)
                          .expect("Failed to create initiate!");

        let client_identity_key =
            server_session.validate_initiate(&initiate_frame)
                          .expect("Failed to unpack PublicKey");
        assert_eq!(&client_identity_key, &client_identity_keypair.public_key);

        let (server_established_session, ready_frame) =
            server_session.make_ready(&initiate_frame, &client_identity_key)
                          .expect("Failed to create ready!");
        assert_eq!(server_established_session.session_state(),
                   SessionState::Ready);
        assert_eq!(server_session.session_state(), SessionState::Ready);

        let client_established_session =
            client_session.read_ready(&ready_frame)
                          .expect("Failed to read ready frame!");
        assert_eq!(client_established_session.session_state(),
                   SessionState::Ready);
        assert_eq!(client_session.session_state(), SessionState::Ready);
    }

    #[test]
    fn test_ping_pong() {
        let (client, server) = handshake();

        let ping_bytes = b"ping";
        let ping = client.make_request(ping_bytes).unwrap();
        assert_eq!(ping.kind, FrameKind::Request);
        let ping_payload = server.read_msg(&ping).unwrap();
        assert_eq!(&ping_payload.as_ref(), &ping_bytes);

        let pong_bytes = b"pong";
        let pong = server.make_response(pong_bytes).unwrap();
        assert_eq!(pong.kind, FrameKind::Response);
        let pong_payload = client.read_msg(&pong).unwrap();
        assert_eq!(&pong_payload.as_ref(), &pong_bytes);

        let score = server.make_notification(b"Player B Scored").unwrap();

        assert_eq!(score.kind, FrameKind::Notification);
    }
}
