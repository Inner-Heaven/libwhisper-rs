//! This is how frames look on the wire. This module doesn't handle Frame
//! generation — generation is done in session module.

use bytes::{BufMut, Bytes, BytesMut};
use secp256k1::key::PublicKey;
use sodiumoxide::crypto::box_::Nonce;

/// How many bytes of overhead each frame has.
pub static HEADER_SIZE: usize = 57;


/// Frame type. Frame kind takes 1 byte.
#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub enum FrameKind {
    /// Initial frame. Sent from client.
    Hello = 1,
    /// Reply to initial frame. Sent from server.
    Welcome,
    /// Authentication frame. Sent from client.
    Initiate,
    /// After successful handshake this frame is sent from server.
    Ready,
    /// A message that requres remote side to reply. Can be sent from either
    /// side.
    Request,
    /// A message that is a reply to corresponsing Request. Can be sent from
    /// either side.
    Response,
    /// A message that doesn't require response. Can be sent from either side.
    Notification,
    /// Termination frame. Usually used to indicate handshake error or session
    /// termination. Can be sent from either side.
    Termination,
}

/// Each frame has it's kind. Meant to be expandable.
impl FrameKind {
    /// Since we don't have TryFrom...
    pub fn from(kind: u8) -> Option<FrameKind> {
        match kind {
            1 => Some(FrameKind::Hello),
            2 => Some(FrameKind::Welcome),
            3 => Some(FrameKind::Initiate),
            4 => Some(FrameKind::Ready),
            5 => Some(FrameKind::Request),
            6 => Some(FrameKind::Response),
            7 => Some(FrameKind::Notification),
            255 => Some(FrameKind::Termination),
            _ => None,
        }
    }
    /// Alias to method above, but returns an error if there're more than one
    /// byte.
    pub fn from_slice(kind: &[u8]) -> Option<FrameKind> {
        if kind.len() != 1 {
            return None;
        }
        FrameKind::from(kind[0])
    }
}

/// The main unit of information passed from client to server and vice versa.
/// This thing doesn't
/// care what payload it as long as Frame has correct header.
/// This way you can use whatever you want as your internal message format —
/// JSON, BSON, TSV, Protocol Buffers, etc.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Frame {
    /// Session identificator. 32 bytes
    pub id: PublicKey,
    /// Nonce used to encrypt payload. Nonce is also used as Request ID in
    /// multiplexing. 24 bytes
    pub nonce: Nonce,
    /// Message type as u8 BigEndian. 1 byte
    pub kind: FrameKind,
    /// Payload (that may or may not be encrypted)
    pub payload: Bytes,
}


impl Frame {
    /// Calculates length of a frame;
    pub fn length(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /*
    /// Writes packed bytes to supplied buffer. This doesn't include legnth of
    /// the message.
    pub fn pack_to_buf(&self, buf: &mut BytesMut) {
        buf.reserve(self.length());
        buf.extend_from_slice(&self.id.0);
        buf.extend_from_slice(&self.nonce.0);
        buf.put_u8(self.kind as u8);
        buf.extend_from_slice(&self.payload);
        ()
    }
    */
    /*
    /// Pack frame header and its payload into Vec<u8>.
    pub fn pack(&self) -> Bytes {
        let mut frame = BytesMut::with_capacity(self.length());
        self.pack_to_buf(&mut frame);
        frame.freeze()
    }
    */

    /*
    /// Parse packed frame.
    pub fn from_slice(i: &[u8]) -> LlsdResult<Frame> {
        match parse_frame(i) {
            IResult::Done(_, frame) => Ok(frame),
            IResult::Incomplete(_) => Err(LlsdError::IncompleteFrame),
            IResult::Error(_) => Err(LlsdError::BadFrame),
        }
    }
    */
}
