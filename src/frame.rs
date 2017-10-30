//! This is how frames look on the wire. This module doesn't handle Frame
//! generation — generation is done in session module.

use bytes::{BufMut, Bytes, BytesMut};

use errors::{WhisperError, WhisperResult};
use nom::{IResult, rest};
use sodiumoxide::crypto::box_::{Nonce, PublicKey};


/// How many bytes of overhead each frame has. Header consist of:
/// - Session identificator. 32 bytes.
/// - Nonce used to encrypt payload. 24 bytes.
/// - Message type as u8 BigEndian. 1 byte.
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
    pub fn length(&self) -> usize { HEADER_SIZE + self.payload.len() }

    /// Writes packed bytes to supplied buffer. This doesn't include legnth of
    /// the message.
    pub fn pack_to_buf(&self, buf: &mut BytesMut) {
        buf.reserve(self.length());
        buf.extend_from_slice(&self.id.0);
        buf.extend_from_slice(&self.nonce.0);
        buf.put_u8(self.kind as u8);
        buf.extend_from_slice(&self.payload);
    }

    /// Pack frame header and its payload into Vec<u8>.
    pub fn pack(&self) -> Bytes {
        let mut frame = BytesMut::with_capacity(self.length());
        self.pack_to_buf(&mut frame);
        frame.freeze()
    }

    /// Parse packed frame.
    pub fn from_slice(i: &[u8]) -> WhisperResult<Frame> {
        match parse_frame(i) {
            IResult::Done(_, frame) => Ok(frame),
            IResult::Incomplete(_) => Err(WhisperError::IncompleteFrame),
            IResult::Error(_) => Err(WhisperError::BadFrame),
        }
    }
}

named!(parse_frame < &[u8], Frame >,
       do_parse!(
           pk:          map_opt!(take!(32), PublicKey::from_slice)  >>
           nonce:       map_opt!(take!(24), Nonce::from_slice)      >>
           kind:        map_opt!(take!(1),  FrameKind::from_slice)  >>
           payload:     rest                                        >>
           ({
               let mut vec = Vec::with_capacity(payload.len());
               vec.extend(payload.iter().cloned());
               Frame {
                   id: pk,
                   nonce: nonce,
                   kind: kind,
                   payload: vec.into()
               }
           })
           )
      );

#[cfg(test)]
mod test {
    use super::*;

    use errors::WhisperError;
    use sodiumoxide::crypto::box_::{gen_keypair, gen_nonce};

    #[test]
    fn pack_and_unpack() {
        let frame = make_frame();
        let packed_frame = frame.pack();
        assert_eq!(packed_frame.len(), 60);

        let parsed_frame = Frame::from_slice(&packed_frame);

        assert_eq!(frame, parsed_frame.unwrap());
    }
    #[test]
    fn frame_kind_from_slice() {
        let hello = FrameKind::from_slice(&[1]).unwrap();
        let welcome = FrameKind::from_slice(&[2]).unwrap();
        let initiate = FrameKind::from_slice(&[3]).unwrap();
        let ready = FrameKind::from_slice(&[4]).unwrap();
        let request = FrameKind::from_slice(&[5]).unwrap();
        let response = FrameKind::from_slice(&[6]).unwrap();
        let notification = FrameKind::from_slice(&[7]).unwrap();
        let termination = FrameKind::from_slice(&[255]).unwrap();
        let bad = FrameKind::from_slice(&[100]);
        let none = FrameKind::from_slice(&[]);

        assert_eq!(hello, FrameKind::Hello);
        assert_eq!(welcome, FrameKind::Welcome);
        assert_eq!(initiate, FrameKind::Initiate);
        assert_eq!(ready, FrameKind::Ready);
        assert_eq!(request, FrameKind::Request);
        assert_eq!(response, FrameKind::Response);
        assert_eq!(notification, FrameKind::Notification);
        assert_eq!(termination, FrameKind::Termination);
        assert!(bad.is_none());
        assert!(none.is_none());
    }

    #[test]
    fn malformed_frame() {
        let packed_frame = vec![1 as u8, 2, 3];

        let parsed_frame = Frame::from_slice(&packed_frame);

        assert_eq!(parsed_frame.is_err(), true);
        let err = parsed_frame.err().unwrap();

        // nasty
        let mut is_incomplete = false;
        if let WhisperError::IncompleteFrame = err {
            is_incomplete = true;
        }
        assert!(is_incomplete);
    }

    #[test]
    fn bad_frame() {
        // Frames created by this library will never be invalid, but oh well.
        // I present you malformed frame — frame that has FrameType of 13.
        let bad_frame = b"\x85\x0f\xc2?\xce\x80f\x16\xec8\x04\xc7{5\x98\xa7u<\xa5y\xda\x12\xfe\xad\xdc^%[\x8ap\xfa7q.-)\xe4V\xec\x94\xb2\x7f\r\x9a\x91\xc7\xcd\x08\xa4\xee\xbfbpH\x07%\r\0\0\0";
        let result = Frame::from_slice(&bad_frame[0..59]);
        assert!(result.is_err());
        let err = result.err().unwrap();
        // nasty
        let mut is_bad = false;
        if let WhisperError::BadFrame = err {
            is_bad = true;
        }
        assert!(is_bad);
    }

    fn make_frame() -> Frame {
        let (pk, _) = gen_keypair();
        let payload = vec![0, 0, 0];
        let nonce = gen_nonce();

        Frame {
            id: pk,
            nonce: nonce,
            kind: FrameKind::Hello,
            payload: payload.into(),
        }
    }
}
