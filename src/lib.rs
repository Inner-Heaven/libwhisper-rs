//! # Angel Whisper
//! The reference implementation of Angel Whisper Wire Protocol under
//! development. As of today, this is the only documentation of protocol
//! available. This is refactoring of [my first
//! attempt](https://github.com/Inner-Heaven/angel-whisper) to write this
//! thing. However my first attempt was too broad, so I've made a decision to
//! separate `llsd` module into its own crate to allow the creation of
//! implementation in other languages.
//!
//! Angel Whisper is my attempt to build light and fast wire protocol that is
//! suitable in IoT world and the just regular world. This library meant to
//! handle encryption as well and decoding/encoding of frames. This library
//! doesn't handle anything else. The plan is to build very opinionated
//! framework.
//!
//! This library in no way production or even development ready. Meaning
//! everything including wire format is subject to change.
//!
//! ## Questions I would be asking
//! #### Do I need any help?
//!
//! Yes.
//!
//! #### Is it secure?
//!
//! Maybe, maybe not. I'm not a cryptographer, this is just for the lulz. Maybe
//! someone can help with that?
//!
//! ##### Why does it use secp256k1 instead of Curve25519?
//!
//! Because I had a dream where I built ethereum wallet with p2p direct
//! messaging. Therefore, I ended up using secp256k1 public keys for identity.
//! First attempt was using Curve25519.
//!
//! #### What about Session store?
//!
//! This belongs to level above this library.
//!
//! #### What other languages it supports?
//!
//! Right now — only rust. In a very close feature — C via rust library. Next
//! step is Ruby via c library. After that pure Kotlin implementation.
//!
//! #### Why not helix?
//!
//! Seems like a wrong tool for this job. Fight me.
//!
//! #### Why Kotlin and not Java?
//!
//! Have you seen Java?


extern crate chrono;
extern crate sodiumoxide;
extern crate secp256k1;
extern crate rand;
extern crate bytes;

pub mod session;
pub mod frame;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
