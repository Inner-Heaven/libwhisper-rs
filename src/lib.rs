#![deny(missing_docs)]

//! # Angel Whisper
//! [![Gitter](https://badges.gitter.im/Inner-Heaven/angel-whisper.svg)](https://gitter.im/Inner-Heaven/angel-whisper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
//!
//! The reference implementation of Angel Whisper Wire Protocol under
//! development. As of today, this is the only documentation of protocol
//! available. This is refactoring of [my first
//! attempt](https://github.com/Inner-Heaven/angel-whisper) to write this
//! thing. However my first attempt was too broad, so I've made a decision to
//! separate `llsd` module into its own crate to allow the creation of
//! implementation in other languages.
//!
//! Angel Whisper is my attempt to build light and fast wire protocol that is
//! suitable in IoT world and the just regular world. However, no promises.
//! This library meant to handle encryption as well and decoding/encoding of
//! frames.
//! This library doesn't handle anything else like request routing, RPC, etc.
//! The plan is to build a framework on top of this.
//!
//! This library in no way production or even development ready. Meaning
//! everything including wire format is subject to change.
//! The goal is to have at least three languages talking to each other using
//! this protocol by the end of 2017.
//!
//! ## Usage
//! TODO: Write usage instructions here
//!
//! ## Development
//! Right now I'm using taskwarrior for task management, which is obviously
//! won't scale for more than one developer. I use `@andoriyu` handle pretty
//! much everywhere you can find me either on gitter, IRC, //!twitter, whatever
//! and ask for a task or tell me how much this library suck.
//!
//! ## Questions I would be asking
//! #### Do I need any help?
//!
//! Yes.
//!
//! #### Is it secure?
//!
//! Maybe, maybe not. I'm not a cryptographer, this is just for the lulz. Maybe
//! can someone help with that?
//!
//! ##### Why does it use secp256k1 at the beginning instead of Curve25519?
//!
//! Because I had a dream where I built ethereum wallet with p2p direct
//! messaging. Therefore, I ended up using secp256k1 public keys for identity.
//! First attempt was using Curve25519. After some discussions, I've decided to
//! switch back to Curve25519. Honestly, I don't like the way rust binding to
//! `libsecp256k1`work.
//!
//! #### What other languages it supports?
//!
//! Right now — only rust. In a very close feature — C via rust library. Next
//! step is Ruby via c library. After that pure Kotlin implementation.
//!
//! #### Why Rust? You barely even know rust!
//!
//! Well... I wanted to learn rust by writing something interesting in it.
//! Something that involves using many features of rust.
//!
//! #### Why not helix?
//!
//! Seems like a wrong tool for this job. Fight me.
//!
//! #### Why Kotlin and not Java?
//!
//! Because I like Kotlin more than Java. I had enough experience with Java to
//! be interested in Kotlin.


extern crate chrono;
extern crate sodiumoxide;
extern crate bytes;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate nom;


pub mod session;
pub mod frame;
pub mod errors;
