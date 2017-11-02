#![deny(missing_docs)]

//! # Angel Whisper
//! [![Gitter](https://badges.gitter.im/Inner-Heaven/angel-whisper.svg)](https://gitter.im/Inner-Heaven/whisper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
//! [![Build Status](https://travis-ci.org/Inner-Heaven/libwhisper-rs.
//! svg?branch=master)](https://travis-ci.org/Inner-Heaven/libwhisper-rs)
//! [![codecov](https://codecov.
//! io/gh/Inner-Heaven/libwhisper-rs/branch/master/graph/badge.svg)](https:
//! //codecov.io/gh/Inner-Heaven/libwhisper-rs)
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
