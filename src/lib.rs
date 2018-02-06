#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy(conf_file = "../clippy.toml")))]

extern crate base64;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate bytes;
extern crate crypto;
extern crate des;
extern crate digest;
extern crate encoding;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate generic_array;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate md4;
#[macro_use]
extern crate nom;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate rand;
extern crate time;

#[cfg(feature = "hyper")]
#[macro_use]
extern crate hyper;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
extern crate matches;

mod errors;
#[macro_use]
pub mod proto;
pub mod server;
pub mod client;

#[cfg(feature = "hyper")]
pub mod http;
