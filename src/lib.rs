#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy(conf_file = "../clippy.toml")))]

#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate bytes;
extern crate encoding;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate num;
#[macro_use]
extern crate num_derive;

mod errors;
#[macro_use]
pub mod proto;
pub mod server;
pub mod client;
