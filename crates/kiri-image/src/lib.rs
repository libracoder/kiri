//! Images on the host: references, registry pulls and the blob store.

// Unsafe only in `proc`: two plain system calls with no pointers.
#![deny(unsafe_code)]

pub mod archive;
pub mod b64;
pub mod cancel;
pub mod compress;
pub mod goflate;
mod connect;
#[doc(hidden)]
pub mod fault;
pub mod jsonfile;
mod proc;
pub mod reference;
pub mod registry;
mod stamps;
pub mod store;
pub mod tags;

pub use cancel::Cancel;
pub use reference::Reference;
pub use registry::{Client, Credentials, Platform, Progress, PushProgress, set_proxy_source};
pub use store::{Image, Layer, RunConfig, Store};
