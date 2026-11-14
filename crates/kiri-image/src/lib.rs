//! Images on the host: references, registry pulls and the blob store.

#![forbid(unsafe_code)]

pub mod archive;
pub mod b64;
pub mod cancel;
mod connect;
pub mod mirror;
pub mod reference;
pub mod registry;
pub mod store;
pub mod tags;

pub use cancel::Cancel;
pub use mirror::Mirror;
pub use reference::Reference;
pub use registry::{Client, Credentials, MirrorSource, Platform, Progress, PushProgress, set_mirror_source, set_proxy_source};
pub use store::{Image, Layer, RunConfig, Store};
