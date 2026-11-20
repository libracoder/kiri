//! The Windows roots module: [`roots`], compiled by path from
//! crates/kiri-image/src/roots.rs — the same file `kiri` uses — so Share
//! here trusts the system certificate store (and honours
//! `KIRI_TLS_ROOTS=webpki`) exactly as it does on the Mac and Linux.

#[path = "../../kiri-image/src/roots.rs"]
pub(crate) mod roots;
