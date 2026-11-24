//! Secret values the engine keeps on disk sealed with ChaCha20-Poly1305,
//! under a key that stays in the engine's data folder
//! (`secrets.key`, 0600). A list of them, none of their values: a caller
//! puts one with `POST /kiri/secrets` (`{"name", "data"}`), names it into
//! a container's env with a `secret:<name>` entry (alone, or as any
//! entry's value), and only at that container's start does the value
//! reach the guest — the records keep the reference, so a copied
//! `containers.json` carries names, not secrets.

use std::collections::BTreeMap;
use std::path::Path;

use ring::rand::SecureRandom;

/// What an env entry's name (or value) starts with to name a secret.
pub const ENV_PREFIX: &str = "secret:";

/// Whether an env entry names a secret, either as the whole entry
/// (`secret:db-password`, no `=`) or as its value
/// (`DB_PASSWORD=secret:db-password`). An entry with a `=` in the key
/// position (`secret:db=x`) is the user's literal env, not a reference.
pub fn is_secret_ref(entry: &str) -> bool {
    match entry.split_once('=') {
        None => entry.starts_with(ENV_PREFIX),
        Some((_, value)) => value.starts_with(ENV_PREFIX),
    }
}

/// One secret's sealed bytes, as the engine's file holds them.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Entry {
    /// The 12 ChaCha20-Poly1305 nonce bytes that sealed this value, and
    /// the sealed value (ciphertext plus the 16-byte tag); as byte
    /// arrays in `secrets.json`.
    nonce: [u8; 12],
    sealed: Vec<u8>,
    /// Unix seconds of the latest `set` of this name.
    created: u64,
}

/// The engine's secrets, kept as a file of sealed entries beside its
/// other state.
pub struct Secrets {
    list: BTreeMap<String, Entry>,
    path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl Secrets {
    /// Loads the file at `root/secrets.json` (none yet, or a damaged one,
    /// means no secrets — as `Networks::load` reads a damaged file as
    /// none) and makes sure the key exists for the first set.
    pub fn load(root: &Path) -> Secrets {
        let list = std::fs::read(root.join("secrets.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<BTreeMap<String, Entry>>(&b).ok())
            .unwrap_or_default();
        Secrets {
            list,
            path: root.join("secrets.json"),
            key_path: root.join("secrets.key"),
        }
    }

    /// The engine's key: what `secrets.key` holds, making it first if the
    /// file is missing. A file there that is not 32 bytes is damaged — an
    /// error, never a silent reset, which would open every still-sealed
    /// secret's door while closing its value.
    fn key(&self) -> Result<[u8; 32], std::io::Error> {
        let mut key = [0u8; 32];
        match std::fs::read(&self.key_path) {
            Ok(bytes) if bytes.len() == 32 => {
                key.copy_from_slice(&bytes);
                Ok(key)
            }
            Ok(_) => Err(std::io::Error::other("secrets.key is damaged: fix or remove it (and the secrets sealed under it) before setting new secrets")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let rand = ring::rand::SystemRandom::new();
                rand.fill(&mut key).map_err(|_| std::io::Error::other("no randomness for a secrets key"))?;
                write_key(&self.key_path, &key)?;
                Ok(key)
            }
            Err(e) => Err(e),
        }
    }

    /// Seals `value` under the name (replacing an earlier one) and saves.
    pub fn set(&mut self, name: &str, value: &[u8]) -> Result<(), std::io::Error> {
        name_guard(name)?;
        let key = self.key()?;
        let (nonce, sealed) = seal(&key, value);
        let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        self.list.insert(name.to_owned(), Entry { nonce, sealed, created });
        self.save();
        Ok(())
    }

    /// Removes a secret, saving; whether there was one.
    pub fn remove(&mut self, name: &str) -> Result<bool, std::io::Error> {
        if self.list.remove(name).is_some() {
            self.save();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// The names, oldest first, with when each was last set.
    pub fn names(&self) -> Vec<(String, u64)> {
        self.list.iter().map(|(name, e)| (name.clone(), e.created)).collect()
    }

    /// A secret's plain bytes, decrypted on the way out; the caller uses
    /// them and they are in memory only for the length of that.
    pub fn plain(&self, name: &str) -> Result<Vec<u8>, String> {
        let entry = self.list.get(name).ok_or_else(|| format!("no secret named {name}"))?;
        let key = self.key().map_err(|e| e.to_string())?;
        unseal(&key, entry.nonce, entry.sealed.clone()).map_err(|_| format!("the secret named {name} does not open under this engine's key"))
    }

    /// Env entries with their secret references turned into values; an
    /// unknown name is the error (Docker's create answers `no such
    /// secret` the same way at the same moment).
    pub fn resolve(&self, envs: &[String]) -> Result<Vec<String>, String> {
        envs.iter()
            .map(|e| match e.split_once('=') {
                None if e.starts_with(ENV_PREFIX) => {
                    let name = &e[ENV_PREFIX.len()..];
                    self.plain(name).and_then(|p| String::from_utf8(p).map(|p| format!("{name}={p}")).map_err(|_| format!("the secret named {name} is not UTF-8 text")))
                }
                Some((key, value)) if value.starts_with(ENV_PREFIX) => {
                    let name = &value[ENV_PREFIX.len()..];
                    self.plain(name).and_then(|p| String::from_utf8(p).map(|p| format!("{key}={p}")).map_err(|_| format!("the secret named {name} is not UTF-8 text")))
                }
                _ => Ok(e.clone()),
            })
            .collect()
    }

    fn save(&self) {
        if let Ok(json) = serde_json::to_vec(&self.list) {
            let tmp = self.path.with_extension("json.tmp");
            if let Err(e) = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, &self.path)) {
                crate::diag::error!("saving secrets failed", error = e);
            }
        }
    }
}

/// What a secret's name may be: letters, digits and `-_.`, up to 64 of
/// them, not empty — the shape every part of the engine and the guest
/// treats as a plain word.
fn name_guard(name: &str) -> Result<(), std::io::Error> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("a secret's name is 1 to 64 of A-Z a-z 0-9 - _ . (got {name:?})")))
    }
}

fn seal(key: &[u8; 32], plain: &[u8]) -> ([u8; 12], Vec<u8>) {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).expect("a 32-byte ChaCha20 key");
    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new().fill(&mut nonce).expect("randomness for a nonce");
    let mut data = plain.to_vec();
    LessSafeKey::new(unbound)
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
        .expect("sealing plain bytes");
    (nonce, data)
}

fn unseal(key: &[u8; 32], nonce: [u8; 12], mut sealed: Vec<u8>) -> Result<Vec<u8>, ring::error::Unspecified> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    let opened_len = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key)?)
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut sealed)?
        .len();
    sealed.truncate(opened_len);
    Ok(sealed)
}

fn write_key(path: &std::path::Path, key: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("key.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(key)?;
    // Only this user reads the key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A value comes back exactly as it went in, under a key the engine
    /// made itself; the name guard keeps only plain words.
    #[test]
    fn a_secret_returns_its_value_and_none_other() {
        let dir = root("kiri-secrets-round");
        let mut s = Secrets::load(&dir);
        s.set("db-password", b"hunter2").unwrap();
        s.set("tls.key", vec![0xff, 0xfe].as_slice()).unwrap();
        assert_eq!(s.plain("db-password").unwrap(), b"hunter2");
        assert_eq!(s.plain("tls.key").unwrap(), vec![0xff, 0xfe]);
        assert!(s.plain("nope").is_err());
        assert!(s.set("has space", b"x").is_err());
        assert!(s.set("", b"x").is_err());
        assert_eq!(s.names().len(), 2);
        // A second engine on the same data reads what the first sealed.
        drop(s);
        let s2 = Secrets::load(&dir);
        assert_eq!(s2.plain("db-password").unwrap(), b"hunter2");
        drop(s2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The references turn into values at resolve time, both forms, and
    /// an unknown name is the error; plain entries pass through whole.
    #[test]
    fn resolve_turns_references_into_values_and_errors_on_no_such_secret() {
        let dir = root("kiri-secrets-resolve");
        let mut s = Secrets::load(&dir);
        s.set("db-password", b"hunter2").unwrap();
        let env = ["DB=secret:db-password".to_owned(), "secret:db-password".to_owned(), "PATH=/usr/bin".to_owned()];
        assert_eq!(
            s.resolve(&env).unwrap(),
            vec!["DB=hunter2".to_owned(), "db-password=hunter2".to_owned(), "PATH=/usr/bin".to_owned()]
        );
        // A key-side `secret:` with a value after it is the user's own env.
        assert!(!is_secret_ref("secret:db-password=plain"));
        assert!(is_secret_ref("secret:db-password"));
        assert!(is_secret_ref("DB=secret:db-password"));
        assert!(!is_secret_ref("PATH=/secret:notes"));
        assert!(s.resolve(&["secret:nope".to_owned()]).is_err());
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }
}
