//! `kiri raw run`: boots the guest, makes sure the image's layers are unpacked
//! there, runs one container and streams its output.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use kiri_image::{Client, Image, Platform, Reference, Store};
use kiri_proto::{Stream, run_flags};

use crate::guest::{BootOptions, Guest, RunRequest};

const USAGE: &str = "usage: kiri raw run [--rm] [-e KEY=VALUE]... [-u USER] [-w DIR] [--timings] IMAGE [COMMAND [ARG...]]

Containers get their own network namespace with only loopback for now
(like docker run --network none); bridged networking comes next.";

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    remove: bool,
    env: Vec<String>,
    user: Option<String>,
    workdir: Option<String>,
    timings: bool,
    image: String,
    command: Vec<String>,
}

fn parse(args: &[String]) -> io::Result<Option<Options>> {
    let bad = |m: String| io::Error::new(io::ErrorKind::InvalidInput, format!("{m}\n\n{USAGE}"));
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().cloned().ok_or_else(|| bad(format!("{flag} needs a value")));
        match a.as_str() {
            "--rm" => o.remove = true,
            "--timings" => o.timings = true,
            "-e" | "--env" => o.env.push(value(a)?),
            "-u" | "--user" => o.user = Some(value(a)?),
            "-w" | "--workdir" => o.workdir = Some(value(a)?),
            "--network" | "--net" => {
                let v = value(a)?;
                if v != "none" {
                    return Err(bad(format!("--network {v} is not supported yet; only none")));
                }
            }
            "-h" | "--help" => return Ok(None),
            "--" => {
                if let Some(img) = it.next() {
                    o.image = img.clone();
                    o.command = it.cloned().collect();
                }
                break;
            }
            s if s.starts_with('-') => return Err(bad(format!("unknown option {s}"))),
            _ => {
                o.image = a.clone();
                o.command = it.cloned().collect();
                break;
            }
        }
    }
    if o.image.is_empty() {
        return Err(bad("no image given".into()));
    }
    Ok(Some(o))
}

/// Finds the image locally, pulling it first if needed, and holds every blob
/// it references ([`Store::hold_image`]) so a concurrent tag replacement or
/// removal cannot delete them before layers are sent to the guest.
pub fn image(store: &Store, name: &str) -> io::Result<(Image, Vec<kiri_image::store::Pin>)> {
    let reference = Reference::parse(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    if let Some(found) = store.find_pinned(&reference.short())? {
        return Ok(found);
    }
    eprintln!("Unable to find image '{}' locally; pulling", reference.short());
    let pulled = Client::new().pull(store, &reference, &Platform::host_linux(), &|_| {}).map_err(io::Error::other)?;
    let pins = store.hold_image(&pulled);
    Ok((pulled, pins))
}

/// Makes sure every layer of `image` is unpacked in the guest with its
/// verified `diff_id`. Returns how many had to be sent.
pub fn ensure_layers(guest: &mut Guest, store: &Store, image: &Image) -> io::Result<usize> {
    let _held = store.hold_image(image);
    let diff_ids = store.checked_diff_ids(image)?;
    let mut sent = 0;
    for (layer, want) in image.layers.iter().zip(&diff_ids) {
        if !guest.has_layer(&layer.digest, want)? {
            guest.send_layer(&layer.digest, want, &store.blob_path(&layer.digest)?)?;
            sent += 1;
        }
    }
    Ok(sent)
}

/// Docker's rule: the command replaces the image's Cmd; the entrypoint stays.
pub fn argv(image: &Image, command: &[String]) -> Vec<String> {
    let cmd = if command.is_empty() { &image.config.cmd } else { command };
    image.config.entrypoint.iter().chain(cmd).cloned().collect()
}

/// Top layer first, as overlayfs lists lower directories.
pub fn layers_top_down(image: &Image) -> Vec<String> {
    image.layers.iter().rev().map(|l| l.digest.clone()).collect()
}

/// A fresh 12-hex-digit container id.
pub fn new_id() -> String {
    let mut b = [0u8; 6];
    let filled = std::fs::File::open("/dev/urandom").and_then(|mut f| io::Read::read_exact(&mut f, &mut b));
    if filled.is_err() {
        let t = Instant::now().elapsed().as_nanos() as u64 ^ std::process::id() as u64;
        b.copy_from_slice(&t.to_le_bytes()[..6]);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn run(args: &[String]) -> io::Result<()> {
    let Some(o) = parse(args)? else {
        println!("{USAGE}");
        return Ok(());
    };
    let t0 = Instant::now();
    let store = Store::open(Store::default_root()?)?;
    let (image, _blob_pins) = image(&store, &o.image)?;
    let argv = argv(&image, &o.command);
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} has no default command; give one", image.name)));
    }

    let mut guest = Guest::boot(&BootOptions { data_disk: true, ..Default::default() })?;
    let booted = t0.elapsed();
    let sent = ensure_layers(&mut guest, &store, &image)?;
    let layers_ready = t0.elapsed();

    let mut env = image.config.env.clone();
    env.extend(o.env.iter().cloned());
    let id = new_id();
    let layers = layers_top_down(&image);
    let req = RunRequest {
        id: &id,
        layers: &layers,
        argv: &argv,
        env: &env,
        cwd: o.workdir.as_deref().unwrap_or(&image.config.working_dir),
        user: o.user.as_deref().unwrap_or(&image.config.user),
        hostname: &id,
        flags: run_flags::NET_NONE | if o.remove { run_flags::REMOVE } else { 0 },
    };
    let (mut stdout, mut stderr) = (io::stdout().lock(), io::stderr().lock());
    let result = guest.run(&req, |stream, data| {
        let _ = match stream {
            Stream::Stdout => stdout.write_all(data),
            Stream::Stderr => stderr.write_all(data),
        };
    });
    let _ = stdout.flush();
    drop((stdout, stderr));
    let shutdown = guest.shutdown();
    let r = result?;

    if o.timings {
        let ms = |d: Duration| d.as_secs_f64() * 1e3;
        eprintln!("kiri raw run timings");
        eprintln!("  VM boot                  {:7.1} ms", ms(booted));
        eprintln!("  layers ready ({sent} sent)    {:7.1} ms", ms(layers_ready - booted));
        eprintln!("  container start → exit   {:7.2} ms  (guest: setup {:.2} ms, process {:.2} ms)",
            ms(r.total), ms(r.guest_setup), ms(r.guest_run));
        eprintln!("  total                    {:7.1} ms", ms(t0.elapsed()));
    }
    if let Err(e) = shutdown {
        eprintln!("kiri: shutdown: {e}");
    }
    std::process::exit(r.code);
}

#[cfg(test)]
mod tests {
    use super::{Options, parse};

    fn s(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn help_before_image_returns_none_while_help_after_image_stays_in_command() {
        assert_eq!(parse(&s(&["--help"])).unwrap(), None);
        assert_eq!(parse(&s(&["-h"])).unwrap(), None);
        assert_eq!(parse(&s(&["--rm", "--help"])).unwrap(), None);

        let with_cmd_help = parse(&s(&["--rm", "alpine:latest", "ls", "--help"])).unwrap().unwrap();
        assert!(with_cmd_help.remove);
        assert_eq!(with_cmd_help.image, "alpine:latest");
        assert_eq!(with_cmd_help.command, s(&["ls", "--help"]));

        let direct_help = parse(&s(&["alpine", "--help"])).unwrap().unwrap();
        assert_eq!(direct_help.image, "alpine");
        assert_eq!(direct_help.command, s(&["--help"]));

        let double_dash = parse(&s(&["--", "alpine", "-h"])).unwrap().unwrap();
        assert_eq!(
            double_dash,
            Options { image: "alpine".into(), command: s(&["-h"]), ..Options::default() }
        );

        assert!(parse(&[]).is_err());
        assert!(parse(&s(&["--unknown", "alpine"])).is_err());
    }
}
