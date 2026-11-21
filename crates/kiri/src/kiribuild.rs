//! `kiri build`: the native builder in Kiri's engine, with the folder read
//! in place (`POST /kiri/build`), and BuildKit for what it does not cover.
//!
//! The native builder (Forge, Kiri's own build engine) is off unless
//! switched on. The first one given wins: `--builder forge|buildkit` (or
//! `kiri`, Forge's name before) for this build,
//! `KIRI_NATIVE_BUILD` (here, else the engine's), then the setting
//! (`kiri builder use`, Settings → Builds; builderswitch.rs).
//!
//! The fallback is the build `kiri build` has always run, unchanged: the
//! docker CLI's `docker build` on Kiri's daemon (docker.rs), which builds
//! with Kiri's pinned BuildKit. It is taken, with one line saying why, when
//! the native builder says it does not cover the build, and as before the
//! native builder existed when BuildKit is the builder chosen.
//!
//! Which builder ran is said on stderr, once, before the build's own output
//! ("building with Forge", "building with BuildKit"), only to a
//! terminal and never with `-q`: output that goes to a file or a program
//! stays exactly BuildKit's progress. The fallback line is printed as before, terminal or not.

use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::builderswitch::Builder;
use crate::client;

/// What the native builder was asked, or why it is not asked.
#[derive(Debug, PartialEq)]
enum Parsed {
    Native(Value, Flags),
    /// A flag or form it does not take: straight to BuildKit, with this reason.
    Fallback(String),
}

#[derive(Debug, Default, PartialEq)]
struct Flags {
    quiet: bool,
    iidfile: Option<String>,
    /// `-f -`: the Dockerfile comes on stdin.
    stdin_dockerfile: bool,
    /// The context argument as given, for the client's own messages.
    context_arg: String,
    /// `--ssh` ids and their sockets or key files, read when the build
    /// starts (`ssh_session`).
    ssh: Vec<(String, Vec<std::path::PathBuf>)>,
}

/// Reads `docker build` flags. Anything not listed is BuildKit's, by name.
fn parse(args: &[String]) -> Parsed {
    parse_with(args, None)
}

/// [`parse`], keeping the secrets read from files (`held`): a file may be
/// a pipe that gives its bytes once, and a build that goes to BuildKit
/// after all must get the same bytes ([`HeldSecrets`]).
fn parse_holding(args: &[String]) -> (Parsed, Vec<HeldSecret>) {
    let mut held = Vec::new();
    let p = parse_with(args, Some(&mut held));
    (p, held)
}

/// Reads the flags; `held` None reads no secret at all (only the routing
/// matters to the caller), Some keeps those read from a file.
fn parse_with(args: &[String], mut held: Option<&mut Vec<HeldSecret>>) -> Parsed {
    let mut body = Map::new();
    let (mut tags, mut build_args, mut labels, mut secrets, mut contexts) = (Vec::new(), Map::new(), Map::new(), Map::new(), Map::new());
    let mut ulimits = Vec::new();
    let mut flags = Flags::default();
    let mut allow = Vec::new();
    let mut context = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if !a.starts_with('-') || a == "-" {
            if context.is_some() {
                return Parsed::Fallback(format!("a second context argument ({a})"));
            }
            context = Some(a.clone());
            continue;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (a.clone(), None),
        };
        let value = if takes_value(&name) {
            match inline.or_else(|| {
                i += 1;
                args.get(i - 1).cloned()
            }) {
                Some(v) => v,
                None => return Parsed::Fallback(format!("{name} without a value")),
            }
        } else {
            String::new()
        };
        match name.as_str() {
            "-t" | "--tag" => tags.push(Value::String(value)),
            "-f" | "--file" if value == "-" => flags.stdin_dockerfile = true,
            "-f" | "--file" => {
                body.insert("dockerfile".into(), value.into());
            }
            "--build-arg" => match value.split_once('=') {
                Some((k, v)) => {
                    build_args.insert(k.into(), v.into());
                }
                // `--build-arg NAME` takes the value from the environment, if set.
                None => {
                    if let Ok(v) = std::env::var(&value) {
                        build_args.insert(value, v.into());
                    }
                }
            },
            "--target" => {
                body.insert("target".into(), value.into());
            }
            "--label" => {
                let (k, v) = value.split_once('=').unwrap_or((&value, ""));
                labels.insert(k.into(), v.into());
            }
            "--platform" => {
                body.insert("platform".into(), value.into());
            }
            "--progress" => match value.as_str() {
                "auto" | "plain" | "tty" => {}
                "quiet" => flags.quiet = true,
                v => return Parsed::Fallback(format!("--progress={v}")),
            },
            "--iidfile" => flags.iidfile = Some(value),
            "--secret" => match held.as_deref_mut() {
                None => {}
                Some(held) => match read_secret_source(&value) {
                    Ok((id, data, from_file)) => {
                        secrets.insert(id.clone(), kiri_image::b64::encode(&data).into());
                        if from_file {
                            held.push(HeldSecret { spec: value.clone(), id, data });
                        }
                    }
                    Err(_) => return Parsed::Fallback("--secret".into()),
                },
            },
            "--ssh" => match crate::sshfwd::parse_spec(&value) {
                Ok(spec) => flags.ssh.push(spec),
                Err(_) => return Parsed::Fallback("--ssh".into()),
            },
            "--build-context" => match named_context(&value) {
                Some((name, v)) => {
                    contexts.insert(name, v);
                }
                None => return Parsed::Fallback("--build-context".into()),
            },
            "-o" | "--output" => match output(&value) {
                Some((rewrite, epoch)) => {
                    body.insert("rewrite_timestamp".into(), rewrite.into());
                    if let Some(e) = epoch {
                        body.insert("exporter_epoch".into(), e.into());
                    }
                }
                None => return Parsed::Fallback(name.clone()),
            },
            // As buildx sends them to the frontend; a value it would refuse
            // goes to BuildKit, which says why.
            "--network" => match value.as_str() {
                "" | "default" => {}
                "host" | "none" => {
                    body.insert("network".into(), value.into());
                }
                _ => return Parsed::Fallback(name.clone()),
            },
            "--shm-size" => match kiri_forge::dockerfile::instructions::ram_in_bytes(&value) {
                Some(n) if n > 0 => {
                    body.insert("shm_size".into(), n.into());
                }
                Some(_) => {}
                None => return Parsed::Fallback(name.clone()),
            },
            "--ulimit" => match kiri_forge::ports::Ulimit::parse(&value) {
                Ok(u) => ulimits.push(json!({"name": u.name, "soft": u.soft, "hard": u.hard})),
                Err(_) => return Parsed::Fallback(name.clone()),
            },
            "--no-cache" => {
                body.insert("no_cache".into(), true.into());
            }
            "--no-cache-filter" => {
                let list = body.entry("no_cache_filter").or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(a) = list {
                    a.push(value.into());
                }
            }
            // The engine grants these as dockerd would (nativebuild.rs);
            // device entitlements go to BuildKit.
            "--allow" => {
                for e in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                    if !matches!(e, "security.insecure" | "network.host") {
                        return Parsed::Fallback(format!("--allow {e}"));
                    }
                    allow.push(Value::String(e.to_owned()));
                }
            }
            "-q" | "--quiet" => flags.quiet = true,
            // The image always lands in Kiri's store.
            "--load" => {}
            other => return Parsed::Fallback(other.to_owned()),
        }
    }
    let Some(context) = context else { return Parsed::Fallback("no context argument".into()) };
    flags.context_arg = context.clone();
    if context == "-" {
        return Parsed::Fallback("a context from stdin".into());
    }
    // BuildKit's own test (dockerui DetectGitContext): a context it reads as
    // Git, or fails to read as Git, never goes to the plain URL fetch. Kiri's
    // builder fetches no git repository: such a build is BuildKit's.
    let git = !matches!(kiri_forge::convert::git::parse_git_ref(&context), Ok(None));
    let http = context.starts_with("http://") || context.starts_with("https://");
    if http && !git {
        // A URL context: the engine fetches it (a Dockerfile, or an archive
        // whose files are the context); `-f` names a file of the archive,
        // as given (only its last part names a downloaded Dockerfile).
        body.insert("context_url".into(), context.clone().into());
        body.insert("context".into(), "/".into());
        body.insert("tags".into(), tags.into());
        body.insert("build_args".into(), build_args.into());
        body.insert("labels".into(), labels.into());
        body.insert("secrets".into(), secrets.into());
        body.insert("build_contexts".into(), contexts.into());
        body.insert("allow".into(), allow.into());
        body.insert("ulimits".into(), ulimits.into());
        return Parsed::Native(Value::Object(body), flags);
    }
    if context.contains("://") || git {
        return Parsed::Fallback("a remote context".into());
    }
    let abs = match std::path::absolute(Path::new(&context)) {
        Ok(p) => p,
        Err(_) => return Parsed::Fallback(format!("the context {context}")),
    };
    // `-f` is relative to the working directory, as docker build reads it.
    if let Some(f) = body.get("dockerfile").and_then(Value::as_str).map(str::to_owned) {
        let p = std::path::absolute(Path::new(&f)).unwrap_or_else(|_| f.clone().into());
        body.insert("dockerfile".into(), p.display().to_string().into());
    }
    body.insert("context".into(), abs.display().to_string().into());
    body.insert("tags".into(), tags.into());
    body.insert("build_args".into(), build_args.into());
    body.insert("labels".into(), labels.into());
    body.insert("secrets".into(), secrets.into());
    body.insert("build_contexts".into(), contexts.into());
    body.insert("allow".into(), allow.into());
    body.insert("ulimits".into(), ulimits.into());
    // Where the build's time went, printed after it (the engine logs it
    // on every build as "build stages").
    if std::env::var_os("KIRI_BUILD_TIMING").is_some_and(|v| !v.is_empty() && v != "0") {
        body.insert("timing".into(), true.into());
    }
    Parsed::Native(Value::Object(body), flags)
}

/// The flags the native builder reads that take a value.
fn takes_value(name: &str) -> bool {
    matches!(name, "-t" | "--tag" | "-f" | "--file" | "--build-arg" | "--target" | "--label" | "--platform" | "--progress" | "--iidfile" | "--secret" | "--ssh" | "--build-context" | "-o" | "--output" | "--network" | "--allow" | "--shm-size" | "--ulimit" | "--no-cache-filter")
}

/// Takes `--builder forge|kiri|buildkit` (either form) and `--no-native` (the
/// same as `--builder buildkit`) out of the arguments; the last one given
/// counts. `--builder` with another value names a buildx builder, as for
/// `docker build`, and stays, for BuildKit.
fn take_builder(args: &[String]) -> (Option<Builder>, Vec<String>) {
    let (mut chosen, mut rest) = (None, Vec::with_capacity(args.len()));
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--no-native" {
            chosen = Some(Builder::Buildkit);
            continue;
        }
        if let Some(b) = a.strip_prefix("--builder=").and_then(Builder::parse) {
            chosen = Some(b);
            continue;
        }
        if a == "--builder"
            && let Some(b) = args.get(i).and_then(|v| Builder::parse(v))
        {
            chosen = Some(b);
            i += 1;
            continue;
        }
        rest.push(a.clone());
        // A flag's value is never read as a flag (`-t --builder`).
        if takes_value(a) && i < args.len() {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    (chosen, rest)
}

/// The builder this build asked for: its flag, else `KIRI_NATIVE_BUILD`
/// where it runs. None: the engine decides (its `KIRI_NATIVE_BUILD`, then
/// the setting).
fn chosen(flag: Option<Builder>, env: Option<&str>) -> Option<Builder> {
    flag.or_else(|| env.and_then(Builder::from_env))
}

/// `-q`, `--quiet` or `--progress quiet`: nothing but the image id.
fn quiet(args: &[String]) -> bool {
    args.iter().enumerate().any(|(i, a)| a == "-q" || a == "--quiet" || a == "--progress=quiet" || (a == "--progress" && args.get(i + 1).is_some_and(|v| v == "quiet")))
}

/// The line saying which builder runs: to a person at a terminal only.
fn say_builder(b: Builder, quiet: bool) {
    if !quiet && io::stderr().is_terminal() {
        eprintln!("{}", builder_line(b));
    }
}

fn builder_line(b: Builder) -> &'static str {
    match b {
        Builder::Forge => "building with Forge",
        Builder::Buildkit => "building with BuildKit",
    }
}

const HELP: &str = "\
Usage:  kiri build [OPTIONS] PATH

Build an image from a Dockerfile, with BuildKit or with Forge, Kiri's own
build engine. Forge is off by default; it reads the folder in place, and a
build it does not cover yet goes to BuildKit, with a line saying why.
Turn it on with `kiri builder use forge`, or for one build with --builder forge.

Options:
  -f, --file string          Name of the Dockerfile (default: PATH/Dockerfile; - for stdin)
  -t, --tag stringArray      Name and optionally a tag (format: name:tag)
      --build-arg stringArray  Set build-time variables
      --label stringArray    Set metadata for an image
      --target string        Set the target build stage to build
      --no-cache             Do not use cache when building the image
      --no-cache-filter stringArray
                             Do not cache specified stages
      --platform string      Set target platform for build (natively: one the engine runs)
      --iidfile string       Write the image ID to the file
      --progress string      Set type of progress output (auto, plain, tty, quiet)
      --load                 Load the image into the store (always done)
  -q, --quiet                Suppress the build output and print image ID on success
      --secret stringArray   Secret to expose to the build (id=x,src=path or id=x,env=VAR)
      --ssh stringArray      SSH agent socket or keys to expose to the build
                             (format: default|<id>[=<socket>|<key>[,<key>]])
      --build-context stringArray  Additional build contexts (name=docker-image://ref, name=URL or name=path)
      --allow stringArray    Allow extra privileged entitlement (network.host, security.insecure; the engine must allow it too)
  -o, --output stringArray   type=docker[,rewrite-timestamp=true][,source-date-epoch=N]; other outputs go to BuildKit
      --network string       Set the networking mode for the RUN instructions during build (default, none, host)
      --shm-size bytes       Shared memory size for build containers
      --ulimit ulimit        Ulimit options
      --builder string       Builder for this build only: forge (Kiri's own build engine;
                             kiri is the same) or buildkit.
                             Default: KIRI_NATIVE_BUILD (1 or 0) if set, else the setting
                             (kiri builder use forge|buildkit; BuildKit unless switched on).
                             Any other value names a buildx builder, for BuildKit
      --no-native            The same as --builder buildkit

Any other docker build option is passed to BuildKit with the whole build.
";

/// Where a build goes, decided before anything of the build is read.
#[derive(Debug, PartialEq)]
enum Route {
    /// BuildKit, the build `kiri build` has always run, given exactly as
    /// typed; `say`: the builder line may be printed (an engine answered or
    /// the build chose BuildKit).
    Buildkit { say: bool },
    /// Forge; `asked`: this build asked for it (flag or
    /// environment) rather than the engine's setting.
    Native { asked: bool },
}

/// The builder for this build, in order: its flag or `KIRI_NATIVE_BUILD`
/// (`choice`), else what the engine says (`engine`: None when it does not
/// answer). Forge asked for with no engine there is BuildKit's
/// build, as before.
fn route(choice: Option<Builder>, engine: impl FnOnce() -> Option<Builder>, alive: impl FnOnce() -> bool) -> Route {
    match choice {
        Some(Builder::Buildkit) => Route::Buildkit { say: true },
        Some(Builder::Forge) if alive() => Route::Native { asked: true },
        Some(Builder::Forge) => Route::Buildkit { say: false },
        None => match engine() {
            Some(Builder::Forge) => Route::Native { asked: false },
            Some(Builder::Buildkit) => Route::Buildkit { say: true },
            None => Route::Buildkit { say: false },
        },
    }
}

/// What the engine builds with when the build does not say (its
/// `KIRI_NATIVE_BUILD`, then the setting): one small GET. None when it does
/// not answer.
fn engine_setting() -> Option<Builder> {
    let v = client::get("/kiri/builder").ok()?;
    Some(match v["native_env"].as_str().and_then(Builder::from_env) {
        Some(b) => b,
        None if v["native"].as_bool().unwrap_or(false) => Builder::Forge,
        None => Builder::Buildkit,
    })
}

/// What the native path read that docker would otherwise read itself: the
/// Dockerfile from stdin (`-f -`), or from a `-f` that is not a regular file
/// (`-f <(...)`, a fifo), already consumed. Handed to docker on its stdin
/// whenever the build goes to BuildKit after all.
struct Consumed {
    text: Vec<u8>,
    /// The `-f` value read here, given to docker as `-f -`; None for `-f -`.
    special: Option<String>,
}

/// `kiri build ARGS` (args[0] is `build`).
pub fn run(args: &[String]) -> io::Result<()> {
    if args[1..].iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    let (flag, rest) = take_builder(&args[1..]);
    let choice = chosen(flag, std::env::var("KIRI_NATIVE_BUILD").ok().as_deref());
    let quiet = quiet(&rest);
    // Decided first: with BuildKit nothing of the build is read here (no
    // secret, ssh agent, stdin or check of its own), and docker gets the
    // arguments and stdin exactly as given.
    let asked = match route(choice, engine_setting, client::alive) {
        Route::Buildkit { say } => {
            if say {
                say_builder(Builder::Buildkit, quiet);
            }
            return crate::docker::run(&docker_args(&rest));
        }
        Route::Native { asked } => asked,
    };
    // Secrets are read once, here; whichever builder builds gets those bytes.
    let (parsed, held) = parse_holding(&rest);
    let (mut body, flags) = match parsed {
        Parsed::Native(b, f) => (b, f),
        // Decided before stdin is read: a context from stdin is docker's to read.
        Parsed::Fallback(reason) => return fallback(&rest, &reason, None, &held),
    };
    if let Some(m) = client_refusal(&body, &flags) {
        eprintln!("ERROR: failed to build: {m}");
        std::process::exit(1);
    }
    if asked {
        body["builder"] = "kiri".into();
    }
    let mut consumed = None;
    if flags.stdin_dockerfile {
        let mut t = Vec::new();
        io::stdin().read_to_end(&mut t)?;
        body["dockerfile_text"] = String::from_utf8_lossy(&t).into_owned().into();
        consumed = Some(Consumed { text: t, special: None });
    } else if let Some(path) = body["dockerfile"].as_str().map(str::to_owned)
        && let Some(t) = read_special_dockerfile(&path)
    {
        // The engine reads only a regular file it is named; anything else
        // (`-f <(...)`, a fifo, a device) is read here, by the user, as the
        // docker CLI reads it, and sent as the text.
        body["dockerfile_text"] = String::from_utf8_lossy(&t).into_owned().into();
        consumed = Some(Consumed { text: t, special: Some(dockerfile_arg(&rest).unwrap_or(path)) });
    }
    if !flags.ssh.is_empty() {
        match ssh_session(&flags.ssh) {
            Ok(token) => body["ssh"] = json!({ "session": token }),
            // What this client cannot forward (a key type it does not
            // read, an engine without sessions) is BuildKit's to try.
            Err(_) => return fallback(&rest, "--ssh", consumed, &held),
        }
    }
    let mut answer: Option<Value> = None;
    let mut warnings = Vec::new();
    let mut err = io::stderr();
    on_ctrl_c_cancel();
    let mut said = false;
    let status = client::post_json_lines("/kiri/build", &body, |v| {
        if let Some(text) = v["stream"].as_str() {
            if !said {
                said = true;
                say_builder(Builder::Forge, flags.quiet);
            }
            if !flags.quiet {
                let _ = err.write_all(text.as_bytes());
            }
        } else if let Some(w) = v["warnings"].as_array() {
            warnings.extend(w.iter().filter_map(|w| w.as_str().map(str::to_owned)));
        } else {
            answer = Some(v);
        }
    })?;
    let answer = answer.unwrap_or(Value::Null);
    // An engine without the native builder, or whose setting changed since
    // it was asked: BuildKit's build, with whatever was read here handed on.
    if status == 404 || answer["native"] == "off" {
        say_builder(Builder::Buildkit, flags.quiet);
        let status = run_docker(&rest, None, consumed, &held)?;
        std::process::exit(status.code().unwrap_or(1));
    }
    if let Some(reason) = answer["fallback"].as_str() {
        return fallback(&rest, reason, consumed, &held);
    }
    // After the progress, before any error, as buildx prints them.
    if !flags.quiet {
        eprint!("{}", kiri_forge::build::warnings_summary(&warnings));
    }
    if let Some(id) = answer["aux"]["ID"].as_str() {
        if let Some(f) = &flags.iidfile {
            std::fs::write(f, id)?;
        }
        if flags.quiet {
            println!("{id}");
        }
        return Ok(());
    }
    let m = answer["error"].as_str().or_else(|| answer["message"].as_str()).map(str::to_owned).unwrap_or_else(|| format!("the engine answered {status}"));
    eprint!("{}", answer["source"].as_str().unwrap_or_default());
    eprintln!("ERROR: failed to build: failed to solve: {m}");
    std::process::exit(1)
}

/// The `-f`/`--file` value as typed (the last one given).
fn dockerfile_arg(rest: &[String]) -> Option<String> {
    let mut found = None;
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        i += 1;
        if let Some(v) = a.strip_prefix("--file=") {
            found = Some(v.to_owned());
        } else if a == "-f" || a == "--file" {
            found = rest.get(i).cloned();
            i += 1;
        } else if takes_value(a) {
            i += 1;
        }
    }
    found
}

/// docker's arguments for a build whose Dockerfile was read here from a
/// path that cannot be read twice: that `-f` becomes `-f -`, and the text
/// goes on docker's stdin. Everything else as given.
fn with_dockerfile_on_stdin(rest: &[String], path: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(rest.len());
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        i += 1;
        if a.strip_prefix("--file=") == Some(path) {
            out.push("--file=-".to_owned());
        } else if (a == "-f" || a == "--file") && rest.get(i).map(String::as_str) == Some(path) {
            out.push(a.clone());
            out.push("-".to_owned());
            i += 1;
        } else {
            out.push(a.clone());
            if takes_value(a) && i < rest.len() {
                out.push(rest[i].clone());
                i += 1;
            }
        }
    }
    out
}

/// `docker build` with these arguments (`iidfile` added first if given),
/// as a child: its stdin is this process's, or the Dockerfile text read
/// here (`consumed`). Returns docker's status.
fn run_docker(rest: &[String], iidfile: Option<&Path>, consumed: Option<Consumed>, held: &[HeldSecret]) -> io::Result<std::process::ExitStatus> {
    // Removed when docker is done, whatever its status.
    let given = HeldSecrets::write(held, &std::env::temp_dir())?;
    let rest = given.args(rest);
    let mut args = match consumed.as_ref().and_then(|c| c.special.as_deref()) {
        Some(path) => docker_args(&with_dockerfile_on_stdin(&rest, path)),
        None => docker_args(&rest),
    };
    if let Some(f) = iidfile {
        args.insert(1, format!("--iidfile={}", f.display()));
    }
    let mut cmd = crate::docker::command(&args)?;
    if consumed.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    if let (Some(c), Some(mut stdin)) = (consumed, child.stdin.take()) {
        // A docker that stops early closes its end: its status says why.
        let _ = stdin.write_all(&c.text);
    }
    child.wait()
}

/// `--ssh`: each id's agent, read as the user who runs `kiri build` (a
/// socket it reaches, or key files it serves), and the engine session the
/// build names them by. The session lasts as long as this process.
fn ssh_session(specs: &[(String, Vec<std::path::PathBuf>)]) -> Result<String, String> {
    let auth_sock = std::env::var("SSH_AUTH_SOCK").ok();
    let mut agents = std::collections::BTreeMap::new();
    for (id, paths) in specs {
        agents.insert(id.clone(), crate::sshfwd::load(paths, auth_sock.as_deref())?);
    }
    let socket = client::socket().map_err(|e| e.to_string())?;
    crate::sshfwd::open(&socket, agents).map_err(|e| e.to_string())
}

/// Ctrl-C during a native build: one line, then the process ends and its
/// end of the stream closes, which the engine takes as the cancel (it ends
/// the running step and keeps nothing of the build).
fn on_ctrl_c_cancel() {
    extern "C" fn cancelled(_: libc::c_int) {
        const LINE: &[u8] = b"cancelling\n";
        // SAFETY: write and _exit are async-signal-safe; the buffer is static.
        unsafe {
            libc::write(2, LINE.as_ptr().cast(), LINE.len());
            libc::_exit(130);
        }
    }
    // SAFETY: installs a handler that only calls async-signal-safe functions.
    unsafe {
        libc::signal(libc::SIGINT, cancelled as *const () as libc::sighandler_t);
    }
}

/// A `-f` that names something other than a regular file: its text, at
/// most one byte over the engine's limit (the engine says it is too big).
/// None for a regular file or a path that is not there (the engine reads
/// those and words the error).
fn read_special_dockerfile(path: &str) -> Option<Vec<u8>> {
    let m = std::fs::metadata(path).ok()?;
    if m.is_file() || m.is_dir() {
        return None;
    }
    let mut t = Vec::new();
    std::fs::File::open(path).ok()?.take(kiri_forge::build::MAX_DOCKERFILE as u64 + 1).read_to_end(&mut t).ok()?;
    Some(t)
}

/// `--secret id=x[,src=path|,env=VAR][,type=file|env]`, read here as the
/// user who runs `kiri build`, as buildx reads it. With neither source an
/// environment variable named like the id is taken if set, else the file.
#[cfg(test)]
fn read_secret(spec: &str) -> Result<(String, Vec<u8>), String> {
    read_secret_source(spec).map(|(id, d, _)| (id, d))
}

/// [`read_secret`], and whether the bytes came from a file.
fn read_secret_source(spec: &str) -> Result<(String, Vec<u8>, bool), String> {
    let (mut id, mut src, mut env, mut typ) = (None, None, None, None);
    for part in spec.split(',') {
        let (k, v) = part.split_once('=').ok_or_else(|| format!("invalid secret {spec}"))?;
        match k.trim().to_ascii_lowercase().as_str() {
            "id" => id = Some(v.to_owned()),
            "src" | "source" => src = Some(v.to_owned()),
            "env" => env = Some(v.to_owned()),
            "type" => typ = Some(v.to_owned()),
            _ => return Err(format!("unexpected key {k} in {spec}")),
        }
    }
    let id = id.or_else(|| src.clone()).or_else(|| env.clone()).ok_or_else(|| format!("no id in {spec}"))?;
    let from_env = |name: &str| std::env::var_os(name).map(|v| v.as_encoded_bytes().to_vec());
    let (data, from_file) = match (typ.as_deref(), &src, &env) {
        (Some("env"), _, _) => (from_env(env.as_deref().or(src.as_deref()).unwrap_or(&id)), false),
        (_, Some(path), _) => (std::fs::read(path).ok(), true),
        (_, None, Some(name)) => (from_env(name), false),
        (_, None, None) => (from_env(&id), false),
    };
    data.map(|d| (id, d, from_file)).ok_or_else(|| format!("secret {spec} not found"))
}

/// A `--secret` read from a file: the value as typed, its id and bytes.
#[derive(Debug)]
struct HeldSecret {
    spec: String,
    id: String,
    data: Vec<u8>,
}

/// The secrets read here, given to a BuildKit build as private files
/// (0600, in a fresh 0700 folder only this user enters) in place of the
/// sources already read; removed when dropped. Never in arguments or the
/// environment: docker gets only the files' paths.
struct HeldSecrets {
    dir: Option<std::path::PathBuf>,
    /// The `--secret` value as typed, and the one docker gets instead.
    swap: Vec<(String, String)>,
}

impl HeldSecrets {
    fn write(held: &[HeldSecret], base: &Path) -> io::Result<HeldSecrets> {
        use std::os::unix::fs::OpenOptionsExt as _;
        if held.is_empty() {
            return Ok(HeldSecrets { dir: None, swap: Vec::new() });
        }
        let dir = private_dir(base, "kiri-build-secrets")?;
        let mut out = HeldSecrets { dir: Some(dir.clone()), swap: Vec::new() };
        for (i, s) in held.iter().enumerate() {
            let f = dir.join(i.to_string());
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&f)?.write_all(&s.data)?;
            out.swap.push((s.spec.clone(), format!("id={},src={}", s.id, f.display())));
        }
        Ok(out)
    }

    /// `rest` with each held `--secret` pointing at its file.
    fn args(&self, rest: &[String]) -> Vec<String> {
        let swap = |v: &str| self.swap.iter().find(|(s, _)| s == v).map(|(_, n)| n.clone());
        let mut out = Vec::with_capacity(rest.len());
        let mut i = 0;
        while i < rest.len() {
            let a = &rest[i];
            i += 1;
            if let Some(n) = a.strip_prefix("--secret=").and_then(swap) {
                out.push(format!("--secret={n}"));
            } else if a == "--secret" && i < rest.len() {
                out.push(a.clone());
                out.push(swap(&rest[i]).unwrap_or_else(|| rest[i].clone()));
                i += 1;
            } else {
                out.push(a.clone());
                if a != "--secret" && takes_value(a) && i < rest.len() {
                    out.push(rest[i].clone());
                    i += 1;
                }
            }
        }
        out
    }
}

impl Drop for HeldSecrets {
    fn drop(&mut self) {
        if let Some(d) = &self.dir {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// `--output type=docker[,rewrite-timestamp=true][,source-date-epoch=N]`:
/// the image into the store, as the native builder always gives it, with
/// the exporter's time options. Any other output is BuildKit's.
fn output(spec: &str) -> Option<(bool, Option<String>)> {
    let (mut kind, mut rewrite, mut epoch) = (None, false, None);
    for part in spec.split(',') {
        let (k, v) = part.split_once('=')?;
        match k.trim() {
            "type" => kind = Some(v.to_owned()),
            "rewrite-timestamp" => rewrite = v.parse::<bool>().ok()?,
            "source-date-epoch" => epoch = Some(v.to_owned()),
            _ => return None,
        }
    }
    matches!(kind.as_deref(), Some("docker")).then_some((rewrite, epoch))
}

/// `--build-context name=value` as buildx reads it: an image
/// (`docker-image://ref`), a URL the engine downloads, or a folder (a
/// path, relative to here). Git, oci-layout and another target are
/// BuildKit's.
fn named_context(spec: &str) -> Option<(String, Value)> {
    let (name, v) = spec.split_once('=')?;
    if name.is_empty() || v.is_empty() {
        return None;
    }
    if let Some(r) = v.strip_prefix("docker-image://") {
        return Some((name.to_owned(), json!({"image": r})));
    }
    if kiri_forge::convert::git::is_http_source(v) && matches!(kiri_forge::convert::git::parse_git_ref(v), Ok(None)) {
        return Some((name.to_owned(), json!({"url": v})));
    }
    // Whatever BuildKit would read as Git (`github.com/o/r` too) is its own.
    if v.contains("://") || v.starts_with("git@") || v.starts_with("target:") || v.ends_with(".git") || !matches!(kiri_forge::convert::git::parse_git_ref(v), Ok(None)) {
        return None;
    }
    let abs = std::path::absolute(Path::new(v)).ok()?;
    Some((name.to_owned(), json!({"local": abs.display().to_string()})))
}

fn docker_args(rest: &[String]) -> Vec<String> {
    std::iter::once("build".to_owned()).chain(rest.iter().cloned()).collect()
}

/// The build as `kiri build` always ran it, and a record of who built the
/// image for the engine (`fallback <reason>`). The record needs the image
/// id, so an `--iidfile` of its own is added when the build has none, in a
/// folder only this user reaches, made for this build and removed after;
/// the image is the same either way.
fn fallback(rest: &[String], reason: &str, consumed: Option<Consumed>, held: &[HeldSecret]) -> io::Result<()> {
    eprintln!("falling back to BuildKit: {reason}");
    if let Some(missing) = crate::docker::buildkit_missing(needs_buildx(rest).as_deref()) {
        eprintln!("ERROR: kiri build cannot fall back to BuildKit: {missing}");
        std::process::exit(1);
    }
    let given = iidfile_of(rest);
    // Without a private folder the build still runs, unrecorded.
    let own = if given.is_none() && takes_iidfile(rest) { private_iid_file(&std::env::temp_dir()).ok() } else { None };
    let status = run_docker(rest, own.as_deref(), consumed, held);
    let id = match (&given, &own) {
        (Some(g), _) => std::fs::read_to_string(g).ok(),
        (None, Some(o)) => std::fs::read_to_string(o).ok(),
        (None, None) => None,
    };
    if let Some(o) = &own {
        remove_private_iid_file(o);
    }
    let status = status?;
    if status.success()
        && let Some(id) = id.filter(|i| !i.trim().is_empty())
    {
        let _ = client::request("POST", "/kiri/build-path", Some(&json!({"image": id.trim(), "path": format!("fallback {reason}")})));
    }
    std::process::exit(status.code().unwrap_or(1))
}

/// A new, empty file for an image id, in a folder of its own under `base`:
/// the folder has a random name, is made only if no such name exists
/// (never an existing folder or link), and only its owner may enter it.
fn private_iid_file(base: &Path) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = private_dir(base, "kiri-build")?;
    let f = dir.join("image.iid");
    if let Err(e) = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&f) {
        let _ = std::fs::remove_dir(&dir);
        return Err(e);
    }
    Ok(f)
}

/// A new folder `<prefix>-<random>` under `base`, made only if no such
/// name exists (never an existing folder or link), that only its owner
/// may enter.
fn private_dir(base: &Path, prefix: &str) -> io::Result<std::path::PathBuf> {
    use ring::rand::SecureRandom as _;
    use std::os::unix::fs::DirBuilderExt as _;
    let rng = ring::rand::SystemRandom::new();
    for _ in 0..16 {
        let mut b = [0u8; 16];
        rng.fill(&mut b).map_err(|_| io::Error::other("no random source"))?;
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = base.join(format!("{prefix}-{name}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free name for a private folder"))
}

/// Removes what [`private_iid_file`] made: the file and its folder.
fn remove_private_iid_file(f: &Path) {
    let _ = std::fs::remove_file(f);
    if let Some(d) = f.parent() {
        let _ = std::fs::remove_dir(d);
    }
}

/// `docker build` options only buildx takes: the legacy builder (a docker
/// CLI without the plugin) stops at each with "unknown flag".
const BUILDX_ONLY: &[&str] = &[
    "--ssh", "--secret", "--build-context", "-o", "--output", "--allow", "--progress", "--load", "--push", "--cache-to", "--attest", "--sbom",
    "--provenance", "--builder", "--call", "--check", "--annotation", "--metadata-file", "--no-cache-filter",
];

/// What in this build only buildx gives, if anything: one of its options,
/// or a Git context (the legacy CLI clones it on this machine, by its own
/// rules, where the engine's names may not resolve).
fn needs_buildx(rest: &[String]) -> Option<String> {
    let names = rest.iter().filter(|a| a.starts_with('-')).map(|a| a.split_once('=').map_or(a.as_str(), |(n, _)| n));
    if let Some(n) = names.into_iter().find(|n| BUILDX_ONLY.contains(n)) {
        return Some(n.to_owned());
    }
    matches!(parse(rest), Parsed::Fallback(r) if r == "a remote context").then(|| "a Git context".to_owned())
}

/// Whether buildx takes an `--iidfile` with these options: not with a
/// local or tar export (`-o <dir>`, `-o -`, `type=local`, `type=tar`).
fn takes_iidfile(args: &[String]) -> bool {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let value = match a.as_str() {
            "-o" | "--output" => it.next().map(String::as_str),
            _ => a.strip_prefix("--output=").or_else(|| a.strip_prefix("-o=")),
        };
        let Some(v) = value else { continue };
        if !v.contains('=') {
            return false;
        }
        if v.split(',').any(|f| matches!(f.trim(), "type=local" | "type=tar")) {
            return false;
        }
    }
    true
}

/// What buildx refuses on the client before it sends anything, as it
/// words it: a tag that does not parse (`invalid tag "<t>": <why>`), then a
/// local context folder that is not there.
fn client_refusal(body: &Value, flags: &Flags) -> Option<String> {
    for t in body["tags"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if let Err(e) = kiri_forge::convert::reference::parse(t) {
            return Some(format!("invalid tag {t:?}: {e}"));
        }
    }
    let ctx = body["context"].as_str()?;
    if body.get("context_url").is_none() && !Path::new(ctx).exists() {
        return Some(format!("unable to prepare context: path {:?} not found", flags.context_arg));
    }
    None
}

fn iidfile_of(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--iidfile=") {
            return Some(v.to_owned());
        }
        if a == "--iidfile" {
            return it.next().cloned();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Parsed {
        // as `run` reads them: secrets read, so an unreadable one routes
        parse_holding(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).0
    }

    /// `-f <(...)` and other files that are not regular are read by the
    /// client; a regular file is left to the engine.
    #[test]
    fn a_dockerfile_that_is_not_a_regular_file_is_read_by_the_client() {
        assert_eq!(read_special_dockerfile("/dev/null").as_deref(), Some(&b""[..]));
        let z = read_special_dockerfile("/dev/zero").unwrap();
        assert_eq!(z.len(), kiri_forge::build::MAX_DOCKERFILE + 1, "bounded");
        let f = std::env::temp_dir().join(format!("kiri-special-df-{}", std::process::id()));
        std::fs::write(&f, "FROM scratch\n").unwrap();
        assert_eq!(read_special_dockerfile(f.to_str().unwrap()), None);
        let _ = std::fs::remove_file(&f);
        assert_eq!(read_special_dockerfile("/nonexistent/Dockerfile"), None);
    }

    #[test]
    fn takes_the_flags_it_serves() {
        let Parsed::Native(body, flags) = p(&["-t", "app", "--tag=app:2", "--build-arg", "A=1", "--label=x=y", "--target", "t", "--no-cache", "--load", "-q", "/w/ctx"]) else { panic!() };
        assert_eq!(body["context"], "/w/ctx");
        assert_eq!(body["tags"], json!(["app", "app:2"]));
        assert_eq!(body["build_args"], json!({"A": "1"}));
        assert_eq!(body["labels"], json!({"x": "y"}));
        assert_eq!(body["target"], "t");
        assert_eq!(body["no_cache"], true);
        assert!(flags.quiet);
    }

    #[test]
    fn anything_else_goes_to_buildkit_by_name() {
        assert_eq!(p(&["--secret", "id=kiri-no-such-secret-env", "."]), Parsed::Fallback("--secret".into()));
        assert_eq!(p(&["--ssh==/a", "."]), Parsed::Fallback("--ssh".into()), "an ssh spec without an id");
        assert_eq!(p(&["--pull", "."]), Parsed::Fallback("--pull".into()));
        assert_eq!(p(&["-o", "type=tar", "."]), Parsed::Fallback("-o".into()));
        assert_eq!(p(&["--output", "type=docker,dest=/x.tar", "."]), Parsed::Fallback("--output".into()));
        let Parsed::Native(body, _) = p(&["--output", "type=docker,rewrite-timestamp=true,source-date-epoch=", "/w"]) else { panic!() };
        assert_eq!((body["rewrite_timestamp"].clone(), body["exporter_epoch"].clone()), (json!(true), json!("")));
        assert_eq!(p(&["--build-context", "a=https://example.invalid/x.git", "."]), Parsed::Fallback("--build-context".into()));
        assert_eq!(p(&["--build-context", "a=git@example.invalid:x/y", "."]), Parsed::Fallback("--build-context".into()));
        assert_eq!(p(&["-"]), Parsed::Fallback("a context from stdin".into()));
        // A Git context is BuildKit's, in every form it reads as one, and
        // whatever else the build asks (Kiri's builder fetches no git
        // repository in this release).
        let gits = [
            "https://github.com/a/b.git",
            "https://example.invalid/r.git#main:sub",
            "http://h:8999/repo.git?tag=v0.0.2#refs/tags/v0.0.2",
            "http://h/repo.git?branch=base",
            "http://h/repo.git?ref=x&commit=y",
            "http://h/repo.git?subdir=s",
            "http://h/repo.git?invalid=1",
            "ssh://git@h/r",
            "git://h/r",
            "github.com/a/b",
            "git@h:a/b",
            "git@h:a/b.git#main:sub",
        ];
        for git in gits {
            assert_eq!(p(&[git]), Parsed::Fallback("a remote context".into()), "{git}");
            assert_eq!(p(&["-f", "sub/my.df", git]), Parsed::Fallback("a remote context".into()), "{git}");
            assert_eq!(p(&["--build-arg", "SOURCE_DATE_EPOCH=context", git]), Parsed::Fallback("a remote context".into()), "{git}");
            assert_eq!(p(&["--build-context", &format!("n={git}"), "."]), Parsed::Fallback("--build-context".into()), "{git}");
        }
        let Parsed::Native(body, _) = p(&["-f", "sub/my.df", "http://example.invalid/df"]) else { panic!() };
        assert_eq!((body["context_url"].as_str(), body["dockerfile"].as_str()), (Some("http://example.invalid/df"), Some("sub/my.df")));
        assert_eq!(p(&["--progress=rawjson", "."]), Parsed::Fallback("--progress=rawjson".into()));
    }

    #[test]
    fn build_wide_run_options_are_taken() {
        let Parsed::Native(body, _) = p(&["--network", "host", "--allow=network.host", "--shm-size", "128m", "--ulimit", "nofile=1062:1062", "--ulimit=nproc=5", "/w"]) else { panic!() };
        assert_eq!(body["network"], "host");
        assert_eq!(body["allow"], json!(["network.host"]));
        assert_eq!(body["shm_size"], 134_217_728);
        assert_eq!(body["ulimits"], json!([{"name": "nofile", "soft": 1062, "hard": 1062}, {"name": "nproc", "soft": 5, "hard": 5}]));
        let Parsed::Native(body, _) = p(&["--network=default", "/w"]) else { panic!() };
        assert!(body["network"].is_null());
        assert_eq!(p(&["--network", "bridge", "."]), Parsed::Fallback("--network".into()));
        assert_eq!(p(&["--allow", "device", "."]), Parsed::Fallback("--allow device".into()));
        assert_eq!(p(&["--shm-size", "lots", "."]), Parsed::Fallback("--shm-size".into()));
        assert_eq!(p(&["--ulimit", "as=1", "."]), Parsed::Fallback("--ulimit".into()));
    }

    #[test]
    fn named_contexts_of_images_and_folders_are_taken() {
        let Parsed::Native(body, _) = p(&["--build-context", "base=docker-image://alpine:3", "--build-context=src=/w/src", "/w"]) else { panic!() };
        assert_eq!(body["build_contexts"], json!({"base": {"image": "alpine:3"}, "src": {"local": "/w/src"}}));
        let Parsed::Native(body, _) = p(&["--build-context", "t=http://h:8000/src.tar", "/w"]) else { panic!() };
        assert_eq!(body["build_contexts"], json!({"t": {"url": "http://h:8000/src.tar"}}));
    }

    fn sv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_builder_flag_is_taken_out() {
        assert_eq!(take_builder(&sv(&["--builder", "forge", "-t", "a", "."])), (Some(Builder::Forge), sv(&["-t", "a", "."])));
        assert_eq!(take_builder(&sv(&["--builder=forge", "."])), (Some(Builder::Forge), sv(&["."])));
        // `kiri`, Forge's name before it had one, is still taken.
        assert_eq!(take_builder(&sv(&["--builder", "kiri", "-t", "a", "."])), (Some(Builder::Forge), sv(&["-t", "a", "."])));
        assert_eq!(take_builder(&sv(&["-t", "a", "--builder=buildkit", "."])), (Some(Builder::Buildkit), sv(&["-t", "a", "."])));
        assert_eq!(take_builder(&sv(&["--no-native", "."])), (Some(Builder::Buildkit), sv(&["."])));
        assert_eq!(take_builder(&sv(&["--builder", "kiri", "--builder", "buildkit", "."])).0, Some(Builder::Buildkit), "the last one counts");
        assert_eq!(take_builder(&sv(&["."])), (None, sv(&["."])));
        // A buildx builder's name stays, for BuildKit (which it then goes to, by name).
        assert_eq!(take_builder(&sv(&["--builder", "mybuilder", "."])), (None, sv(&["--builder", "mybuilder", "."])));
        assert_eq!(take_builder(&sv(&["--builder=mybuilder", "."])), (None, sv(&["--builder=mybuilder", "."])));
        assert_eq!(p(&["--builder", "mybuilder", "."]), Parsed::Fallback("--builder".into()));
        // A flag's value is a value, even one spelled like the flag.
        assert_eq!(take_builder(&sv(&["-t", "--builder", "kiri", "."])), (None, sv(&["-t", "--builder", "kiri", "."])));
        assert_eq!(take_builder(&sv(&["--label=x", "--builder", "kiri", "."])), (Some(Builder::Forge), sv(&["--label=x", "."])));
    }

    #[test]
    fn the_flag_comes_before_the_environment() {
        assert_eq!(chosen(Some(Builder::Buildkit), Some("1")), Some(Builder::Buildkit));
        assert_eq!(chosen(Some(Builder::Forge), Some("0")), Some(Builder::Forge));
        assert_eq!(chosen(None, Some("1")), Some(Builder::Forge));
        assert_eq!(chosen(None, Some("off")), Some(Builder::Buildkit));
        assert_eq!(chosen(None, Some("")), None);
        assert_eq!(chosen(None, None), None, "the engine decides: its KIRI_NATIVE_BUILD, then the setting");
    }

    #[test]
    fn quiet_in_every_form() {
        for q in [&["-q", "."][..], &["--quiet", "."], &["--progress=quiet", "."], &["--progress", "quiet", "."]] {
            assert!(quiet(&sv(q)), "{q:?}");
        }
        assert!(!quiet(&sv(&["--progress=plain", "."])));
        assert_eq!(builder_line(Builder::Forge), "building with Forge");
        assert!(!builder_line(Builder::Buildkit).starts_with('#'), "not a progress line");
    }

    /// `--ssh` is the native builder's: ids and paths are kept as given and
    /// read when the build starts; nothing of them goes in the body.
    #[test]
    fn ssh_specs_are_taken() {
        let Parsed::Native(body, flags) = p(&["--ssh", "default", "--ssh=k=/a,/b", "/w"]) else { panic!() };
        assert_eq!(flags.ssh, [("default".to_string(), vec![]), ("k".to_string(), vec![std::path::PathBuf::from("/a"), std::path::PathBuf::from("/b")])]);
        assert!(body.get("ssh").is_none());
    }

    #[test]
    fn help_names_its_own_flags() {
        assert!(HELP.starts_with("Usage:  kiri build"));
        assert!(HELP.contains("--builder string") && HELP.contains("off by default"));
        for f in ["--no-native", "--tag", "--file", "--build-arg", "--target", "--no-cache", "--iidfile", "--quiet"] {
            assert!(HELP.contains(f), "{f}");
        }
    }

    #[test]
    fn secrets_read_from_a_file_or_the_environment() {
        let f = std::env::temp_dir().join(format!("kiri-secret-{}", std::process::id()));
        std::fs::write(&f, b"s3cret").unwrap();
        assert_eq!(read_secret(&format!("id=a,src={}", f.display())), Ok(("a".to_string(), b"s3cret".to_vec())));
        let Parsed::Native(body, _) = p(&["--secret", &format!("id=a,src={}", f.display()), "/w"]) else { panic!() };
        assert_eq!(body["secrets"]["a"], kiri_image::b64::encode(b"s3cret"));
        assert!(read_secret("id=b,env=KIRI_NO_SUCH_VAR_HERE").is_err());
        let _ = std::fs::remove_file(&f);
    }

    /// A secret whose source can be read once (a pipe) is read here once;
    /// a build that then goes to BuildKit gets the same bytes, from a
    /// private file removed after, never the drained pipe.
    #[test]
    fn a_secret_from_a_pipe_reaches_the_fallback_whole() {
        let dir = std::env::temp_dir().join(format!("kiri-secret-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("s");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid C string path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let w = fifo.clone();
        let writer = std::thread::spawn(move || std::fs::write(&w, b"from-a-pipe").unwrap());
        let rest = sv(&["--secret", &format!("id=a,src={}", fifo.display()), "--pull", "/w"]);
        let (parsed, held) = parse_holding(&rest);
        writer.join().unwrap();
        assert_eq!(parsed, Parsed::Fallback("--pull".into()));
        let given = HeldSecrets::write(&held, &dir).unwrap();
        let args = given.args(&rest);
        let src = args.iter().find_map(|a| a.strip_prefix("id=a,src=")).expect("the secret rewritten");
        assert_ne!(Path::new(src), fifo.as_path());
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(src).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(src).unwrap(), b"from-a-pipe");
        assert!(args.contains(&"--pull".to_string()) && args.last().map(String::as_str) == Some("/w"));
        let kept = std::path::PathBuf::from(src);
        drop(given);
        assert!(!kept.exists() && !kept.parent().unwrap().exists(), "removed after");
        // env-sourced secrets and a build with none are left as given
        let rest = sv(&["--secret=id=b,env=HOME", "."]);
        let (_, held) = parse_holding(&rest);
        assert!(held.is_empty());
        assert_eq!(HeldSecrets::write(&held, &dir).unwrap().args(&rest), rest);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn what_only_buildx_takes_is_named() {
        let v = |a: &[&str]| needs_buildx(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(v(&["--ssh", "default", "."]), Some("--ssh".into()));
        assert_eq!(v(&["--build-context=a=https://example.invalid/x.git", "."]), Some("--build-context".into()));
        assert_eq!(v(&["--allow", "network.host", "--network=host", "."]), Some("--allow".into()));
        assert_eq!(v(&["-o", "type=tar", "."]), Some("-o".into()));
        assert_eq!(v(&["http://h:8999/repo.git?tag=v1"]), Some("a Git context".into()));
        assert_eq!(v(&["-t", "github.com/a/b", "."]), None);
        assert_eq!(v(&["--pull", "--build-arg", "A=1", "."]), None, "the legacy builder takes these");
    }

    /// buildx refuses `--iidfile` with a local or tar export ("local and
    /// tar exporters are incompatible with image ID file"), so the
    /// fallback adds one of its own only when the build may take it.
    #[test]
    fn the_fallback_adds_no_iidfile_to_a_local_or_tar_export() {
        let v = |a: &[&str]| takes_iidfile(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(v(&["--provenance=true", "."]));
        assert!(v(&["--output", "type=docker,dest=/x.tar", "."]));
        assert!(v(&["-o", "type=image,push=true", "."]));
        assert!(v(&["--output=type=registry", "."]));
        assert!(!v(&["--output", "type=local,dest=/o", "."]));
        assert!(!v(&["--output=type=tar,dest=/o.tar", "."]));
        assert!(!v(&["-o", "dest=/o,type=local", "."]));
        assert!(!v(&["-o", "/some/dir", "."]));
        assert!(!v(&["-o", "-", "."]));
        assert!(!v(&["-o=type=local,dest=/o", "."]));
    }

    /// What buildx refuses before it sends anything, in its words: a tag
    /// that is no reference, then a local context folder that is not there.
    #[test]
    fn the_client_refuses_a_bad_tag_and_a_missing_context_as_buildx_does() {
        let r = |a: &[&str]| match p(a) {
            Parsed::Native(body, flags) => client_refusal(&body, &flags),
            other => panic!("{other:?}"),
        };
        let dir = std::env::temp_dir();
        let d = dir.to_str().unwrap();
        assert_eq!(r(&["-t", "Bad:Tag", d]).as_deref(), Some(r#"invalid tag "Bad:Tag": repository name must be lowercase"#));
        assert_eq!(r(&["-t", "x:Bad Tag", d]).as_deref(), Some(r#"invalid tag "x:Bad Tag": invalid reference format"#));
        assert_eq!(r(&["-t", "ok", "-t", "ok:2", d]), None);
        // A digest is the engine's refusal, not the client's.
        assert_eq!(r(&["-t", &format!("x@sha256:{}", "0".repeat(64)), d]), None);
        assert_eq!(r(&["/no/such/kiri-ctx"]).as_deref(), Some(r#"unable to prepare context: path "/no/such/kiri-ctx" not found"#));
        assert_eq!(r(&["-t", "Bad", "/no/such/kiri-ctx"]).as_deref(), Some(r#"invalid tag "Bad": repository name must be lowercase"#));
    }

    #[test]
    fn a_no_cache_filter_is_built_natively() {
        let Parsed::Native(body, _) = p(&["--no-cache-filter", "a", "--no-cache-filter=B", "/w"]) else { panic!() };
        assert_eq!(body["no_cache_filter"], json!(["a", "B"]));
    }

    /// The builder is decided before anything of the build is read: the
    /// flag or environment first, then the engine (asked only then), and no
    /// engine is BuildKit's build as typed, with no line.
    #[test]
    fn the_builder_is_decided_first() {
        let never = || -> Option<Builder> { panic!("the engine is not asked when the build chose") };
        let never_alive = || -> bool { panic!("not asked") };
        assert_eq!(route(Some(Builder::Buildkit), never, never_alive), Route::Buildkit { say: true });
        assert_eq!(route(Some(Builder::Forge), never, || true), Route::Native { asked: true });
        assert_eq!(route(Some(Builder::Forge), never, || false), Route::Buildkit { say: false });
        assert_eq!(route(None, || Some(Builder::Forge), never_alive), Route::Native { asked: false });
        assert_eq!(route(None, || Some(Builder::Buildkit), never_alive), Route::Buildkit { say: true });
        assert_eq!(route(None, || None, never_alive), Route::Buildkit { say: false });
    }

    /// A `-f` read here (a fifo, `<(...)`) is given to docker as `-f -`
    /// with its text on stdin; nothing else changes.
    #[test]
    fn a_dockerfile_read_here_goes_to_docker_on_stdin() {
        assert_eq!(with_dockerfile_on_stdin(&sv(&["-t", "a", "-f", "/dev/fd/63", "."]), "/dev/fd/63"), sv(&["-t", "a", "-f", "-", "."]));
        assert_eq!(with_dockerfile_on_stdin(&sv(&["--file=/p", "."]), "/p"), sv(&["--file=-", "."]));
        assert_eq!(with_dockerfile_on_stdin(&sv(&["-t", "/p", "--file", "/p", "."]), "/p"), sv(&["-t", "/p", "--file", "-", "."]), "a tag spelled like the path stays");
        assert_eq!(dockerfile_arg(&sv(&["-t", "-f", "--file", "rel/df", "."])).as_deref(), Some("rel/df"));
        assert_eq!(dockerfile_arg(&sv(&["--file=x", "."])).as_deref(), Some("x"));
        assert_eq!(dockerfile_arg(&sv(&["."])), None);
    }

    /// The fallback's image id file: a random folder name, made only if
    /// new, owner-only, an empty file made only if new, all removed after.
    #[test]
    fn the_fallbacks_id_file_is_private_and_unpredictable() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = std::env::temp_dir().join(format!("kiri-iid-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let (a, b) = (private_iid_file(&base).unwrap(), private_iid_file(&base).unwrap());
        assert_ne!(a.parent(), b.parent(), "a new name each time");
        for f in [&a, &b] {
            let dir = f.parent().unwrap();
            assert_eq!(dir.parent().unwrap(), base);
            let name = dir.file_name().unwrap().to_str().unwrap();
            assert!(!name.contains(&std::process::id().to_string()) && name.len() >= "kiri-build-".len() + 32, "{name}");
            assert_eq!(std::fs::symlink_metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert!(std::fs::symlink_metadata(f).unwrap().is_file());
            assert_eq!(std::fs::metadata(f).unwrap().len(), 0);
        }
        remove_private_iid_file(&a);
        assert!(!a.exists() && !a.parent().unwrap().exists());
        remove_private_iid_file(&b);
        // Made only when the name is new: an existing folder or link is refused.
        let taken = base.join("taken");
        std::os::unix::fs::symlink("/", &taken).unwrap();
        use std::os::unix::fs::DirBuilderExt as _;
        assert_eq!(std::fs::DirBuilder::new().mode(0o700).create(&taken).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn iidfile_found_in_either_form() {
        let v = |a: &[&str]| iidfile_of(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(v(&["--iidfile", "/x", "."]), Some("/x".into()));
        assert_eq!(v(&["--iidfile=/y", "."]), Some("/y".into()));
        assert_eq!(v(&["."]), None);
    }
}
