#!/usr/bin/env python3
"""Checks the window's translations (crates/kiri/src/ui/lang/*.json) against
the words in use.

English is the key: the pages' tr("…") and trn(n, "…", "…") (index.html, langstep.js and
kiri-win's setup.html), index.html's data-i18n* attributes, and the Rust's
tr("…") and trf("…") (the Mac's menus, the Windows tray, setup steps and the
notices the app sends the page). Each language file must have every key, no
key nothing uses, the same {placeholders} as its key, the same tags as its
key, each written exactly as there (the words go into the page as HTML: no
attribute, event handler, style, link or tag the English does not have), and
no ASCII double quote (the words go into HTML attributes).

    python3 scripts/i18n-check.py              # check
    python3 scripts/i18n-check.py --missing    # print the keys a file lacks, as JSON
    python3 scripts/i18n-check.py --since REF  # check, with notes against REF rather than main
    python3 scripts/i18n-check.py --lang-dir DIR  # check other files (tests/i18n-markup.py)

It also notes, without failing, the short words where a language you added or
changed is longer than every other language: those are the ones most likely
to be cut off in a button, a badge or a column header. "Changed" means
differs from where the branch left origin/main (or from --since REF), new
files not yet committed included.
"""
import json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "crates/kiri/src/ui")
PAGES = [os.path.join(UI, "index.html"), os.path.join(UI, "langstep.js"), os.path.join(ROOT, "crates/kiri-win/src/setup.html")]
# The Rust that draws native words or sends the page words (notices, setup steps).
# (lang.rs is the lookup itself: its tests call tr(lang, words).)
NATIVE = sorted([os.path.join(UI, f) for f in os.listdir(UI) if f.endswith(".rs") and f != "lang.rs"]
                + [os.path.join(ROOT, "crates/kiri-win/src", f) for f in os.listdir(os.path.join(ROOT, "crates/kiri-win/src")) if f.endswith(".rs")])
# Words the native side looks up without a literal tr("…"): the engine states
# shown in the menus ("Linux VM: Running").
NATIVE_STATES = ["Not running", "Running", "Stopped", "Asleep"]

STR = r'"((?:[^"\\\n]|\\.)*)"'


def unquote(lit):
    return json.loads(f'"{lit}"')


def page_keys(src):
    keys = {}
    for m in re.finditer(r"(?<![\w.$])tr\(\s*" + STR, src):
        keys.setdefault(unquote(m.group(1)), src.count("\n", 0, m.start()) + 1)
    for m in re.finditer(r"(?<![\w.$])(?<!function )trn\(", src):
        lits = re.findall(STR, src[m.end(): m.end() + 400])[:2]
        for lit in lits:
            keys.setdefault(unquote(lit), src.count("\n", 0, m.start()) + 1)
    for m in re.finditer(r'data-i18n(?:-title|-label|-ph)?="([^"]*)"', src):
        keys.setdefault(m.group(1), src.count("\n", 0, m.start()) + 1)
    return keys


def native_keys():
    keys = {}
    for path in NATIVE:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for m in re.finditer(r"(?<![\w.$])(?:tr|trf|app)\(\s*" + STR, src):
            keys.setdefault(unquote(m.group(1)), (os.path.relpath(path, ROOT), src.count("\n", 0, m.start()) + 1))
    for k in NATIVE_STATES:
        keys.setdefault(k, ("menus", 0))
    return keys


def holes(s):
    return sorted(re.findall(r"\{\w+\}", s))


TAG = re.compile(r"<[^<>]*>")
# Markup that runs code, loads something or restyles the window: never in a
# translation unless its English key has the same.
RISKY = [(re.compile(r"\bon[a-z]+\s*=", re.I), "an event handler (on…=)"), (re.compile(r"\bstyle\s*=", re.I), "style="),
         (re.compile(r"\bhref\s*=", re.I), "href="), (re.compile(r"\bsrc\s*=", re.I), "src="), (re.compile(r"javascript\s*:", re.I), "javascript:")]


def tags(s):
    """Each tag's full text, attributes and all, as the page's safeWords compares them."""
    return sorted(TAG.findall(s))


def markup_problems(k, v):
    """What in the words `v` is not markup its English key `k` has."""
    out = []
    have = set(tags(k))
    for t in tags(v):
        if t in have:
            continue
        name = re.match(r"</?\s*([a-zA-Z][\w-]*)", t)
        if name and any(re.match(rf"</?\s*{re.escape(name.group(1))}\b", e, re.I) for e in have):
            out.append(f"tag {t} has attributes its English {sorted(e for e in have if re.match(rf'</?{re.escape(name.group(1))}\b', e, re.I))} does not")
        else:
            out.append(f"tag {t} is not in the English")
    if tags(v) != tags(k) and not out:
        out.append(f"tags {tags(v)} should be {tags(k)}")
    if TAG.sub("", v).count("<") > TAG.sub("", k).count("<"):
        out.append("a < that does not close into one of the English tags")
    for rx, what in RISKY:
        if rx.search(v) and not rx.search(k):
            out.append(f"{what} the English does not have")
    return out


def self_test():
    """The markup rule on words made to slip past it: run with every check, so
    a change that lets one through fails here, not in the window."""
    k = "Run <code>kiri run</code> or <span class=mono>{x}</span>"
    caught = [
        "Starte <code onclick=alert(1)>kiri run</code> oder <span class=mono>{x}</span>",
        "Starte <code>kiri run</code> oder <span class=mono style=color:red>{x}</span>",
        "Starte <code>kiri run</code> oder <span class=mono>{x}</span><img src=x onerror=alert(1)>",
        "Starte <code>kiri run</code> oder <span class=mono>{x}</span><a href=javascript:alert(1)>x</a>",
        "Starte <code>kiri run</code> oder <span class=mono>{x}</span> <img src=x onerror=alert(1) ",
        "Starte <code>kiri run</code> oder <span class=mono>{x}</span> <b>x</b>",
        "Starte <code>kiri run</code> oder <span class=mono>{x}</span> <CODE>x</CODE>",
        "Starte <code>kiri run</code> oder <span class='mono' onmouseover=alert(1)>{x}</span>",
    ]
    for v in caught:
        if not markup_problems(k, v):
            return f"the markup check let through {v!r}"
    if markup_problems(k, "Starte <code>kiri run</code> oder <span class=mono>{x}</span>"):
        return "the markup check refused words with the English tags"
    return None


# Words up to this long sit in buttons, badges and headers; longer ones wrap.
SHORT = 20


def gha_escape_data(s):
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gha_escape_prop(s):
    return gha_escape_data(s).replace(":", "%3A").replace(",", "%2C")


def changed_files():
    """The language files that differ from main (or --since REF), by name; none if git can't say."""
    lang = os.path.relpath(os.path.join(UI, "lang"), ROOT)
    git = lambda *a: subprocess.run(["git", "-C", ROOT, *a], capture_output=True, text=True, encoding="utf-8", check=True).stdout.splitlines()
    ref = None
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--since":
            if i + 1 >= len(sys.argv) or not sys.argv[i + 1] or sys.argv[i + 1].startswith("-"):
                return []
            ref = sys.argv[i + 1]
    try:
        resolved = (
            git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
            if ref is not None
            else git("merge-base", "HEAD", "origin/main")
        )
        if not resolved:
            return []
        since = resolved[0]
        names = git("diff", "--name-only", since, "--", lang) + git("ls-files", "--others", "--exclude-standard", "--", lang)
    except (OSError, subprocess.CalledProcessError):
        return []
    return sorted({os.path.basename(n) for n in names if n.endswith(".json")})


def length_notes(files, langs):
    """Each changed file's short words that are longer than in English and every other language, with their lines."""
    notes = []
    for f in files:
        if f not in langs:
            continue
        path = os.path.relpath(os.path.join(UI, "lang", f), ROOT)
        with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        for key, text in langs[f].items():
            if not isinstance(text, str) or len(text) > SHORT:
                continue
            others = [(len(key), "en")] + [(len(m[key]), o[:-5]) for o, m in langs.items() if o != f and isinstance(m.get(key), str)]
            longest, who = max(others)
            if len(text) > longest:
                quoted = json.dumps(key, ensure_ascii=False)
                line = next((i + 1 for i, l in enumerate(lines) if l.lstrip().startswith(quoted + ":")), 1)
                notes.append((path, line, f"{json.dumps(text, ensure_ascii=False)} ({quoted}) is longer than in every other language "
                                          f"(next: {longest} characters, {who}), so it may be cut off; a shorter word fits better if there is one"))
    return notes


def main():
    broken = self_test()
    if broken:
        print("FAIL " + broken)
        return 1
    custom_dir = "--lang-dir" in sys.argv
    lang_dir = sys.argv[sys.argv.index("--lang-dir") + 1] if custom_dir else os.path.join(UI, "lang")
    keys = {}
    for page in PAGES:
        with open(page, encoding="utf-8") as fh:
            src = fh.read()
        for k, line in page_keys(src).items():
            keys.setdefault(k, (os.path.relpath(page, ROOT), line))
    for k, v in native_keys().items():
        keys.setdefault(k, v)
    files = sorted(f for f in os.listdir(lang_dir) if f.endswith(".json"))
    if "--missing" in sys.argv:
        for f in files:
            with open(os.path.join(lang_dir, f), encoding="utf-8") as fh:
                have = json.load(fh)
            print(json.dumps({k: "" for k in keys if k not in have}, ensure_ascii=False, indent=2))
        return 0
    bad, langs = [], {}
    for f in files:
        path = os.path.join(lang_dir, f)
        try:
            with open(path, encoding="utf-8") as fh:
                have = json.load(fh)
        except ValueError as e:
            bad.append(f"{f}: not JSON ({e})")
            continue
        langs[f] = have
        for k, (where, line) in sorted(keys.items(), key=lambda x: x[1]):
            if k not in have:
                bad.append(f"{f}: no translation for {json.dumps(k, ensure_ascii=False)} ({where}:{line})")
        for k, v in have.items():
            if k not in keys:
                bad.append(f"{f}: {json.dumps(k, ensure_ascii=False)} isn't used any more; remove it")
            elif not isinstance(v, str) or not v.strip():
                bad.append(f"{f}: {json.dumps(k, ensure_ascii=False)} has no words")
            else:
                if holes(v) != holes(k):
                    bad.append(f"{f}: {json.dumps(k, ensure_ascii=False)}: placeholders {holes(v)} should be {holes(k)}")
                for problem in markup_problems(k, v):
                    bad.append(f"{f}: {json.dumps(k, ensure_ascii=False)}: {problem}")
                if '"' in v and '"' not in k:
                    bad.append(f"{f}: {json.dumps(k, ensure_ascii=False)}: use “ ” rather than \" in the words")
    for line in bad:
        print("FAIL " + line)
    print(f"{'FAIL' if bad else 'PASS'} {len(keys)} keys, {len(files)} language file(s), {len(bad)} problem(s)")
    if not custom_dir:
        # Advice only: never changes the result. On GitHub it also shows on the pull request.
        for path, line, text in length_notes(changed_files(), langs):
            print(f"NOTE {path}:{line}: {text}")
            if os.environ.get("GITHUB_ACTIONS"):
                title = gha_escape_prop("May be cut off")
                print(f"::notice file={gha_escape_prop(path.replace(os.sep, '/'))},line={gha_escape_prop(line)},title={title}::{gha_escape_data(text)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
