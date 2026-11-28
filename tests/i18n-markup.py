#!/usr/bin/env python3
"""scripts/i18n-check.py refuses a translation that adds markup its English key
does not have. Each case copies the language files, changes one translation of
a key with <code>, and expects the checker to fail on it; the unchanged copy
must pass.

    python3 tests/i18n-markup.py
"""
import json, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANG = os.path.join(ROOT, "crates/kiri/src/ui/lang")
CHECK = os.path.join(ROOT, "scripts/i18n-check.py")

de = json.load(open(os.path.join(LANG, "de.json")))
KEY = next(k for k in sorted(de) if k.count("<code>") == 1 and "{" not in k)
WORDS = de[KEY]
CASES = {
    "an event handler on a kept tag": WORDS.replace("<code>", "<code onclick=alert(1)>", 1),
    "an event handler, quoted": WORDS.replace("<code>", "<code onmouseover='alert(1)'>", 1),
    "a style on a kept tag": WORDS.replace("<code>", "<code style=position:fixed>", 1),
    "a new tag with src": WORDS + " <img src=x onerror=alert(1)>",
    "a link with javascript:": WORDS + " <a href=javascript:alert(1)>x</a>",
    "a tag the English does not have": WORDS + " <b>x</b>",
    "an unclosed tag": WORDS + " <img src=x onerror=alert(1) ",
    "the kept tag swapped for another": WORDS.replace("<code>", "<b>", 1).replace("</code>", "</b>", 1),
}


def run(words):
    with tempfile.TemporaryDirectory() as d:
        for f in os.listdir(LANG):
            shutil.copy(os.path.join(LANG, f), d)
        if words is not None:
            m = dict(de)
            m[KEY] = words
            json.dump(m, open(os.path.join(d, "de.json"), "w"), ensure_ascii=False)
        out = subprocess.run([sys.executable, CHECK, "--lang-dir", d], capture_output=True, text=True)
        return out.returncode, out.stdout


bad = 0
code, out = run(None)
print(("PASS" if code == 0 else "FAIL") + " the unchanged files pass")
bad += code != 0
for name, words in CASES.items():
    code, out = run(words)
    hit = code != 0 and any(line.startswith("FAIL de.json") and json.dumps(KEY, ensure_ascii=False) in line for line in out.splitlines())
    print(("PASS" if hit else "FAIL") + f" refused: {name}")
    bad += not hit
sys.exit(1 if bad else 0)
