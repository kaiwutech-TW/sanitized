#!/usr/bin/env python3
"""Translation checks for Sanitized.

  scripts/i18n.py check                                 check every source file against src/i18n/strings.json
  scripts/i18n.py check-part <part.json> <file.rs>...   check one module's translations in a separate file
  scripts/i18n.py merge                                 merge i18n/parts/*.json (if any) into src/i18n/strings.json, then check all

To add text: wrap it in t!/tf!/n! and add an entry to src/i18n/strings.json
({"<zh-Hant>": {"en": …, "ja": …, "zh-Hans": …}}), following i18n/GLOSSARY.md.

Keys are the Traditional Chinese literals inside t!("…"), tf!("…", …) and n!("…").
A check fails when a key has no en / ja / zh-Hans text, when placeholder counts differ,
or when a string literal with CJK text is not wrapped in one of those macros
(add `// i18n-ignore` on the line for the rare literal that must stay as is).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRINGS = ROOT / "src/i18n/strings.json"
PARTS = ROOT / "i18n/parts"
LANGS = ("en", "ja", "zh-Hans")
SKIP = {"src/tests.rs", "src/i18n.rs"}
CJK = re.compile(r"[぀-ヿ㐀-鿿豈-﫿＀-￯]")
MACRO_BEFORE = re.compile(r"(?<![A-Za-z0-9_])(t|tf|n)!\(\s*$")


def unescape(body):
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        n = body[i + 1]
        if n == "\n":  # line continuation: skip newline and leading whitespace
            i += 2
            while i < len(body) and body[i] in " \t\n":
                i += 1
            continue
        if n == "u":
            j = body.index("}", i)
            out.append(chr(int(body[i + 3 : j], 16)))
            i = j + 1
            continue
        out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}.get(n, n))
        i += 2
    return "".join(out)


def literals(src):
    """Yield (line, value, wrapped, ignored) for every string literal outside comments."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            j = src.find("*/", i)
            i = n if j < 0 else j + 2
        elif c == "'":
            # char literal ('x', '\n', '"') or lifetime ('a)
            if i + 2 < n and src[i + 1] == "\\":
                i = src.index("'", i + 2) + 1
            elif i + 2 < n and src[i + 2] == "'":
                i += 3
            else:
                i += 1
        elif c == "r" and re.match(r'r#*"', src[i:]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            hashes = re.match(r"r(#*)\"", src[i:]).group(1)
            start = i + 2 + len(hashes)
            end = src.index('"' + hashes, start)
            yield from emit(src, i, src[start:end])
            i = end + 1 + len(hashes)
        elif c == '"':
            j = i + 1
            while src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            yield from emit(src, i, unescape(src[i + 1 : j]))
            i = j + 1
        else:
            i += 1


def emit(src, at, value):
    line_start = src.rfind("\n", 0, at) + 1
    line_end = src.find("\n", at)
    line = src[line_start : line_end if line_end >= 0 else len(src)]
    wrapped = bool(MACRO_BEFORE.search(src[max(0, at - 40) : at]))
    yield src.count("\n", 0, at) + 1, value, wrapped, "i18n-ignore" in line


def scan(files):
    keys, unwrapped = {}, []
    for f in files:
        rel = str(Path(f).resolve().relative_to(ROOT))
        if rel in SKIP:
            continue
        for line, value, wrapped, ignored in literals(Path(f).read_text()):
            if wrapped:
                keys.setdefault(value, f"{rel}:{line}")
            elif CJK.search(value) and not ignored:
                unwrapped.append(f"{rel}:{line}: {value[:60]!r}")
    return keys, unwrapped


def placeholders(s):
    return s.replace("{{", "").replace("}}", "").count("{")


def problems(keys, table):
    out = []
    for k, where in sorted(keys.items(), key=lambda kv: kv[1]):
        e = table.get(k)
        if not e:
            out.append(f"{where}: missing translation for {k[:60]!r}")
            continue
        for lang in LANGS:
            v = e.get(lang, "")
            if not v.strip():
                out.append(f"{where}: no {lang} text for {k[:60]!r}")
            elif placeholders(v) != placeholders(k):
                out.append(f"{where}: {lang} has {placeholders(v)} placeholders, source has {placeholders(k)}: {k[:50]!r}")
    return out


def all_sources():
    return sorted(str(p) for p in (ROOT / "src").rglob("*.rs"))


def report(keys, unwrapped, probs):
    for u in unwrapped:
        print("UNWRAPPED", u)
    for p in probs:
        print("PROBLEM  ", p)
    print(f"{len(keys)} keys, {len(unwrapped)} unwrapped CJK literals, {len(probs)} translation problems")
    return 1 if unwrapped or probs else 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "check-part":
        table = json.loads(Path(sys.argv[2]).read_text())
        keys, unwrapped = scan(sys.argv[3:])
        extra = sorted(set(table) - set(keys))
        for e in extra:
            print("UNUSED   ", repr(e[:60]))
        return report(keys, unwrapped, problems(keys, table))
    if cmd == "merge":
        table = json.loads(STRINGS.read_text()) if STRINGS.exists() else {}
        for part in sorted(PARTS.glob("*.json")):
            for k, v in json.loads(part.read_text()).items():
                table[k] = v
        keys, unwrapped = scan(all_sources())
        table = {k: table[k] for k in sorted(table) if k in keys}
        STRINGS.write_text(json.dumps(table, ensure_ascii=False, indent=1) + "\n")
        print(f"wrote {STRINGS.relative_to(ROOT)} ({len(table)} entries)")
        return report(keys, unwrapped, problems(keys, table))
    if cmd == "check":
        table = json.loads(STRINGS.read_text())
        keys, unwrapped = scan(all_sources())
        return report(keys, unwrapped, problems(keys, table))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
