#!/usr/bin/env python3
"""Build the landing page in every language.

  scripts/build-site.py           write site/index.html (繁體中文), site/en/, site/ja/, site/zh-hans/
  scripts/build-site.py check     only report missing or unused translations

Source: site-src/index.html (Traditional Chinese template), site-src/style.css and
site-src/strings.json ({"<zh-Hant text>": {"en": …, "ja": …, "zh-Hans": …}}).
Translated units: the inner HTML of elements marked data-t, plus any content/alt/aria-label
value with Chinese text. Keys have their whitespace collapsed to single spaces.
Screenshots and the share image come from site/img/<dir>/ on the other language pages.
After building: `npx wrangler deploy`.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "site-src"
OUT = ROOT / "site"
BASE = "https://sanitized.kaiwu.com.tw"

# code, folder ("" = site root), og:locale, label in the switcher button
LANGS = [
    ("zh-Hant", "", "zh_TW", "繁中"),
    ("zh-Hans", "zh-hans", "zh_CN", "简中"),
    ("en", "en", "en_US", "EN"),
    ("ja", "ja", "ja_JP", "日本語"),
]
NATIVE = {"zh-Hant": "繁體中文", "zh-Hans": "简体中文", "en": "English", "ja": "日本語"}
CJK = re.compile(r"[぀-ヿ㐀-鿿豈-﫿＀-￯]")
TAG_WITH_T = re.compile(r"<([a-z0-9]+)([^>]*?)\sdata-t(?:=\"\")?([^>]*)>")
ATTR = re.compile(r'\b(content|alt|aria-label)="([^"]*)"')

# On the root page only: send a first-time visitor to their browser's language. Skipped for
# crawlers, for visits coming from another page of this site (so the switcher's 繁中 link
# sticks) and once a language has been picked in the switcher.
REDIRECT = """<script>
(function () {
  if (/bot|crawl|spider|slurp|lighthouse|preview/i.test(navigator.userAgent)) return;
  if (document.referrer.indexOf(location.origin + "/") === 0) return;
  var saved = null;
  try { saved = localStorage.getItem("lang"); } catch (e) {}
  var pick = function (t) {
    t = (t || "").toLowerCase();
    if (t.indexOf("zh") === 0) return /hant|^zh-(tw|hk|mo)/.test(t) ? "zh-Hant" : "zh-Hans";
    if (t.indexOf("ja") === 0) return "ja";
    return "en";
  };
  var lang = saved || pick((navigator.languages && navigator.languages[0]) || navigator.language);
  var to = { "zh-Hans": "/zh-hans/", en: "/en/", ja: "/ja/" }[lang];
  if (to) location.replace(to + location.hash);
})();
</script>"""

SWITCHER_JS = """<script>
document.querySelectorAll(".lang a[data-lang]").forEach(function (a) {
  a.addEventListener("click", function () { try { localStorage.setItem("lang", a.dataset.lang); } catch (e) {} });
});
document.addEventListener("click", function (e) {
  var d = document.querySelector("details.lang");
  if (d && d.open && !d.contains(e.target)) d.open = false;
});
</script>"""


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def path_of(folder):
    return "/" if not folder else f"/{folder}/"


def find_close(html, tag, start):
    """Index of the closing tag matching an element whose content starts at `start`."""
    depth, pos = 1, start
    pat = re.compile(rf"<(/?){tag}\b[^>]*>")
    while True:
        m = pat.search(html, pos)
        if not m:
            raise SystemExit(f"no closing </{tag}> after offset {start}")
        depth += -1 if m.group(1) else 1
        if depth == 0:
            return m.start(), m.end()
        pos = m.end()


def units(html):
    """Yield (start, end, open_tag_without_marker, tag, inner) for each data-t element."""
    pos = 0
    while True:
        m = TAG_WITH_T.search(html, pos)
        if not m:
            return
        tag = m.group(1)
        c_start, c_end = find_close(html, tag, m.end())
        inner = html[m.end():c_start]
        if "data-t" in inner:
            raise SystemExit(f"nested data-t inside <{tag}> {norm(inner)[:40]!r}")
        yield m.start(), c_end, f"<{tag}{m.group(2)}{m.group(3)}>", tag, inner
        pos = c_end


def keys_of(template):
    keys = [norm(u[4]) for u in units(template)]
    keys += [v for _, v in ATTR.findall(template) if CJK.search(v)]
    return keys


def switcher(lang, tr):
    items = []
    for code, folder, _, _ in LANGS:
        cur = ' aria-current="page"' if code == lang else ""
        items.append(
            f'<li><a href="{path_of(folder)}" hreflang="{code}" lang="{code}" data-lang="{code}"{cur}>{NATIVE[code]}</a></li>'
        )
    label = dict((c, s) for c, _, _, s in LANGS)[lang]
    globe = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
             'stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/>'
             '<path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/></svg>')
    return (f'<details class="lang"><summary aria-label="{tr("語言")}">{globe}<span>{label}</span></summary>'
            f'<ul>{"".join(items)}</ul></details>')


def build(lang, folder, locale, template, style, table, version):
    def tr(s):
        if lang == "zh-Hant":
            return s
        return table[norm(s)][lang]

    out, pos = [], 0
    for start, end, open_tag, tag, inner in units(template):
        out.append(template[pos:start])
        out.append(f"{open_tag}{tr(inner) if lang != 'zh-Hant' else inner.strip()}</{tag}>")
        pos = end
    out.append(template[pos:])
    html = "".join(out)
    html = ATTR.sub(lambda m: f'{m.group(1)}="{tr(m.group(2)) if CJK.search(m.group(2)) else m.group(2)}"', html)
    html = re.sub(r"<!--.*?-->\n", "", html, count=1, flags=re.S)

    if folder:
        html = html.replace("/img/shot-", f"/img/{folder}/shot-").replace("/img/og.jpg", f"/img/{folder}/og.jpg")

    alternates = [f'<link rel="canonical" href="{BASE}{path_of(folder)}">']
    for code, f, _, _ in LANGS:
        alternates.append(f'<link rel="alternate" hreflang="{code}" href="{BASE}{path_of(f)}">')
    alternates.append(f'<link rel="alternate" hreflang="x-default" href="{BASE}/">')
    alternates.append(f'<meta property="og:url" content="{BASE}{path_of(folder)}">')
    alternates.append(f'<meta property="og:locale" content="{locale}">')

    fills = {
        "lang": lang,
        "redirect": REDIRECT if not folder else "",
        "style": style.rstrip(),
        "alternates": "\n".join(alternates),
        "switcher": switcher(lang, tr),
        "home": path_of(folder),
        "version": version,
    }
    html = re.sub(r"\{\{(\w+)\}\}", lambda m: fills[m.group(1)], html)
    html = html.replace("</body>", SWITCHER_JS + "\n</body>")
    html = re.sub(r"\n{3,}", "\n\n", html)
    return html


def leftover_cjk(html):
    """Chinese/Japanese text left in the English page outside the language names."""
    text = re.sub(r"<style>.*?</style>|<script>.*?</script>", "", html, flags=re.S)
    for name in list(NATIVE.values()) + ["繁中", "简中", "日本語", "繁中 · 简中 · English · 日本語"]:
        text = text.replace(name, "")
    return sorted(set(re.findall(r"[^<>\"]*[぀-ヿ㐀-鿿][^<>\"]*", text)))


def main():
    template = (SRC / "index.html").read_text()
    style = (SRC / "style.css").read_text()
    table = json.loads((SRC / "strings.json").read_text())
    version = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)

    keys = keys_of(template) + ["語言"]
    bad = []
    for k in dict.fromkeys(keys):
        e = table.get(k)
        for code, *_ in LANGS[1:]:
            if not e or not e.get(code, "").strip():
                bad.append(f"missing {code}: {k[:70]!r}")
            elif e[code].count("<") != k.count("<"):
                bad.append(f"{code} has different markup: {k[:50]!r}")
    for k in sorted(set(table) - set(keys)):
        print("UNUSED  ", repr(k[:70]))
    for b in bad:
        print("PROBLEM ", b)
    print(f"{len(set(keys))} strings, {len(bad)} problems")
    if bad:
        return 1
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        return 0

    for code, folder, locale, _ in LANGS:
        html = build(code, folder, locale, template, style, table, version)
        if code == "en":
            left = leftover_cjk(html)
            if left:
                print("Chinese text left in the English page:", left)
                return 1
        dest = OUT / folder / "index.html" if folder else OUT / "index.html"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(html)
        missing = [p for p in re.findall(r'src="(/img/[^"]+)"', html) if not (OUT / p.lstrip("/")).exists()]
        print(f"wrote {dest.relative_to(ROOT)}" + (f"  (missing images: {missing})" if missing else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
