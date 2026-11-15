//! Interface languages. The Traditional Chinese text in the source is the key; `strings.json`
//! holds the English, Japanese and Simplified Chinese text for each key.
//!
//! - `t!("…")`: translate a literal (returns `&str`).
//! - `tf!("… {} …", a, b)`: translate, then fill `{}` in order (translations may use `{0}`,
//!   `{1}` to reorder). Format numbers before passing them, e.g. `format!("{:.1}", x)`.
//! - `n!("…")`: mark a literal for translation without translating it here (const tables,
//!   names stored in files); translate it where it is shown with `i18n::tr(s)`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Lang {
    #[serde(rename = "zh-Hant")]
    ZhHant,
    #[serde(rename = "zh-Hans")]
    ZhHans,
    #[serde(rename = "en")]
    En,
    #[serde(rename = "ja")]
    Ja,
}

impl Lang {
    pub const ALL: [Lang; 4] = [Lang::ZhHant, Lang::ZhHans, Lang::En, Lang::Ja];

    /// The language's own name, shown in the language picker.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::ZhHant => "繁體中文",
            Lang::ZhHans => "简体中文",
            Lang::En => "English",
            Lang::Ja => "日本語",
        }
    }

    /// Map a BCP 47 tag such as "zh-Hant-TW", "zh-CN", "ja-JP" or "en-US".
    pub fn from_tag(tag: &str) -> Lang {
        let t = tag.trim().trim_matches('"').to_ascii_lowercase().replace('_', "-");
        if t.starts_with("zh") {
            let traditional = t.contains("hant") || t.starts_with("zh-tw") || t.starts_with("zh-hk") || t.starts_with("zh-mo");
            if traditional { Lang::ZhHant } else { Lang::ZhHans }
        } else if t.starts_with("ja") {
            Lang::Ja
        } else {
            Lang::En
        }
    }

    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(v: u8) -> Lang {
        match v {
            1 => Lang::ZhHans,
            2 => Lang::En,
            3 => Lang::Ja,
            _ => Lang::ZhHant,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set(lang: Lang) {
    CURRENT.store(lang.to_u8(), Ordering::Relaxed);
}

pub fn current() -> Lang {
    Lang::from_u8(CURRENT.load(Ordering::Relaxed))
}

/// The Mac's preferred language (first entry of System Settings → Language & Region).
/// `SANITIZED_LANG=ja` overrides it (used for screenshots and testing).
pub fn system() -> Lang {
    if let Ok(v) = std::env::var("SANITIZED_LANG") {
        return Lang::from_tag(&v);
    }
    let out = std::process::Command::new("defaults").args(["read", "-g", "AppleLanguages"]).output();
    let text = out.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    // Output looks like: (\n    "zh-Hant-TW",\n    "en-TW"\n)
    text.split(|c: char| c == '\n' || c == ',' || c == '(' || c == ')')
        .map(|s| s.trim().trim_matches('"'))
        .find(|s| !s.is_empty())
        .map(Lang::from_tag)
        .unwrap_or(Lang::En)
}

#[derive(Deserialize)]
struct Entry {
    en: String,
    ja: String,
    #[serde(rename = "zh-Hans")]
    zh_hans: String,
}

/// Translations: index 0 = Simplified Chinese, 1 = English, 2 = Japanese.
fn tables() -> &'static [HashMap<String, String>; 3] {
    static T: OnceLock<[HashMap<String, String>; 3]> = OnceLock::new();
    T.get_or_init(|| {
        let all: HashMap<String, Entry> = serde_json::from_str(include_str!("i18n/strings.json")).unwrap_or_default();
        let mut t: [HashMap<String, String>; 3] = Default::default();
        for (k, e) in all {
            t[0].insert(k.clone(), e.zh_hans);
            t[1].insert(k.clone(), e.en);
            t[2].insert(k, e.ja);
        }
        t
    })
}

/// Translate `s` (Traditional Chinese source text) into the current language. Text without a
/// translation is returned unchanged.
pub fn tr(s: &str) -> &str {
    let idx = match current() {
        Lang::ZhHant => return s,
        Lang::ZhHans => 0,
        Lang::En => 1,
        Lang::Ja => 2,
    };
    match tables()[idx].get(s) {
        Some(v) if !v.is_empty() => v.as_str(),
        _ => s,
    }
}

/// Fill `{}` (next argument) and `{0}`, `{1}` (argument by position) in a translated template.
/// `{{` and `}}` give literal braces.
pub fn fill(template: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut next = 0;
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut inner = String::new();
                for d in chars.by_ref() {
                    if d == '}' {
                        break;
                    }
                    inner.push(d);
                }
                let i = if inner.is_empty() {
                    next += 1;
                    next - 1
                } else {
                    inner.parse().unwrap_or(usize::MAX)
                };
                match args.get(i) {
                    Some(a) => out.push_str(a),
                    None => {
                        out.push('{');
                        out.push_str(&inner);
                        out.push('}');
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Number of placeholders (`{}` or `{N}`) in a template.
#[cfg(test)]
pub fn placeholders(template: &str) -> usize {
    let s = template.replace("{{", "").replace("}}", "");
    s.matches('{').count()
}

#[macro_export]
macro_rules! t {
    ($s:literal) => {
        $crate::i18n::tr($s)
    };
}

#[macro_export]
macro_rules! tf {
    ($s:literal $(, $a:expr)* $(,)?) => {
        $crate::i18n::fill($crate::i18n::tr($s), &[$(($a).to_string()),*])
    };
}

#[macro_export]
macro_rules! n {
    ($s:literal) => {
        $s
    };
}
