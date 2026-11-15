//! App preferences kept in prefs.json (scan options stay in settings.json).

use crate::i18n::Lang;
use crate::util;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Interface language; `None` follows the Mac's language.
    pub lang: Option<Lang>,
    /// Check GitHub once a day for a newer version.
    pub check_updates: bool,
    /// When the last check finished (seconds since 1970).
    pub last_update_check: u64,
    /// Newest version seen on GitHub, without the "v".
    pub latest_version: Option<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { lang: None, check_updates: true, last_update_check: 0, latest_version: None }
    }
}

impl Prefs {
    pub fn load() -> Prefs {
        std::fs::read_to_string(util::data_dir().join("prefs.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self) {
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(util::data_dir().join("prefs.json"), t);
        }
    }

    /// The language in use: the chosen one, or the Mac's.
    pub fn effective_lang(&self) -> Lang {
        // SANITIZED_LANG (testing, screenshots) wins over the saved choice.
        if let Ok(v) = std::env::var("SANITIZED_LANG") {
            return Lang::from_tag(&v);
        }
        self.lang.unwrap_or_else(crate::i18n::system)
    }
}
