//! New-version check: asks GitHub which release is the latest. Nothing about the Mac or the
//! person is sent; the app never downloads or installs anything by itself.
//!
//! It reads where github.com/…/releases/latest redirects to (…/releases/tag/v0.1.3) instead of
//! calling api.github.com, whose 60-requests-an-hour limit per IP runs out quickly behind
//! shared addresses (VPNs, offices).

/// Redirects to the newest release's page; also the page the "new version" notice opens.
pub const RELEASES_PAGE: &str = "https://github.com/kaiwutech-TW/sanitized/releases/latest";
/// Automatic checks run at most this often.
pub const CHECK_EVERY_SECS: u64 = 24 * 3600;

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Version number of the newest release, e.g. "0.1.3".
pub fn fetch_latest() -> Result<String, String> {
    let out = std::process::Command::new("curl")
        .args(["-sS", "-o", "/dev/null", "--max-time", "15", "-w", "%{http_code} %{redirect_url}", RELEASES_PAGE])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    version_from_redirect(&text).ok_or_else(|| format!("GitHub: {}", text.trim()))
}

/// "302 https://github.com/o/r/releases/tag/v0.1.3" → "0.1.3".
pub fn version_from_redirect(s: &str) -> Option<String> {
    let tag = s.trim().rsplit("/releases/tag/").next().filter(|_| s.contains("/releases/tag/"))?;
    let v = tag.trim().trim_start_matches('v');
    (!v.is_empty() && v.chars().next().is_some_and(|c| c.is_ascii_digit())).then(|| v.to_string())
}

/// True when `latest` is a higher version than this build.
pub fn is_newer(latest: &str) -> bool {
    crate::vuln::cmp_ver(latest, current_version()).is_gt()
}
