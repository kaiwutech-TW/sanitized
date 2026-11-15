//! Small shared helpers: paths, sizes, folder walking, moving to the Trash.

use std::fs;
use std::path::{Path, PathBuf};

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// `~/x/y` → absolute path; absolute paths are returned unchanged.
pub fn expand(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        home().join(rest)
    } else if p == "~" {
        home()
    } else {
        PathBuf::from(p)
    }
}

/// Absolute path → `~/…` for display.
pub fn collapse(p: &Path) -> String {
    let h = home();
    match p.strip_prefix(&h) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", b, U[0])
    } else if v >= 100.0 {
        format!("{:.0} {}", v, U[i])
    } else {
        format!("{:.1} {}", v, U[i])
    }
}

// ---------------------------------------------------------------- sizes (one place for all)

/// Bytes a file really occupies on disk: allocated blocks (st_blocks × 512), not its nominal
/// length. A sparse file such as Docker's Docker.raw claims the whole disk but only uses what
/// was written; Finder's "on disk" figure and `du` count it this way too.
pub fn alloc_size(md: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.blocks() * 512
    }
    #[cfg(not(unix))]
    {
        md.len()
    }
}

/// Real disk usage of one file (0 when unreadable).
pub fn file_size_on_disk(p: &Path) -> u64 {
    fs::symlink_metadata(p).map(|m| alloc_size(&m)).unwrap_or(0)
}

/// (device, inode) of a file with more than one hard link, so it is counted once.
fn link_key(md: &fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.is_file() && md.nlink() > 1 {
            return Some((md.dev(), md.ino()));
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

/// Options for `walk_size`.
#[derive(Default)]
pub struct WalkOpts<'a> {
    /// Stop after this many entries (0 = no limit).
    pub limit: usize,
    pub cancel: Option<&'a std::sync::atomic::AtomicBool>,
    /// Called once per entry (progress counters).
    pub on_entry: Option<&'a (dyn Fn() + Sync)>,
    /// Hard-link set shared between several walks (e.g. the disk map's parallel folders).
    pub links: Option<&'a std::sync::Mutex<std::collections::HashSet<(u64, u64)>>>,
}

/// Disk usage of a file or folder tree, the way `du` counts it: allocated blocks of files and
/// folders, symlinks not followed, hard-linked files once. Returns (bytes, entries, complete).
pub fn walk_size(p: &Path, o: &WalkOpts) -> (u64, u64, bool) {
    use std::sync::atomic::Ordering;
    let mut own_links = std::collections::HashSet::new();
    // Stay on the disk being measured (like `du -x`): mounted file systems inside it, such as
    // Xcode's DeviceFS (files that live on connected iPhones), aren't this disk's usage and can
    // take minutes to read.
    #[cfg(unix)]
    let root_dev = {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(p).map(|m| m.dev()).ok()
    };
    let mut total = 0u64;
    let mut count = 0u64;
    let mut stack = vec![p.to_path_buf()];
    while let Some(cur) = stack.pop() {
        if count % 256 == 0 {
            if let Some(c) = o.cancel {
                if c.load(Ordering::Relaxed) {
                    return (total, count, false);
                }
            }
        }
        if o.limit > 0 && count as usize >= o.limit {
            return (total, count, false);
        }
        let Ok(md) = fs::symlink_metadata(&cur) else { continue };
        count += 1;
        if let Some(f) = o.on_entry {
            f();
        }
        if md.file_type().is_symlink() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if root_dev.is_some() && Some(md.dev()) != root_dev {
                continue;
            }
        }
        if let Some(k) = link_key(&md) {
            let first = match o.links {
                Some(shared) => shared.lock().unwrap().insert(k),
                None => own_links.insert(k),
            };
            if !first {
                continue;
            }
        }
        total += alloc_size(&md);
        if md.is_dir() {
            if let Ok(rd) = fs::read_dir(&cur) {
                for e in rd.flatten() {
                    stack.push(e.path());
                }
            }
        }
    }
    (total, count, true)
}

/// Capacity of the disk holding `p` (cached per device; 0 when unknown).
pub fn volume_capacity(p: &Path) -> u64 {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, u64>>> = std::sync::OnceLock::new();
    #[cfg(unix)]
    let dev = {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(p).map(|m| m.dev()).unwrap_or(0)
    };
    #[cfg(not(unix))]
    let dev = 0u64;
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&dev) {
        return *v;
    }
    let out = run("df", &["-k", &p.to_string_lossy()]);
    let cap = out.lines().nth(1).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) * 1024;
    cache.lock().unwrap().insert(dev, cap);
    cap
}

/// Guard: no folder can be bigger than its disk. A bigger result means the count is wrong,
/// so it is written to size_warnings.log and capped at the disk's capacity.
pub fn checked_size(p: &Path, size: u64) -> u64 {
    let cap = volume_capacity(p);
    if cap > 0 && size > cap {
        let line = format!("{} {} 計算出 {} 位元組，超過所在磁碟容量 {}\n", now_secs(), p.display(), size, cap); // i18n-ignore
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(data_dir().join("size_warnings.log")) {
            use std::io::Write;
            let _ = f.write_all(line.as_bytes());
        }
        return cap;
    }
    size
}

/// Disk usage of a file or folder; `limit` caps the entries visited (0 = no limit).
pub fn tree_size(p: &Path, limit: usize) -> u64 {
    let (size, _, _) = walk_size(p, &WalkOpts { limit, ..Default::default() });
    checked_size(p, size)
}

/// Paths whose deletion destroys data that can't be rebuilt: Docker's whole data store and
/// virtual-machine disk images. Returns why, for the warning shown instead of a delete button.
pub fn protected_reason(p: &Path) -> Option<&'static str> {
    let s = p.to_string_lossy();
    if s.contains("/Library/Containers/com.docker.docker") || s.contains("/Library/Group Containers/group.com.docker") {
        return Some(t!("這是 Docker 的資料（全部映像檔、容器與資料庫 volume），丟掉就救不回來。請改用「Docker 清理」，由 Docker 自己刪除不需要的項目。"));
    }
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if matches!(ext.as_str(), "raw" | "qcow2" | "vmdk" | "vdi" | "vhd" | "vhdx" | "sparseimage" | "sparsebundle" | "utm" | "pvm" | "vmwarevm") {
        return Some(t!("這是虛擬機器或磁碟映像檔，裡面是整個系統或資料，刪除後無法復原。請在建立它的程式（Docker、UTM、Parallels、VMware、磁碟工具程式）裡處理。"));
    }
    None
}

/// Immediate children of a folder (empty when unreadable).
pub fn children(p: &Path) -> Vec<PathBuf> {
    fs::read_dir(p)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Move to the Trash so every cleanup can be undone from Finder.
pub fn move_to_trash(p: &Path) -> Result<(), String> {
    // Second line of defence: Docker data and virtual disks are never removed this way.
    if let Some(why) = protected_reason(p) {
        return Err(why.to_string());
    }
    // Through the system's file manager instead of asking Finder: no "crumple" sound for every
    // item and faster. Items still land in the Trash; only Finder's "Put Back" may be missing,
    // so the original location is shown in the app's list.
    #[cfg(target_os = "macos")]
    {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};
        let mut ctx = trash::TrashContext::default();
        ctx.set_delete_method(DeleteMethod::NsFileManager);
        ctx.delete(p).map_err(|e| e.to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        trash::delete(p).map_err(|e| e.to_string())
    }
}

pub fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Local-ish clock text (UTC offset not applied; good enough for a log).
/// Date (UTC) as YYYY-MM-DD.
pub fn date(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

pub fn clock(secs: u64) -> String {
    let s = secs % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// Days since a file was last modified.
pub fn age_days(md: &fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(0)
}

/// Run a command and return stdout (empty on failure).
pub fn run(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Run a shell command with administrator rights (macOS shows its own password prompt).
pub fn run_admin(shell: &str) -> Result<(), String> {
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        shell.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let out = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn open_url(url: &str) {
    let _ = std::process::Command::new("open").arg(url).spawn();
}

pub fn reveal(p: &Path) {
    let _ = std::process::Command::new("open").arg("-R").arg(p).spawn();
}

/// Where this app keeps its own data (quarantine, safe list, signatures, history).
pub fn data_dir() -> PathBuf {
    let d = home().join("Library/Application Support/MacCareGuard");
    let _ = fs::create_dir_all(&d);
    d
}

/// Decode a PNG into RGBA pixels (for the logo).
pub fn png_rgba(bytes: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Png).ok()?.to_rgba8();
    let (w, h) = img.dimensions();
    Some((img.into_raw(), w, h))
}
