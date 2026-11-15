# Sanitized

A Mac cleanup and maintenance tool written in Rust (egui). The interface is in Traditional Chinese.

## Features

- **Mac 狀態** (Mac status): live health score, CPU, memory pressure, disk, network and a menu-bar indicator
- **一鍵健檢** (quick checkup): runs junk cleanup, security and performance checks in one go
- **垃圾清理** (junk cleanup): caches, logs, broken preferences, Xcode leftovers, developer package caches, trash
- **安全防護** (security): malware scan (quick, balanced or deep), real-time monitoring of launch agents, apps and Downloads, plus quarantine with restore
- **效能最佳化** (performance): maintenance tasks, launch items and memory diagnosis
- **應用程式** (applications): uninstaller and leftover files
- **整理雜亂** (clutter): large files and duplicates
- **空間地圖** (disk map): folder sizes with drill-down and a time estimate
- **雲端檔案** (cloud files): large cloud files stored locally
- **Docker 清理** (Docker cleanup): safe, step-by-step Docker disk cleanup that never prunes volumes
- **漏洞檢查** (vulnerability check): finds known CVEs in project dependencies via [OSV.dev](https://osv.dev)

Files are moved to the Trash or the quarantine. Nothing is deleted permanently without asking.

## Install

1. Download `Sanitized-x.y.z-arm64.dmg` from [Releases](../../releases). Apple Silicon only.
2. Open the DMG and drag **Sanitized** into **Applications**.
3. Open Sanitized. The app is signed with a Developer ID and notarized by Apple.
4. For a full scan, give the app **Full Disk Access** in System Settings → Privacy & Security.

## Build from source

```sh
cargo run --release          # run directly
scripts/build-dmg.sh         # build dist/Sanitized.app and dist/Sanitized-<version>-<arch>.dmg
```

`build-dmg.sh` signs with the first "Developer ID Application" identity in your keychain and notarizes when a
`notarytool` keychain profile named `sanitized` exists (override with `SIGN_ID` / `NOTARY_PROFILE`). Without them it makes an ad-hoc signed build.

Requires Rust 1.80+ and the Xcode command-line tools.

## Malware rule sources

- **Apple XProtect**: the YARA rules macOS ships, read from this Mac at run time (not bundled).
- **MalwareBazaar** ([abuse.ch](https://bazaar.abuse.ch/), CC0): optional SHA-256 fingerprints of Mac malware. Needs your own free API key, which is stored in the macOS Keychain.
- **[Objective-See](https://github.com/Objective-see/Malware)**: public list of Mac malware family names and documented install locations.
- Built-in rules: the EICAR test file, common adware families and our own script patterns.

## Credits

The health score weights, memory diagnosis thresholds, developer-cache locations and some maintenance tasks follow the open-source [Mole](https://github.com/tw93/Mole) project.

## License

GPL-3.0. See [LICENSE](LICENSE).
