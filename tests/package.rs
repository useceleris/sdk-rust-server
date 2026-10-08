//! The signing secret never leaves a trusted server: the crate has no way to
//! print or log, forbids unsafe code, and depends only on the signing crates
//! and the client (AUTH-05).

use std::fs;
use std::path::{Path, PathBuf};

fn source_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();

        // The unit tests are not part of the built crate.
        if path.is_dir() && path.file_name().is_some_and(|name| name != "tests") {
            files.extend(source_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }

    files
} // end fn source_files

#[test]
fn the_crate_neither_prints_nor_logs() {
    let forbidden = [
        "print!",
        "println!",
        "eprint!",
        "eprintln!",
        "dbg!",
        "stdout",
        "stderr",
        "log::",
        "tracing::",
        "info!",
        "warn!",
        "error!",
        "debug!",
        "trace!",
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = source_files(&root.join("src"));
    let library = fs::read_to_string(root.join("src/lib.rs")).unwrap();

    assert!(library.contains("#![forbid(unsafe_code)]"));

    assert!(files.len() >= 6, "found {} source files", files.len());

    for path in files {
        let source = fs::read_to_string(&path).unwrap();

        for word in forbidden {
            let uses = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(|line| line.contains(word));

            assert!(!uses, "{} uses {word}", path.display());
        }
    }
} // end fn the_crate_neither_prints_nor_logs

#[test]
fn the_runtime_dependencies_are_pinned() {
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();

    let section = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .unwrap();

    let names: Vec<&str> = section
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .collect();

    assert_eq!(names, ["base64", "hmac", "sha2", "useceleris-client"]);
} // end fn the_runtime_dependencies_are_pinned
