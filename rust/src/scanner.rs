use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn scan(paths: &[PathBuf]) -> Vec<PathBuf> {
    let skip: HashSet<&str> = [
        "node_modules", ".git", ".hg", ".svn",
        "build", "dist", "out", "bin", "obj",
        "cmake-build-debug", "cmake-build-release",
        ".cache", ".idea", ".vscode",
        "third_party", "vendor", "target",
    ].iter().copied().collect();

    let mut out = Vec::new();
    for p in paths {
        walk(p, &skip, &mut out);
    }
    out
}

fn walk(p: &Path, skip: &HashSet<&str>, out: &mut Vec<PathBuf>) {
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.is_dir() {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if skip.contains(name) {
                return;
            }
        }
        let entries = match fs::read_dir(p) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            walk(&entry.path(), skip, out);
        }
    } else if meta.is_file() {
        if is_c_file(p) {
            out.push(p.to_path_buf());
        }
    }
}

fn is_c_file(p: &Path) -> bool {
    match p.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let lower = ext.to_ascii_lowercase();
            lower == "c" || lower == "h"
        }
        None => false,
    }
}
