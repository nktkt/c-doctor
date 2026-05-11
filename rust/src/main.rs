mod config;
mod preprocess;
mod reporter;
mod rules;
mod scanner;
mod scorer;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

struct Options {
    paths: Vec<PathBuf>,
    json: bool,
    fail_under: Option<u32>,
    config_path: Option<PathBuf>,
    no_config: bool,
}

fn parse_args() -> Result<Options, String> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut json = false;
    let mut fail_under: Option<u32> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut no_config = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => json = true,
            "--fail-under" => {
                let v = args.next().ok_or_else(|| "--fail-under requires an integer".to_string())?;
                fail_under = Some(v.parse().map_err(|_| format!("invalid --fail-under value: {v}"))?);
            }
            "--config" => {
                let v = args.next().ok_or_else(|| "--config requires a path".to_string())?;
                config_path = Some(PathBuf::from(v));
            }
            "--no-config" => no_config = true,
            "-h" | "--help" => {
                println!(
                    "Usage: c-doctor [paths...] [--json] [--fail-under N] [--config PATH] [--no-config]\n\n  \
                     Scans .c / .h files and reports a 0-100 health score with diagnostics.\n\n  \
                     --json           emit a JSON report instead of the formatted view\n  \
                     --fail-under N   exit with code 2 if the score is below N (for CI)\n  \
                     --config PATH    use PATH as the config file instead of discovering one\n  \
                     --no-config      ignore any .c-doctor.toml that would be discovered\n\n  \
                     Config:\n  \
                       Looks for .c-doctor.toml starting in the current directory and\n  \
                       walking upward to the filesystem root. Supports [rules] severity\n  \
                       overrides / 'off', [scan] ignore patterns, and [score] fail_under."
                );
                std::process::exit(0);
            }
            other => paths.push(PathBuf::from(other)),
        }
    }

    if paths.is_empty() {
        paths.push(PathBuf::from("."));
    }

    Ok(Options { paths, json, fail_under, config_path, no_config })
}

fn load_config(opts: &Options) -> Result<config::Config, String> {
    if opts.no_config {
        return Ok(config::Config::empty());
    }
    if let Some(p) = &opts.config_path {
        let src = fs::read_to_string(p).map_err(|e| format!("reading {}: {}", p.display(), e))?;
        let mut c = config::Config::parse(&src)?;
        c.source = Some(p.clone());
        return Ok(c);
    }
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    config::Config::discover(&cwd)
}

fn run() -> Result<u32, String> {
    let opts = parse_args()?;
    let cfg = load_config(&opts)?;

    let raw_files = scanner::scan(&opts.paths);
    let files: Vec<PathBuf> = raw_files
        .into_iter()
        .filter(|f| !cfg.path_ignored(f))
        .collect();

    let mut all_issues = Vec::new();
    let mut total_loc = 0usize;

    for file in &files {
        let src = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        total_loc += src.split('\n').count();
        let clean = preprocess::preprocess(&src);
        let file_str = file.to_string_lossy().into_owned();
        let issues = rules::run_rules(&file_str, &src, &clean);
        all_issues.extend(issues);
    }

    cfg.apply_rules(&mut all_issues);

    let result = scorer::score(&all_issues, files.len(), total_loc);

    if opts.json {
        reporter::report_json(&result, &all_issues);
    } else {
        reporter::report(&result, &all_issues);
    }

    let threshold = opts.fail_under.or(cfg.fail_under);
    if let Some(threshold) = threshold {
        if result.score < threshold {
            return Ok(2);
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("c-doctor: {e}");
            ExitCode::from(1)
        }
    }
}
