use std::fs;
use std::path::{Path, PathBuf};

use crate::rules::{Issue, Severity};

#[derive(Debug, Clone)]
pub enum RuleAction {
    Off,
    Severity(Severity),
}

#[derive(Debug, Default, Clone)]
pub struct Config {
    pub rules: std::collections::HashMap<String, RuleAction>,
    pub ignore: Vec<String>,
    pub fail_under: Option<u32>,
    pub source: Option<PathBuf>,
}

impl Config {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Look for `.c-doctor.toml` starting at `start` and walking upward to the
    /// filesystem root. Returns an empty config if none was found.
    pub fn discover(start: &Path) -> Result<Self, String> {
        let mut dir: Option<&Path> = Some(start);
        while let Some(d) = dir {
            let candidate = d.join(".c-doctor.toml");
            if candidate.is_file() {
                let src = fs::read_to_string(&candidate)
                    .map_err(|e| format!("reading {}: {}", candidate.display(), e))?;
                let mut cfg = Self::parse(&src)?;
                cfg.source = Some(candidate);
                return Ok(cfg);
            }
            dir = d.parent();
        }
        Ok(Self::empty())
    }

    pub fn parse(src: &str) -> Result<Self, String> {
        let value: toml::Value = toml::from_str(src)
            .map_err(|e| format!("parsing .c-doctor.toml: {}", e))?;
        let mut cfg = Self::empty();

        if let Some(rules) = value.get("rules").and_then(|v| v.as_table()) {
            for (k, v) in rules {
                let s = v.as_str().ok_or_else(|| {
                    format!("rules.{} must be a string (off|critical|high|medium|low)", k)
                })?;
                let action = match s {
                    "off" | "disabled" | "false" => RuleAction::Off,
                    "critical" => RuleAction::Severity(Severity::Critical),
                    "high"     => RuleAction::Severity(Severity::High),
                    "medium"   => RuleAction::Severity(Severity::Medium),
                    "low"      => RuleAction::Severity(Severity::Low),
                    other => return Err(format!(
                        "rules.{} = \"{}\": expected off|critical|high|medium|low", k, other
                    )),
                };
                cfg.rules.insert(k.clone(), action);
            }
        }

        if let Some(scan) = value.get("scan").and_then(|v| v.as_table()) {
            if let Some(arr) = scan.get("ignore").and_then(|v| v.as_array()) {
                for entry in arr {
                    if let Some(s) = entry.as_str() {
                        cfg.ignore.push(s.to_string());
                    }
                }
            }
        }

        if let Some(score) = value.get("score").and_then(|v| v.as_table()) {
            if let Some(n) = score.get("fail_under").and_then(|v| v.as_integer()) {
                if (0..=100).contains(&n) {
                    cfg.fail_under = Some(n as u32);
                }
            }
        }

        Ok(cfg)
    }

    /// True if `path` matches any ignore pattern (simple substring or "*" glob).
    pub fn path_ignored(&self, path: &Path) -> bool {
        let p = path.to_string_lossy();
        self.ignore.iter().any(|pat| match_pattern(pat, &p))
    }

    /// Apply rule actions to issues collected from a run. Drops off-rules and
    /// rewrites severity overrides.
    pub fn apply_rules(&self, issues: &mut Vec<Issue>) {
        if self.rules.is_empty() {
            return;
        }
        issues.retain_mut(|issue| match self.rules.get(issue.rule) {
            Some(RuleAction::Off) => false,
            Some(RuleAction::Severity(sev)) => {
                issue.severity = *sev;
                true
            }
            None => true,
        });
    }
}

fn match_pattern(pattern: &str, path: &str) -> bool {
    if !pattern.contains('*') {
        return path.contains(pattern);
    }
    // Simple glob: `*` matches any run of characters within the path. We don't
    // try to be POSIX-accurate; this is for "ignore third_party/*.gen.c"-style
    // patterns.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut idx = 0usize;
    let first = parts.first().copied().unwrap_or("");
    let last = parts.last().copied().unwrap_or("");
    if !first.is_empty() && !path.starts_with(first) && !path.contains(first) {
        // anchor relaxation: allow substring (paths often have a prefix)
        if !path.contains(first) {
            return false;
        }
    }
    if !last.is_empty() && !path.ends_with(last) {
        return false;
    }
    for piece in &parts {
        if piece.is_empty() {
            continue;
        }
        match path[idx..].find(piece) {
            Some(p) => idx += p + piece.len(),
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let c = Config::parse("").unwrap();
        assert!(c.rules.is_empty());
        assert!(c.ignore.is_empty());
        assert!(c.fail_under.is_none());
    }

    #[test]
    fn parse_full_example() {
        let src = r#"
            [rules]
            unsafe-strcpy = "off"
            unsafe-sprintf = "low"
            unsafe-gets = "critical"

            [scan]
            ignore = ["third_party/", "*.gen.c"]

            [score]
            fail_under = 75
        "#;
        let c = Config::parse(src).unwrap();
        assert!(matches!(c.rules.get("unsafe-strcpy"), Some(RuleAction::Off)));
        assert!(matches!(c.rules.get("unsafe-sprintf"), Some(RuleAction::Severity(Severity::Low))));
        assert!(matches!(c.rules.get("unsafe-gets"), Some(RuleAction::Severity(Severity::Critical))));
        assert_eq!(c.ignore.len(), 2);
        assert_eq!(c.fail_under, Some(75));
    }

    #[test]
    fn parse_rejects_bad_severity() {
        assert!(Config::parse(r#"[rules]
            unsafe-gets = "kinda-bad"
        "#).is_err());
    }

    #[test]
    fn path_ignored_substring() {
        let c = Config {
            ignore: vec!["third_party/".into()],
            ..Default::default()
        };
        assert!(c.path_ignored(Path::new("src/third_party/foo.c")));
        assert!(!c.path_ignored(Path::new("src/main.c")));
    }

    #[test]
    fn path_ignored_glob() {
        let c = Config {
            ignore: vec!["*.gen.c".into()],
            ..Default::default()
        };
        assert!(c.path_ignored(Path::new("src/foo.gen.c")));
        assert!(!c.path_ignored(Path::new("src/foo.c")));
    }

    #[test]
    fn apply_drops_off_rules() {
        use crate::rules::Issue;
        let cfg = Config::parse(r#"[rules]
            unsafe-strcpy = "off"
        "#).unwrap();
        let mut issues = vec![
            Issue {
                file: "t.c".into(), line: 1, col: 1,
                rule: "unsafe-strcpy", category: "safety",
                severity: Severity::High, message: String::new(), suggestion: None,
            },
            Issue {
                file: "t.c".into(), line: 2, col: 1,
                rule: "unsafe-gets", category: "safety",
                severity: Severity::Critical, message: String::new(), suggestion: None,
            },
        ];
        cfg.apply_rules(&mut issues);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "unsafe-gets");
    }

    #[test]
    fn apply_overrides_severity() {
        use crate::rules::Issue;
        let cfg = Config::parse(r#"[rules]
            unsafe-sprintf = "low"
        "#).unwrap();
        let mut issues = vec![Issue {
            file: "t.c".into(), line: 1, col: 1,
            rule: "unsafe-sprintf", category: "safety",
            severity: Severity::High, message: String::new(), suggestion: None,
        }];
        cfg.apply_rules(&mut issues);
        assert_eq!(issues.len(), 1);
        assert!(matches!(issues[0].severity, Severity::Low));
    }
}
