use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};

use crate::rules::{Issue, Severity};
use crate::scorer::Score;

struct Pal {
    enabled: bool,
}

impl Pal {
    fn reset(&self) -> &'static str { if self.enabled { "\x1b[0m" } else { "" } }
    fn bold(&self)  -> &'static str { if self.enabled { "\x1b[1m" } else { "" } }
    fn dim(&self)   -> &'static str { if self.enabled { "\x1b[2m" } else { "" } }
    fn red(&self)   -> &'static str { if self.enabled { "\x1b[31m" } else { "" } }
    fn green(&self) -> &'static str { if self.enabled { "\x1b[32m" } else { "" } }
    fn yellow(&self)-> &'static str { if self.enabled { "\x1b[33m" } else { "" } }
    fn cyan(&self)  -> &'static str { if self.enabled { "\x1b[36m" } else { "" } }
}

fn sev_color<'a>(s: Severity, p: &'a Pal) -> String {
    match s {
        Severity::Critical => format!("{}{}", p.red(), p.bold()),
        Severity::High => p.red().to_string(),
        Severity::Medium => p.yellow().to_string(),
        Severity::Low => p.dim().to_string(),
    }
}

fn plural(n: usize, s: &str) -> String {
    if n == 1 { s.to_string() } else { format!("{}s", s) }
}

pub fn report(result: &Score, issues: &[Issue]) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let p = Pal { enabled: io::stdout().is_terminal() };

    let score_color = if result.score >= 75 {
        p.green().to_string()
    } else if result.score >= 50 {
        p.yellow().to_string()
    } else {
        p.red().to_string()
    };

    writeln!(out).ok();
    writeln!(out, "{}c-doctor{} {}— C codebase health{}", p.bold(), p.reset(), p.dim(), p.reset()).ok();
    writeln!(
        out,
        "{}scanned {} {} ({} LOC), found {} {}{}",
        p.dim(),
        result.files,
        plural(result.files, "file"),
        result.loc,
        result.issue_count,
        plural(result.issue_count, "issue"),
        p.reset()
    ).ok();
    writeln!(out).ok();
    writeln!(
        out,
        "  {}{}{}{}{}/100{}  {}{}{}{}",
        score_color, p.bold(), result.score, p.reset(),
        p.dim(), p.reset(),
        score_color, p.bold(), result.label, p.reset()
    ).ok();
    writeln!(out).ok();

    if issues.is_empty() {
        writeln!(out, "  {}clean — no issues found{}", p.green(), p.reset()).ok();
        writeln!(out).ok();
        return;
    }

    // group by file
    let mut by_file: BTreeMap<&str, Vec<&Issue>> = BTreeMap::new();
    for i in issues {
        by_file.entry(i.file.as_str()).or_default().push(i);
    }

    for (file, mut list) in by_file {
        writeln!(out, "{}{}{}", p.cyan(), file, p.reset()).ok();
        list.sort_by(|a, b| {
            a.severity.order().cmp(&b.severity.order())
                .then(a.line.cmp(&b.line))
                .then(a.col.cmp(&b.col))
        });
        for i in list {
            let sev = sev_color(i.severity, &p);
            let loc = format!("{}:{}", i.line, i.col);
            writeln!(
                out,
                "  {}{:>7}{}  {}{:<8}{}  {}  {}[{}]{}",
                p.dim(), loc, p.reset(),
                sev, i.severity.as_str(), p.reset(),
                i.message,
                p.dim(), i.rule, p.reset()
            ).ok();
            if let Some(s) = &i.suggestion {
                let suggestion = s.replace('\n', "\n             ");
                writeln!(out, "           {}↳ {}{}", p.dim(), suggestion, p.reset()).ok();
            }
        }
        writeln!(out).ok();
    }

    writeln!(out, "{}by category{}", p.bold(), p.reset()).ok();
    let mut cats: Vec<(&String, &usize)> = result.by_category.iter().collect();
    cats.sort_by(|a, b| b.1.cmp(a.1));
    for (cat, n) in cats {
        writeln!(out, "  {:<14} {}", cat, n).ok();
    }
    writeln!(out).ok();

    writeln!(out, "{}by severity{}", p.bold(), p.reset()).ok();
    for sev in ["critical", "high", "medium", "low"] {
        if let Some(n) = result.by_severity.get(sev) {
            let color = match sev {
                "critical" => format!("{}{}", p.red(), p.bold()),
                "high" => p.red().to_string(),
                "medium" => p.yellow().to_string(),
                _ => p.dim().to_string(),
            };
            writeln!(out, "  {}{:<10}{} {}", color, sev, p.reset(), n).ok();
        }
    }
    writeln!(out).ok();
}

// ---------- JSON output (manual, no serde) ----------

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn report_json(result: &Score, issues: &[Issue]) {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"score\": {},\n", result.score));
    s.push_str(&format!("  \"label\": \"{}\",\n", result.label));
    s.push_str(&format!("  \"files\": {},\n", result.files));
    s.push_str(&format!("  \"loc\": {},\n", result.loc));
    s.push_str(&format!("  \"issueCount\": {},\n", result.issue_count));

    s.push_str("  \"byCategory\": {");
    let mut first = true;
    for (k, v) in &result.by_category {
        if !first { s.push_str(", "); }
        first = false;
        s.push_str(&format!("\"{}\": {}", json_escape(k), v));
    }
    s.push_str("},\n");

    s.push_str("  \"bySeverity\": {");
    let mut first = true;
    for (k, v) in &result.by_severity {
        if !first { s.push_str(", "); }
        first = false;
        s.push_str(&format!("\"{}\": {}", json_escape(k), v));
    }
    s.push_str("},\n");

    s.push_str("  \"issues\": [");
    for (idx, i) in issues.iter().enumerate() {
        if idx > 0 { s.push(','); }
        s.push_str("\n    {");
        s.push_str(&format!("\"file\": \"{}\", ", json_escape(&i.file)));
        s.push_str(&format!("\"line\": {}, ", i.line));
        s.push_str(&format!("\"col\": {}, ", i.col));
        s.push_str(&format!("\"rule\": \"{}\", ", json_escape(i.rule)));
        s.push_str(&format!("\"category\": \"{}\", ", json_escape(i.category)));
        s.push_str(&format!("\"severity\": \"{}\", ", json_escape(i.severity.as_str())));
        s.push_str(&format!("\"message\": \"{}\"", json_escape(&i.message)));
        if let Some(sg) = &i.suggestion {
            s.push_str(&format!(", \"suggestion\": \"{}\"", json_escape(sg)));
        }
        s.push('}');
    }
    if !issues.is_empty() { s.push_str("\n  "); }
    s.push_str("]\n}\n");

    print!("{}", s);
}
