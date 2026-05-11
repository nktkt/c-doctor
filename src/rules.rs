// Rule detectors. Each `check_*` function pushes findings into the shared
// issues vec. We intentionally compile per-issue regexes (e.g. `alloc-no-null-
// check`, `use-after-free`) since the variable name being matched is dynamic,
// and we keep the `#[cfg(test)] mod tests` block at the end of the file for
// proximity to the rule definitions even though the entry point sits above it.
#![allow(clippy::regex_creation_in_loops)]
#![allow(clippy::items_after_test_module)]

use regex::Regex;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Severity::Critical => 10,
            Severity::High => 5,
            Severity::Medium => 2,
            Severity::Low => 1,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
    pub fn order(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        }
    }
}

#[derive(Debug)]
pub struct Issue {
    pub file: String,
    pub line: usize,
    pub col: usize,
    pub rule: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub message: String,
    pub suggestion: Option<String>,
}

pub struct Ctx<'a> {
    pub file: String,
    pub src_orig: &'a str,
    pub clean: &'a str,
    pub line_starts: Vec<usize>,
    pub lines: Vec<&'a str>,
}

impl<'a> Ctx<'a> {
    fn new(file: String, src_orig: &'a str, clean: &'a str) -> Self {
        let mut line_starts = vec![0usize];
        for (i, b) in clean.as_bytes().iter().enumerate() {
            if *b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        let lines: Vec<&str> = clean.split('\n').collect();
        Self {
            file,
            src_orig,
            clean,
            line_starts,
            lines,
        }
    }
    fn pos_of(&self, idx: usize) -> (usize, usize) {
        let line = match self.line_starts.binary_search(&idx) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        (line + 1, idx - self.line_starts[line] + 1)
    }
}

macro_rules! re {
    ($pat:expr) => {{
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new($pat).expect("valid regex"))
    }};
}

// ---------- safety ----------

struct UnsafeFunc {
    name: &'static str,
    severity: Severity,
    msg: &'static str,
    fix: &'static str,
}

const UNSAFE_FUNCS: &[UnsafeFunc] = &[
    UnsafeFunc {
        name: "gets",
        severity: Severity::Critical,
        msg: "gets() cannot bound input and is removed from C11; always overflows on long input",
        fix: "fgets(buf, sizeof(buf), stdin)",
    },
    UnsafeFunc {
        name: "strcpy",
        severity: Severity::High,
        msg: "strcpy() has no bounds check; one wrong size assumption is a buffer overflow",
        fix: "strlcpy(dst, src, sizeof(dst)) or snprintf",
    },
    UnsafeFunc {
        name: "strcat",
        severity: Severity::High,
        msg: "strcat() has no bounds check on the destination",
        fix: "strlcat(dst, src, sizeof(dst))",
    },
    UnsafeFunc {
        name: "sprintf",
        severity: Severity::High,
        msg: "sprintf() has no buffer size argument; output length can exceed the destination",
        fix: "snprintf(buf, sizeof(buf), ...)",
    },
    UnsafeFunc {
        name: "vsprintf",
        severity: Severity::High,
        msg: "vsprintf() has no buffer size argument",
        fix: "vsnprintf(buf, sizeof(buf), ...)",
    },
];

fn check_unsafe_funcs(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(");
    for cap in re.captures_iter(ctx.clean) {
        let name = &cap[1];
        let info = UNSAFE_FUNCS.iter().find(|f| f.name == name).unwrap();
        let m = cap.get(0).unwrap();
        let (line, col) = ctx.pos_of(m.start());
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: match name {
                "gets" => "unsafe-gets",
                "strcpy" => "unsafe-strcpy",
                "strcat" => "unsafe-strcat",
                "sprintf" => "unsafe-sprintf",
                "vsprintf" => "unsafe-vsprintf",
                _ => "unsafe-fn",
            },
            category: "safety",
            severity: info.severity,
            message: info.msg.to_string(),
            suggestion: Some(info.fix.to_string()),
        });
    }
}

fn check_scanf_no_width(ctx: &Ctx, out: &mut Vec<Issue>) {
    // Locate call site in preprocessed source (so comments are ignored), then
    // read the format string from the original source (preprocess blanked it).
    let re = re!(r"\b(?:s|f)?scanf\s*\(");
    let orig = ctx.src_orig.as_bytes();
    for m in re.find_iter(ctx.clean) {
        // walk parens in original to find the closing one
        let start = m.start();
        if start >= orig.len() {
            continue;
        }
        let mut depth: i32 = 0;
        let mut end = None;
        // start from the '(' position
        let paren_pos = match orig[start..].iter().position(|&b| b == b'(') {
            Some(p) => start + p,
            None => continue,
        };
        for (k, b) in orig.iter().enumerate().skip(paren_pos) {
            if *b == b'(' {
                depth += 1;
            } else if *b == b')' {
                depth -= 1;
                if depth == 0 {
                    end = Some(k);
                    break;
                }
            }
        }
        let end = match end {
            Some(e) => e,
            None => continue,
        };
        let args = &ctx.src_orig[start..=end];
        let fmt_re = re!(r#""((?:[^"\\]|\\.)*)""#);
        let fmt = match fmt_re.captures(args) {
            Some(c) => c.get(1).unwrap().as_str().to_string(),
            None => continue,
        };
        // %s or %[ without an explicit width:
        //   reject any digits between % and the conversion char
        let unbounded = re!(r"%\*?[hlLjzt]?[s\[]");
        if unbounded.is_match(&fmt) {
            let (line, col) = ctx.pos_of(start);
            out.push(Issue {
                file: ctx.file.clone(),
                line,
                col,
                rule: "scanf-no-width",
                category: "safety",
                severity: Severity::High,
                message: "scanf %s/%[ without a width specifier risks buffer overflow".to_string(),
                suggestion: Some(
                    "add an explicit field width, e.g. %63s for a 64-byte buffer".to_string(),
                ),
            });
        }
    }
}

fn check_format_string_vuln(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"\bprintf\s*\(\s*([a-zA-Z_]\w*)\s*\)");
    for cap in re.captures_iter(ctx.clean) {
        let m = cap.get(0).unwrap();
        let var = cap.get(1).unwrap().as_str();
        let (line, col) = ctx.pos_of(m.start());
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "format-string-vuln",
            category: "safety",
            severity: Severity::High,
            message: format!(
                "printf() called with bare variable '{}' as format string — attacker-controlled %n/%s = RCE/leak",
                var
            ),
            suggestion: Some(format!("printf(\"%s\", {})", var)),
        });
    }
}

fn check_system_call(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"\bsystem\s*\(");
    for m in re.find_iter(ctx.clean) {
        let (line, col) = ctx.pos_of(m.start());
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "system-call",
            category: "security",
            severity: Severity::Medium,
            message: "system() invokes a shell; any user-controlled portion of the command is an injection vector".to_string(),
            suggestion: Some("posix_spawn() or fork()+execvp() with arguments as a separate array".to_string()),
        });
    }
}

// ---------- memory ----------

fn check_alloc_null_check(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(");
    for cap in re.captures_iter(ctx.clean) {
        let var = cap.get(1).unwrap().as_str();
        let fn_name = cap.get(2).unwrap().as_str();
        let m = cap.get(0).unwrap();
        let (line, col) = ctx.pos_of(m.start());
        let start = line.saturating_sub(1);
        let end = (start + 6).min(ctx.lines.len());
        let slice = ctx.lines[start..end].join("\n");
        let pat = format!(
            r"(?:if\s*\(\s*!?\s*{var}\b)|(?:\b{var}\s*==\s*NULL\b)|(?:\bNULL\s*==\s*{var}\b)|(?:\b{var}\s*!=\s*NULL\b)|(?:\bassert\s*\(\s*{var}\b)",
            var = regex::escape(var)
        );
        let check = Regex::new(&pat).unwrap();
        if !check.is_match(&slice) {
            out.push(Issue {
                file: ctx.file.clone(),
                line,
                col,
                rule: "alloc-no-null-check",
                category: "memory",
                severity: Severity::Medium,
                message: format!(
                    "{fn_name}() result '{var}' is not checked against NULL within 5 lines"
                ),
                suggestion: Some(format!(
                    "if ({var} == NULL) {{ /* handle allocation failure */ }}"
                )),
            });
        }
    }
}

fn check_realloc_self_assign(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"\b(\w+)\s*=\s*realloc\s*\(\s*(\w+)\s*,");
    for cap in re.captures_iter(ctx.clean) {
        if cap.get(1).unwrap().as_str() != cap.get(2).unwrap().as_str() {
            continue;
        }
        let var = cap.get(1).unwrap().as_str().to_string();
        let m = cap.get(0).unwrap();
        let (line, col) = ctx.pos_of(m.start());
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "realloc-self-assign",
            category: "memory",
            severity: Severity::Medium,
            message: format!(
                "realloc result assigned back to '{var}' — on failure realloc returns NULL and the original pointer is leaked"
            ),
            suggestion: Some(format!(
                "void *tmp = realloc({var}, n); if (tmp) {var} = tmp;"
            )),
        });
    }
}

// ---------- performance ----------

fn check_strlen_in_loop(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"\bfor\s*\([^;]*;[^;{}]*\bstrlen\s*\([^;{}]*;[^){}]*\)");
    for m in re.find_iter(ctx.clean) {
        let (line, col) = ctx.pos_of(m.start());
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "strlen-in-loop-condition",
            category: "performance",
            severity: Severity::Medium,
            message: "strlen() in a for-loop condition is recomputed every iteration — O(n²) over the string".to_string(),
            suggestion: Some("hoist: size_t len = strlen(s); for (size_t i = 0; i < len; i++) ...".to_string()),
        });
    }
}

// ---------- architecture ----------

fn check_header_guards(ctx: &Ctx, out: &mut Vec<Issue>) {
    if !ctx.file.to_lowercase().ends_with(".h") {
        return;
    }
    let head_end = ctx.clean.len().min(4000);
    let head = &ctx.clean[..head_end];
    if re!(r"#\s*pragma\s+once\b").is_match(head) {
        return;
    }
    let ifndef = re!(r"#\s*ifndef\s+(\w+)");
    if let Some(cap) = ifndef.captures(head) {
        let guard = cap.get(1).unwrap().as_str();
        let define_pat = format!(r"#\s*define\s+{}\b", regex::escape(guard));
        if Regex::new(&define_pat).unwrap().is_match(head) {
            return;
        }
    }
    out.push(Issue {
        file: ctx.file.clone(),
        line: 1,
        col: 1,
        rule: "missing-header-guard",
        category: "architecture",
        severity: Severity::Medium,
        message:
            "header has no include guard or #pragma once — multiple inclusion will redefine symbols"
                .to_string(),
        suggestion: Some("#pragma once  (or #ifndef FOO_H / #define FOO_H ... #endif)".to_string()),
    });
}

#[derive(Debug)]
struct Func {
    name: String,
    start_line: usize, // 0-indexed
    body_line: usize,  // line containing the opening `{`
    end_line: usize,   // line containing the matching `}`
    max_depth: i32,
}

// C reserved words that can appear in `keyword (...) { ... }` form and would
// otherwise be miscaptured as function names by a permissive signature regex.
const CONTROL_KEYWORDS: &[&str] = &[
    "if",
    "else",
    "while",
    "for",
    "do",
    "switch",
    "case",
    "default",
    "return",
    "break",
    "continue",
    "goto",
    "sizeof",
    "typedef",
    "struct",
    "union",
    "enum",
    "__attribute__",
];

fn find_functions(ctx: &Ctx) -> Vec<Func> {
    // Type prefix must start with a word char (or `*`/`[`/`]`) — bare leading
    // whitespace was letting `switch (x)` capture `switch` as a "function".
    let same_line = re!(
        r"^[ \t]*(?:(?:static|inline|extern|const|unsigned|signed|register|volatile|_Noreturn|__inline__|__attribute__\s*\([^)]*\))\s+)*[\w\*\[\]][\w\*\[\]\s]*?\s+\b(\w+)\s*\([^;{}]*\)\s*\{[ \t]*$"
    );
    let head_only = re!(
        r"^[ \t]*(?:(?:static|inline|extern|const|unsigned|signed|register|volatile|_Noreturn|__inline__|__attribute__\s*\([^)]*\))\s+)*[\w\*\[\]][\w\*\[\]\s]*?\s+\b(\w+)\s*\([^;{}]*\)[ \t]*$"
    );
    let open_brace_only = re!(r"^[ \t]*\{[ \t]*$");

    let mut funcs = Vec::new();
    let lines = &ctx.lines;
    let mut i = 0;
    while i < lines.len() {
        let (name, body_line) = if let Some(cap) = same_line.captures(lines[i]) {
            (cap[1].to_string(), i)
        } else if let Some(cap) = head_only.captures(lines[i]) {
            if i + 1 < lines.len() && open_brace_only.is_match(lines[i + 1]) {
                (cap[1].to_string(), i + 1)
            } else {
                i += 1;
                continue;
            }
        } else {
            i += 1;
            continue;
        };

        if CONTROL_KEYWORDS.contains(&name.as_str()) {
            i += 1;
            continue;
        }

        let open_col = lines[body_line].find('{').unwrap_or(0);
        let mut depth: i32 = 0;
        let mut max_depth: i32 = 0;
        let mut end_line = body_line;
        let mut stopped = false;
        let mut li = body_line;
        while li < lines.len() && !stopped {
            let bytes = lines[li].as_bytes();
            let from = if li == body_line { open_col } else { 0 };
            for &c in bytes.iter().skip(from) {
                match c {
                    b'{' => {
                        depth += 1;
                        if depth > max_depth {
                            max_depth = depth;
                        }
                    }
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            end_line = li;
                            stopped = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if !stopped {
                li += 1;
            }
        }
        funcs.push(Func {
            name,
            start_line: i,
            body_line,
            end_line,
            max_depth,
        });
        i = end_line + 1;
    }
    funcs
}

fn check_function_metrics(ctx: &Ctx, out: &mut Vec<Issue>) {
    for fn_info in find_functions(ctx) {
        let body_lines = fn_info.end_line - fn_info.body_line + 1;
        if body_lines > 60 {
            out.push(Issue {
                file: ctx.file.clone(),
                line: fn_info.start_line + 1,
                col: 1,
                rule: "function-too-long",
                category: "architecture",
                severity: Severity::Low,
                message: format!(
                    "function '{}' is {} lines (>60) — extract helpers",
                    fn_info.name, body_lines
                ),
                suggestion: None,
            });
        }
        if fn_info.max_depth >= 5 {
            out.push(Issue {
                file: ctx.file.clone(),
                line: fn_info.start_line + 1,
                col: 1,
                rule: "deep-nesting",
                category: "architecture",
                severity: Severity::Medium,
                message: format!(
                    "function '{}' nests {} levels deep — flatten with early returns or extract helpers",
                    fn_info.name,
                    fn_info.max_depth - 1
                ),
                suggestion: None,
            });
        }
    }
}

// ---------- dead code ----------

fn check_dead_code(ctx: &Ctx, out: &mut Vec<Issue>) {
    let term = re!(
        r"\b(?:return\b[^;]*;|break\s*;|continue\s*;|goto\s+\w+\s*;|exit\s*\([^)]*\)\s*;|abort\s*\(\s*\)\s*;)"
    );
    let case_re = re!(r"^(?:case\b|default\s*:)");
    let label_re = re!(r"^\w+\s*:[^:]");
    // Terminator is the body of an unbraced control statement (so the "next"
    // line is reached when the controlling condition is false, not dead).
    let unbraced_ctrl = re!(r"\b(?:if|while|for|else|do)\b");

    for fn_info in find_functions(ctx) {
        let body_text = ctx.lines[fn_info.body_line..=fn_info.end_line].join("\n");
        let bytes = body_text.as_bytes();
        for m in term.find_iter(&body_text) {
            // Look at what follows the terminator's semicolon. Treat `\` at
            // end of line (macro continuation) as whitespace so we correctly
            // skip past `return X;\<NL>} while(0)` macro tails.
            let mut k = m.end();
            while k < bytes.len() {
                if bytes[k].is_ascii_whitespace() {
                    k += 1;
                } else if bytes[k] == b'\\' && k + 1 < bytes.len() && bytes[k + 1] == b'\n' {
                    k += 2;
                } else {
                    break;
                }
            }
            if k >= bytes.len() {
                continue;
            }
            let rest_end = (k + 64).min(bytes.len());
            let rest = &body_text[k..rest_end];
            if rest.starts_with('}') {
                continue;
            }
            if case_re.is_match(rest) {
                continue;
            }
            if label_re.is_match(rest) {
                continue;
            }
            if rest.starts_with('#') {
                continue;
            }

            // Walk backwards from the terminator to the most recent statement
            // boundary (`;`, `{`, `}`). If the prefix between that boundary and
            // the terminator contains a control keyword without a `{` (which
            // would have been the boundary), the terminator is the body of an
            // unbraced if/while/for/else/do — the next line is reachable.
            let term_start = m.start();
            let mut j = term_start;
            while j > 0 {
                let c = bytes[j - 1];
                if c == b';' || c == b'{' || c == b'}' {
                    break;
                }
                j -= 1;
            }
            let prefix = &body_text[j..term_start];
            if unbraced_ctrl.is_match(prefix) {
                continue;
            }

            let before = &body_text[..k];
            let line_offset = before.matches('\n').count();
            let line_number = fn_info.body_line + line_offset + 1;
            let term_word = m.as_str().split_whitespace().next().unwrap_or("return");
            out.push(Issue {
                file: ctx.file.clone(),
                line: line_number,
                col: 1,
                rule: "dead-code-after-terminator",
                category: "deadcode",
                severity: Severity::Low,
                message: format!("code after {} is unreachable", term_word),
                suggestion: None,
            });
        }
    }
}

// ---------- correctness ----------

fn check_strcmp_as_bool(ctx: &Ctx, out: &mut Vec<Issue>) {
    // `if (strcmp(a,b))` — strcmp returns 0 on equal, so a bare truthiness test
    // reads inverted from the typical English intent. Also catches !strcmp,
    // which is "works but confusing".
    let re =
        re!(r"\bif\s*\(\s*(!?)\s*(strcmp|strncmp|memcmp|wcscmp)\s*\(([^()]|\([^()]*\))*\)\s*\)");
    for cap in re.captures_iter(ctx.clean) {
        let bang = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let fn_name = cap.get(2).unwrap().as_str();
        let m = cap.get(0).unwrap();
        let (line, col) = ctx.pos_of(m.start());
        let (msg, sev) = if bang.is_empty() {
            (
                format!("`if ({fn_name}(...))` reads inverted: {fn_name} returns 0 on equal, so this branch runs on *inequality*"),
                Severity::Medium,
            )
        } else {
            (
                format!("`if (!{fn_name}(...))` works but obscures intent: prefer `{fn_name}(...) == 0` for clarity"),
                Severity::Low,
            )
        };
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "cmp-as-bool",
            category: "correctness",
            severity: sev,
            message: msg,
            suggestion: Some(format!("{fn_name}(...) == 0  or  {fn_name}(...) != 0")),
        });
    }
}

fn check_assign_in_condition(ctx: &Ctx, out: &mut Vec<Issue>) {
    // `if (x = foo())` — likely a typo for `==`. We require the `=` to not be
    // followed by another `=`, and we skip the well-known intentional
    // double-paren idiom `if ((x = ...))`.
    let re = re!(r"\bif\s*\(\s*(\w+)\s*=([^=])");
    for cap in re.captures_iter(ctx.clean) {
        let m = cap.get(0).unwrap();
        // Skip when the inner expression is wrapped in extra parens, the
        // conventional "I meant this assignment" signal: `if ((x = ...))`.
        let after_if = &ctx.clean[m.start()..];
        if let Some(after_open) = after_if.find('(') {
            let rest = &after_if[after_open + 1..];
            if rest.trim_start().starts_with('(') {
                continue;
            }
        }
        let var = cap.get(1).unwrap().as_str();
        let (line, col) = ctx.pos_of(m.start());
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "assign-in-condition",
            category: "correctness",
            severity: Severity::Medium,
            message: format!(
                "`if ({var} = ...)` assigns to {var}; almost certainly meant `==`. Wrap in extra parens if intentional."
            ),
            suggestion: Some(format!("if ({var} == ...)  or  if (({var} = ...))")),
        });
        let _ = cap.get(2);
    }
}

fn check_use_after_free(ctx: &Ctx, out: &mut Vec<Issue>) {
    // After `free(x);`, search forward for a dereference of `x` (`x->`, `x[`,
    // `x(`). Stop at the end of the enclosing block (`}` at depth 0) so we
    // don't flag uses in sibling scopes. Skip if `x` is reassigned first, or
    // if a `return`/`goto` between free and use diverts control.
    //
    // Note: we deliberately *don't* match `*x` — that pattern is too easily
    // confused with declarations like `char *x = ...`.
    let re = re!(r"\bfree\s*\(\s*(\w+)\s*\)\s*;");
    let div_re = re!(r"\b(?:return\b|goto\b)");
    let bytes = ctx.clean.as_bytes();

    for cap in re.captures_iter(ctx.clean) {
        let var = cap.get(1).unwrap().as_str().to_string();
        if var == "NULL" {
            continue;
        }
        let m = cap.get(0).unwrap();

        // Walk forward tracking brace depth so we don't cross out of the
        // free's containing block.
        let mut k = m.end();
        let limit = (m.end() + 4000).min(bytes.len());
        let mut depth: i32 = 0;
        let mut end_idx = limit;
        while k < limit {
            match bytes[k] {
                b'{' => depth += 1,
                b'}' => {
                    if depth == 0 {
                        end_idx = k;
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            k += 1;
        }
        if end_idx <= m.end() {
            continue;
        }
        let slice = &ctx.clean[m.end()..end_idx];

        let use_pat = format!(
            r"(?:\b{v}\s*->|\b{v}\s*\[|\b{v}\s*\()",
            v = regex::escape(&var)
        );
        let use_re = Regex::new(&use_pat).unwrap();
        let Some(use_m) = use_re.find(slice) else {
            continue;
        };
        let use_idx = use_m.start();

        let reassign_pat = format!(r"\b{}\s*=([^=])", regex::escape(&var));
        let reassign_re = Regex::new(&reassign_pat).unwrap();
        if let Some(ra) = reassign_re.find(slice) {
            if ra.start() < use_idx {
                continue;
            }
        }
        if let Some(d) = div_re.find(slice) {
            if d.start() < use_idx {
                continue;
            }
        }

        let absolute = m.end() + use_idx;
        let (line, col) = ctx.pos_of(absolute);
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "use-after-free",
            category: "memory",
            severity: Severity::High,
            message: format!("'{var}' is used after free() — undefined behavior"),
            suggestion: Some(format!(
                "set {var} = NULL after free, or restructure so the pointer is not touched again"
            )),
        });
    }
}

// ---------- portability ----------

fn check_portability(ctx: &Ctx, out: &mut Vec<Issue>) {
    let re = re!(r"(?m)^[ \t]*#\s*include\s*<(conio\.h|windows\.h|direct\.h|io\.h|process\.h)>");
    let guard = re!(r"#\s*if(?:def|ndef)?\b[^\n]*(_WIN32|_MSC_VER|WIN32|_WIN64)");
    for cap in re.captures_iter(ctx.clean) {
        let header = cap.get(1).unwrap().as_str().to_string();
        let m = cap.get(0).unwrap();
        let (line, col) = ctx.pos_of(m.start());
        let start = line.saturating_sub(6);
        let end = line.saturating_sub(1).min(ctx.lines.len());
        let before = if start < end {
            ctx.lines[start..end].join("\n")
        } else {
            String::new()
        };
        if guard.is_match(&before) {
            continue;
        }
        out.push(Issue {
            file: ctx.file.clone(),
            line,
            col,
            rule: "unportable-header",
            category: "portability",
            severity: Severity::Low,
            message: format!(
                "<{header}> is Windows-only — wrap in #ifdef _WIN32 for cross-platform builds"
            ),
            suggestion: Some(format!("#ifdef _WIN32\n#include <{header}>\n#endif")),
        });
    }
}

// ---------- entry ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocess::preprocess;

    fn scan(src: &str) -> Vec<Issue> {
        let clean = preprocess(src);
        run_rules("test.c", src, &clean)
    }
    fn scan_h(src: &str) -> Vec<Issue> {
        let clean = preprocess(src);
        run_rules("test.h", src, &clean)
    }

    fn has_rule(issues: &[Issue], rule: &str) -> bool {
        issues.iter().any(|i| i.rule == rule)
    }
    fn assert_fires(src: &str, rule: &str) {
        let issues = scan(src);
        assert!(
            has_rule(&issues, rule),
            "expected '{}' to fire. Got: {:?}\nSource:\n{}",
            rule,
            issues.iter().map(|i| i.rule).collect::<Vec<_>>(),
            src
        );
    }
    fn assert_quiet(src: &str, rule: &str) {
        let issues = scan(src);
        assert!(
            !has_rule(&issues, rule),
            "expected '{}' to NOT fire. Got: {:?}\nSource:\n{}",
            rule,
            issues.iter().filter(|i| i.rule == rule).collect::<Vec<_>>(),
            src
        );
    }

    // ---------- safety ----------

    #[test]
    fn unsafe_gets_fires() {
        assert_fires("int main(){char b[8]; gets(b); return 0;}", "unsafe-gets");
    }
    #[test]
    fn unsafe_gets_ignored_in_comment() {
        assert_quiet("// gets(b);\nint main(){return 0;}", "unsafe-gets");
    }
    #[test]
    fn unsafe_gets_ignored_in_string_literal() {
        assert_quiet(
            "int main(){const char *s = \"gets(b)\"; return 0;}",
            "unsafe-gets",
        );
    }
    #[test]
    fn unsafe_strcpy_strcat_sprintf_vsprintf_fire() {
        assert_fires("void f(char*d,char*s){strcpy(d,s);}", "unsafe-strcpy");
        assert_fires("void f(char*d,char*s){strcat(d,s);}", "unsafe-strcat");
        assert_fires("void f(char*b){sprintf(b,\"x\");}", "unsafe-sprintf");
        assert_fires(
            "#include <stdarg.h>\nvoid f(char*b,va_list a){vsprintf(b,\"x\",a);}",
            "unsafe-vsprintf",
        );
    }
    #[test]
    fn strcpy_s_is_not_strcpy() {
        // word-boundary should not match strcpy in strcpy_s
        assert_quiet("void f(char*d,char*s){strcpy_s(d,8,s);}", "unsafe-strcpy");
    }

    #[test]
    fn scanf_percent_s_without_width_fires() {
        assert_fires("void f(char*b){scanf(\"%s\", b);}", "scanf-no-width");
    }
    #[test]
    fn scanf_with_width_is_ok() {
        assert_quiet("void f(char*b){scanf(\"%63s\", b);}", "scanf-no-width");
    }
    #[test]
    fn scanf_for_int_is_ok() {
        assert_quiet("void f(int*x){scanf(\"%d\", x);}", "scanf-no-width");
    }

    #[test]
    fn format_string_vuln_fires_on_bare_var() {
        assert_fires("void f(const char*m){printf(m);}", "format-string-vuln");
    }
    #[test]
    fn format_string_vuln_quiet_on_literal() {
        assert_quiet("void f(){printf(\"hello\\n\");}", "format-string-vuln");
    }
    #[test]
    fn format_string_vuln_quiet_with_format_arg() {
        assert_quiet(
            "void f(const char*m){printf(\"%s\", m);}",
            "format-string-vuln",
        );
    }

    #[test]
    fn system_call_fires() {
        assert_fires("void f(){system(\"ls\");}", "system-call");
    }

    // ---------- memory ----------

    #[test]
    fn alloc_without_null_check_fires() {
        let src = "void f(){char *p = malloc(8); strcpy(p, \"a\"); return;}";
        assert_fires(src, "alloc-no-null-check");
    }
    #[test]
    fn alloc_with_null_check_is_ok() {
        let src = "void f(){char *p = malloc(8); if (p == NULL) return; *p = 0;}";
        assert_quiet(src, "alloc-no-null-check");
    }
    #[test]
    fn alloc_with_bang_check_is_ok() {
        let src = "void f(){char *p = malloc(8); if (!p) return; *p = 0;}";
        assert_quiet(src, "alloc-no-null-check");
    }

    #[test]
    fn realloc_self_assign_fires() {
        let src = "void f(){void *p = 0; p = realloc(p, 8);}";
        assert_fires(src, "realloc-self-assign");
    }
    #[test]
    fn realloc_to_tmp_is_ok() {
        let src = "void f(){void *p = 0; void *t = realloc(p, 8); if (t) p = t;}";
        assert_quiet(src, "realloc-self-assign");
    }

    #[test]
    fn use_after_free_fires() {
        let src = "void f(){char *p = 0; free(p); p[0] = 'x';}";
        assert_fires(src, "use-after-free");
    }
    #[test]
    fn use_after_free_quiet_with_reassign() {
        let src = "void f(){char *p = 0; free(p); p = 0; if(p){}}";
        assert_quiet(src, "use-after-free");
    }
    #[test]
    fn use_after_free_quiet_after_return() {
        // free is in an if-branch ending in return; outer use is unreachable from this free
        let src = "void f(int c, char *p){if(c){free(p); return;} p[0]='x';}";
        assert_quiet(src, "use-after-free");
    }
    #[test]
    fn use_after_free_quiet_on_declaration_lookalike() {
        // `char *p` declaration mustn't be detected as `*p` deref.
        let src = "void f(char*x){free(x);} void g(){char *p; (void)p;}";
        assert_quiet(src, "use-after-free");
    }

    // ---------- performance ----------

    #[test]
    fn strlen_in_loop_fires() {
        let src = "void f(const char *s){for (int i = 0; i < strlen(s); i++){}}";
        assert_fires(src, "strlen-in-loop-condition");
    }
    #[test]
    fn strlen_outside_loop_is_ok() {
        let src = "void f(const char *s){size_t n = strlen(s); for (int i = 0; i < n; i++){}}";
        assert_quiet(src, "strlen-in-loop-condition");
    }

    // ---------- architecture ----------

    #[test]
    fn missing_header_guard_fires() {
        let issues = scan_h("int x(void);\n");
        assert!(has_rule(&issues, "missing-header-guard"));
    }
    #[test]
    fn pragma_once_is_ok() {
        let issues = scan_h("#pragma once\nint x(void);\n");
        assert!(!has_rule(&issues, "missing-header-guard"));
    }
    #[test]
    fn ifndef_define_is_ok() {
        let issues = scan_h("#ifndef FOO_H\n#define FOO_H\nint x(void);\n#endif\n");
        assert!(!has_rule(&issues, "missing-header-guard"));
    }

    #[test]
    fn deep_nesting_fires() {
        let mut src = String::from("void f(){\n");
        for _ in 0..6 {
            src.push_str("    if (1) {\n");
        }
        src.push_str("        int x = 0; (void)x;\n");
        for _ in 0..6 {
            src.push_str("    }\n");
        }
        src.push_str("}\n");
        assert_fires(&src, "deep-nesting");
    }
    #[test]
    fn switch_is_not_a_function() {
        let src = "int f(int x){\n    switch (x)\n    {\n        case 1: return 1;\n        default: return 0;\n    }\n}\n";
        let issues = scan(src);
        // Make sure no architecture issue with name "switch" exists.
        let bad = issues.iter().any(|i| i.message.contains("'switch'"));
        assert!(
            !bad,
            "should not detect 'switch' as a function. Issues: {:?}",
            issues.iter().collect::<Vec<_>>()
        );
    }

    // ---------- dead code ----------

    #[test]
    fn dead_code_after_return_fires() {
        // Function detector requires K&R/Allman brace style (one-line bodies
        // are intentionally not parsed as functions), so the function spans
        // multiple lines here.
        let src = "int f(void) {\n    return 0;\n    printf(\"x\");\n}\n";
        assert_fires(src, "dead-code-after-terminator");
    }
    #[test]
    fn unbraced_if_return_is_not_dead() {
        let src = "int f(int x) {\n    if (x) return 0;\n    return 1;\n}\n";
        assert_quiet(src, "dead-code-after-terminator");
    }
    #[test]
    fn macro_continuation_is_not_dead() {
        // `return X;\<NL>} while(0)` inside a do-while macro must not flag.
        let src = "void f(void){\n#define M() do {\\\n    return;\\\n} while(0)\nM();\n}\n";
        assert_quiet(src, "dead-code-after-terminator");
    }

    // ---------- correctness ----------

    #[test]
    fn cmp_as_bool_fires_on_inverted_strcmp() {
        let src = "int f(const char *a, const char *b){if (strcmp(a, b)) return 1; return 0;}";
        assert_fires(src, "cmp-as-bool");
    }
    #[test]
    fn cmp_as_bool_quiet_when_compared_to_zero() {
        let src = "int f(const char *a, const char *b){if (strcmp(a, b) == 0) return 1; return 0;}";
        assert_quiet(src, "cmp-as-bool");
    }

    #[test]
    fn assign_in_condition_fires() {
        let src = "int f(int x){if (x = 1) return 1; return 0;}";
        assert_fires(src, "assign-in-condition");
    }
    #[test]
    fn assign_in_condition_quiet_with_double_paren() {
        let src = "int f(int x){if ((x = 1)) return 1; return 0;}";
        assert_quiet(src, "assign-in-condition");
    }
    #[test]
    fn assign_in_condition_quiet_for_equality() {
        let src = "int f(int x){if (x == 1) return 1; return 0;}";
        assert_quiet(src, "assign-in-condition");
    }

    // ---------- portability ----------

    #[test]
    fn unportable_header_fires() {
        let src = "#include <windows.h>\nint main(void){return 0;}\n";
        assert_fires(src, "unportable-header");
    }
    #[test]
    fn unportable_header_quiet_with_win32_guard() {
        let src = "#ifdef _WIN32\n#include <windows.h>\n#endif\nint main(void){return 0;}\n";
        assert_quiet(src, "unportable-header");
    }
}

pub fn run_rules(file: &str, src_orig: &str, clean: &str) -> Vec<Issue> {
    let ctx = Ctx::new(file.to_string(), src_orig, clean);
    let mut issues = Vec::new();
    check_unsafe_funcs(&ctx, &mut issues);
    check_scanf_no_width(&ctx, &mut issues);
    check_format_string_vuln(&ctx, &mut issues);
    check_system_call(&ctx, &mut issues);
    check_alloc_null_check(&ctx, &mut issues);
    check_realloc_self_assign(&ctx, &mut issues);
    check_strlen_in_loop(&ctx, &mut issues);
    check_header_guards(&ctx, &mut issues);
    check_function_metrics(&ctx, &mut issues);
    check_dead_code(&ctx, &mut issues);
    check_strcmp_as_bool(&ctx, &mut issues);
    check_assign_in_condition(&ctx, &mut issues);
    check_use_after_free(&ctx, &mut issues);
    check_portability(&ctx, &mut issues);

    // Deduplicate exact (line, col, rule) repeats — overlapping regex iteration
    // can flag the same position twice.
    issues.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then(a.col.cmp(&b.col))
            .then_with(|| a.rule.cmp(b.rule))
    });
    issues.dedup_by(|a, b| a.line == b.line && a.col == b.col && a.rule == b.rule);
    issues
}
