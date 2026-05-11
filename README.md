# c-doctor

[![CI](https://github.com/nktkt/c-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/nktkt/c-doctor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Health diagnostics for C codebases. Scans `.c` / `.h` files and outputs a 0–100
score with actionable issues — the patterns AI coding agents (and humans) get
wrong: unsafe functions, memory hazards, dead code, deep nesting, format-string
vulnerabilities.

Inspired by [react-doctor](https://github.com/millionco/react-doctor), targeted
at C. Pure Rust, single dependency on `regex` and `toml`, no AST — just
preprocessor-aware pattern matching that's been tuned against real codebases
(cJSON, Redis) to keep the false-positive rate low.

```
c-doctor — C codebase health
scanned 212 files (194546 LOC), found 777 issues

  65/100  Needs work

src/redis-cli.c
    2312:5  high      'exit(1); return REDIS_ERR;' is unreachable  [dead-code-after-terminator]
   ...

by category
  architecture   568
  correctness    194
  safety          11
  ...
```

## What it catches

| Category      | Examples |
|---------------|----------|
| **safety**       | `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `scanf %s` without width, `printf(var)` format-string vuln |
| **memory**       | `malloc`/`calloc`/`realloc` with no NULL check, `p = realloc(p, …)` self-assignment, use-after-free |
| **correctness**  | `if (strcmp(a, b))` inverted logic, `if (x = y)` assignment-in-condition |
| **security**     | `system()` shell injection risk |
| **performance**  | `strlen()` in `for` condition (O(n²) walk) |
| **architecture** | functions over 60 lines, nesting depth ≥ 5, missing header guards |
| **deadcode**     | code after `return` / `break` / `continue` / `exit()` |
| **portability**  | `<windows.h>` etc. used without `#ifdef _WIN32` |

Each rule has a positive *and* negative test fixture in `src/rules.rs` —
50 unit tests in total. Rules are tuned to skip well-known idioms:
`if (!p) return;` (NULL check), `do { … } while(0)` macros (continuation), the
`if ((x = …))` "I really meant this assignment" idiom, declarations like
`char *p;` (not a deref).

## Install

```sh
git clone https://github.com/nktkt/c-doctor
cd c-doctor
cargo build --release
./target/release/c-doctor --help
```

Or install directly with cargo:

```sh
cargo install --git https://github.com/nktkt/c-doctor
```

Once it's published to crates.io:

```sh
cargo install c-doctor
```

## Usage

```sh
c-doctor path/to/src           # human-readable report
c-doctor . --json              # machine-readable JSON
c-doctor . --fail-under 75     # CI gate: exit 2 if score < 75
c-doctor . --no-config         # ignore any .c-doctor.toml
c-doctor . --config ./foo.toml # use a specific config file
```

The binary returns:

| exit | meaning |
|------|---------|
| `0`  | success; score ≥ `--fail-under` threshold (or no threshold set) |
| `2`  | score below `--fail-under` threshold |
| `1`  | runtime error |

## Configuration

Drop a `.c-doctor.toml` at your project root (or any ancestor — c-doctor walks
upward to find it):

```toml
[rules]
# Silence a rule entirely:
unsafe-strcpy = "off"

# Or rewrite its severity (still reported, just at a different level):
unsafe-sprintf = "low"
unsafe-gets    = "critical"

[scan]
# Substring or simple-glob patterns. Any scanned path containing a
# substring match, or matching a `*`-glob, is skipped.
ignore = ["third_party/", "*.gen.c", "vendor/"]

[score]
# Default fail-under threshold (CLI --fail-under wins if both are set).
fail_under = 75
```

Valid `[rules]` values: `off` / `critical` / `high` / `medium` / `low`.

## Scoring

```
weighted_sum = sum(severity_weight) for each issue
               (critical = 10, high = 5, medium = 2, low = 1)
kloc         = max(1.0, total_loc / 1000)
density      = weighted_sum / kloc
score        = max(0, round(100 - sqrt(density) * 15))
```

Labels: `Great` (≥ 75) · `Needs work` (≥ 50) · `Critical` (< 50).

The `kloc` floor at 1.0 prevents a single bad finding in a 50-line file from
zeroing out the score — small files behave as if they were 1k LOC. Large
codebases still get gradation because the denominator scales with size.
Benchmarks at the time of writing:

| Codebase | LOC     | Issues | Score |
|----------|---------|--------|-------|
| Redis    | 194,546 | 777    | 65 — *Needs work* |
| cJSON    | 3,514   | 24     | 34 — *Critical* (heavy `strcpy`/`sprintf` usage) |

## Claude Code integration

The `.claude/` directory ships an opt-in integration:

- **Slash command** — `/c-doctor [path]` runs the binary and summarizes the
  top issues without touching code.
- **PostToolUse hook** — silently re-scans any `.c` / `.h` file after Claude
  edits it; prints the report only when issues are found, stays quiet on
  clean files and non-C edits.

Both pieces auto-locate the binary at `target/release/c-doctor` relative
to the project root.

To enable in another project: copy `.claude/commands/c-doctor.md`,
`.claude/hooks/c-doctor-post-edit.sh`, and `.claude/settings.json` over, then
build the binary once.

## Limitations

c-doctor is a *linter*, not a static analyzer. It works on lexically
preprocessed source (comments and string contents are blanked out, layout
preserved). It does **not** track types, full control flow, or interprocedural
state. Consequences:

- The use-after-free check stops at the end of the enclosing block and treats
  any intervening `return`/`goto` as a "control diverges" signal. It catches
  the common case, not every case.
- `function-too-long` and `deep-nesting` use brace structure, not cyclomatic
  complexity. K&R and Allman brace styles are recognized; one-line function
  bodies (`int f() { return 0; }`) are intentionally skipped.
- Format-string vuln detection is conservative — only flags `printf(<bare
  variable>)`. Won't catch `fprintf(stderr, var)` or wrappers.

For deeper analysis pair c-doctor with `clang-tidy`, `cppcheck`, or
`scan-build`. The goal here is fast, opinionated triage that runs in tens of
milliseconds even on 200k-LOC codebases.

## Project layout

```
.
├── Cargo.toml
├── src/
│   ├── main.rs       # CLI, arg parsing, exit codes
│   ├── preprocess.rs # comment/string blanking, layout-preserving
│   ├── scanner.rs    # .c/.h discovery, skip dirs
│   ├── rules.rs      # 14 detectors + 38 unit tests
│   ├── scorer.rs     # density-based scoring
│   ├── reporter.rs   # ANSI + JSON output
│   └── config.rs     # .c-doctor.toml loader
├── examples/         # bad.c (dirty), good.c (clean), sample config
└── .claude/          # Claude Code slash command + post-edit hook
```

## Contributing

```sh
cargo test --release   # 50 tests
cargo build --release  # ~1.8 MB binary
```

When adding a new rule, add both a positive and a negative test fixture next
to the rule in `src/rules.rs`. The detector should run in milliseconds
even on large codebases — prefer cheap regex passes over per-line work where
both are options.

## License

MIT.
