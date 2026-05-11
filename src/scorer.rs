use std::collections::BTreeMap;

use crate::rules::Issue;

// Density-based scoring: total severity weight per kloc, mapped through a
// sqrt curve so a single bad file doesn't zero out a small project.
//
//   weighted_sum = sum(severity_weight for each issue)
//   kloc         = max(1.0, loc / 1000)     # floor: <1k LOC behaves as 1 kloc
//   density      = weighted_sum / kloc
//   score        = max(0, round(100 - sqrt(density) * 15))
//
// Rationale for the floor: without it a tiny file with one high-severity
// issue zeros out (density = 5 / 0.05 = 100). With a 1-kloc floor that
// becomes density = 5, score = 100 - sqrt(5)*15 ≈ 66 — "needs work" not
// "obliterated". Larger codebases still get meaningful gradation because
// their LOC pushes the denominator past 1.
const SCORE_FACTOR: f64 = 15.0;
const KLOC_FLOOR: f64 = 1.0;

pub struct Score {
    pub score: u32,
    pub label: &'static str,
    pub files: usize,
    pub loc: usize,
    pub issue_count: usize,
    pub by_category: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<&'static str, usize>,
}

pub fn score(issues: &[Issue], file_count: usize, total_loc: usize) -> Score {
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_severity: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut weighted_sum: u32 = 0;

    for i in issues {
        weighted_sum += i.severity.weight();
        *by_category.entry(i.category.to_string()).or_insert(0) += 1;
        *by_severity.entry(i.severity.as_str()).or_insert(0) += 1;
    }

    let kloc = (total_loc as f64 / 1000.0).max(KLOC_FLOOR);
    let density = weighted_sum as f64 / kloc;
    let raw = 100.0 - density.sqrt() * SCORE_FACTOR;
    let final_score = raw.clamp(0.0, 100.0).round() as u32;

    let label = if final_score >= 75 {
        "Great"
    } else if final_score >= 50 {
        "Needs work"
    } else {
        "Critical"
    };

    Score {
        score: final_score,
        label,
        files: file_count,
        loc: total_loc,
        issue_count: issues.len(),
        by_category,
        by_severity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    fn issue(sev: Severity) -> Issue {
        Issue {
            file: "t.c".into(),
            line: 1,
            col: 1,
            rule: "t",
            category: "safety",
            severity: sev,
            message: String::new(),
            suggestion: None,
        }
    }

    #[test]
    fn clean_codebase_scores_100() {
        let s = score(&[], 1, 500);
        assert_eq!(s.score, 100);
        assert_eq!(s.label, "Great");
    }

    #[test]
    fn one_high_in_tiny_file_is_not_obliterating() {
        // 50 LOC + 1 high (weight 5). With kloc floor at 1.0, density=5,
        // score ≈ 100 - sqrt(5)*15 ≈ 66.
        let s = score(&[issue(Severity::High)], 1, 50);
        assert!(s.score >= 50 && s.score <= 75, "got {}", s.score);
    }

    #[test]
    fn many_issues_in_small_file_become_critical() {
        let issues: Vec<Issue> = (0..20).map(|_| issue(Severity::High)).collect();
        let s = score(&issues, 1, 70);
        assert!(s.score < 50, "got {}", s.score);
        assert_eq!(s.label, "Critical");
    }

    #[test]
    fn density_is_what_matters_for_large_codebases() {
        // Two scenarios with the same density should produce same score.
        let small_issues: Vec<Issue> = (0..5).map(|_| issue(Severity::High)).collect();
        let large_issues: Vec<Issue> = (0..50).map(|_| issue(Severity::High)).collect();
        let s1 = score(&small_issues, 1, 5000); // 5 issues / 5 kloc
        let s2 = score(&large_issues, 10, 50000); // 50 issues / 50 kloc
        assert_eq!(s1.score, s2.score);
    }

    #[test]
    fn label_thresholds() {
        let s_great = score(&[], 1, 0);
        assert_eq!(s_great.label, "Great");
        // weight = 15, kloc = 1, density = 15, score = 100 - sqrt(15)*15 ≈ 42
        let three: Vec<Issue> = (0..3).map(|_| issue(Severity::High)).collect();
        let s_low = score(&three, 1, 0);
        assert!(s_low.label == "Critical" || s_low.label == "Needs work");
    }
}
