pub mod accounts;
pub mod cpi;
pub mod pda;

use serde::Serialize;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub check: String,
    pub message: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
}

impl AnalysisReport {
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::High)
    }

    pub fn has_medium_or_above(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::High || f.severity == Severity::Medium)
    }
}

/// Discover all .rs files under the given root directory.
pub fn discover_rust_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "rs")
                && !e.path().to_string_lossy().contains("/target/")
        })
        .map(|e| e.into_path())
        .collect()
}

/// Run all checks against a set of Rust source files.
pub fn analyze(files: &[PathBuf]) -> AnalysisReport {
    let mut findings = Vec::new();

    for file in files {
        let source = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let syntax = match syn::parse_file(&source) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let file_str = file.to_string_lossy().to_string();

        findings.extend(accounts::check_account_validation(&syntax, &file_str, &source));
        findings.extend(cpi::check_cpi_safety(&syntax, &file_str, &source));
        findings.extend(pda::check_pda_usage(&syntax, &file_str, &source));
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    AnalysisReport {
        files_scanned: files.len(),
        findings,
    }
}
