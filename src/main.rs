mod analyzer;
mod github;

use std::path::PathBuf;
use std::process;

#[tokio::main]
async fn main() {
    let scan_path = std::env::var("INPUT_PATH")
        .or_else(|_| std::env::var("GITHUB_WORKSPACE"))
        .unwrap_or_else(|_| ".".into());

    let fail_on = std::env::var("INPUT_FAIL_ON").unwrap_or_else(|_| "high".into());

    eprintln!("anchor-audit: scanning {}", scan_path);

    // Discover and analyze files
    let root = PathBuf::from(&scan_path);
    let files = analyzer::discover_rust_files(&root);

    if files.is_empty() {
        eprintln!("anchor-audit: no Rust files found under {}", scan_path);
        process::exit(0);
    }

    eprintln!("anchor-audit: found {} Rust files", files.len());

    let report = analyzer::analyze(&files);

    // Print JSON report to stdout
    let json_output = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
    println!("{}", json_output);

    // Format markdown report
    let markdown = github::format_report(&report);
    eprintln!("\n{}\n", markdown);

    // GitHub integration (only when running in Actions)
    let in_actions = std::env::var("GITHUB_ACTIONS").is_ok();

    if in_actions {
        let token = std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("INPUT_GITHUB_TOKEN"))
            .ok();
        let repo = std::env::var("GITHUB_REPOSITORY").ok();
        let event_path = std::env::var("GITHUB_EVENT_PATH").ok();

        if let (Some(token), Some(repo)) = (token.as_ref(), repo.as_ref()) {
            // Post PR comment if we have a PR number
            if let Some(event_path) = event_path.as_ref() {
                if let Some(pr_number) = github::get_pr_number_from_event(event_path) {
                    eprintln!("anchor-audit: posting comment on PR #{}", pr_number);
                    if let Err(e) =
                        github::post_pr_comment(token, repo, pr_number, &markdown).await
                    {
                        eprintln!("anchor-audit: failed to post PR comment: {}", e);
                    }
                }

                // Create check run if we have a head SHA
                if let Some(sha) = github::get_head_sha_from_event(event_path) {
                    eprintln!("anchor-audit: creating check run for {}", &sha[..8]);
                    if let Err(e) =
                        github::create_check_run(token, repo, &sha, &report).await
                    {
                        eprintln!("anchor-audit: failed to create check run: {}", e);
                    }
                }
            }
        } else {
            eprintln!("anchor-audit: GITHUB_TOKEN or GITHUB_REPOSITORY not set, skipping PR integration");
        }
    }

    // Set output for GitHub Actions
    if in_actions {
        if let Ok(output_file) = std::env::var("GITHUB_OUTPUT") {
            let _ = std::fs::write(
                &output_file,
                format!(
                    "finding-count={}\nhas-high={}\nhas-medium={}\n",
                    report.findings.len(),
                    report.has_high(),
                    report.has_medium_or_above(),
                ),
            );
        }
    }

    // Exit code based on fail_on setting
    let should_fail = match fail_on.as_str() {
        "high" => report.has_high(),
        "medium" => report.has_medium_or_above(),
        "low" => !report.findings.is_empty(),
        "none" => false,
        _ => report.has_high(),
    };

    if should_fail {
        eprintln!(
            "anchor-audit: failing with {} issue(s) (fail_on={})",
            report.findings.len(),
            fail_on
        );
        process::exit(1);
    }

    eprintln!("anchor-audit: done");
}
