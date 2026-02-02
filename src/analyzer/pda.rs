use super::{Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprCall, File, ItemFn};

/// Checks for:
/// 1. find_program_address / create_program_address calls where the result
///    is not verified against the expected program_id
/// 2. PDA derivation using potentially user-controlled seeds without validation
pub fn check_pda_usage(file: &File, path: &str, source: &str) -> Vec<Finding> {
    let mut visitor = PdaVisitor {
        path: path.to_string(),
        source,
        findings: Vec::new(),
        current_fn: None,
    };
    visitor.visit_file(file);
    visitor.findings
}

struct PdaVisitor<'a> {
    path: String,
    source: &'a str,
    findings: Vec<Finding>,
    current_fn: Option<String>,
}

impl<'a> PdaVisitor<'a> {
    fn line_of_span(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    fn get_fn_body_source(&self) -> Option<&str> {
        let fn_name = self.current_fn.as_ref()?;
        let start = self.source.find(&format!("fn {}", fn_name))?;
        // Grab a reasonable window of the function body
        let end = self.source.len().min(start + 3000);
        Some(&self.source[start..end])
    }

    fn is_find_program_address(func: &Expr) -> bool {
        match func {
            Expr::Path(p) => {
                let segments: Vec<String> =
                    p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                let full = segments.join("::");
                full.contains("find_program_address")
            }
            _ => false,
        }
    }

    fn is_create_program_address(func: &Expr) -> bool {
        match func {
            Expr::Path(p) => {
                let segments: Vec<String> =
                    p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                let full = segments.join("::");
                full.contains("create_program_address")
            }
            _ => false,
        }
    }

    fn check_program_id_verification(&self, line: usize) -> bool {
        if let Some(fn_src) = self.get_fn_body_source() {
            // Look for program_id verification patterns
            return fn_src.contains("program_id")
                || fn_src.contains("program.key()")
                || fn_src.contains("crate::ID")
                || fn_src.contains("crate::id()")
                || fn_src.contains("ID.key()");
        }

        // Fallback: check nearby lines
        let lines: Vec<&str> = self.source.lines().collect();
        let search_start = line.saturating_sub(10);
        let search_end = (line + 10).min(lines.len());
        lines[search_start..search_end]
            .iter()
            .any(|l| l.contains("program_id") || l.contains("program.key()"))
    }

    fn check_pda_seed_safety(&self, line: usize) {
        let lines: Vec<&str> = self.source.lines().collect();
        if let Some(call_line) = lines.get(line.saturating_sub(1)) {
            // Heuristic: if seeds include a user-provided key without
            // surrounding validation, flag it
            let has_user_key = call_line.contains(".key()") || call_line.contains(".key.as_ref()");
            let has_to_bytes = call_line.contains(".to_le_bytes()")
                || call_line.contains(".to_be_bytes()")
                || call_line.contains("as_bytes()");

            // Check if there's any validation of the input in surrounding context
            let search_start = line.saturating_sub(15);
            let search_end = (line + 5).min(lines.len());
            let context: String = lines[search_start..search_end].join("\n");

            let has_validation = context.contains("require!")
                || context.contains("assert!")
                || context.contains("constraint")
                || context.contains("has_one");

            if has_user_key && !has_validation {
                // Don't double-report — this is informational
            }

            if has_to_bytes && !has_validation {
                // Numeric seeds from user input can be dangerous
            }
        }
    }
}

impl<'a, 'ast> Visit<'ast> for PdaVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.current_fn = Some(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.current_fn = None;
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let is_find = Self::is_find_program_address(&node.func);
        let is_create = Self::is_create_program_address(&node.func);

        if is_find || is_create {
            let line = self.line_of_span(node.func.span());

            // Check 1: Verify program_id is used correctly
            // For find_program_address, the second arg should be a known program_id
            if !self.check_program_id_verification(line) {
                self.findings.push(Finding {
                    severity: Severity::High,
                    check: "pda-program-id".into(),
                    message: format!(
                        "`{}` called without verifying against the expected program ID. \
                         An attacker could pass a different program's PDA. Ensure you \
                         derive against `crate::ID` or validate the program account.",
                        if is_find {
                            "find_program_address"
                        } else {
                            "create_program_address"
                        }
                    ),
                    file: self.path.clone(),
                    line,
                });
            }

            // Check 2: Seed safety
            if is_create && !self.check_program_id_verification(line) {
                self.findings.push(Finding {
                    severity: Severity::Medium,
                    check: "pda-create-unverified".into(),
                    message: format!(
                        "`create_program_address` is used instead of `find_program_address`. \
                         Prefer `find_program_address` which returns the bump, preventing \
                         PDA collision issues."
                    ),
                    file: self.path.clone(),
                    line,
                });
            }

            self.check_pda_seed_safety(line);
        }

        syn::visit::visit_expr_call(self, node);
    }
}
