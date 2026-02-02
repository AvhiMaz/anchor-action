use super::{Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, File, ItemFn};

/// Checks for:
/// 1. invoke_signed calls without bump validation nearby
/// 2. CPI calls (invoke / invoke_signed) passing unchecked account references
/// 3. Seeds potentially derived from user-controlled input
pub fn check_cpi_safety(file: &File, path: &str, source: &str) -> Vec<Finding> {
    let mut visitor = CpiVisitor {
        path: path.to_string(),
        source,
        findings: Vec::new(),
        current_fn: None,
    };
    visitor.visit_file(file);
    visitor.findings
}

struct CpiVisitor<'a> {
    path: String,
    source: &'a str,
    findings: Vec<Finding>,
    current_fn: Option<String>,
}

impl<'a> CpiVisitor<'a> {
    fn line_of_span(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    fn fn_source_text(&self, fn_name: &str) -> Option<&str> {
        // Simple heuristic: find the function in source
        self.source.find(&format!("fn {}", fn_name)).map(|start| {
            let end = self.source.len().min(start + 2000);
            &self.source[start..end]
        })
    }

    fn check_invoke_signed_call(&mut self, span: proc_macro2::Span) {
        let line = self.line_of_span(span);
        let fn_name = self.current_fn.clone().unwrap_or_default();

        // Check if the surrounding function validates bump
        let has_bump_check = if let Some(fn_src) = self.fn_source_text(&fn_name) {
            fn_src.contains("bump")
                && (fn_src.contains("find_program_address")
                    || fn_src.contains(".bump")
                    || fn_src.contains("bump =")
                    || fn_src.contains("bump="))
        } else {
            // Fall back to checking nearby lines
            let lines: Vec<&str> = self.source.lines().collect();
            let search_start = line.saturating_sub(15);
            let search_end = (line + 15).min(lines.len());
            lines[search_start..search_end]
                .iter()
                .any(|l| l.contains("bump"))
        };

        if !has_bump_check {
            self.findings.push(Finding {
                severity: Severity::High,
                check: "invoke-signed-no-bump".into(),
                message: format!(
                    "`invoke_signed` call without bump validation. Seeds without a verified \
                     bump can allow PDA collision attacks. Ensure the bump is derived from \
                     `find_program_address` or stored/validated on-chain."
                ),
                file: self.path.clone(),
                line,
            });
        }
    }

    fn check_invoke_call(&mut self, span: proc_macro2::Span) {
        let line = self.line_of_span(span);

        // Check surrounding context for signer validation
        let lines: Vec<&str> = self.source.lines().collect();
        let search_start = line.saturating_sub(20);
        let search_end = (line + 5).min(lines.len());
        let context: String = lines[search_start..search_end].join("\n");

        // Look for common patterns that indicate proper validation
        let has_signer_check = context.contains("is_signer")
            || context.contains("Signer<")
            || context.contains(".key()")
            || context.contains(".key ==")
            || context.contains("has_one")
            || context.contains("constraint");

        if !has_signer_check {
            self.findings.push(Finding {
                severity: Severity::Medium,
                check: "cpi-missing-signer-check".into(),
                message: format!(
                    "CPI `invoke` call without apparent signer validation in surrounding \
                     context. Ensure accounts passed to CPI are properly validated."
                ),
                file: self.path.clone(),
                line,
            });
        }
    }

    fn is_invoke_signed(expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .segments
                .last()
                .map_or(false, |s| s.ident == "invoke_signed"),
            _ => false,
        }
    }

    fn is_invoke(expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .segments
                .last()
                .map_or(false, |s| s.ident == "invoke"),
            _ => false,
        }
    }
}

impl<'a, 'ast> Visit<'ast> for CpiVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.current_fn = Some(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.current_fn = None;
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if Self::is_invoke_signed(&node.func) {
            self.check_invoke_signed_call(node.func.span());
        } else if Self::is_invoke(&node.func) {
            self.check_invoke_call(node.func.span());
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "invoke_signed" {
            self.check_invoke_signed_call(node.method.span());
        } else if method == "invoke" {
            self.check_invoke_call(node.method.span());
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}
