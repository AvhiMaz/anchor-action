use super::{Finding, Severity};
use syn::visit::Visit;
use syn::{Attribute, File, ItemStruct};

/// Checks for:
/// 1. #[derive(Accounts)] structs with fields missing constraints
/// 2. Raw AccountInfo<'info> usage where Account<'info, T> is safer
pub fn check_account_validation(file: &File, path: &str, source: &str) -> Vec<Finding> {
    let mut visitor = AccountVisitor {
        path: path.to_string(),
        source,
        findings: Vec::new(),
    };
    visitor.visit_file(file);
    visitor.findings
}

struct AccountVisitor<'a> {
    path: String,
    source: &'a str,
    findings: Vec<Finding>,
}

impl<'a> AccountVisitor<'a> {
    fn line_of_span(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    fn has_derive_accounts(attrs: &[Attribute]) -> bool {
        attrs.iter().any(|attr| {
            if !attr.path().is_ident("derive") {
                return false;
            }
            let mut found = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("Accounts") {
                    found = true;
                }
                Ok(())
            });
            found
        })
    }

    fn field_has_constraint(attrs: &[Attribute]) -> bool {
        attrs.iter().any(|attr| {
            let path = attr.path();
            path.is_ident("account") || path.is_ident("has_one") || path.is_ident("constraint")
        })
    }

    fn is_raw_account_info(ty: &syn::Type) -> bool {
        if let syn::Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                if seg.ident == "AccountInfo" || seg.ident == "UncheckedAccount" {
                    return true;
                }
            }
        }
        false
    }

    fn is_signer_type(ty: &syn::Type) -> bool {
        if let syn::Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                return seg.ident == "Signer";
            }
        }
        false
    }

    fn is_program_type(ty: &syn::Type) -> bool {
        if let syn::Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                return seg.ident == "Program" || seg.ident == "SystemProgram";
            }
        }
        false
    }

    fn has_check_comment(&self, line: usize) -> bool {
        if line == 0 {
            return false;
        }
        let lines: Vec<&str> = self.source.lines().collect();
        // Check the 3 lines above for a CHECK comment
        let start = line.saturating_sub(4);
        for i in start..line {
            if let Some(l) = lines.get(i) {
                let trimmed = l.trim();
                if trimmed.contains("/// CHECK:")
                    || trimmed.contains("// CHECK:")
                    || trimmed.contains("/// SAFETY:")
                {
                    return true;
                }
            }
        }
        false
    }
}

impl<'a, 'ast> Visit<'ast> for AccountVisitor<'a> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if !Self::has_derive_accounts(&node.attrs) {
            return;
        }

        if let syn::Fields::Named(ref fields) = node.fields {
            for field in &fields.named {
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let line = self.line_of_span(field.ident.as_ref().unwrap().span());

                // Check 1: Raw AccountInfo without CHECK comment
                if Self::is_raw_account_info(&field.ty) {
                    if !self.has_check_comment(line) {
                        self.findings.push(Finding {
                            severity: Severity::High,
                            check: "unchecked-account".into(),
                            message: format!(
                                "Raw `AccountInfo` field `{}` in `{}` without `/// CHECK:` comment. \
                                 Use `Account<'info, T>` for type-safe deserialization, or add a \
                                 `/// CHECK:` comment explaining why this is safe.",
                                field_name, node.ident
                            ),
                            file: self.path.clone(),
                            line,
                        });
                    }
                }

                // Check 2: Missing constraints on non-trivial account fields
                // Skip signers and program types — they don't need constraints
                if Self::is_signer_type(&field.ty) || Self::is_program_type(&field.ty) {
                    continue;
                }

                if Self::is_raw_account_info(&field.ty) {
                    continue; // Already flagged above
                }

                if !Self::field_has_constraint(&field.attrs) {
                    // Check if the #[account] attribute exists but is empty vs missing entirely
                    let has_any_account_attr =
                        field.attrs.iter().any(|a| a.path().is_ident("account"));

                    if has_any_account_attr {
                        // Has #[account] but no constraints inside it
                        self.findings.push(Finding {
                            severity: Severity::Medium,
                            check: "missing-constraint".into(),
                            message: format!(
                                "Field `{}` in `{}` has `#[account]` without constraints. \
                                 Consider adding `has_one`, `constraint`, `seeds`, or `address` \
                                 to validate this account.",
                                field_name, node.ident
                            ),
                            file: self.path.clone(),
                            line,
                        });
                    }
                }
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}
