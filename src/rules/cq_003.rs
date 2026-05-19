use tree_sitter::Node;

use crate::engine::ast::python;
use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CQ-003",
    name: "eval/exec call (AST-precise)",
    severity: Severity::High,
    category: Category::CodeQuality,
    default_remediation:
        "`eval` and `exec` execute arbitrary code. With a non-literal argument they are a direct \
         RCE channel. Refactor to direct calls or remove. Complements the regex-based OBF-001 by \
         eliminating false positives from docs/comments and adding confidence based on argument \
         shape.",
};

const DANGEROUS_FNS: &[&str] = &["eval", "exec"];

#[derive(Debug)]
pub struct EvalExecAstRule;

impl Rule for EvalExecAstRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &skill.files {
            if file.kind != FileKind::Python {
                continue;
            }
            let Some(content) = &file.content else {
                continue;
            };
            let Some(tree) = python::parse(content) else {
                continue;
            };
            let bytes = content.as_bytes();

            python::walk(tree.root_node(), &mut |node| {
                let Some(callee) = python::call_callee_text(node, bytes) else {
                    return;
                };
                if !DANGEROUS_FNS.contains(&callee) {
                    return;
                }
                let confidence = first_arg_confidence(node);
                let span = python::span_of(node);
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence,
                    file: file.rel_path.clone(),
                    span: Some(span),
                    message: format!(
                        "`{callee}(...)` call — runs arbitrary code (confidence {confidence})."
                    ),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            });
        }

        findings
    }
}

/// Higher confidence when the first arg is anything other than a string literal (i.e. dynamic).
fn first_arg_confidence(call: Node<'_>) -> u8 {
    let Some(args) = call.child_by_field_name("arguments") else {
        return 80;
    };
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if matches!(child.kind(), "(" | ")" | ",") {
            continue;
        }
        return if child.kind() == "string" { 50 } else { 95 };
    }
    80
}
