use crate::engine::ast::bash;
use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CQ-005",
    name: "bash `eval` (AST-precise)",
    severity: Severity::High,
    category: Category::CodeQuality,
    default_remediation:
        "`eval` in bash runs its argument through the parser a second time, executing whatever \
         the argument expands to. If any input is user-controlled this is RCE. Replace with \
         direct invocation.",
};

#[derive(Debug)]
pub struct BashEvalRule;

impl Rule for BashEvalRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &skill.files {
            if file.kind != FileKind::Bash {
                continue;
            }
            let Some(content) = &file.content else {
                continue;
            };
            let Some(tree) = bash::parse(content) else {
                continue;
            };
            let bytes = content.as_bytes();

            bash::walk(tree.root_node(), &mut |node| {
                let Some(name) = bash::command_name(node, bytes) else {
                    return;
                };
                if name != "eval" {
                    return;
                }
                let span = bash::span_of(node);
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 95,
                    file: file.rel_path.clone(),
                    span: Some(span),
                    message: "`eval` in bash — re-evaluates its argument as shell.".into(),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            });
        }
        findings
    }
}
