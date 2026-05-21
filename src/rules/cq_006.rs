use crate::engine::ast::bash;
use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CQ-006",
    name: "bash `source`/`.` with a variable target",
    severity: Severity::High,
    category: Category::CodeQuality,
    default_remediation:
        "Sourcing a file whose path is held in a variable is equivalent to `eval`-ing whatever \
         the attacker can write to that path. Source a fixed, audited path instead.",
};

#[derive(Debug)]
pub struct BashDynamicSourceRule;

impl Rule for BashDynamicSourceRule {
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
                if name != "source" && name != "." {
                    return;
                }
                let has_variable_arg = bash::command_args(node).iter().any(|arg| {
                    let mut found = false;
                    bash::walk(*arg, &mut |n| {
                        if matches!(
                            n.kind(),
                            "simple_expansion" | "expansion" | "command_substitution"
                        ) {
                            found = true;
                        }
                    });
                    found
                });
                if !has_variable_arg {
                    return;
                }
                let span = bash::span_of(node);
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 90,
                    file: file.rel_path.clone(),
                    span: Some(span),
                    message: format!("`{name}` of a variable expansion."),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            });
        }
        findings
    }
}
