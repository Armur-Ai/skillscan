use crate::engine::ast::python;
use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CQ-002",
    name: "os.system call",
    severity: Severity::High,
    category: Category::CodeQuality,
    default_remediation:
        "`os.system` runs its argument through a shell with no escaping. Switch to \
         `subprocess.run([...])` with the command as a list.",
};

#[derive(Debug)]
pub struct OsSystemRule;

impl Rule for OsSystemRule {
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
                if callee != "os.system" && callee != "popen" && callee != "os.popen" {
                    return;
                }
                let span = python::span_of(node);
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 95,
                    file: file.rel_path.clone(),
                    span: Some(span),
                    message: format!("`{callee}(...)` runs its argument through a shell."),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            });
        }

        findings
    }
}
