use crate::engine::ast::python;
use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CQ-001",
    name: "subprocess call with shell=True",
    severity: Severity::High,
    category: Category::CodeQuality,
    default_remediation:
        "Pass the command as a list (`subprocess.run([\"git\", \"status\"])`) without `shell=True`. \
         With `shell=True`, any unsanitized input becomes a shell-injection vector.",
};

const SUBPROCESS_FNS: &[&str] = &[
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
];

#[derive(Debug)]
pub struct SubprocessShellTrueRule;

impl Rule for SubprocessShellTrueRule {
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
                if !SUBPROCESS_FNS.contains(&callee) {
                    return;
                }
                let Some(shell_value) = python::call_keyword_arg(node, "shell", bytes) else {
                    return;
                };
                let v = python::node_text(shell_value, bytes);
                if v != "True" {
                    return;
                }
                let span = python::span_of(node);
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 95,
                    file: file.rel_path.clone(),
                    span: Some(span),
                    message: format!("`{callee}(..., shell=True)` enables shell-injection."),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            });
        }

        findings
    }
}
