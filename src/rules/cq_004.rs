use crate::engine::ast::python;
use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CQ-004",
    name: "Unsafe Python deserialization (AST-precise)",
    severity: Severity::High,
    category: Category::CodeQuality,
    default_remediation:
        "`pickle.loads`, `marshal.loads`, `dill.loads`, `joblib.load` execute arbitrary code \
         embedded in their input. Switch to a safe serialization format (json, msgpack). \
         Complements the regex-based OBF-003 with AST precision (no false positives from \
         comments/docs).",
};

const UNSAFE_LOADERS: &[&str] = &[
    "pickle.load",
    "pickle.loads",
    "marshal.load",
    "marshal.loads",
    "dill.load",
    "dill.loads",
    "joblib.load",
    "joblib.loads",
];

#[derive(Debug)]
pub struct UnsafeDeserializationRule;

impl Rule for UnsafeDeserializationRule {
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
                if !UNSAFE_LOADERS.contains(&callee) {
                    return;
                }
                let span = python::span_of(node);
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 95,
                    file: file.rel_path.clone(),
                    span: Some(span),
                    message: format!("Unsafe deserialization call: `{callee}(...)`"),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            });
        }
        findings
    }
}
