use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill, Span};

const META: RuleMeta = RuleMeta {
    id: "SKILL-INJ-009",
    name: "Invisible unicode tag character in prompt content",
    severity: Severity::Critical,
    category: Category::Injection,
    default_remediation:
        "Unicode Tag characters (U+E0020 – U+E007F) are an invisible alphabet that LLMs can read \
         but humans cannot. They are an active prompt-injection smuggling vector. Strip them from \
         all prompt content.",
};

pub const TAG_BLOCK_START: u32 = 0xE0020;
pub const TAG_BLOCK_END: u32 = 0xE007F;

#[derive(Debug)]
pub struct UnicodeTagRule;

impl Rule for UnicodeTagRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in &skill.files {
            if !matches!(file.kind, FileKind::SkillMd | FileKind::Markdown) {
                continue;
            }
            let Some(content) = &file.content else {
                continue;
            };

            let mut line_no = 0usize;
            for line in content.lines() {
                line_no += 1;
                if let Some((col, ch)) = first_tag_char(line) {
                    findings.push(Finding {
                        rule_id: META.id.into(),
                        severity: META.severity,
                        confidence: 100,
                        file: file.rel_path.clone(),
                        span: Some(Span {
                            line: line_no,
                            col: col + 1,
                            end_line: line_no,
                            end_col: col + 1 + ch.len_utf8(),
                            byte_start: 0,
                            byte_end: 0,
                        }),
                        message: format!(
                            "Invisible Tag char U+{:04X} at line {line_no}, col {} — smuggled prompt content.",
                            ch as u32,
                            col + 1
                        ),
                        remediation: META.default_remediation.into(),
                        references: vec![],
                    });
                }
            }
        }
        findings
    }
}

fn first_tag_char(line: &str) -> Option<(usize, char)> {
    for (idx, ch) in line.char_indices() {
        let cp = ch as u32;
        if (TAG_BLOCK_START..=TAG_BLOCK_END).contains(&cp) {
            return Some((idx, ch));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::first_tag_char;

    #[test]
    fn detects_tag_a() {
        // U+E0041 = TAG LATIN CAPITAL LETTER A
        let s = "hello\u{E0041} world";
        let (idx, ch) = first_tag_char(s).unwrap();
        assert_eq!(idx, 5);
        assert_eq!(ch as u32, 0xE0041);
    }

    #[test]
    fn ignores_plain_ascii() {
        assert!(first_tag_char("hello world").is_none());
    }
}
