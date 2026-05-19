use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill, Span};

const META: RuleMeta = RuleMeta {
    id: "SKILL-INJ-001",
    name: "Zero-width character in prompt content",
    severity: Severity::Critical,
    category: Category::Injection,
    default_remediation:
        "Strip zero-width unicode characters from prompt content. They are invisible to humans \
         but parsed by the model, and are a common prompt-injection smuggling technique.",
};

#[derive(Debug)]
pub struct ZeroWidthRule;

impl Rule for ZeroWidthRule {
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
                if let Some((col, ch)) = first_zero_width(line) {
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
                            "Zero-width character U+{:04X} found at line {}, col {}",
                            ch as u32,
                            line_no,
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

fn first_zero_width(line: &str) -> Option<(usize, char)> {
    for (idx, ch) in line.char_indices() {
        if is_zero_width(ch) {
            return Some((idx, ch));
        }
    }
    None
}

fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // zero-width space
            | '\u{200C}' // zero-width non-joiner
            | '\u{200D}' // zero-width joiner
            | '\u{2060}' // word joiner
            | '\u{FEFF}' // zero-width no-break space / BOM
    )
}

#[cfg(test)]
mod tests {
    use super::{first_zero_width, is_zero_width};

    #[test]
    fn detects_zero_width_space() {
        assert!(is_zero_width('\u{200B}'));
        assert!(!is_zero_width(' '));
        assert!(!is_zero_width('a'));
    }

    #[test]
    fn finds_first_offset() {
        let s = "hello\u{200B}world";
        let (idx, ch) = first_zero_width(s).unwrap();
        assert_eq!(idx, 5);
        assert_eq!(ch, '\u{200B}');
    }
}
