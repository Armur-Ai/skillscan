use std::path::PathBuf;

use super::Frontmatter;

/// What kind of file we think this is — used to route rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    SkillMd,
    Markdown,
    Python,
    Bash,
    Yaml,
    Json,
    Binary,
    Other,
}

impl FileKind {
    /// Classify a file by its lowercase extension. `SKILL.md` should be detected by the loader
    /// before this fallback is consulted.
    #[must_use]
    pub fn from_extension(ext: Option<&str>) -> Self {
        match ext.map(str::to_ascii_lowercase).as_deref() {
            Some("md" | "markdown") => Self::Markdown,
            Some("py") => Self::Python,
            Some("sh" | "bash" | "zsh") => Self::Bash,
            Some("yaml" | "yml") => Self::Yaml,
            Some("json") => Self::Json,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Self::SkillMd
                | Self::Markdown
                | Self::Python
                | Self::Bash
                | Self::Yaml
                | Self::Json
                | Self::Other
        )
    }
}

#[derive(Debug, Clone)]
pub struct SkillFile {
    /// Absolute path on disk.
    pub abs_path: PathBuf,
    /// Path relative to the skill root, used in findings and reports.
    pub rel_path: PathBuf,
    pub kind: FileKind,
    pub size_bytes: u64,
    /// UTF-8 contents for text files. `None` for binaries or files that failed to decode.
    pub content: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub root: PathBuf,
    pub files: Vec<SkillFile>,
    pub frontmatter: Frontmatter,
}
