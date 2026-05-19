use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::model::{FileKind, Frontmatter, Skill, SkillFile};

pub const SKILL_FILE_NAME: &str = "SKILL.md";
pub const MAX_FILES: usize = 5000;
pub const MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024;
/// Files larger than this are not read into memory as text. They still count toward the bundle
/// budget but rules that need `content` will simply see `None`.
const MAX_TEXT_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Loads a skill from a directory on disk.
#[derive(Debug)]
pub struct DirectoryLoader {
    root: PathBuf,
}

impl DirectoryLoader {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Walk the skill directory, classify files, parse `SKILL.md` frontmatter, and return a
    /// [`Skill`].
    ///
    /// # Errors
    /// Returns an error if the path is missing, is not a directory, contains no `SKILL.md`, or
    /// the bundle exceeds the file-count or byte-size budget.
    pub fn load(self) -> Result<Skill> {
        let root = self
            .root
            .canonicalize()
            .with_context(|| format!("could not resolve {}", self.root.display()))?;

        if !root.is_dir() {
            bail!("{} is not a directory", root.display());
        }

        let skill_md_path = root.join(SKILL_FILE_NAME);
        if !skill_md_path.exists() {
            bail!("{} does not contain a {}", root.display(), SKILL_FILE_NAME);
        }

        let walker = ignore::WalkBuilder::new(&root)
            .standard_filters(true)
            .git_ignore(true)
            .build();

        let mut files = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut frontmatter = Frontmatter::default();

        for entry in walker {
            let entry = entry.context("walking skill directory")?;

            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }

            let path = entry.path();
            let rel = path
                .strip_prefix(&root)
                .context("file outside skill root")?
                .to_path_buf();

            let metadata = fs::metadata(path)?;
            let size = metadata.len();
            total_bytes = total_bytes.saturating_add(size);

            let is_skill_md = rel == Path::new(SKILL_FILE_NAME);
            let kind = if is_skill_md {
                FileKind::SkillMd
            } else {
                FileKind::from_extension(path.extension().and_then(|s| s.to_str()))
            };

            let content = if kind.is_text() && size <= MAX_TEXT_FILE_BYTES {
                read_text(path).ok()
            } else {
                None
            };

            if is_skill_md {
                if let Some(c) = &content {
                    let (fm, _body) = split_frontmatter(c);
                    frontmatter = fm;
                }
            }

            files.push(SkillFile {
                abs_path: path.to_path_buf(),
                rel_path: rel,
                kind,
                size_bytes: size,
                content,
            });

            if files.len() > MAX_FILES {
                bail!("skill exceeds {} file limit", MAX_FILES);
            }
        }

        if total_bytes > MAX_TOTAL_BYTES {
            bail!(
                "skill exceeds {} MiB size limit (was {} bytes)",
                MAX_TOTAL_BYTES / 1024 / 1024,
                total_bytes
            );
        }

        files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

        Ok(Skill {
            root,
            files,
            frontmatter,
        })
    }
}

fn read_text(path: &Path) -> Result<String> {
    let mut s = String::new();
    fs::File::open(path)?.read_to_string(&mut s)?;
    Ok(s)
}

/// Split a `SKILL.md` source into typed frontmatter and the markdown body. Malformed YAML yields
/// the default frontmatter rather than an error — surfacing that as a finding is the engine's
/// job, not the loader's.
pub fn split_frontmatter(content: &str) -> (Frontmatter, &str) {
    let trimmed = content.strip_prefix('\u{FEFF}').unwrap_or(content);
    let Some(after_marker) = trimmed.strip_prefix("---") else {
        return (Frontmatter::default(), trimmed);
    };
    let after_first = after_marker
        .strip_prefix('\n')
        .or_else(|| after_marker.strip_prefix("\r\n"))
        .unwrap_or(after_marker);

    let mut byte_offset = 0;
    for line in after_first.split_inclusive('\n') {
        if line.trim_end() == "---" {
            let yaml = &after_first[..byte_offset];
            let body = &after_first[byte_offset + line.len()..];
            let fm = serde_yml::from_str::<Frontmatter>(yaml).unwrap_or_default();
            return (fm, body);
        }
        byte_offset += line.len();
    }
    (Frontmatter::default(), trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_frontmatter() {
        let content = "---\nname: foo\ndescription: a sample skill description here\n---\n# Body\n";
        let (fm, body) = split_frontmatter(content);
        assert_eq!(fm.name.as_deref(), Some("foo"));
        assert_eq!(
            fm.description.as_deref(),
            Some("a sample skill description here")
        );
        assert!(body.starts_with("# Body"));
    }

    #[test]
    fn handles_missing_frontmatter() {
        let content = "# Just a body\n";
        let (fm, body) = split_frontmatter(content);
        assert!(fm.name.is_none());
        assert_eq!(body, content);
    }

    #[test]
    fn handles_bom() {
        let content = "\u{FEFF}---\nname: with-bom\n---\nbody\n";
        let (fm, _body) = split_frontmatter(content);
        assert_eq!(fm.name.as_deref(), Some("with-bom"));
    }

    #[test]
    fn malformed_yaml_yields_default() {
        let content = "---\nname: [unclosed\n---\nbody\n";
        let (fm, _body) = split_frontmatter(content);
        assert!(fm.name.is_none());
    }
}
