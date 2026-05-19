use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Typed view of the YAML frontmatter of a `SKILL.md` file.
///
/// Unknown keys land in `extra` so we stay forward-compatible with future Claude Skill spec
/// versions instead of failing to parse.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Frontmatter {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, rename = "allowed-tools")]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub license: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yml::Value>,
}
