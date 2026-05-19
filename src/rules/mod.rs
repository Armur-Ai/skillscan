//! Built-in rule implementations.

use crate::engine::Rule;

mod cmp_001;
mod cmp_002;
mod cmp_003;
mod inj_001;
mod prm_001;
mod prm_006;
mod prm_007;
mod sec_001;
mod sup_001;
pub mod yaml;

/// The default rule set shipped with SkillScan. Combines hand-written Rust rules with regex
/// rules loaded from the built-in YAML pack (`src/rules/packs/builtin/`).
#[must_use]
pub fn builtin_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = vec![
        Box::new(cmp_001::DescriptionRule),
        Box::new(cmp_002::VersionRule),
        Box::new(cmp_003::LicenseRule),
        Box::new(prm_001::BashWildcardRule),
        Box::new(prm_006::AllowedToolsMissingRule),
        Box::new(prm_007::ExcessiveToolsRule),
        Box::new(inj_001::ZeroWidthRule),
        Box::new(sup_001::CurlPipeShellRule),
        Box::new(sec_001::SecretsRule),
    ];
    rules.extend(yaml::load_builtin_yaml_rules());
    rules
}
