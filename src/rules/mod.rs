//! Built-in rule implementations.

use crate::engine::Rule;

mod cmp_001;
mod cmp_002;
mod cmp_003;
mod cq_001;
mod cq_002;
mod cq_003;
mod cq_004;
mod inj_001;
mod inj_009;
mod prm_001;
mod prm_002;
mod prm_003;
mod prm_004;
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
        Box::new(prm_002::SensitiveWritePathRule),
        Box::new(prm_003::SensitiveReadPathRule),
        Box::new(prm_004::UnscopedWebFetchRule),
        Box::new(prm_006::AllowedToolsMissingRule),
        Box::new(prm_007::ExcessiveToolsRule),
        Box::new(inj_001::ZeroWidthRule),
        Box::new(inj_009::UnicodeTagRule),
        Box::new(sup_001::CurlPipeShellRule),
        Box::new(sec_001::SecretsRule),
        Box::new(cq_001::SubprocessShellTrueRule),
        Box::new(cq_002::OsSystemRule),
        Box::new(cq_003::EvalExecAstRule),
        Box::new(cq_004::UnsafeDeserializationRule),
    ];
    rules.extend(yaml::load_builtin_yaml_rules());
    rules
}
