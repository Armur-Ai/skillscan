//! Built-in rule implementations.

use crate::engine::Rule;

mod cmp_001;
mod inj_001;
mod prm_001;
mod sec_001;
mod sup_001;

/// The default rule set shipped with SkillScan. Phase 1 ships 5 rules; Phase 2 widens to 40+.
#[must_use]
pub fn builtin_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(cmp_001::DescriptionRule),
        Box::new(prm_001::BashWildcardRule),
        Box::new(inj_001::ZeroWidthRule),
        Box::new(sup_001::CurlPipeShellRule),
        Box::new(sec_001::SecretsRule),
    ]
}
