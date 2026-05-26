# Writing rules

SkillScan ships ~50 built-in rules. You can extend that catalog two ways:

1. **YAML rules** — declarative, regex-over-file. Suitable for the long tail of pattern checks.
2. **Rust rules** — needed when you want frontmatter access, AST inspection, cross-file state, entropy calculations, etc.

This guide covers both.

## YAML rules

A YAML rule is a single file under your rule-pack directory (or under `src/rules/packs/builtin/` if you're contributing it to the built-in pack).

### Schema

```yaml
id: ORG-INJ-001                # required. Format: <NS>-<CAT>-<NNN>. Built-ins use SKILL-.
name: Detect MAGIC-CANARY     # required. Short human-readable.
severity: high                # required. critical / high / medium / low / info.
category: injection           # required. injection / permissions / exfiltration /
                              #           supply-chain / obfuscation / secrets /
                              #           compliance / code-quality.
confidence: 85                # optional. 0..=100. Defaults to 80.
message: |                    # required. {match} and {line} are substituted at finding time.
  Magic canary at line {line}: `{match}`
remediation: |                # required. Plain prose; appears in every reporter.
  Remove the canary. If you need a marker, switch to a comment that says so.
references:                   # optional. Free-form URLs surfaced in JSON / SARIF.
  - https://example.com/incident-123
match:
  regex: 'MAGIC-CANARY-\d+'   # required. Rust `regex` crate syntax. No lookaheads/backrefs.
files:                        # optional. Glob list, applied to paths relative to skill root.
  - '**/*.md'                 # Defaults to `**/*` (every file).
  - '**/*.py'
```

### Loading a custom pack

```bash
skillscan scan ./my-skill --rules ./my-rule-pack
```

Every `*.yml` / `*.yaml` file in the pack directory is parsed and compiled. A parse or regex error tells you which file is at fault so authors can find typos fast.

### Conventions for the `match.regex`

- Anchor with `\b` when matching identifier-shaped tokens; otherwise the rule fires on substrings of unrelated strings.
- Prefer `[^|\n]` over `.` when the body should not cross a logical boundary (e.g., the curl-pipe-sh rule uses `[^|\n]*` so a multi-line script doesn't get a spurious match).
- Case insensitivity: prefix with `(?i)`.
- Multi-line: SkillScan scans line by line, so `^` and `$` already match line boundaries. You don't need `(?m)`.

### Conventions for `files`

- Use `'**/*'` only when the pattern is so distinctive (a key shape, a webhook URL) that the file kind doesn't matter.
- Otherwise list explicit extensions — fewer false positives, faster scans.

### Message templates

`{match}` interpolates the substring the regex matched. `{line}` interpolates the 1-based line number. No other placeholders are recognized.

## Rust rules

Reach for a Rust rule when YAML can't express the check:

- **Frontmatter** (`description`, `allowed-tools`, `version`, …).
- **AST analysis** (tree-sitter-python / tree-sitter-bash already wired up under `src/engine/ast/`).
- **Cross-file state** (e.g., "does the skill claim to read `~/.ssh` *and* call `curl`?").
- **Numeric thresholds** (entropy, bundle size, tool count).

### Skeleton

```rust
// src/rules/cmp_002.rs
use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CMP-002",
    name: "Missing version field",
    severity: Severity::Low,
    category: Category::Compliance,
    default_remediation:
        "Add a `version:` field to the frontmatter so consumers can pin to a known revision.",
};

#[derive(Debug)]
pub struct VersionRule;

impl Rule for VersionRule {
    fn meta(&self) -> &'static RuleMeta { &META }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        if skill.frontmatter.version.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return vec![];
        }
        vec![Finding {
            rule_id: META.id.into(),
            severity: META.severity,
            confidence: 100,
            file: PathBuf::from("SKILL.md"),
            span: None,
            message: "Frontmatter is missing a `version` field.".into(),
            remediation: META.default_remediation.into(),
            references: vec![],
        }]
    }
}
```

Then register it in `src/rules/mod.rs`:

```rust
mod cmp_002;

pub fn builtin_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = vec![
        // ...existing...
        Box::new(cmp_002::VersionRule),
    ];
    rules.extend(yaml::load_builtin_yaml_rules());
    rules
}
```

### AST rules (Python / bash)

`src/engine/ast/python.rs` and `src/engine/ast/bash.rs` give you:

```rust
parse(src: &str) -> Option<Tree>
walk<F: FnMut(Node<'_>)>(node, &mut F)
node_text(node, src_bytes) -> &str
span_of(node) -> Span
call_callee_text / call_keyword_arg          # python helpers
command_name / command_args                  # bash helpers
```

Pattern:

```rust
fn check(&self, skill: &Skill) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in &skill.files {
        if file.kind != FileKind::Python { continue; }
        let Some(content) = &file.content else { continue };
        let Some(tree) = python::parse(content) else { continue };
        let bytes = content.as_bytes();

        python::walk(tree.root_node(), &mut |node| {
            let Some(callee) = python::call_callee_text(node, bytes) else { return };
            if callee != "os.system" { return; }
            findings.push(Finding {
                rule_id: META.id.into(),
                /* ... */
                span: Some(python::span_of(node)),
                /* ... */
            });
        });
    }
    findings
}
```

### Determinism

The engine sorts rules by id at registration so the order of `check()` invocations is stable. It also sorts findings by `(file, line, rule_id)` before returning the report, so two scans of the same input produce byte-identical output (modulo timing). Don't rely on iteration order inside your `check` — produce the same `Finding` set for the same input.

### Panic safety

If your `check()` panics, the engine catches it and emits a `SKILL-ENG-001` finding instead of crashing the scan. Don't `unwrap()` on user data — return an empty finding list and move on. The convention `Some(content) = &file.content else { continue }` is the right shape.

## Testing your rule

Add an integration test to `tests/scan.rs`:

```rust
#[test]
fn my_rule_is_flagged() {
    let dir = skill_with_md(
        "---\n\
         name: bad\n\
         description: A skill that triggers MY-RULE-001 for testing coverage.\n\
         version: 0.1.0\n\
         license: Apache-2.0\n\
         allowed-tools:\n  - Read\n\
         ---\n\
         # Bad\n\
         \n\
         MAGIC-CANARY-42\n",
    );
    bin().arg("scan").arg(dir.path()).assert().code(2).stdout(contains("MY-RULE-001"));
}
```

And confirm the **clean** fixture still passes with `--fail-on low` once your rule is registered:

```bash
cargo test clean_committed_fixture_passes_strict
```

That's the negative-control test. If your rule fires on the clean fixture, you've got a false positive baked in — refine the regex / AST check before merging.

## Style notes

- Rules are tiny. A Rust rule is one file under ~80 LOC; a YAML rule is ~15 lines.
- Don't import `serde_json` from inside a rule — use the engine's `Finding` shape directly.
- Don't read files yourself — the loader already gave you `skill.files[].content`.
- Don't perform network calls from inside a rule. Anything network-reaching belongs in Phase 3 loaders or the optional `--llm` pass.
