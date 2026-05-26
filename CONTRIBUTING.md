# Contributing to SkillScan

Thank you for considering a contribution. Most of the long-tail value of SkillScan is in its rule catalog, so new rules are the easiest and most appreciated place to start.

## Dev setup

```bash
git clone git@github.com:Armur-Ai/skillscan.git
cd skillscan
cargo build
cargo test
just lint           # cargo fmt --check + cargo clippy -D warnings
just scan           # demo scan against the committed clean fixture
```

MSRV is **Rust 1.80** (for `std::sync::LazyLock`). Toolchain is pinned in `rust-toolchain.toml`; `rustup` will install the right components on first build.

## Project layout

```
src/
├── cli.rs              # clap CLI surface
├── model/              # Skill, Frontmatter, Finding, Severity, Span, Report, RuleTiming
├── loaders/            # DirectoryLoader (Phase 3 will add archive/git/url)
├── engine/             # Rule trait, Engine, ruleset hash, panic isolation
│   └── ast/            # tree-sitter parse + walk helpers (python, bash)
├── rules/              # Built-in rules (Rust + YAML pack under packs/builtin)
└── reporters/          # term, json, sarif, md, html
tests/
├── cli.rs              # binary smoke tests (--help, --version, missing path)
├── scan.rs             # end-to-end rule fixtures (tempdir-based)
└── fixtures/skills/    # committed clean fixture for `just scan`
```

## Adding a rule

You have two options:

1. **YAML rule** — best when the check is a regex over file content. See [`docs/writing-rules.md`](docs/writing-rules.md). Drop a file under `src/rules/packs/builtin/SKILL-<CAT>-<NNN>-<slug>.yml`, register it in `src/rules/yaml.rs::BUILTIN_YAML_PACK`, and add a positive integration test in `tests/scan.rs`.

2. **Rust rule** — necessary when the check needs frontmatter access, AST inspection, cross-file state, or anything beyond a regex match. Create `src/rules/<id>.rs`, implement the `Rule` trait from `src/engine/mod.rs`, and register it in `src/rules/mod.rs::builtin_rules()`.

Every new rule must come with:
- A positive fixture test (rule fires on a synthetic-bad skill).
- A negative fixture test (rule stays quiet on the committed `clean` fixture).
- An ID following `SKILL-<CAT>-<NNN>` for built-ins, `<NS>-<CAT>-<NNN>` for third-party packs.

## Categories and severities

| Category | Code | Use when |
|----------|------|----------|
| Injection | `INJ` | The skill smuggles content meant to be interpreted by Claude as instruction. |
| Permissions | `PRM` | The `allowed-tools` declaration grants more than the skill needs. |
| Exfiltration | `EXF` | The skill could send data off the user's machine. |
| Supply chain | `SUP` | The skill pulls remote code or dependencies at runtime. |
| Obfuscation | `OBF` | Content is encoded/compressed/hidden in a way that resists review. |
| Secrets | `SEC` | A credential is embedded in the bundle. |
| Compliance | `CMP` | Metadata/structural issue that doesn't itself cause harm. |
| Code quality | `CQ` | Unsafe coding pattern in shipped scripts. |

| Severity | When |
|----------|------|
| critical | RCE channel or live credential. |
| high | Plausibly malicious or a known dangerous pattern with low FP. |
| medium | Suspicious — worth a human look but FP-prone. |
| low | Hygiene / compliance. Won't fail the default CI threshold. |
| info | Diagnostic; never fails CI. |

## Linter and test gate

CI runs on `stable` and MSRV (`1.80`) across ubuntu + macos:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo-deny check`

`-D warnings` on clippy is strict by design — please address or `#[allow(...)]` deliberately with a comment if a lint truly doesn't apply.

## Reporting issues

- Bugs and feature requests: open a GitHub issue.
- Security vulnerabilities in SkillScan itself: see [`SECURITY.md`](SECURITY.md).
- Vulnerable third-party skills discovered with SkillScan: see [`SECURITY.md`](SECURITY.md#vulnerabilities-found-in-third-party-skills) for our coordinated-disclosure recommendation.

## License

By contributing you agree your code is licensed under Apache 2.0.
