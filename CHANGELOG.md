# Changelog

All notable changes to SkillScan are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No changes since 0.1.0._

## [0.1.0] — 2026-05-26

First public release.

### Added

- **Engine.** `Rule` trait, `Engine` with deterministic sort and per-rule panic isolation (`SKILL-ENG-001`), SHA-256 `ruleset_hash` embedded in every report.
- **Loader.** `DirectoryLoader` walks the skill root via the `ignore` crate, parses YAML frontmatter (BOM-tolerant, forward-compatible via `Frontmatter.extra`), enforces a 50 MiB / 5000-file budget.
- **Parallelism.** Rule execution runs through `rayon::par_iter`. Findings are still sorted by `(file, line, rule_id)` after the parallel pass so output is byte-deterministic.
- **AST analysis.** tree-sitter-python and tree-sitter-bash scaffolding (`parse`, `walk`, `node_text`, `span_of`, `call_callee_text` / `call_keyword_arg`, `command_name` / `command_args`). Six AST-precise rules ship in `code-quality`.
- **YAML rule DSL.** Built-in pack lives under `src/rules/packs/builtin/`, embedded at compile time via `include_str!`. Users supply custom packs via `--rules <PATH>`. Message templates support `{match}` / `{line}` substitution.
- **Reporters.** Five formats: terminal (`owo-colors`, stream-aware), JSON (versioned schema), SARIF 2.1.0 (GitHub Code Scanning–ready with `security-severity` scores), Markdown (PR-comment shape with escaped pipes), HTML (single-file, inline CSS, XSS-safe escaping).
- **CLI.** `skillscan scan <path>` with `--format`, `--fail-on`, `--rules`, `--quiet`, `--profile`, `--log-level`, `--no-color`. `skillscan rules list` prints the tabular catalog.
- **Distribution.** Cross-platform release workflow (macOS arm64/x86_64, Linux gnu/musl/arm64, Windows). One-line `install.sh` installer. Multi-arch Docker image published to `ghcr.io/armur-ai/skillscan`. Composite GitHub Action under `.github/actions/scan`.
- **Docs.** `CONTRIBUTING.md`, `SECURITY.md`, `docs/writing-rules.md`, `docs/threat-model.md`.

### Rules (50 total)

| Category | Rules |
|----------|-------|
| Injection (7) | `INJ-001` zero-width, `INJ-003` ignore-previous, `INJ-004` role-switch, `INJ-005` long base64, `INJ-007` HTML-comment instructions, `INJ-008` long line, `INJ-009` Tag chars, `INJ-010` bidi controls |
| Permissions (6) | `PRM-001` Bash wildcard, `PRM-002` Write to sensitive path, `PRM-003` Read of sensitive dotfiles, `PRM-004` unscoped Web*, `PRM-006` allowed-tools missing, `PRM-007` >15 tools |
| Exfiltration (7) | `EXF-001` paste services, `EXF-002` long DNS subdomain, `EXF-003` credential dirs, `EXF-004` env dump piped, `EXF-005` clipboard, `EXF-006` webhooks, `EXF-007` netcat, `EXF-008` cloud metadata |
| Supply chain (4) | `SUP-001` curl\|sh, `SUP-003` fetch-and-exec, `SUP-005` runtime git clone, `SUP-006` npm install -g |
| Obfuscation (5) | `OBF-001` eval/exec regex, `OBF-002` hex blob, `OBF-003` pickle/marshal regex, `OBF-004` compile() of dynamic source, `OBF-005` decompress packed payload |
| Secrets (8) | `SEC-001` AWS / GitHub / private-key headers, `SEC-002` Google API, `SEC-003` Slack, `SEC-004` Stripe live, `SEC-005` JWT, `SEC-006` Twilio, `SEC-007` SendGrid, `SEC-008` Anthropic, `SEC-009` OpenAI |
| Compliance (4) | `CMP-001` description, `CMP-002` version, `CMP-003` license, `CMP-004` oversized bundle |
| Code quality (6) | `CQ-001` subprocess shell=True AST, `CQ-002` os.system AST, `CQ-003` eval/exec AST-precise, `CQ-004` unsafe deserialization AST, `CQ-005` bash eval AST, `CQ-006` bash dynamic source AST |

### Engineering

- MSRV: Rust 1.80 (needed for `std::sync::LazyLock`).
- `#![deny(unsafe_code)]` at the workspace root.
- `cargo-deny` policy: licenses allowlisted, no wildcard deps, no unknown registries.
- CI matrix on stable + 1.80 across ubuntu + macos.
- 71 tests (unit + integration); `cargo test` finishes in < 2s warm.

### Also in 0.1.0

- `--llm` opt-in LLM-assisted detection via Claude Haiku 4.5 with prompt caching, disk cache, and a pre-call USD budget guard. Findings appear as `SKILL-LLM-NNN`.

[Unreleased]: https://github.com/Armur-Ai/skillscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Armur-Ai/skillscan/releases/tag/v0.1.0
