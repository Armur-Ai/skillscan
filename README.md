<div align="center">

# SkillScan

**The security scanner for Claude Skills.**

Audit Claude Skills for prompt injection, tool abuse, data exfiltration, hidden instructions, and supply-chain risks — before you install them.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![crates.io](https://img.shields.io/badge/crates.io-skillscan-orange.svg)](https://crates.io/crates/skillscan)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF.svg)](https://github.com/Armur-Ai/skillscan/actions)
[![SARIF](https://img.shields.io/badge/output-SARIF_2.1.0-success.svg)](https://sarifweb.azurewebsites.net/)
[![Built by Armur](https://img.shields.io/badge/built_by-Armur--AI-black.svg)](https://github.com/Armur-Ai)

</div>

---

## Why SkillScan

Claude Skills are powerful — they bundle instructions, scripts, and tool permissions into installable capability packs. They are also a new attack surface. A malicious or sloppy skill can:

- Hide instructions that hijack Claude on your machine.
- Quietly exfiltrate secrets through `curl`, DNS, or webhook calls.
- Request `Bash(*)` and read your entire `$HOME`.
- Smuggle prompt-injection payloads inside images, PDFs, or fetched URLs.
- Ship vulnerable Python or shell scripts that get executed on your dev box.

SkillScan is the missing static + dynamic analyzer for that ecosystem. Point it at a skill directory, a Git URL, or a marketplace listing — get back a triaged report you can act on (or fail your CI on).

Built in Rust for speed, a single static binary, and zero runtime dependencies.

## Features

- **Fast and standalone.** Native Rust binary. No interpreter, no `node_modules`, no `pip install`. A 100-file skill scans in milliseconds.
- **Multi-layer detection.** Frontmatter linting, regex content rules, tree-sitter AST analysis of Python and bash scripts, secret scanning, URL reputation, and an optional LLM-assisted pass for subtle prompt-injection patterns.
- **50+ built-in rules.** Grouped into 8 categories: `injection`, `permissions`, `exfiltration`, `supply-chain`, `obfuscation`, `secrets`, `compliance`, `code-quality`.
- **Severity-rated findings.** `critical` / `high` / `medium` / `low` / `info`, with confidence scores and remediation guidance.
- **SARIF 2.1.0 output.** First-class integration with GitHub Code Scanning, GitLab, and any SARIF-aware viewer.
- **5 report formats.** Rich terminal output (with `--profile` per-rule timing), JSON, SARIF, Markdown (PR-comment-ready), HTML (single-file).
- **Scan anything.** Local directories, `.zip` / `.tar.gz` archives, Git URLs, GitHub repos, or live marketplaces.
- **CI-ready.** Single static binary, deterministic exit codes, `--fail-on` threshold flag, GitHub Action included.
- **Pluggable.** Write custom rules in YAML or as compiled Rust plugins. Ship private rule packs to your team.
- **Offline by default.** No network calls unless you opt in to URL reputation or LLM checks.

## Quickstart

### Install

```bash
# Homebrew
brew install armur-ai/tap/skillscan

# Cargo
cargo install skillscan

# Prebuilt binary (macOS/Linux/Windows)
curl -fsSL https://armur-ai.github.io/skillscan/install.sh | sh

# Docker
docker run --rm -v "$PWD:/work" ghcr.io/armur-ai/skillscan scan /work/my-skill
```

### Scan a skill

```bash
skillscan scan ./path/to/skill
```

```text
SkillScan v0.1.0  •  rules: 47  •  target: ./path/to/skill

✗ critical  SKILL-INJ-003   Hidden zero-width instructions in SKILL.md:14
✗ high      SKILL-PRM-007   allowed-tools grants Bash(*) without scope
✗ medium    SKILL-EXF-002   Outbound POST to non-allowlisted host in scripts/sync.py:42
✓ pass      36 other rules

Result: 3 findings (1 critical, 1 high, 1 medium) — exit code 2
Scanned 18 files in 31ms.
```

### Scan a remote skill

```bash
skillscan scan git+https://github.com/some-author/cool-skill
skillscan scan https://marketplace.example.com/skills/foo.zip
```

### Output formats

```bash
skillscan scan ./skill --format sarif  > results.sarif
skillscan scan ./skill --format json   > results.json
skillscan scan ./skill --format md     > REPORT.md
skillscan scan ./skill --format html   > report.html
skillscan scan ./skill --profile                 # term + per-rule timing
skillscan rules list                              # tabular rule catalog
```

### Use in CI

```yaml
# .github/workflows/skillscan.yml
name: SkillScan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required when sarif-upload is true
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Armur-Ai/skillscan/.github/actions/scan@main
        with:
          path: ./skills
          fail-on: high
          format: sarif
          sarif-upload: 'true'
```

## What it checks

| Category        | Examples |
|-----------------|----------|
| **Prompt injection** | Hidden zero-width chars, base64-encoded instructions, conflicting system directives, role-confusion patterns, indirect injection via fetched URLs |
| **Tool abuse**       | Overbroad `allowed-tools` (`Bash(*)`, `Write(/**)`), unscoped network access, write access to sensitive paths |
| **Data exfiltration**| Outbound HTTP/DNS to non-allowlisted hosts, env-var harvesting, clipboard reads, `~/.ssh` / `~/.aws` access |
| **Supply chain**     | Unpinned dependencies, typosquats, `curl \| sh` patterns, fetching binaries at runtime |
| **Obfuscation**      | Zero-width unicode, homoglyphs, hex/base64 blobs, gzip-in-string, steganography hints |
| **Secrets**          | API keys, tokens, private keys committed inside the skill bundle |
| **Code quality**     | Insecure subprocess calls, shell injection, path traversal, `eval` / `exec` in scripts |
| **Compliance**       | Missing `description`, license, version, author; oversized bundles; LFS misuse |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       skillscan CLI                         │
└──────────────┬──────────────────────────────────┬───────────┘
               │                                  │
       ┌───────▼────────┐                ┌────────▼────────┐
       │   Loaders      │                │   Reporters     │
       │ dir / zip /    │                │ term / json /   │
       │ git / url      │                │ sarif / md      │
       └───────┬────────┘                └────────▲────────┘
               │                                  │
       ┌───────▼──────────────────────────────────┴────────┐
       │                  Engine                            │
       │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────┐ │
       │  │ Front-   │ │ Content  │ │  Script  │ │  LLM  │ │
       │  │ matter   │ │ heur.    │ │   AST    │ │ pass  │ │
       │  └──────────┘ └──────────┘ └──────────┘ └───────┘ │
       └────────────────────┬───────────────────────────────┘
                            │
                     ┌──────▼──────┐
                     │ Rule packs  │  YAML + Rust plugins
                     └─────────────┘
```

## Rule packs

Built-in packs ship under `crates/skillscan-rules/packs/`. You can write your own:

```yaml
# my-pack/no-curl-pipe-sh.yml
id: ORG-SUP-001
name: curl piped to sh
severity: high
category: supply-chain
match:
  regex: "curl[^|]+\\|\\s*(sh|bash)"
  files: ["**/*.{sh,md,py}"]
message: Piping curl into a shell executes unverified remote code.
remediation: Download, verify a checksum, then execute.
```

Load with `skillscan scan ./skill --rules ./my-pack`.

## Roadmap

- [x] CLI skeleton, loaders, engine, term/JSON/SARIF/Markdown/HTML reporters
- [x] Static rule pack v1 (50+ rules across 8 categories)
- [x] tree-sitter Python + bash AST analysis with precision rules
- [x] Parallel rule execution (`rayon`) + per-rule `--profile`
- [x] GitHub Action composite + multi-arch Docker image + cross-platform release pipeline
- [ ] LLM-assisted prompt-injection detector (`--llm`)
- [ ] Pre-commit hook
- [ ] Marketplace crawler + public skill index
- [ ] VS Code extension for inline findings
- [ ] Sandboxed dynamic analysis (skill behavior in a jailed runner)

See [open issues](https://github.com/Armur-Ai/skillscan/issues) for current work.

## Contributing

Pull requests welcome. New rules are the easiest place to start — see [`docs/writing-rules.md`](docs/writing-rules.md). For larger changes, open an issue first.

```bash
git clone git@github.com:Armur-Ai/skillscan.git
cd skillscan
cargo build
cargo test
cargo run -- scan tests/fixtures/skills/clean
```

## Security

Found a vulnerability in SkillScan itself? Please email `security@armur.ai` rather than filing a public issue.

## License

Apache 2.0. See [LICENSE](LICENSE).

---

<div align="center">
Built by <a href="https://github.com/Armur-Ai">Armur-AI</a> — security tooling for the agent era.
</div>
