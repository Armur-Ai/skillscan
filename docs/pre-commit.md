# Pre-commit integration

SkillScan ships a `.pre-commit-hooks.yaml` so it slots into the popular [`pre-commit`](https://pre-commit.com) framework.

## Minimal config

Add SkillScan to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Armur-Ai/skillscan
    rev: v0.1.0
    hooks:
      - id: skillscan
        args: ['./skills', '--fail-on', 'high']
```

Then:

```bash
pre-commit install
pre-commit run skillscan --all-files
```

This expects `skillscan` to be on your PATH already. Install it via one of:

```bash
brew install armur-ai/tap/skillscan        # macOS / Linux
cargo install --locked skillscan           # any Rust toolchain
curl -fsSL https://armur-ai.github.io/skillscan/install.sh | sh
```

## Zero-setup variant

If you do not want every collaborator to install the binary first, use the `skillscan-cargo` hook id instead — pre-commit will build SkillScan from source the first time the hook runs:

```yaml
- id: skillscan-cargo
  args: ['./skills', '--fail-on', 'high']
```

First run takes ~1 minute (cold cargo build); subsequent runs are instant.

## Tuning

| Flag | Effect |
|------|--------|
| `--fail-on critical` | only fail commits on critical findings |
| `--rules ./my-pack` | also load a custom YAML rule pack from `./my-pack` |
| `--format md`        | emit a markdown report on stderr (terminal stays the default) |
| `--llm`              | run the opt-in LLM pass; requires `ANTHROPIC_API_KEY` exported |

Pre-commit passes everything in `args:` straight through to `skillscan scan`, so any CLI flag works.

## Why `pass_filenames: false`?

`skillscan scan` consumes a *directory* (a skill bundle), not a list of individual files. Asking pre-commit to run it once per changed file would be slow and noisy. With `pass_filenames: false`, the hook runs once per `pre-commit` invocation against the path you supply in `args:`.

Combine with `files:` if you want to scope when the hook fires:

```yaml
- id: skillscan
  files: ^skills/.*
  args: ['./skills', '--fail-on', 'high']
```
