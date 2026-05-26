# Threat model

This document spells out what SkillScan is designed to defend against, what it is explicitly not, and the assumptions it makes about the environment it runs in.

## Goal

Give a human reviewer (or a CI pipeline) enough signal to **decide whether a Claude Skill is safe to install** before that skill ever touches a real agent session.

## Scope

### What we look at

A "skill" is a directory containing:

- `SKILL.md` with YAML frontmatter (`name`, `description`, `allowed-tools`, …) and prompt content in the body.
- Optional supporting files: Python / shell scripts, JSON/YAML configs, markdown docs, small data files.

We reason about the skill as **static text** plus **static metadata**. We do not execute the skill.

### Threat actors

| Actor | Motivation | Example |
|-------|------------|---------|
| Malicious skill author | Steal credentials, run code, embarrass the user. | Smuggles a `curl \| sh` install step or a hidden zero-width prompt-injection string. |
| Compromised dependency / supply chain | Skill itself is benign but pulls vulnerable code at install time. | `pip install` of an unpinned typosquat. |
| Careless author | Honest mistake. | Hardcodes an AWS key for "testing." |
| Marketplace operator | Wants to vouch for inventory. | Runs SkillScan in batch over a public marketplace. |

### Defenses we provide

The categories below map 1:1 to the rule prefix scheme (see [`writing-rules.md`](writing-rules.md)).

| Category | What it catches |
|----------|-----------------|
| Injection (`INJ`) | Zero-width / tag / bidi unicode smuggling, role-switch markers (`<|system|>`, `[INST]`), explicit "ignore previous instructions" phrasing, hidden HTML comments, suspicious base64 / very long single lines. |
| Permissions (`PRM`) | Overbroad `allowed-tools` — `Bash(*)`, `WebFetch` unscoped, Write/Read of `/etc`, `~/.ssh`, `~/.aws`. |
| Exfiltration (`EXF`) | Outbound paste/file-share URLs, Discord/Slack webhooks, env-var dumps piped to curl/nc, DNS-tunnel subdomain shapes, clipboard reads, references to credential dirs. |
| Supply chain (`SUP`) | `curl \| sh`, `chmod +x` on fetched binaries, runtime `git clone`. |
| Obfuscation (`OBF`) | Dynamic `eval`/`exec`, `compile()` of variables, pickle/marshal loads, long hex blobs. |
| Secrets (`SEC`) | AWS / GitHub / Google / Anthropic / OpenAI / Stripe / Twilio / SendGrid / Slack tokens, generic private-key headers, JWTs. |
| Compliance (`CMP`) | Missing `description` / `version` / `license`, oversized bundles, unknown frontmatter. |
| Code quality (`CQ`) | AST-precise `subprocess(shell=True)`, `os.system`, `eval`/`exec` calls, unsafe deserialization, bash `eval`, dynamic `source`. |

### What we explicitly do **not** defend against

- **Runtime behavior.** SkillScan never executes the skill, so it cannot catch dynamic decisions a skill makes mid-conversation (Phase 6 sandboxed analysis is on the roadmap but separate).
- **Determined steganography.** A payload encoded into an image's least-significant bits, or split across many files with low individual signal, will pass a static scan. We surface obvious encoded blobs (base64, hex, bidi-reversed) but the long tail is an arms race.
- **Skills authored by the user themselves.** If you are the author, you don't need a scanner — you need a reviewer. Run it anyway to catch hygiene issues.
- **The Claude runtime sandbox.** We do not model what tools the host actually allows; we model what the skill *asks for*. A host that ignores `allowed-tools` is its own problem.
- **Third-party rule packs.** Anything loaded via `--rules <PATH>` runs the same regexes we ship, but we don't vet *those* packs. Use packs from sources you trust.

### Out of scope

- Vulnerabilities in software the skill *uses* but does not ship (e.g., `requests` CVEs). That's the dependency scanner's job.
- License / IP compliance beyond a simple presence check.
- Authorship attribution / "is this skill written by a person we trust."

## Assumptions

1. **The scanner runs in the user's trust boundary.** No network calls happen unless `--allow-network` (Phase 3 archive/git loaders) or `--llm` (Phase 4) is set.
2. **Skill content fits in memory.** The directory loader caps the bundle at 50 MiB (configurable in source); above that it errors rather than truncating. Untrusted skills are sandboxed by your OS, not by SkillScan.
3. **Rule packs are trusted.** Built-in rules ship in-binary. User-supplied YAML rules are compiled and run; a malicious regex could panic or run slowly, but cannot escape the scanner process (we have no exec, no eval).
4. **`ruleset_hash` is stable for equivalent input.** Two scans with the same rule set produce identical findings and identical `ruleset_hash`. Use this in CI to spot drift.

## Detection vs. confidence

Every finding carries a `severity` (impact) and a `confidence` (how sure the rule is).

- A regex-based rule that always matches the exact intended pattern: confidence 95-100.
- A regex that may false-positive on docs/comments: 60-85.
- An LLM-assisted finding (Phase 4): default 50 unless corroborated by a static rule.

CI gates should usually pin on `severity` (`--fail-on high`), not `confidence`. Tune `confidence` only when investigating noise.

## Reproducibility

- `ruleset_hash` (SHA-256 of all loaded rule IDs) is embedded in every report.
- Rule execution is sorted by id at startup; finding output is sorted by `(file, line, rule_id)`.
- Two scans of the same skill with the same rule set on the same SkillScan version produce byte-identical reports modulo timing (`stats.duration_ms`, `rule_timings`).

## Open questions

- How should we publish rule pack versions independent of the binary? Tracked at [#TODO](https://github.com/Armur-Ai/skillscan/issues).
- Should `--fix` exist for trivially auto-fixable findings (e.g., scope down `Bash(*)`)? Probably Phase 6 — implies a SKILL.md writer that preserves formatting.
- Coordinated disclosure of vulnerabilities found in public skills: see [`../SECURITY.md`](../SECURITY.md#vulnerabilities-found-in-third-party-skills).
