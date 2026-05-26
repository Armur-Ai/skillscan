# Security policy

## Reporting a vulnerability in SkillScan itself

**Please do not file public GitHub issues for security bugs.**

Email `security@armur.ai` with:
- A short description of the issue.
- Steps to reproduce (or a PoC skill, if applicable).
- Affected version (`skillscan --version`).
- Your name and how you want to be credited.

We will acknowledge within **2 business days** and aim to ship a fix within **30 days** for high/critical issues. We will credit reporters in the release notes unless you ask us not to.

## Supported versions

SkillScan is pre-1.0. Only the latest minor version receives security fixes. Once we tag 1.0, the policy will move to "last two minor versions."

## Threat model

SkillScan is a static + LLM-assisted analyzer for skills the user is *about to install*. We make no security claim about already-installed skills or about the runtime sandbox a host provides. See [`docs/threat-model.md`](docs/threat-model.md) for the full statement of what we protect against and what we explicitly do not.

The scanner itself runs in the user's local trust boundary. It does not phone home, does not upload skill content anywhere, and only makes outbound network requests when explicitly opted in via `--allow-network` (Phase 3) or `--llm` (Phase 4).

## Vulnerabilities found in third-party skills

If SkillScan flags a real vulnerability in someone else's published skill, please follow coordinated disclosure:

1. Contact the skill author directly.
2. Give them a reasonable window to fix (we suggest 30 days for high/critical, 90 for medium).
3. Open a public issue or write up only after the fix ships or the window expires.

If you can't reach the author and the issue is actively dangerous (e.g., a leaked live credential), email `security@armur.ai` and we will help triage and notify the relevant marketplace.

## What's *not* in scope

- Denial-of-service against the scanner via maliciously crafted input (e.g., a giant SKILL.md). We treat these as bugs and fix them, but they don't go through the embargo process — file a normal issue.
- Findings about Claude / Anthropic infrastructure itself — please report directly to Anthropic.
- Issues in third-party rule packs you load via `--rules`.
