---
name: clean-example-skill
description: A clean, benign skill used as a positive control for SkillScan rules.
version: 0.1.0
allowed-tools:
  - Bash(git status)
  - Bash(git diff)
  - Read
license: Apache-2.0
---

# Clean Example Skill

This skill does nothing dangerous. It is intentionally boring so it can serve as
a control case — SkillScan should produce zero findings on it.

## Usage

Invoke this skill when you want a no-op.
