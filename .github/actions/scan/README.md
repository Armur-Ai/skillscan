# SkillScan Action

A composite GitHub Action that runs SkillScan against a Claude Skill directory and (optionally) uploads results to GitHub Code Scanning.

## Usage

```yaml
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

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `path` | `.` | Skill directory to scan. |
| `fail-on` | `high` | Threshold severity that causes a non-zero exit. |
| `format` | `term` | One of `term`, `json`, `sarif`, `md`. |
| `rules` | _(none)_ | Optional path to a custom YAML rule pack directory. |
| `sarif-upload` | `false` | When `format=sarif`, also upload to GitHub Code Scanning. |
| `version` | _(latest)_ | Pin a specific `skillscan` crate version. |

## Outputs

| Name | Description |
|------|-------------|
| `exit-code` | `0` clean, `2` findings at or above `fail-on`. |
| `sarif-path` | Path to the generated SARIF file (set when `format=sarif`). |

## Notes

The action installs `skillscan` via `cargo install` and caches `~/.cargo` between runs to keep iteration time low. A future release will switch to a prebuilt binary download once a release pipeline is in place.
