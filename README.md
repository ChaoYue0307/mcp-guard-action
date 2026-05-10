# mcp-guard MCP Security Scanner

Scan MCP and AI agent tool configuration in GitHub Actions before risky tools merge.

`mcp-guard` finds risky shell startup commands, leaked secret-like values, broad filesystem access, remote MCP endpoints, dangerous command patterns, and unpinned remote package runners.

## Usage

```yaml
name: mcp-guard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ChaoYue0307/mcp-guard-action@v0.3.1
        with:
          fail-on: high
```

## Upload SARIF to GitHub Security

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ChaoYue0307/mcp-guard-action@v0.3.1
        with:
          config: .mcp.json
          fail-on: high
          upload-sarif: "true"
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `config` | empty | Optional MCP config path. Empty scans default project and user config locations. |
| `fail-on` | `high` | Fails the job for `critical`, `high`, `medium`, or `low` findings. Use `none` for report-only mode. |
| `output-dir` | `mcp-guard-report` | Directory for generated reports. |
| `upload-artifact` | `true` | Uploads generated reports as a workflow artifact. |
| `upload-sarif` | `false` | Uploads SARIF to GitHub code scanning. Requires `security-events: write`. |
| `artifact-name` | `mcp-guard-report` | Name of the uploaded artifact. |

## Outputs

| Output | Description |
| --- | --- |
| `markdown-report` | Path to the generated Markdown report. |
| `html-report` | Path to the generated HTML report. |
| `json-report` | Path to the generated JSON report. |
| `sarif-report` | Path to the generated SARIF report. |
| `exit-code` | `0` when below threshold, `2` when findings met the threshold. |

## Reports

The action generates:

- Markdown for pull request review.
- HTML for review-ready artifacts.
- JSON for automation.
- SARIF 2.1.0 for GitHub code scanning.

Secret-like values are redacted before reports are written.

## Transparent Example

Inspect a committed input config, reproduction commands, and generated Markdown, HTML, JSON, and SARIF artifacts:

https://chaoyue0307.github.io/mcp-guard/e2e/

Inspect a live GitHub Action demo pull request that intentionally fails on risky MCP config:

https://github.com/ChaoYue0307/mcp-guard-demo/pull/1

## Links

- Product site: https://chaoyue0307.github.io/mcp-guard/
- Marketplace listing: https://github.com/marketplace/actions/mcp-guard-mcp-security-scanner
- Live demo repository: https://github.com/ChaoYue0307/mcp-guard-demo
- Main repository: https://github.com/ChaoYue0307/mcp-guard
- npm package: https://www.npmjs.com/package/agent-mcp-guard
