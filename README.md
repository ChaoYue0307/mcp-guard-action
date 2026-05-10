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
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ChaoYue0307/mcp-guard-action@v0.4.3
        with:
          config: .mcp.json
          fail-on: high
          comment-pr: "true"
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
      - uses: actions/checkout@v6
      - uses: ChaoYue0307/mcp-guard-action@v0.4.3
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
| `baseline` | empty | Optional baseline/allowlist JSON path. Matching findings are accepted and do not fail the workflow. |
| `comment-pr` | `false` | Posts or updates a pull request comment with the scan summary. Requires `pull-requests: write`. |
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
| `comment-report` | Path to the generated pull request comment body. |
| `exit-code` | `0` when below threshold, `2` when findings met the threshold. |

## Reports

The action generates:

- Markdown for pull request review.
- HTML for review-ready artifacts.
- JSON for automation.
- SARIF 2.1.0 for GitHub code scanning.

Secret-like values are redacted before reports are written.

## Baseline Mode

Generate and commit a baseline when existing MCP risk is known and accepted:

```bash
mcp-guard scan --config .mcp.json --write-baseline .mcp-guard-baseline.json
```

Then enforce only new findings:

```yaml
- uses: ChaoYue0307/mcp-guard-action@v0.4.3
  with:
    config: .mcp.json
    baseline: .mcp-guard-baseline.json
    fail-on: high
```

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
