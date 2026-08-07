# CLI Reference

This page is the command reference for the current Basilisk CLI surface.

## Top-Level Commands

Current commands:

- `scan`
- `recon`
- `replay`
- `modules`
- `probes`
- `auth-test`
- `interactive`
- `sessions`
- `diff`
- `posture`
- `version`
- `help`
- `eval`

Provider values include `openai`, `anthropic`, `google`, `azure`, `nvidia`,
`ollama`, `github`, `custom`, and `websocket`. NVIDIA credentials are resolved
from `NVIDIA_API_KEY` and default to model `openai/gpt-oss-20b`.

## `basilisk scan`

Run a full scan against a target.

```bash
basilisk scan [OPTIONS]
```

Important options:

| Option | Description |
|--------|-------------|
| `-t, --target` | Target URL or API endpoint |
| `-p, --provider` | Target provider |
| `-m, --model` | Target model override |
| `-k, --api-key` | API key file reference such as `@/path/to/key` |
| `--auth` | Authorization header file reference; alternatively use `BASILISK_AUTH_HEADER` |
| `--mode` | `quick`, `standard`, `deep`, `stealth`, `chaos` |
| `--cost-preview` | Calculate the bounded request/token/cost plan and exit without transmitting |
| `--input-price-per-million` | Optional provider input-token rate used for the USD preview |
| `--output-price-per-million` | Optional provider output-token rate used for the USD preview |
| `--evolve / --no-evolve` | Enable or disable the evolution engine |
| `--generations` | Evolution generations |
| `--module` | Repeatable module selector |
| `--skip-recon` | Skip reconnaissance |
| `--recon-module` | Repeatable recon module selector |
| `--attacker-provider` | Provider for mutation generation |
| `--attacker-model` | Model for mutation generation |
| `--attacker-api-key` | Attacker-model key file reference |
| `--exit-on-first / --no-exit-on-first` | Stop evolution after first breakthrough |
| `--diversity-mode` | `off`, `novelty`, `niche` |
| `--intent-weight` | Intent preservation weight |
| `--cache / --no-cache` | Enable or disable response caching |
| `--include-research-modules / --no-include-research-modules` | Opt into research-tier modules |
| `--execution-mode` | `recon`, `validate`, `exploit_chain`, `research` |
| `--campaign-name` | Campaign name |
| `--operator` | Operator name |
| `--ticket` | Authorization or tracking ticket |
| `--approval-required / --no-approval-required` | Require explicit approval |
| `--approve / --no-approve` | Mark approval confirmed |
| `--dry-run` | Plan only |
| `-o, --output` | `html`, `json`, `sarif`, `markdown`, `pdf` |
| `--output-dir` | Report output directory |
| `--no-dashboard` | Disable the dashboard path |
| `--fail-on` | Threshold for non-zero exit |
| `-v, --verbose` | Verbose output |
| `--debug` | Debug mode |
| `-c, --config` | YAML config file |

## `basilisk recon`

Run reconnaissance only.

```bash
basilisk recon \
  --target https://example.test/v1/chat/completions \
  --provider openai
```

Options:

- `--target`
- `--provider`
- `--api-key`
- `--auth`
- `--recon-module`
- `--verbose`

## `basilisk posture`

Run the posture workflow.

```bash
basilisk posture \
  --provider openai \
  --model gpt-4o
```

Options:

- `--target`
- `--provider`
- `--model`
- `--api-key`
- `--auth`
- `--output-dir`
- `--json`
- `--verbose`

## `basilisk diff`

Compare multiple targets side by side.

```bash
basilisk diff \
  -t openai:gpt-4o \
  -t anthropic:claude-3-5-sonnet-20241022
```

Options:

- `--target` repeatable `provider:model`
- `--api-key`
- `--category`
- `--output-dir`
- `--verbose`

## `basilisk eval`

Run an assertion-based eval suite from YAML.

```bash
basilisk eval evals/guardrails.yaml
```

Options:

- `--format` with `console`, `json`, `junit`, `markdown`
- `--output`
- `--fail-on` with `any` or `all`
- `--parallel / --no-parallel`
- `--diff`
- `--tag`
- `--verbose`

## `basilisk modules`

Inspect the attack catalog.

```bash
basilisk modules
```

Options:

- `--category`
- `--include-research / --no-include-research`
- `--json`

## `basilisk probes`

Browse the YAML probe corpus.

```bash
basilisk probes --stats
```

Options:

- `--category`
- `--tag`
- `--severity`
- `--query`
- `--count`
- `--json`
- `--stats`

## `basilisk interactive`

Start the assisted REPL:

```bash
basilisk interactive \
  --target https://example.test/v1/chat/completions \
  --provider openai
```

## `basilisk sessions`

List stored sessions:

```bash
basilisk sessions
```

Option:

- `--db`

## `basilisk replay`

Replay one stored session:

```bash
basilisk replay BSLK-2026-ABC123
```

Option:

- `--db`

## `basilisk help`

Extended help topics:

```bash
basilisk help overview
basilisk help scan
basilisk help modules
basilisk help evolution
basilisk help diff
basilisk help examples
```

## `basilisk version`

Show Basilisk version and local runtime information.

## Environment Variables

Common provider variables:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GOOGLE_API_KEY`
- `AZURE_API_KEY`
- `GH_MODELS_TOKEN`
- `GROQ_API_KEY`
- `XAI_API_KEY`
- `BASILISK_API_KEY`

## Exit Behavior

For `scan`:

- non-zero exit depends on `--fail-on`

For `eval`:

- `--fail-on any` returns non-zero if any test fails
- `--fail-on all` returns non-zero only if all tests fail

Use the advanced guides for workflow advice and the architecture pages for internals.
