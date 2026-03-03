# CLI Reference

## Commands

### `basilisk scan`
Run a full red team scan against an AI target.

```
basilisk scan [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --target` | *required* | Target URL or API endpoint |
| `-p, --provider` | `openai` | LLM provider (openai, anthropic, google, azure, ollama, custom) |
| `-m, --model` | auto | Model name override |
| `-k, --api-key` | env var | API key (or use environment variables) |
| `--auth` | — | Authorization header value |
| `--mode` | `standard` | Scan mode: quick, standard, deep, stealth, chaos |
| `--evolve / --no-evolve` | `--evolve` | Enable/disable evolution engine |
| `--generations` | `5` | Number of evolution generations |
| `--module` | all | Specific attack module(s) to run |
| `-o, --output` | `html` | Report format: html, json, sarif, markdown, pdf |
| `--output-dir` | `./basilisk-reports` | Report output directory |
| `--no-dashboard` | false | Disable web dashboard |
| `--fail-on` | `high` | CI/CD fail threshold: critical, high, medium, low, info |
| `-v, --verbose` | false | Verbose output |
| `--debug` | false | Debug mode |
| `-c, --config` | — | YAML config file path |

### `basilisk recon`
Run reconnaissance only — fingerprint the target.

```
basilisk recon -t <target> [-p <provider>] [-k <api-key>]
```

### `basilisk replay <session_id>`
Replay a previous scan session.

```
basilisk replay <session_id> [--db <path>]
```

### `basilisk interactive`
Launch interactive REPL for manual + assisted red teaming.

```
basilisk interactive -t <target> [-p <provider>]
```

REPL commands: `/help`, `/recon`, `/attack <module>`, `/evolve`, `/findings`, `/export`, `/profile`, `/quit`

### `basilisk sessions`
List all saved scan sessions.

```
basilisk sessions [--db <path>]
```

### `basilisk modules`
List all available attack modules.

### `basilisk version`
Show version and system info.

## Environment Variables

| Variable | Provider |
|----------|----------|
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic |
| `GOOGLE_API_KEY` | Google |
| `AZURE_API_KEY` | Azure OpenAI |
| `BASILISK_API_KEY` | Fallback for any provider |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings above `--fail-on` threshold |
| `1` | Findings above threshold detected |
