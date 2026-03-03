# Getting Started with Basilisk

## Installation

### From PyPI (recommended)
```bash
pip install basilisk-ai
```

### From Source
```bash
git clone https://github.com/noobforanonymous/basilisk.git
cd basilisk
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```

### Docker
```bash
docker pull rothackers/basilisk
docker run --rm rothackers/basilisk scan --target https://target.com/api/chat
```

## Prerequisites

- Python 3.11+
- An API key for your target LLM provider (OpenAI, Anthropic, Google, etc.)
- Network access to the target endpoint

## Your First Scan

### 1. Set your API key
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

### 2. Run a quick scan
```bash
basilisk scan --target https://api.openai.com/v1/chat/completions \
              --provider openai \
              --mode quick \
              --output html
```

### 3. View results
Open `./basilisk-reports/basilisk_<session_id>_<timestamp>.html` in your browser.

## Scan Modes

| Mode | Description | Speed | Depth |
|------|-------------|-------|-------|
| `quick` | Top 50 payloads per module, no evolution | ⚡Fast | Shallow |
| `standard` | Full payloads, 3 generations of evolution | ⏱️ Medium | Moderate |
| `deep` | Full payloads, 10+ generations, multi-turn | 🐢 Slow | Thorough |
| `stealth` | Rate-limited, human-like timing | 🐢 Slow | Moderate |
| `chaos` | Everything parallel, max evolution | ⚡Variable | Maximum |

## Using Config Files

Instead of CLI flags, you can use a YAML config file:

```yaml
# targets/production.yaml
target:
  url: https://api.your-ai.com/v1/chat
  provider: openai
  model: gpt-4-turbo

mode: standard

evolution:
  enabled: true
  generations: 5
  population_size: 100

output:
  format: html
  output_dir: ./reports
```

```bash
basilisk scan --config targets/production.yaml
```

## CI/CD Integration

```bash
# Exit code is non-zero if findings match --fail-on threshold
basilisk scan --target $AI_ENDPOINT \
              --mode quick \
              --output sarif \
              --fail-on high
```

The SARIF output can be uploaded to GitHub Security tab via the `github/codeql-action/upload-sarif` action.

## Interactive Mode

For manual exploration and assisted testing:

```bash
basilisk interactive --target https://api.target.com/v1/chat --provider openai
```

Commands:
- Type any message to send to the target
- `/recon` — run reconnaissance
- `/attack injection` — run a specific attack module
- `/findings` — view current findings
- `/export html` — generate a report
- `/quit` — exit

## Desktop App

Basilisk also includes an Electron desktop application:

```bash
cd desktop
npm install
npx electron .
```

The desktop app provides a full GUI with real-time scan visualization, module browser, session management, and report generation.

## Next Steps

- Read the [Architecture Guide](architecture.md) to understand how Basilisk works
- Review [Attack Modules](attack-modules.md) for detailed module documentation
- Check [Evolution Engine](evolution-engine.md) for the genetic mutation system
