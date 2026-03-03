<h1 align="center">🐍 Basilisk</h1>

<p align="center">
  <strong>Open-Source AI/LLM Red Teaming Framework with Genetic Prompt Evolution</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-red?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Modules-29-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Desktop-Electron-cyan?style=for-the-badge&logo=electron" />
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#attack-modules">Attack Modules</a> •
  <a href="#desktop-app">Desktop App</a> •
  <a href="#ci-cd-integration">CI/CD</a> •
  <a href="#docker">Docker</a> •
  <a href="https://basilisk.rothackers.com">Website</a>
</p>

---

```
     ██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
     ██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
     ██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝
     ██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗
     ██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
                    AI Red Teaming Framework
```

**Basilisk** is a production-grade offensive security framework for red teaming AI and LLM applications. It combines comprehensive **OWASP LLM Top 10** attack coverage with a novel genetic algorithm engine — **Smart Prompt Evolution (SPE-NL)** — that evolves prompt payloads across generations to discover novel bypasses no static tool can find.

Built by **[Regaan](https://rothackers.com)** — independent security researcher, founder of **[Rot Hackers](https://rothackers.com)**, and creator of **[WSHawk](https://wshawk.rothackers.com)** (WebSocket security scanner) and **[PoCSmith](https://github.com/noobforanonymous)** (exploit PoC generator).

🌐 **Website:** [basilisk.rothackers.com](https://basilisk.rothackers.com)
---

## Quick Start

```bash
# Install from PyPI
pip install basilisk-ai

# Scan an OpenAI-powered chatbot
export OPENAI_API_KEY="sk-..."
basilisk scan -t https://api.target.com/chat -p openai

# Quick scan — top payloads, no evolution
basilisk scan -t https://api.target.com/chat --mode quick

# Deep scan — 10 generations of evolution
basilisk scan -t https://api.target.com/chat --mode deep --generations 10

# Stealth mode — rate-limited, human-like timing
basilisk scan -t https://api.target.com/chat --mode stealth

# Recon only — fingerprint the target
basilisk recon -t https://api.target.com/chat -p openai

# CI/CD mode — SARIF output, fail on high severity
basilisk scan -t https://api.target.com/chat -o sarif --fail-on high
```

### Docker

```bash
docker pull rothackers/basilisk

docker run --rm -e OPENAI_API_KEY=sk-... rothackers/basilisk \
  scan -t https://api.target.com/chat --mode quick
```

---

## Features

### 🧬 Smart Prompt Evolution (SPE-NL)

The core differentiator. Genetic algorithms adapted for natural language attack payloads:

- **10 mutation operators** — synonym swap, encoding wrap, role injection, language shift, structure overhaul, fragment split, nesting, homoglyphs, context padding, token smuggling
- **5 crossover strategies** — single-point, uniform, prefix-suffix, semantic blend, best-of-both
- **Multi-signal fitness function** — refusal avoidance, information leakage, compliance scoring, novelty reward
- **Stagnation detection** with early breakthrough exit
- Payloads that fail get mutated, crossed, and re-evaluated — **surviving payloads get deadlier every generation**

### ⚔️ 29 Attack Modules

Full OWASP LLM Top 10 coverage across 8 attack categories. See [Attack Modules](#attack-modules) below.

### 🔍 5 Reconnaissance Modules

- **Model Fingerprinting** — identifies GPT-4, Claude, Gemini, Llama, Mistral via response patterns and timing
- **Guardrail Profiling** — systematic probing across 8 content categories
- **Tool/Function Discovery** — enumerates available tools and API schemas
- **Context Window Measurement** — determines token limits
- **RAG Pipeline Detection** — identifies retrieval-augmented generation setups

### 📊 5 Report Formats

| Format | Use Case |
|--------|----------|
| **HTML** | Dark-themed report with expandable findings, conversation replay, severity charts |
| **SARIF 2.1.0** | CI/CD integration — GitHub Code Scanning, DefectDojo, Azure DevOps |
| **JSON** | Machine-readable, full metadata |
| **Markdown** | Documentation-ready, commit-friendly |
| **PDF** | Client deliverables (weasyprint / reportlab / text fallback) |

### 🌐 Universal Provider Support

Via `litellm` + custom adapters:
- **Cloud** — OpenAI, Anthropic, Google, Azure, AWS Bedrock
- **Local** — Ollama, vLLM, llama.cpp
- **Custom** — any HTTP REST API or WebSocket endpoint
- **WSHawk** — pairs with WSHawk for WebSocket-based AI testing

### 🖥️ Electron Desktop App

Enterprise-grade desktop GUI with:
- Real-time scan visualization via WebSocket
- Module browser with OWASP mapping
- Session management with replay
- One-click report export
- Custom title bar with dark theme
- Cross-platform: Windows (.exe), macOS (.dmg), Linux (.AppImage/.deb/.rpm/.pacman)

### ⚡ Native C/Go Extensions

Performance-critical operations compiled to native code:
- **C** — fast payload encoding (base64, hex, URL), approximate token counting
- **Go** — concurrent HTTP fuzzer, parallel pattern matching

---

## Attack Modules

| Category | Modules | OWASP | Description |
|----------|---------|-------|-------------|
| **Prompt Injection** | Direct, Indirect, Multilingual, Encoding, Split | LLM01 | Override system instructions via user input |
| **System Prompt Extraction** | Role Confusion, Translation, Simulation, Gradient Walk | LLM06 | Extract confidential system prompts |
| **Data Exfiltration** | Training Data, RAG Data, Tool Schema | LLM06 | Extract PII, documents, and API keys |
| **Tool/Function Abuse** | SSRF, SQLi, Command Injection, Chained | LLM07/08 | Exploit tool-use capabilities for lateral movement |
| **Guardrail Bypass** | Roleplay, Encoding, Logic Trap, Systematic | LLM01/09 | Circumvent content safety filters |
| **Denial of Service** | Token Exhaustion, Context Bomb, Loop Trigger | LLM04 | Resource exhaustion and infinite loops |
| **Multi-Turn Manipulation** | Gradual Escalation, Persona Lock, Memory Manipulation | LLM01 | Progressive trust exploitation over conversations |
| **RAG Attacks** | Poisoning, Document Injection, Knowledge Enumeration | LLM03/06 | Compromise retrieval-augmented generation pipelines |

---

## Scan Modes

| Mode | Description | Evolution | Speed |
|------|-------------|-----------|-------|
| `quick` | Top 50 payloads per module, no evolution | ✗ | ⚡ Fast |
| `standard` | Full payloads, 5 generations of evolution | ✓ | 🔄 Normal |
| `deep` | Full payloads, 10+ generations, multi-turn chains | ✓✓ | 🐢 Thorough |
| `stealth` | Rate-limited, human-like timing delays | ✓ | 🥷 Stealthy |
| `chaos` | Everything parallel, maximum evolution pressure | ✓✓✓ | 💥 Aggressive |

---

## CLI Reference

```bash
basilisk scan          # Full red team scan
basilisk recon         # Fingerprint target only
basilisk replay <id>   # Replay a saved session
basilisk interactive   # Manual REPL with assisted attacks
basilisk modules       # List all 29 attack modules
basilisk sessions      # List saved scan sessions
basilisk version       # Version and system info
```

See full [CLI documentation](docs/cli-reference.md).

---

## Configuration

```yaml
# basilisk.yaml
target:
  url: https://api.target.com/chat
  provider: openai
  model: gpt-4
  api_key: ${OPENAI_API_KEY}

mode: standard

evolution:
  enabled: true
  population_size: 100
  generations: 5
  mutation_rate: 0.3
  crossover_rate: 0.5

output:
  format: html
  output_dir: ./reports
  include_conversations: true
```

```bash
basilisk scan -c basilisk.yaml
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: AI Security Scan
  run: |
    pip install basilisk-ai
    basilisk scan -t ${{ secrets.TARGET_URL }} -o sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: basilisk-reports/*.sarif
```

### GitLab CI

```yaml
ai-security:
  image: rothackers/basilisk
  script:
    - basilisk scan -t $TARGET_URL -o sarif --fail-on high
  artifacts:
    reports:
      sast: basilisk-reports/*.sarif
```

---

## Desktop App

The Electron desktop app provides a full GUI experience:

```bash
cd desktop
npm install
npx electron .
```

For production builds (no Python required — backend is compiled via PyInstaller):

```bash
chmod +x build-desktop.sh
./build-desktop.sh
```

Output in `desktop/dist/` — ready for distribution.

---

## Architecture

```
basilisk/
├── core/          # Engine: session, config, database, findings, profiles
├── providers/     # LLM adapters: litellm, custom HTTP, WebSocket
├── evolution/     # SPE-NL: genetic algorithm, operators, fitness, crossover
├── recon/         # Fingerprinting, guardrails, tools, context, RAG detection
├── attacks/       # 8 categories, 29 modules
│   ├── injection/       # LLM01 — 5 modules
│   ├── extraction/      # LLM06 — 4 modules
│   ├── exfil/           # LLM06 — 3 modules
│   ├── toolabuse/       # LLM07/08 — 4 modules
│   ├── guardrails/      # LLM01/09 — 4 modules
│   ├── dos/             # LLM04 — 3 modules
│   ├── multiturn/       # LLM01 — 3 modules
│   └── rag/             # LLM03/06 — 3 modules
├── payloads/      # 6 YAML payload databases
├── cli/           # Click + Rich terminal interface
├── report/        # HTML, JSON, SARIF, Markdown, PDF generators
└── desktop_backend.py   # FastAPI sidecar for Electron app
desktop/           # Electron desktop application
native/            # C and Go performance extensions
```

---

## Documentation

- [Getting Started](docs/getting-started.md) — Installation, first scan, quickstart
- [Architecture](docs/architecture.md) — System design, module overview, data flow
- [CLI Reference](docs/cli-reference.md) — All commands and options
- [Attack Modules](docs/attack-modules.md) — Detailed module documentation
- [Evolution Engine](docs/evolution-engine.md) — SPE-NL genetic mutation system
- [Reporting](docs/reporting.md) — Report formats and CI/CD integration
- [API Reference](docs/api-reference.md) — Desktop backend API endpoints

---

## About the Creator

**Basilisk** is built by **[Regaan](https://rothackers.com)** — an independent security researcher and the founder of **[Rot Hackers](https://rothackers.com)**. Every tool under the Rot Hackers banner is built solo, from architecture to deployment.

Other projects by Regaan:
- **[WSHawk](https://wshawk.rothackers.com)** — Enterprise-grade WebSocket security scanner and web pentest toolkit
- **[PoCSmith](https://github.com/noobforanonymous)** — Automated exploit Proof-of-Concept generator
- **[Rot Hackers Platform](https://rothackers.com)** — Open-source offensive security tool hub

> *"I build offensive security tools that actually work. No corporate bloat, no team overhead — just clean code that ships."* — Regaan

---

## Legal

Basilisk is designed for **authorized security testing only**. Always obtain proper written authorization before testing AI systems you do not own. Unauthorized use may violate computer fraud and abuse laws in your jurisdiction.

The authors assume no liability for misuse of this tool.

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>Built with 🐍 by <a href="https://rothackers.com">Regaan</a></strong> — Founder of Rot Hackers | <a href="https://basilisk.rothackers.com">basilisk.rothackers.com</a>
</p>
