# Basilisk — Open-Source AI Red Teaming Framework

> **Basilisk** is an open-source AI red teaming and LLM security testing framework. It automates adversarial prompt testing against ChatGPT, Claude, Gemini, Grok, and any LLM API using genetic prompt evolution. Built for security researchers, penetration testers, and AI safety engineers who need to find vulnerabilities in AI systems before attackers do.

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.1.0-red?style=for-the-badge" alt="Basilisk version 1.1.0" />
  <img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=for-the-badge" alt="License: AGPL-3.0" />
   <a href="https://doi.org/10.5281/zenodo.18909538"><img src="https://img.shields.io/badge/DOI-10.5281%2Fzenodo.18909538-blue?style=for-the-badge" alt="Zenodo DOI"></a>
  <a href="https://doi.org/10.6084/m9.figshare.31566853"><img src="https://img.shields.io/badge/Mirror-10.6084%2Fm9.figshare.31566853-emerald?style=for-the-badge" alt="Figshare DOI"></a>
  <a href="https://doi.org/10.17605/OSF.IO/H7BVR"><img src="https://img.shields.io/badge/DOI-10.17605%2FOSF.IO%2FH7BVR-lightgrey?style=for-the-badge" alt="OSF DOI"></a>
  <img src="https://img.shields.io/badge/Adoption-110+_Active_Users-blueviolet?style=for-the-badge&logo=github" alt="Adoption: 110+ Users" />
</p>

<p align="center">
  <b>Basilisk</b> is an industrial-strength, open-source AI red teaming framework designed to stress-test LLM security filters through advanced genetic prompt evolution. It automates the discovery of jailbreaks, data exfiltration vulnerabilities, and logic bypasses with forensic precision.
</p>

---

<div align="center">
  <img src="assets/demo.gif" alt="Basilisk AI Red Teaming Demo - Genetic Prompt Evolution Dashboard" style="border-radius: 12px; margin: 20px 0; max-width: 100%; border: 1px solid #1f1f27;" />
  <p><i>Basilisk v1.1.0 — Automated LLM Jailbreaking & Security Testing</i></p>
  <a href="https://youtu.be/sgFcM1y_omY">
    <img src="https://img.shields.io/badge/Watch-Full%20Demo%20on%20YouTube-red?style=for-the-badge&logo=youtube" alt="Basilisk YouTube Demo" />
  </a>
</div>

### Key Features Shown in Demo

*   **Genetic Prompt Evolution**: Automated mutation engine for high-success jailbreaks.
*   **Differential Mode**: Side-by-side behavioral comparison across providers.
*   **Guardrail Posture Scan**: Non-destructive A+ to F security grading.
*   **Visual Feedback Engine**: Real-time toast notifications and interactive logs.
*   **Forensic Audit Reports**: Export findings in HTML, JSON, and SARIF formats.

<p align="center">
  <a href="https://github.com/regaan/basilisk/actions/workflows/build.yml"><img src="https://github.com/regaan/basilisk/actions/workflows/build.yml/badge.svg" alt="Build Desktop" /></a>
  <a href="https://github.com/regaan/basilisk/actions/workflows/docker-build.yml"><img src="https://github.com/regaan/basilisk/actions/workflows/docker-build.yml/badge.svg" alt="Docker" /></a>
  <a href="https://github.com/regaan/basilisk/actions/workflows/python-publish.yml"><img src="https://github.com/regaan/basilisk/actions/workflows/python-publish.yml/badge.svg" alt="PyPI" /></a>
  <a href="https://github.com/marketplace/actions/basilisk-ai-security-scan"><img src="https://img.shields.io/badge/Marketplace-Action-blue?logo=github" alt="GitHub Marketplace" /></a>
</p>

<p align="center">
  <a href="#what-is-basilisk">What is Basilisk?</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#whats-new-in-v110">What's New</a> •
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
                    AI Red Teaming Framework v1.1.0
```

## What is Basilisk?

**Basilisk** is a production-grade, open-source offensive security framework purpose-built for **AI red teaming** and **LLM penetration testing**. It is the first automated red teaming tool to combine full **OWASP LLM Top 10** attack coverage with a genetic algorithm engine called **Smart Prompt Evolution (SPE-NL)** that evolves adversarial prompt payloads across generations to discover novel AI vulnerabilities and jailbreaks that no static tool can find.

Whether you are testing **OpenAI GPT-4o**, **Anthropic Claude**, **Google Gemini**, **xAI Grok**, **Meta Llama**, or any custom LLM endpoint, Basilisk provides 32 attack modules, 5 recon modules, differential multi-model scanning, guardrail posture grading, and forensic audit logging out of the box.

### Why Basilisk?

- **Automated AI Red Teaming**: Stop manually copy-pasting jailbreak prompts. Basilisk evolves thousands of adversarial payloads automatically.
- **Genetic Prompt Evolution**: The SPE-NL engine mutates, crosses over, and scores prompts like biological organisms, finding bypasses humans would never think of.
- **Full OWASP LLM Top 10 Coverage**: 32 modules covering prompt injection, system prompt extraction, data exfiltration, tool abuse, guardrail bypass, denial of service, multi-turn manipulation, and RAG attacks.
- **Works with Every LLM Provider**: OpenAI, Anthropic, Google, xAI (Grok), Groq, Azure, AWS Bedrock, GitHub Models, Ollama, vLLM, and any custom HTTP/WebSocket endpoint.
- **CI/CD Ready**: Native GitHub Action with SARIF output for automated AI security testing in your pipeline.
- **Desktop App**: Full Electron GUI for visual red teaming with real-time scan dashboards.

Built by **[Regaan](https://regaan.rothackers.com)**, Lead Researcher at **[ROT Independent Security Research Lab](https://rothackers.com)**, and creator of **[WSHawk](https://wshawk.rothackers.com)**.

🌐 **Website:** [basilisk.rothackers.com](https://basilisk.rothackers.com)

---

## Quick Start

```bash
# Install Basilisk from PyPI
pip install basilisk-ai

# Full AI red team scan against an OpenAI chatbot
export OPENAI_API_KEY="sk-..."
basilisk scan -t https://api.target.com/chat -p openai

# Quick scan — top payloads, no evolution
basilisk scan -t https://api.target.com/chat --mode quick

# Deep scan — 10 generations of genetic prompt evolution
basilisk scan -t https://api.target.com/chat --mode deep --generations 10

# Stealth mode — rate-limited, human-like timing
basilisk scan -t https://api.target.com/chat --mode stealth

# Recon only — fingerprint the target LLM
basilisk recon -t https://api.target.com/chat -p openai

# Guardrail posture check (no attacks, safe for production)
basilisk posture -p openai -m gpt-4o -v

# Differential scan across AI providers
basilisk diff -t openai:gpt-4o -t anthropic:claude-3-5-sonnet-20241022

# Use GitHub Models (FREE — no API key purchase required!)
export GH_MODELS_TOKEN="ghp_..."   # github.com/settings/tokens → models:read
basilisk scan -t https://api.target.com/chat -p github -m gpt-4o

# CI/CD mode — SARIF output, fail on high severity
basilisk scan -t https://api.target.com/chat -o sarif --fail-on high
```

## Zero-Setup Live Demo

Want to see Basilisk in action right now without configuring API keys? We maintain an **intentionally vulnerable** LLM target for security testing:

**Target URL:** `https://basilisk-vulnbot.onrender.com/v1/chat/completions`

Run a quick scan against it immediately:
```bash
# No API keys required for this target!
basilisk scan -t https://basilisk-vulnbot.onrender.com/v1/chat/completions -p custom --model vulnbot-1.0 --mode quick
```

Or use the **Desktop App**:
1. Open the **New Scan** tab.
2. Set **Endpoint URL** to `https://basilisk-vulnbot.onrender.com/v1/chat/completions`.
3. Set **Provider** to `Custom HTTP`.
4. Set **Model** to `vulnbot-1.0`.
5. Click **Start Scan**.

Watch as Basilisk's genetic engine discovers 30+ vulnerabilities in real-time, including prompt injections, system leakage, and tool abuse.


### Docker

```bash
docker pull rothackers/basilisk

docker run --rm -e OPENAI_API_KEY=sk-... rothackers/basilisk \
  scan -t https://api.target.com/chat --mode quick
```

---

## Features

### Smart Prompt Evolution (SPE-NL)

The core differentiator. Genetic algorithms adapted for natural language attack payloads:

- **15 mutation operators** — synonym swap, encoding wrap, role injection, language shift, structure overhaul, fragment split, nesting, homoglyphs, context padding, token smuggling, role assumption, temporal anchoring, nested context, authority tone
- **5 crossover strategies** — single-point, uniform, prefix-suffix, semantic blend, best-of-both
- **Multi-signal fitness function** — refusal avoidance, information leakage, compliance scoring, novelty reward
- **Population diversity tracking** — Jaccard distance sampling to prevent convergence collapse
- **Stagnation detection** with adaptive mutation rate and early breakthrough exit
- Payloads that fail get mutated, crossed, and re-evaluated — **surviving payloads get deadlier every generation**

### 32 Attack Modules

Full OWASP LLM Top 10 coverage across 8 attack categories + 3 multi-turn specialist modules. See [Attack Modules](#attack-modules) below.

### 5 Reconnaissance Modules

- **Model Fingerprinting** — identifies GPT-4, Claude, Gemini, Llama, Mistral via response patterns and timing
- **Guardrail Profiling** — systematic probing across 8 content categories
- **Tool/Function Discovery** — enumerates available tools and API schemas
- **Context Window Measurement** — determines token limits
- **RAG Pipeline Detection** — identifies retrieval-augmented generation setups

### Differential Testing

Compare model behavior across providers — a feature nobody else has:
- Run identical probes against OpenAI, Anthropic, Google, xAI (Grok), Azure, Ollama simultaneously
- Detect divergences where some models refuse but others comply
- Per-model resistance rate scoring

### Guardrail Posture Assessment

Production-safe, recon-only security grading:
- A+ through F posture grades
- 8 categories with 3-tier probing (benign/moderate/adversarial)
- Actionable recommendations

### Forensic Audit Logging

Tamper-evident audit trails enabled by default:
- JSONL with SHA-256 chain integrity
- Automatic secret redaction
- Every prompt, response, finding, and error logged

### 5 Report Formats

| Format | Use Case |
|--------|----------|
| **HTML** | Dark-themed report with expandable findings, conversation replay, severity charts |
| **SARIF 2.1.0** | CI/CD integration — GitHub Code Scanning, DefectDojo, Azure DevOps |
| **JSON** | Machine-readable, full metadata |
| **Markdown** | Documentation-ready, commit-friendly |
| **PDF** | Client deliverables (weasyprint / reportlab / text fallback) |

### Universal Provider Support

Via `litellm` + custom adapters:
- **Cloud** — OpenAI, Anthropic, Google, xAI (Grok), Groq, Azure, AWS Bedrock
- **GitHub Models** — **FREE** access to GPT-4o, o1, and more via `github.com/marketplace/models`
- **Local** — Ollama, vLLM, llama.cpp
- **Custom** — any HTTP REST API or WebSocket endpoint
- **WSHawk** — pairs with WSHawk for WebSocket-based AI testing

### Electron Desktop App

Enterprise-grade desktop GUI with:
- Real-time scan visualization via WebSocket
- **Differential scan** tab with multi-model comparison
- **Guardrail posture** tab with live A+-F grading
- **Audit trail** viewer with integrity verification
- Module browser with OWASP mapping
- Session management with replay
- One-click report export
- Custom title bar with dark theme
- Cross-platform: Windows (.exe), macOS (.dmg), Linux (.AppImage/.deb/.rpm/.pacman)

### Native C/Go Extensions

Performance-critical operations compiled to native code with Python fallbacks:
- **C** — fast BPE token estimation, Shannon entropy, Levenshtein distance, confusable detection, BMH substring search, payload encoding (base64, hex, ROT13, URL, Unicode)
- **Go** — 15 mutation operators (including 4 multi-turn aware), 3 crossover modes, batch mutation, population diversity scoring, Aho-Corasick multi-pattern matching, refusal/compliance/sensitive data detection

---

## What's New in v1.1.0

### xAI Grok Provider Support (New)
- **Grok-2 and Grok-beta** — Full support for xAI's Grok models via the Grok API
- Set `XAI_API_KEY` and scan with `-p xai -m grok-2`
- Differential scan support: compare Grok against GPT-4o, Claude, and Gemini side-by-side
- Desktop app provider dropdown and model suggestions updated

### Security Hardening
- **CORS lockdown** — Backend restricted to localhost-only origins (was `*`)
- **API key isolation** — Keys stored in-memory, never leaked to `os.environ`
- **Concurrency safety** — `asyncio.Lock` protecting shared WebSocket and scan state
- **Streaming error fix** — Provider errors logged instead of yielded as fake content
- **Preload bypass closed** — Electron `window.api` shim now enforces channel allowlist
- **Refusal detection centralized** — Single source of truth for Python and Go paths
- **Audit log improvement** — Auto-generated secrets emit a `WARNING` with save instructions

### Multi-Turn Attack Modules
- **Prompt Cultivation** — 5-phase conversational attack chain (baseline → paradox → sleeper → cultivation → loop_close) with 7 adaptive scenarios and guardrail drift monitoring. *(Concept by [@TheMadhAtter464](https://github.com/TheMadhAtter464))*
- **Authority Escalation** — Progressive authority impersonation across turns with role-stacking and compliance detection
- **Sycophancy Exploitation** — Leverages LLM agreement bias through escalating agreement sequences with acceptance scoring

### Evolution Engine Upgrades
- **Population Statistics** — Track mean fitness, diversity scores, stagnation counters, and mutation rates across generations
- **Diversity Tracking** — Jaccard distance sampling across population to detect convergence collapse
- **Tournament Selection** — `k`-tournament selection for parent picking with configurable pressure
- **4 New Native Mutations** — Role assumption, temporal anchoring, nested context injection, authority tone escalation (Go, 10-100x faster)
- **Population Diversity Scorer** — Native Go `BasiliskPopulationDiversity` for real-time diversity measurement during evolution

### Desktop App Enhancements
- **Multi-Turn Breakdown Panel** — Scenario/sequence counts for cultivation, authority escalation, and sycophancy with feature comparison matrix
- **Evolution KPI Dashboard** — Real-time mean fitness, diversity %, stagnation counter, and mutation rate during scans
- **Engine Capabilities View** — Metaphor vocabulary size, opener/closer variant counts, and feature tags
- **Backend Proxies** — IPC handlers for `/api/modules/multiturn` and `/api/evolution/operators`
- **PDF Export** — Added PDF to report export dialog filters
- **Error Resilience** — Uncaught exception and unhandled rejection handlers for crash prevention
- **Modular Renderer** — Split 1000+ line monolith into 6 focused modules (core, scan, modules, sessions, advanced, updates)

### CLI Improvements
- **Help Command** — `basilisk help [topic]` with 6 topic guides: overview, scan, modules, evolution, diff, examples
- **Enhanced Modules List** — Category filtering, JSON output, numbered rows, severity coloring, and category summary

### Native Extensions
- **Full Python Bindings** — Complete ctypes bridge (`native_bridge.py`) with wrappers and pure Python fallbacks for all 4 shared libraries
- **Compliance Detection** — New Aho-Corasick matcher with 20 capitulation indicators for detecting bypassed guardrails
- **Extended Patterns** — 40 refusal patterns (11 multi-turn aware), 27 sensitive data patterns (AWS/Azure/GCP/SSH/JWT)
- **Build Verification** — `./build.sh verify` validates compiled libraries and exported symbols, `./build.sh info` shows module details

### Infrastructure
- **Version bump** to v1.1.0 across all 12 project files
- **PyInstaller spec** updated with multi-turn module hidden imports
- **Keyboard shortcuts** updated: Ctrl+5 = Evolution, Ctrl+8 = Posture

## What's New in v1.0.6

### Enhanced Evolution Breakthroughs
- **High-Sensitivity Detection** — The SPE-NL engine now recognizes and reports "Relative Breakthroughs." It no longer waits for a perfect 1.0 fitness score but alerts you the moment it finds a significant improvement (fitness >= 0.7) that breaks previous defenses.
- **Real-Time Progress Logging** — Added detailed console logging for every breakthrough discovered during the evolution phase, ensuring the user is never left in the dark during long scans.
- **Optimized Fitness Logic** — Refined the mutation scoring to better detect "Authority Deception" and "Obfuscation" tactics used by the attacker brain.

### Stability and Bug Fixes
- **CLI Logging Fix** — Resolved a `NameError` in the evolution stats logger that caused occasional crashes at the end of generations.
- **Version Alignment** — Synchronized versioning across the Core Engine, Desktop Backend, Docker, and Electron UI to 1.0.6.

## What's New in v1.0.5
- **Protective Open Source** — To ensure Basilisk remains a property of the community and Rot Hackers, we have transitioned from MIT to the **Affero General Public License (AGPL-3.0)**. This protects against predatory proprietary forks and ensures all hosted improvements are contributed back.

### Visual Feedback Engine
- **Toast Notifications** — Real-time non-intrusive alerts for scan status, errors, and success events.
- **Auto-Open Reports** — Reports now automatically launch in your default system browser (Brave, Chrome, Firefox) immediately after generation.

### Differential Mode (v1.0.3)
Compare how different LLM providers respond to the same attacks side-by-side. Detects behavioral divergences where one model refuses but another complies, exposing provider-specific weaknesses.

### Guardrail Posture Scan (v1.0.3)
Non-destructive recon-only security assessment. Produces an **A+ to F security grade** without running any active attacks. CISO-friendly and safe for production.

```bash
basilisk posture -p openai -m gpt-4o -v
```

- 8 guardrail categories probed (prompt injection, content filtering, data boundary, role manipulation, etc.)
- Each category tested benign → moderate → adversarial
- Strength classification: None, Weak, Moderate, Strong, Aggressive
- Actionable recommendations for weak spots and over-filtering

### Default Audit Logging

Forensic-grade, tamper-evident audit trails are now **on by default** for every scan. Every prompt sent, response received, and finding discovered is logged with SHA-256 chain integrity.

- JSONL format with checksummed entries
- API keys automatically redacted
- Disable with `BASILISK_AUDIT=0` environment variable
- View in the desktop app's Audit tab or via `GET /api/audit/{session_id}`

### CI/CD GitHub Action

First-class GitHub Action for pipeline integration with SARIF baseline regression detection.

```yaml
- uses: regaan/basilisk@main
  with:
    target: 'https://api.yourapp.com/chat'
    api-key: ${{ secrets.OPENAI_API_KEY }}
    mode: 'quick'
    fail-on: 'high'
    output: 'sarif'
    baseline: './baseline.sarif'
```

- Full scan or posture-only mode
- Automatic SARIF upload to GitHub Security tab
- Baseline regression detection (fails pipeline on new findings)
- Report artifacts uploaded automatically

### Desktop App Enhancements (v1.0.3)

Three new tabs added to the Electron desktop application:

- **Diff** — multi-model comparison with dynamic target input
- **Posture** — guardrail assessment with live grade display
- **Audit** — session audit trail viewer with integrity verification

### GitHub Community Files

- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 with responsible security tooling section
- `CONTRIBUTING.md` — development setup, PR process, coding standards, module creation guide
- `SECURITY.md` — vulnerability disclosure policy with SLAs
- `.github/PULL_REQUEST_TEMPLATE.md` — OWASP-mapped PR template

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
| **Multi-Turn Specialist** | Prompt Cultivation, Authority Escalation, Sycophancy | LLM01 | Advanced multi-phase conversational attacks with adaptive monitoring |
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
basilisk scan            # Full AI red team scan
basilisk recon           # Fingerprint target LLM
basilisk diff            # Differential scan across AI models
basilisk posture         # Guardrail posture assessment
basilisk replay <id>     # Replay a saved session
basilisk interactive     # Manual REPL with assisted attacks
basilisk modules         # List all 32 attack modules
basilisk sessions        # List saved scan sessions
basilisk help [topic]    # Topic guides: overview, scan, modules, evolution, diff, examples
basilisk version         # Version and system info
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

### GitHub Actions (Recommended — Native Action)

```yaml
name: AI Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  basilisk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Basilisk AI Security Scan
        uses: regaan/basilisk@main
        with:
          target: ${{ secrets.TARGET_URL }}
          api-key: ${{ secrets.OPENAI_API_KEY }}
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          google-api-key: ${{ secrets.GOOGLE_API_KEY }}
          provider: openai
          mode: quick
          fail-on: high
          output: sarif
          # Optional: detect regressions against a committed baseline
          # baseline: ./security/baseline.sarif
```

**Using GitHub Models (FREE — no API key purchase required):**

```yaml
      - name: Basilisk AI Security Scan (Free via GitHub Models)
        uses: regaan/basilisk@main
        with:
          target: ${{ secrets.TARGET_URL }}
          provider: github
          github-token: ${{ secrets.GH_MODELS_TOKEN }}
          model: gpt-4o-mini    # Best for CI/CD: fast + highest free rate limit
          mode: quick
          fail-on: high
          output: sarif
```

> **Tip:** You can use GitHub Models for free. Go to [github.com/marketplace/models](https://github.com/marketplace/models), create a [personal access token](https://github.com/settings/tokens) with `models:read` permission, and save it as a repository secret named `GH_MODELS_TOKEN`.

**Required GitHub Secrets:**

| Secret | Provider | Required |
|--------|----------|----------|
| `OPENAI_API_KEY` | OpenAI (GPT-4, etc.) | If using OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic (Claude) | If using Anthropic |
| `GOOGLE_API_KEY` | Google (Gemini) | If using Google |
| `XAI_API_KEY` | xAI (Grok) | If using Grok |
| `GH_MODELS_TOKEN` | GitHub Models (GPT-4o, o1, etc.) | If using GitHub Models (**FREE**) |

You only need the secret for whichever provider you're scanning against.

### GitHub Actions (Manual)

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

The Electron desktop app provides a full GUI experience for AI red teaming:

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
├── core/          # Engine: session, config, database, findings, profiles, audit
├── providers/     # LLM adapters: litellm, custom HTTP, WebSocket
├── evolution/     # SPE-NL: genetic algorithm, operators, fitness, crossover
├── recon/         # Fingerprinting, guardrails, tools, context, RAG detection
├── attacks/       # 8 categories, 32 modules
│   ├── injection/       # LLM01 — 5 modules
│   ├── extraction/      # LLM06 — 4 modules
│   ├── exfil/           # LLM06 — 3 modules
│   ├── toolabuse/       # LLM07/08 — 4 modules
│   ├── guardrails/      # LLM01/09 — 4 modules
│   ├── dos/             # LLM04 — 3 modules
│   ├── multiturn/       # LLM01 — 6 modules (3 base + 3 specialist)
│   └── rag/             # LLM03/06 — 3 modules
├── payloads/      # 6 YAML payload databases
├── cli/           # Click + Rich terminal interface
├── report/        # HTML, JSON, SARIF, Markdown, PDF generators
├── native_bridge.py     # ctypes bindings for C/Go shared libraries
├── differential.py      # Multi-model comparison engine
├── posture.py           # Guardrail posture scanner
└── desktop_backend.py   # FastAPI sidecar for Electron app
desktop/           # Electron desktop application
native/            # C and Go performance extensions (4 shared libraries)
│   ├── c/               # Token analyzer + payload encoder
│   └── go/              # Fuzzer (15 mutations) + matcher (Aho-Corasick)
action.yml         # GitHub Action for CI/CD
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
- [Contributing](CONTRIBUTING.md) — Development setup, PR process, coding standards
- [Security Policy](SECURITY.md) — Vulnerability disclosure and supported versions
- [Code of Conduct](CODE_OF_CONDUCT.md) — Community guidelines

---

## Frequently Asked Questions

### What is Basilisk used for?
Basilisk is used for automated AI red teaming and LLM security testing. It finds vulnerabilities like prompt injection, jailbreaks, data leakage, and guardrail bypasses in AI applications powered by GPT-4, Claude, Gemini, Grok, Llama, and other large language models.

### How is Basilisk different from other AI security tools?
Basilisk is the only open-source tool that uses **genetic prompt evolution** to automatically discover new attack vectors. Instead of relying on a static list of known jailbreaks, it evolves adversarial prompts across generations, finding bypasses that no human or static fuzzer would discover.

### Does Basilisk work with local models?
Yes. Basilisk supports Ollama, vLLM, llama.cpp, and any custom HTTP or WebSocket endpoint. You can red team your self-hosted Llama, Mistral, or any open-weight model.

### Does Basilisk support xAI Grok?
Yes. As of v1.1.0, Basilisk has full support for xAI's Grok models (Grok-2, Grok-beta). Set `XAI_API_KEY` and scan with `basilisk scan -p xai -m grok-2`. You can also use Grok in differential mode to compare its behavior against GPT-4, Claude, and Gemini.

### Is Basilisk free?
Yes. Basilisk is fully open-source under the AGPL-3.0 license with zero restrictions on private security testing use.

### Can I use Basilisk in CI/CD pipelines?
Yes. Basilisk ships with a native GitHub Action and SARIF report output, making it easy to integrate automated AI security scanning into your CI/CD workflow with baseline regression detection.

---

## About the Creator

**Basilisk** is built by **[Regaan](https://regaan.rothackers.com)**, Lead Researcher at the **[ROT Independent Security Research Lab](https://rothackers.com)**. Every tool under the Rot Hackers banner is built to bridge the gap between academic research and production-grade offensive artifacts.

> *"I build offensive security tools that actually work. No corporate bloat, no team overhead — just clean code that ships."* — Regaan

---

## Citation

If you use Basilisk in your research or wish to cite the framework, please use the following BibTeX entry:

```bibtex
@misc{regaan2026basilisk,
  author       = {Regaan},
  title        = {Basilisk: An Evolutionary AI Red-Teaming Framework for Systematic Security Evaluation of Large Language Models},
  year         = {2026},
  version      = {1.1.0},
  publisher    = {ROT Independent Security Research Lab},
  doi          = {10.5281/zenodo.18909538},
  url          = {https://doi.org/10.5281/zenodo.18909538}
}
```

Full research paper archived at:
- **Zenodo**: [https://doi.org/10.5281/zenodo.18909538](https://doi.org/10.5281/zenodo.18909538)
- **Figshare (Mirror)**: [https://doi.org/10.6084/m9.figshare.31566853](https://doi.org/10.6084/m9.figshare.31566853)
- **OSF (Mirror)**: [https://doi.org/10.17605/OSF.IO/H7BVR](https://doi.org/10.17605/OSF.IO/H7BVR)

## Legal

Basilisk is designed for **authorized security testing only**. Always obtain proper written authorization before testing AI systems you do not own. Unauthorized use may violate computer fraud and abuse laws in your jurisdiction.

The authors assume no liability for misuse of this tool.

## License

AGPL-3.0 License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>Built with 🐍 by <a href="https://rothackers.com">Regaan</a></strong> — Founder of Rot Hackers | <a href="https://basilisk.rothackers.com">basilisk.rothackers.com</a>
</p>
