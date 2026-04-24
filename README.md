# Basilisk - Open-Source AI Red Teaming Framework

> **Basilisk** is an open-source AI red teaming and LLM security testing framework. It automates adversarial prompt testing against Claude, Gemini, Grok, GPT-family models, local model runtimes, and custom LLM APIs using evolutionary prompt search. Built for security researchers, penetration testers, and defensive teams that need repeatable adversarial testing against LLM applications.

> 📄 Research Paper: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6373439
> 📌 DOI: https://doi.org/10.2139/ssrn.6373439

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-red?style=for-the-badge" alt="Basilisk version 2.0.0" />
  <img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=for-the-badge" alt="License: AGPL-3.0" />
  <a href="https://doi.org/10.5281/zenodo.18909538"><img src="https://img.shields.io/badge/DOI-10.5281%2Fzenodo.18909538-blue?style=for-the-badge" alt="Zenodo DOI"></a>
  <a href="https://doi.org/10.6084/m9.figshare.31566853"><img src="https://img.shields.io/badge/Mirror-10.6084%2Fm9.figshare.31566853-emerald?style=for-the-badge" alt="Figshare DOI"></a>
  <a href="https://doi.org/10.17605/OSF.IO/H7BVR"><img src="https://img.shields.io/badge/DOI-10.17605%2FOSF.IO%2FH7BVR-lightgrey?style=for-the-badge" alt="OSF DOI"></a>
</p>

<p align="center">
  Basilisk combines structured attack modules, evolutionary prompt search, typed evidence bundles, signed audit logs, and exportable reports for repeatable LLM security testing workflows.
</p>

---

<div align="center">
  <img src="assets/demo.gif" alt="Basilisk AI Red Teaming Demo - Genetic Prompt Evolution Dashboard" style="border-radius: 12px; margin: 20px 0; max-width: 100%; border: 1px solid #1f1f27;" />
  <p><i>Basilisk v2.0.0 -- Automated LLM Security Testing with Genetic Prompt Evolution</i></p>
  <a href="https://youtu.be/sgFcM1y_omY">
    <img src="https://img.shields.io/badge/Watch-Full%20Demo%20on%20YouTube-red?style=for-the-badge&logo=youtube" alt="Basilisk YouTube Demo" />
  </a>
</div>

### What the Demo Shows

*   **Genetic Prompt Evolution**: Watch the mutation engine iterate through payload families across generations.
*   **Differential Mode**: Compare behavior across multiple LLM providers and model targets.
*   **Guardrail Posture Scan**: Run recon-oriented posture grading without a full exploit pass.
*   **Real-Time Scan Dashboard**: Review live findings, evolution stats, and operator telemetry.
*   **Report Export**: Export results as HTML, JSON, SARIF, Markdown, and PDF.

<p align="center">
  <a href="https://github.com/regaan/basilisk/actions/workflows/build.yml"><img src="https://github.com/regaan/basilisk/actions/workflows/build.yml/badge.svg" alt="Build Desktop" /></a>
  <a href="https://github.com/regaan/basilisk/actions/workflows/docker-build.yml"><img src="https://github.com/regaan/basilisk/actions/workflows/docker-build.yml/badge.svg" alt="Docker" /></a>
  <a href="https://github.com/regaan/basilisk/actions/workflows/python-publish.yml"><img src="https://github.com/regaan/basilisk/actions/workflows/python-publish.yml/badge.svg" alt="PyPI" /></a>
  <a href="https://github.com/marketplace/actions/basilisk-ai-security-scan"><img src="https://img.shields.io/badge/Marketplace-Action-blue?logo=github" alt="GitHub Marketplace" /></a>
</p>

<p align="center">
  <a href="#what-is-basilisk">What is Basilisk?</a> &bull;
  <a href="#research-context">Research Context</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#whats-new-in-v200">What's New</a> &bull;
  <a href="#attack-modules">Attack Modules</a> &bull;
  <a href="#desktop-app">Desktop App</a> &bull;
  <a href="#ci-cd-integration">CI/CD</a> &bull;
  <a href="#docker">Docker</a> &bull;
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
                    AI Red Teaming Framework v2.0.0
```

## What is Basilisk?

**Basilisk** is an open-source offensive security framework purpose-built for **AI red teaming** and **LLM penetration testing**. It maps its attack surface to the **OWASP LLM Top 10** threat model and combines that coverage with a genetic algorithm engine called **Smart Prompt Evolution (SPE-NL)** that evolves adversarial prompt payloads across generations.

Whether you are testing **OpenAI GPT-4o**, **Anthropic Claude**, **Google Gemini**, **xAI Grok**, **Meta Llama**, or a custom LLM endpoint, Basilisk provides 33 attack modules, 5 recon modules, differential multi-model scanning, guardrail posture grading, and signed audit logging out of the box.

v2.0.0 introduces cryptographically signed native libraries, Ed25519 audit log integrity, a dedicated SQLite worker architecture, evidence-backed findings with trust tiers, and hardened secret handling across the CLI and desktop app. The code is the proof -- read the hardening section below or audit the source directly.

### Why Basilisk?

- **Automated AI Red Teaming**: Start from probes and attack modules, then let Basilisk iterate through payload variants automatically.
- **Genetic Prompt Evolution**: The SPE-NL engine mutates, crosses over, and scores prompts across generations. When a static payload gets refused, evolution searches for nearby variants that preserve intent while changing delivery.
- **OWASP-Aligned Attack Coverage**: 33 modules covering prompt injection, system prompt extraction, data exfiltration, tool abuse, guardrail bypass, denial of service, multi-turn manipulation, RAG attacks, and multimodal injection.
- **Evidence-Backed Findings**: Every finding carries structured evidence signals, replay steps, and calibrated verdicts. Production-tier findings get downgraded if the proof is weak. No more "the model said something bad" as your entire evidence chain.
- **Broad Provider Support**: OpenAI, Anthropic, Google, xAI (Grok), Groq, Azure, AWS Bedrock, GitHub Models, Ollama, vLLM, and custom HTTP/WebSocket endpoints.
- **CI/CD Ready**: Native GitHub Action with SARIF output and baseline regression detection for automated AI security testing in your pipeline.
- **Desktop App**: Electron GUI for visual red teaming with live scan dashboards, campaign controls, and report export.

Built by **[Regaan](https://regaan.rothackers.com)**, Lead Researcher at **[ROT Independent Security Research Lab](https://rothackers.com)**, and creator of **[WSHawk](https://wshawk.rothackers.com)**.

Website: [basilisk.rothackers.com](https://basilisk.rothackers.com)

---

## Research Context

Basilisk is described in the following research paper:

Regaan R. *Basilisk: An Evolutionary AI Red-Teaming Framework for Systematic Security Evaluation of Large Language Models*. SSRN Electronic Journal, 2026.

The paper formalizes:
- Evolutionary prompt search (SPE-NL)
- Multi-objective fitness scoring
- Behavioral space exploration
- Differential model evaluation

This repository contains the full implementation used for experimental evaluation.

---

## Key Contributions

- Introduces evolutionary prompt search (SPE-NL) for LLM security testing
- Demonstrates multi-objective fitness scoring for adversarial prompts
- Enables behavioral space exploration beyond static jailbreaks
- Provides reproducible evaluation framework across multiple LLM providers

## Quick Start

```bash
# Install from PyPI
pip install basilisk-ai

# Baseline scan against an OpenAI target
export OPENAI_API_KEY="sk-..."
basilisk scan -t https://api.target.com/chat -p openai

# Quick mode: top payloads, no evolution
basilisk scan -t https://api.target.com/chat --mode quick

# Deep mode: extended evolution search
basilisk scan -t https://api.target.com/chat --mode deep --generations 10

# Stealth mode: rate-limited execution
basilisk scan -t https://api.target.com/chat --mode stealth

# Recon only: fingerprint the target
basilisk recon -t https://api.target.com/chat -p openai

# Guardrail posture check
basilisk posture -p openai -m gpt-4o -v

# Differential scan across model targets
basilisk diff -t openai:gpt-4o -t anthropic:claude-3-5-sonnet-20241022

# Deterministic eval suite
basilisk eval evals/guardrails.yaml --format junit --output results.xml

# GitHub Models path
export GH_MODELS_TOKEN="ghp_..."
basilisk scan -t https://api.target.com/chat -p github -m gpt-4o

# Pipeline gate with SARIF output
basilisk scan -t https://api.target.com/chat -o sarif --fail-on high
```

## Zero-Setup Live Demo

Want to see Basilisk in action without configuring API keys? We maintain an intentionally vulnerable LLM target for testing:

**Target URL:** `https://basilisk-vulnbot.onrender.com/v1/chat/completions`

```bash
# No API keys required for this target
basilisk scan -t https://basilisk-vulnbot.onrender.com/v1/chat/completions -p custom --model vulnbot-1.0 --mode quick
```

Or use the Desktop App: open **New Scan**, set the endpoint URL above, pick **Custom HTTP** as the provider, and hit start.

### Docker

```bash
docker pull rothackers/basilisk

docker run --rm -e OPENAI_API_KEY=sk-... rothackers/basilisk \
  scan -t https://api.target.com/chat --mode quick
```

---

## Reproduce Results

Run a minimal experiment from the paper:

```bash
basilisk scan -t https://basilisk-vulnbot.onrender.com/v1/chat/completions \
  -p custom \
  --mode standard \
  --generations 5 \
  --output results/
```

This reproduces:

- Evolutionary prompt search
- Guardrail bypass discovery
- Behavioral divergence patterns

---

## Experimental Setup

- Models tested: GPT-4o, Claude 3.5, Gemini 2.0
- Attack modules: 33 (OWASP LLM Top 10 aligned)
- Evaluation metrics:
  - Refusal bypass rate
  - Leakage success rate
  - Behavioral diversity score
  - Evolution convergence rate

---

## Features

### Smart Prompt Evolution (SPE-NL)

The core differentiator. Genetic algorithms adapted for natural language attack payloads:

- **10 mutation operators** -- synonym swap, encoding wrap, role injection, language shift, structure overhaul, fragment split, homoglyph substitution, context padding, token smuggling, LLM-driven mutation
- **5 crossover strategies** -- single-point, uniform, prefix-suffix, semantic blend, best-of-both
- **Multi-objective fitness** -- refusal avoidance, information leakage, compliance scoring, target pattern matching, cost efficiency, intent preservation, reproducibility, and novelty. NSGA-II Pareto ranking when multiple objectives are active.
- **Curiosity-driven exploration** -- behavioral space partitioning with TF-IDF clustering and adaptive bin splitting. Rewards mutations that land in under-visited response regions instead of repeating the same refusal pattern.
- **Intent preservation** -- tracks semantic drift from original seed payloads across generations. Mutations that stray too far from the attack goal get penalized.
- **Operator learning** -- multi-armed bandit selects which mutation operators work best against the current target
- **Stagnation detection** with adaptive mutation rate, early breakthrough exit, and population deduplication
- **Response cache** -- SHA-256 keyed LRU cache avoids burning API tokens on duplicate payloads

Payloads that fail get mutated, crossed, and re-evaluated. The search loop keeps useful variants, removes duplicates, and shifts pressure when the target response distribution stagnates.

### 33 Attack Modules

33 modules across 9 attack categories with 3 trust tiers, mapped to the OWASP LLM Top 10 threat model. See [Attack Modules](#attack-modules) below.

### Trust Tiers and Evidence Policy

Not every module is treated the same. Basilisk assigns each module a trust tier:

- **production** (11 modules) -- strictest evidence requirements, included by default
- **beta** (18 modules) -- included by default but held to a lower proof standard
- **research** (4 modules) -- excluded unless you explicitly opt in

High and critical findings from production modules get checked against module-specific proof requirements. If the evidence is weak, the finding is downgraded and the downgrade reason is preserved in session data and reports. This is how Basilisk separates "interesting behavior" from "defensible evidence."

### 5 Reconnaissance Modules

- **Model Fingerprinting** -- identifies GPT-4, Claude, Gemini, Llama, Mistral via response patterns and timing
- **Guardrail Profiling** -- systematic probing across 8 content categories
- **Tool/Function Discovery** -- enumerates available tools and API schemas
- **Context Window Measurement** -- determines token limits
- **RAG Pipeline Detection** -- identifies retrieval-augmented generation setups

### Differential Testing

Run identical probes against multiple providers or model targets and compare where one path refuses while another complies. Basilisk records per-model outcomes and per-probe breakdowns for side-by-side review.

```bash
basilisk diff -t openai:gpt-4o -t anthropic:claude-3-5-sonnet-20241022 -t google:gemini/gemini-2.0-flash
```

### Guardrail Posture Assessment

Recon-only guardrail grading:
- A+ through F posture grades
- 8 categories with 3-tier probing (benign/moderate/adversarial)
- Strength classification: None, Weak, Moderate, Strong, Aggressive
- Actionable recommendations for weak spots and over-filtering

### Eval Runner

When you already know the exact prompts and assertions you need, skip the exploratory scan and run a deterministic eval suite:

- Assertion types: `must_refuse`, `must_not_refuse`, `must_contain`, `must_not_contain`, `max_compliance`, `max_tokens`, `regex_match`, `regex_no_match`, `similarity`, `llm_grade`
- Output in console, JSON, JUnit XML, or Markdown
- Diff against previous results for regression detection
- Tag-based filtering and parallel execution

### Probe Corpus

223 probes in YAML across 9 categories. Each probe carries structured metadata: objective, expected signals, failure modes, target archetypes, tool requirements, follow-up probe IDs, and OWASP mapping. The corpus seeds evolution runs and feeds the effectiveness tracker.

### Audit Logging

On by default. Ed25519-signed JSONL with SHA-256 chain integrity:
- Every prompt sent, response received, finding discovered, and error is logged
- API keys automatically redacted before writing
- Audit key resolution: key file, encrypted secret store, or legacy environment variable
- Tamper detection through chained checksums and digital signatures

### 5 Report Formats

| Format | Use Case |
|--------|----------|
| **HTML** | Dark-themed report with expandable findings, conversation replay, severity charts |
| **SARIF 2.1.0** | CI/CD integration -- GitHub Code Scanning, DefectDojo, Azure DevOps |
| **JSON** | Machine-readable with full metadata |
| **Markdown** | Documentation-ready, commit-friendly |
| **PDF** | Offline sharing and stakeholder delivery (weasyprint / reportlab fallback) |

### Campaign and Policy Controls

Scans carry operator context and execution policy:
- Campaign metadata: operator name, ticket ID, target owner, objective, hypothesis
- Execution modes: `recon`, `validate`, `exploit_chain`, `research`
- Evidence thresholds, retention windows, module allow/deny lists
- Approval gates and dry-run planning
- All of this lands in session state and reports -- not decorative fields

### Universal Provider Support

Via `litellm` + custom adapters:
- **Cloud** -- OpenAI, Anthropic, Google, xAI (Grok), Groq, Azure, AWS Bedrock
- **GitHub Models** -- free access to GPT-4o, o1, and more via `github.com/marketplace/models`
- **Local** -- Ollama, vLLM, llama.cpp
- **Custom** -- any HTTP REST API or WebSocket endpoint
- **WSHawk** -- pairs with WSHawk for WebSocket-based AI testing

### Electron Desktop App

Full desktop GUI with:
- Live scan visualization via the desktop event bridge
- Campaign control plane with operator, ticket, and policy fields
- Differential scan tab with multi-model comparison
- Guardrail posture tab with live grading
- Audit trail viewer with integrity verification
- Module browser with OWASP mapping and trust tier display
- Probe explorer with filtering and stats
- Eval runner with assertion-driven testing
- Session management with replay and evidence review
- Report export dialog for HTML, JSON, SARIF, and PDF
- Cross-platform: Windows (.exe), macOS (.dmg), Linux (.AppImage/.deb/.rpm/.pacman)

### Native C/Go Extensions

Performance-critical paths compiled to shared libraries with full Python fallbacks:
- **C** -- BPE token estimation, Shannon entropy, Levenshtein distance, confusable detection, payload encoding (base64, hex, ROT13, URL, Unicode escape)
- **Go** -- concurrent mutation operators (including 4 multi-turn aware), crossover modes, batch mutation, population diversity scoring, Aho-Corasick multi-pattern matching, refusal/compliance/sensitive data detection
- All native libraries are verified against an **Ed25519-signed manifest** before loading. Hash mismatches block the load.

---

## What's New in v2.0.0

### Security Hardening

v2.0.0 focuses on runtime hardening, evidence handling, desktop isolation, and operator workflow improvements:

- **Ed25519 Signed Native Libraries** -- Native libraries are loaded only after verifying their SHA-256 hashes against an Ed25519-signed manifest.
- **Ed25519 Audit Log Signatures** -- Every audit log entry is digitally signed. Legacy HMAC-SHA256 is deprecated. Audit key resolution prefers encrypted local storage over environment variables.
- **CLI Secret Rejection** -- `--api-key sk-...` is rejected at parse time. Secrets must come from environment variables or `@file` references. This keeps credentials out of shell history and `/proc` listings.
- **SQLite Worker Architecture** -- Replaced ad-hoc locking with a dedicated worker thread per database path. WAL mode, async queue, and single-writer semantics reduce event-loop contention.
- **Native Bridge Input Guardrails** -- FFI calls enforce input size limits. Oversized Levenshtein or similarity calls are rejected before reaching native code.
- **Path Traversal Protection** -- Config file loading uses `Path.resolve()` and ancestry checks against a safe root allowlist. String-prefix matching is gone.
- **LLM Mutation Isolation** -- The attacker-model mutation prompt wraps payloads in JSON and explicitly treats embedded payload content as untrusted data.
- **Go Fuzzer Crypto Seeding** -- PRNG seeded from `crypto/rand` instead of `time.Now()`. Mutation sequences are no longer predictable.
- **Retention Timestamp Hardening** -- Artifact pruning prefers embedded UTC timestamps over filesystem mtime, which is trivially spoofable.
- **Desktop Context Isolation** -- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, webview and navigation blocked, permission requests denied, external URLs allowlisted, backend requests gated through the desktop request bridge.

### Evidence-Backed Findings

Findings now carry structured `EvidenceBundle` objects with typed signals, replay steps, calibrated verdicts, and per-module proof requirements. The evidence policy engine can downgrade severity when proof is insufficient.

### Curiosity-Driven Exploration

The evolution engine now partitions the response space into behavioral clusters and rewards mutations that land in sparse, under-visited regions. Adaptive bin splitting helps prevent curiosity collapse. The novelty signal combines visit frequency, semantic novelty, and behavioral novelty.

### Multi-Objective Fitness

NSGA-II Pareto ranking with crowding distance. The fitness function evaluates exploit evidence, target-signal match, refusal avoidance, novelty, intent preservation, reproducibility, and cost efficiency as separate objectives when multi-objective mode is active.

### Probe Effectiveness Tracking

SQLite-backed tracker at `~/.basilisk/probe_effectiveness.db`. Records which probes worked against which models, categories, and archetypes. Computes bypass rates, block rates, and historical trends. Feeds back into probe prioritization.

### Eval Runner

Deterministic assertion-driven test harness. YAML config with typed assertions (`must_refuse`, `must_contain`, `regex_match`, `similarity`, `llm_grade`, etc.). Console, JSON, JUnit, and Markdown output. Diff against previous results for regression detection. Parallel execution. Tag-based filtering.

### Previous Releases

See [CHANGELOG.md](CHANGELOG.md) for v1.1.0, v1.0.6, v1.0.5, and earlier release notes.

---

## Attack Modules

| Category | Modules | OWASP | What They Test |
|----------|---------|-------|----------------|
| **Prompt Injection** | Direct, Indirect, Multilingual, Encoding, Split | LLM01 | Override system instructions via user input |
| **System Prompt Extraction** | Role Confusion, Translation, Simulation, Gradient Walk | LLM06 | Extract confidential system prompts and policies |
| **Data Exfiltration** | Training Data, RAG Data, Tool Schema | LLM06 | Extract PII, documents, and API schemas |
| **Tool/Function Abuse** | SSRF, SQLi, Command Injection, Chained | LLM07/08 | Exploit tool-use capabilities for lateral movement |
| **Guardrail Bypass** | Roleplay, Encoding, Logic Trap, Systematic | LLM01/09 | Circumvent content safety filters |
| **Denial of Service** | Token Exhaustion, Context Bomb, Loop Trigger | LLM04 | Resource exhaustion and infinite loops |
| **Multi-Turn** | Cultivation, Authority Escalation, Escalation, Persona Lock, Sycophancy, Memory Manipulation | LLM01 | Progressive trust exploitation and conversational drift |
| **RAG Attacks** | Poisoning, Document Injection, Knowledge Enumeration | LLM03/06 | Compromise retrieval-augmented generation pipelines |
| **Multimodal** | Image+Text Injection | LLM01 | Combined image and text attack paths |

**Trust tier split**: 11 production / 18 beta / 4 research. Research modules are excluded by default.

---

## Scan Modes

| Mode | Description | Evolution | Speed |
|------|-------------|-----------|-------|
| `quick` | Top payloads per module, no evolution | No | Fast |
| `standard` | Full payloads, 5 generations of evolution | Yes | Normal |
| `deep` | Full payloads, 10+ generations, multi-turn chains | Yes | Slow |
| `stealth` | Rate-limited, human-like timing delays | Yes | Careful |
| `chaos` | Everything enabled, maximum evolution pressure | Yes | Aggressive |

Scan mode and execution mode are separate controls. Scan mode shapes runtime behavior. Execution mode (`recon`, `validate`, `exploit_chain`, `research`) shapes the operational policy and evidence requirements. They are orthogonal.

---

## CLI Reference

```bash
basilisk scan            # Full scan
basilisk recon           # Fingerprint target
basilisk diff            # Differential scan across models
basilisk posture         # Guardrail posture assessment
basilisk eval            # Assertion-based eval suite
basilisk replay <id>     # Replay a saved session
basilisk interactive     # Manual REPL with assisted attacks
basilisk modules         # List attack modules
basilisk probes          # Browse payload corpus
basilisk sessions        # List saved sessions
basilisk help [topic]    # Topic guides: overview, scan, modules, evolution, diff, examples
basilisk version         # Version and system info
```

Full [CLI Reference](docs/cli-reference.md).

---

## Configuration

```yaml
# basilisk.yaml
target:
  url: https://api.target.com/chat
  provider: openai
  model: gpt-4o
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

### GitHub Actions (Native Action)

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
```

**Using GitHub Models (free, no API key purchase needed):**

```yaml
      - name: Basilisk Scan via GitHub Models
        uses: regaan/basilisk@main
        with:
          target: ${{ secrets.TARGET_URL }}
          provider: github
          github-token: ${{ secrets.GH_MODELS_TOKEN }}
          model: gpt-4o-mini
          mode: quick
          fail-on: high
          output: sarif
```

> **Tip:** Create a [personal access token](https://github.com/settings/tokens) with `models:read` permission and save it as `GH_MODELS_TOKEN`.

**Required Secrets:**

| Secret | Provider | When Needed |
|--------|----------|-------------|
| `OPENAI_API_KEY` | OpenAI | If scanning with OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic | If scanning with Anthropic |
| `GOOGLE_API_KEY` | Google | If scanning with Google |
| `XAI_API_KEY` | xAI | If scanning with Grok |
| `GH_MODELS_TOKEN` | GitHub Models | Free access to GPT-4o, o1, etc. |

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

The Electron desktop app wraps the same scan runtime as the CLI in a full GUI.

```bash
cd desktop
npm install
npx electron .
```

For production builds (standalone, no Python install needed -- backend compiled via PyInstaller):

```bash
chmod +x build-desktop.sh
./build-desktop.sh
```

Output in `desktop/dist/`.

---

## Architecture

```
basilisk/
  core/          # Session, config, database, findings, evidence, audit, policy
  providers/     # LLM adapters: litellm, custom HTTP, WebSocket
  evolution/     # SPE-NL: engine, operators, fitness, curiosity, diversity, crossover, intent, cache
  recon/         # Fingerprinting, guardrails, tools, context, RAG detection
  attacks/       # 9 categories, 33 modules
    injection/         # LLM01 -- 5 modules
    extraction/        # LLM06 -- 4 modules
    exfil/             # LLM06 -- 3 modules
    toolabuse/         # LLM07/08 -- 4 modules
    guardrails/        # LLM01/09 -- 4 modules
    dos/               # LLM04 -- 3 modules
    multiturn/         # LLM01 -- 6 modules
    rag/               # LLM03/06 -- 3 modules
    multimodal.py      # LLM01 -- 1 module
  payloads/      # 223 YAML probes + effectiveness tracker
  eval/          # Assertion-driven eval runner + config + reporting
  cli/           # Click + Rich terminal interface
  report/        # HTML, JSON, SARIF, Markdown, PDF generators
  campaign/      # Campaign graph and phased attack planning
  policy/        # Execution mode and evidence policy enforcement
  native_bridge.py     # ctypes bindings for C/Go shared libraries
  differential.py      # Multi-model comparison engine
  posture.py           # Guardrail posture scanner
  desktop_backend.py   # FastAPI sidecar for Electron app
desktop/         # Electron desktop application
native/          # C and Go shared libraries
  c/                   # Token analyzer + payload encoder
  go/                  # Fuzzer (mutation operators) + matcher (Aho-Corasick)
action.yml       # GitHub Action for CI/CD
```

---

## Documentation

| Document | What It Covers |
|----------|----------------|
| [CLI Beginner Guide](docs/cli-beginner-guide.md) | First scan, basic commands, reading results |
| [Desktop Beginner Guide](docs/desktop-beginner-guide.md) | First desktop scan, UI walkthrough, report export |
| [CLI Advanced Guide](docs/cli-advanced-guide.md) | Campaign controls, module selection, evidence policy, advanced workflows |
| [Desktop Advanced Guide](docs/desktop-advanced-guide.md) | Campaign control plane, module catalog, session review, operator workflows |
| [Architecture](docs/architecture.md) | System design, module breakdown, data flow |
| [CLI Reference](docs/cli-reference.md) | All commands and options |
| [Attack Modules](docs/attack-modules.md) | Module catalog with trust tiers and evidence requirements |
| [Eval, Probes, and Curiosity](docs/eval-probes-curiosity.md) | Probe corpus, eval runner, curiosity steering, effectiveness tracking |
| [Reporting](docs/reporting.md) | Report formats and CI/CD integration |
| [API Reference](docs/api-reference.md) | Desktop backend API endpoints |
| [Contributing](CONTRIBUTING.md) | Development setup, PR process, coding standards |
| [Security Policy](SECURITY.md) | Vulnerability disclosure with SLAs |

---

## FAQ

### What is Basilisk used for?

Basilisk is used for automated AI red teaming and LLM security testing. It is designed to exercise prompt injection, jailbreak, data leakage, tool-abuse, RAG, and guardrail bypass paths in AI applications built on hosted or local large language models.

### How does it compare to manual jailbreak testing?

Manual testing stops at static payloads. Basilisk starts there and then evolves them. When a payload gets refused, the mutation engine generates variants by changing structure, encoding, framing, and composition while keeping the same objective. Over multiple generations, the search pressure moves toward payload families that better match the current target.

### Does Basilisk work with local models?

Yes. Basilisk supports Ollama, vLLM, llama.cpp, and any custom HTTP or WebSocket endpoint. You can test self-hosted Llama, Mistral, Qwen, or any open-weight model.

### Can I use Basilisk in CI/CD?

Yes. Basilisk ships a native GitHub Action (`regaan/basilisk@main`) and supports SARIF output for GitHub Code Scanning, DefectDojo, and Azure DevOps. Baseline regression detection is built in -- your pipeline fails when new findings appear that were not in the previous baseline.

### What does the trust tier system do?

It controls evidence expectations. A production-tier finding must carry structured evidence signals and module-specific proof markers. If those are missing, the finding gets downgraded automatically. Beta and research tiers have progressively looser requirements. This is how Basilisk separates "the model said something weird" from "here is a reproducible vulnerability with replay steps."

### Is Basilisk free?

Fully open-source under AGPL-3.0. No restrictions on authorized security testing use.

---

## About the Creator

**Basilisk** is built by **[Regaan](https://regaan.rothackers.com)**, Lead Researcher at the **[ROT Independent Security Research Lab](https://rothackers.com)**.

---

## Citation

If you reference Basilisk in research or publications:

```bibtex
@misc{regaan2026basilisk,
  author       = {Regaan},
  title        = {Basilisk: An Evolutionary AI Red-Teaming Framework for Systematic Security Evaluation of Large Language Models},
  year         = {2026},
  version      = {2.0.0},
  publisher    = {ROT Independent Security Research Lab},
  doi          = {10.5281/zenodo.18909538},
  url          = {https://doi.org/10.5281/zenodo.18909538}
}

@article{regaan2026basilisk_ssrn,
  title        = {Basilisk: An Evolutionary AI Red-Teaming Framework for Systematic Security Evaluation of Large Language Models},
  author       = {Regaan, R},
  journal      = {SSRN Electronic Journal},
  year         = {2026},
  doi          = {10.2139/ssrn.6373439}
}
```

Archived at:
- **SSRN**: [https://doi.org/10.2139/ssrn.6373439](https://doi.org/10.2139/ssrn.6373439)
- **Zenodo**: [https://doi.org/10.5281/zenodo.18909538](https://doi.org/10.5281/zenodo.18909538)
- **Figshare**: [https://doi.org/10.6084/m9.figshare.31566853](https://doi.org/10.6084/m9.figshare.31566853)
- **OSF**: [https://doi.org/10.17605/OSF.IO/H7BVR](https://doi.org/10.17605/OSF.IO/H7BVR)

## Legal

Basilisk is designed for **authorized security testing only**. Obtain proper written authorization before testing AI systems you do not own. Unauthorized use may violate computer fraud and abuse laws in your jurisdiction.

The authors assume no liability for misuse.

## License

AGPL-3.0 -- see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Built by <a href="https://rothackers.com">Regaan</a></strong> -- Founder of Rot Hackers | <a href="https://basilisk.rothackers.com">basilisk.rothackers.com</a>
</p>
