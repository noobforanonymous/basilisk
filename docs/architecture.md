# Basilisk Architecture

## System Overview

Basilisk follows a pipeline architecture: **Recon → Attack → Evolution → Report**.

```
User (CLI/Desktop/API)
    │
    ▼
┌─────────────────────────────────┐
│         Configuration           │
│  (CLI args / YAML / env vars)   │
└──────────────┬──────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│         Scanner Engine           │
│  (Orchestration + Session Mgmt)  │
└──────────────┬───────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌──────────┐
│ Recon  │ │ Attack │ │Evolution │
│ Module │ │Modules │ │ Engine   │
│        │ │(8 cats)│ │ (SPE-NL) │
└────┬───┘ └────┬───┘ └────┬─────┘
     │          │          │
     ▼          ▼          ▼
┌──────────────────────────────────┐
│       Provider Adapters          │
│  (LiteLLM / Custom HTTP / WS)   │
└──────────────┬───────────────────┘
               │
               ▼
       Target AI System
```

## Module Breakdown

### Core (`basilisk/core/`)
- **config.py** — YAML-based configuration with CLI override, env var resolution
- **session.py** — Scan lifecycle, finding collection, SQLite persistence, event system
- **finding.py** — Finding dataclass with severity/category enums, OWASP mapping
- **profile.py** — BasiliskProfile with attack surface scoring
- **database.py** — SQLite WAL-mode database for scan persistence and replay

### Recon (`basilisk/recon/`)
- **fingerprint.py** — Model identification via response patterns and timing
- **guardrails.py** — Guardrail level detection via systematic probing
- **tools.py** — Tool/function schema discovery
- **context.py** — Context window size measurement
- **rag.py** — RAG pipeline detection

### Attacks (`basilisk/attacks/`)

8 categories, 29 sub-modules:

| Category | Modules | OWASP |
|----------|---------|-------|
| `injection/` | direct, indirect, multilingual, encoding, split | LLM01 |
| `extraction/` | role_confusion, translation, simulation, gradient_walk | LLM06 |
| `exfil/` | training_data, rag_data, tool_schema | LLM06 |
| `toolabuse/` | ssrf, sqli, command_injection, chained | LLM07/08 |
| `guardrails/` | roleplay, encoding_bypass, logic_trap, systematic | LLM01/09 |
| `dos/` | token_exhaustion, context_bomb, loop_trigger | LLM04 |
| `multiturn/` | escalation, persona_lock, memory_manipulation | LLM01 |
| `rag/` | poisoning, document_injection, knowledge_enum | LLM03 |

### Evolution (`basilisk/evolution/`)
- **engine.py** — Main SPE-NL genetic algorithm loop
- **operators.py** — Mutation operators (synonym, encoding, role, homoglyph, etc.)
- **fitness.py** — Multi-factor fitness scoring with refusal detection
- **population.py** — Population management with tournament selection
- **crossover.py** — Single-point, uniform, and semantic crossover strategies

### Providers (`basilisk/providers/`)
- **litellm_adapter.py** — Universal adapter for all major LLM providers
- **custom_http.py** — Raw HTTP REST endpoint adapter
- **websocket.py** — WebSocket AI endpoint adapter

### Report (`basilisk/report/`)
- **generator.py** — Format orchestrator
- **html.py** — Dark-themed HTML report with conversation replay
- **sarif.py** — SARIF 2.1.0 for CI/CD integration
- **pdf.py** — PDF with weasyprint/reportlab/text fallback
- **templates/** — Jinja2 templates

### Native Extensions (`native/`)
- **c/encoder.c** — Fast payload encoding (base64, hex, URL)
- **c/tokens.c** — Approximate token counting
- **go/fuzzer/** — Concurrent HTTP fuzzer
- **go/matcher/** — Fast pattern matching

## Data Flow

1. **Configuration** loads from CLI args, YAML file, and environment variables
2. **Session** is created with a unique ID and connected to SQLite
3. **Recon** runs 5 probes against the target, building a `BasiliskProfile`
4. **Attack modules** execute sequentially, generating `Finding` objects
5. **Evolution engine** takes promising payloads and breeds better variants
6. **Findings** are persisted to SQLite in real-time
7. **Report** is generated in the requested format

## Event System

The `ScanSession` has an event listener system:
- `finding` — emitted when a new vulnerability is discovered
- `evolution` — emitted per generation with statistics
- Used by the desktop app (via WebSocket) and CLI (via Rich live display)
