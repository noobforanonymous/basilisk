# Desktop Backend API Reference

The Basilisk desktop backend runs on `http://127.0.0.1:8741` and provides the following endpoints.

## Health

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.3",
  "timestamp": "2026-01-15T10:00:00Z"
}
```

## Scan

### `POST /api/scan`
Start a new scan.

**Request Body:**
```json
{
  "target": "https://api.target.com/v1/chat",
  "provider": "openai",
  "mode": "standard",
  "api_key": "sk-...",
  "evolve": true,
  "generations": 5,
  "modules": []
}
```

**Response:**
```json
{
  "session_id": "abc123def456",
  "status": "running"
}
```

### `POST /api/scan/{session_id}/stop`
Stop a running scan.

### `GET /api/scan/{session_id}`
Get scan status and findings.

**Response:**
```json
{
  "status": "running",
  "phase": "attack",
  "progress": 0.65,
  "findings": [...],
  "findings_count": 5,
  "module": "DirectInjection"
}
```

## Differential Scan (v1.0.3)

### `POST /api/diff`
Run identical probes across multiple LLM providers.

**Request Body:**
```json
{
  "targets": [
    {"provider": "openai", "model": "gpt-4o", "api_key": ""},
    {"provider": "anthropic", "model": "claude-3-5-sonnet-20241022", "api_key": ""}
  ],
  "categories": []
}
```

**Response:**
```json
{
  "total_probes": 15,
  "total_divergences": 3,
  "divergence_rate": "20.0%",
  "probes": [{"category": "...", "has_divergence": true, "vulnerable_models": [...], "resistant_models": [...]}]
}
```

## Guardrail Posture (v1.0.3)

### `POST /api/posture`
Run a non-destructive guardrail posture scan.

**Request Body:**
```json
{
  "provider": "openai",
  "model": "gpt-4o",
  "target": "",
  "api_key": ""
}
```

**Response:**
```json
{
  "overall_grade": "B",
  "overall_score": 0.72,
  "categories": [{"name": "Prompt Injection", "strength": "strong", "score": 1.0}],
  "recommendations": ["..."]
}
```

## Audit Logs (v1.0.3)

### `GET /api/audit/{session_id}`
Retrieve audit log entries for a scan session.

**Response:**
```json
{
  "path": "./basilisk-reports/audit_session_20260304.jsonl",
  "entries": [{"seq": 0, "event": "session_start", "data": {...}, "checksum": "..."}]
}
```

## Providers (v1.0.3)

### `GET /api/providers`
List all supported LLM providers and their configuration status.

**Response:**
```json
{
  "providers": [
    {"id": "openai", "name": "OpenAI", "models": ["gpt-4", "gpt-4o"], "configured": true},
    {"id": "anthropic", "name": "Anthropic", "models": ["claude-3-5-sonnet-20241022"], "configured": false}
  ]
}
```

## Sessions

### `GET /api/sessions`
List all sessions.

### `GET /api/sessions/{session_id}`
Get detailed session data.

## Modules

### `GET /api/modules`
List all attack modules.

**Response:**
```json
{
  "modules": [
    {
      "name": "DirectInjection",
      "category": "prompt_injection",
      "owasp_id": "LLM01",
      "description": "Override system instructions via user input"
    }
  ]
}
```

## Reports

### `POST /api/report/{session_id}`
Generate a report.

**Request Body:**
```json
{
  "format": "html"
}
```

### `POST /api/report/{session_id}/export`
Export report to file.

## Settings

### `POST /api/settings/apikey`
Save an API key.

**Request Body:**
```json
{
  "provider": "openai",
  "key": "sk-..."
}
```

## Native Extensions

### `GET /api/native/status`
Check native C/Go extension status.

## WebSocket

### `WS /ws`
Real-time scan events.

**Messages:**
```json
{"event": "scan:progress", "data": {"progress": 0.5, "module": "DirectInjection"}}
{"event": "scan:finding", "data": {"finding": {...}}}
{"event": "scan:profile", "data": {"profile": {...}}}
{"event": "scan:complete", "data": {"total_findings": 12}}
{"event": "scan:error", "data": {"error": "..."}}
```
