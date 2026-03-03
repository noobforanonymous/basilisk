# Desktop Backend API Reference

The Basilisk desktop backend runs on `http://127.0.0.1:8741` and provides the following endpoints.

## Health

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
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
