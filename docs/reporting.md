# Reporting

Basilisk generates reports in 5 formats for different use cases.

## Formats

### HTML
Professional dark-themed report with:
- Severity breakdown cards
- Finding details with expandable payloads and responses
- Conversation replay sections
- Target profile and OWASP mapping

```bash
basilisk scan --target https://target.com -o html
```

### SARIF 2.1.0
Static Analysis Results Interchange Format for CI/CD:
- GitHub Security tab integration
- GitLab SAST compatible
- Proper rule deduplication and fingerprints
- Conversation code flows

```bash
basilisk scan --target https://target.com -o sarif
```

#### GitHub Actions Integration
```yaml
- name: Basilisk AI Scan
  run: basilisk scan --target ${{ secrets.AI_ENDPOINT }} -o sarif --output-dir ./results --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./results/
```

### JSON
Machine-readable format:
- Full finding details with all metadata
- Profile data
- Session summary

```bash
basilisk scan --target https://target.com -o json
```

### Markdown
Documentation-friendly format:
- Target profile summary
- Formatted findings with code blocks
- Conversation transcripts

```bash
basilisk scan --target https://target.com -o markdown
```

### PDF
Client deliverables (requires `weasyprint` or `reportlab`):

```bash
pip install weasyprint  # recommended
basilisk scan --target https://target.com -o pdf
```

Falls back to reportlab, then text format if neither is installed.

## Export from Desktop App

The Electron desktop app can export reports for any completed session:
1. Navigate to the **Reports** tab
2. Select a session from the dropdown
3. Choose format (HTML, JSON, SARIF, Markdown)
4. Click **Generate & Export**

## Export from Interactive Mode

```bash
basilisk interactive --target https://target.com
# ... run attacks ...
/export html
/export sarif
```

## Export from Replay

```bash
basilisk replay <session_id> --export html
```
