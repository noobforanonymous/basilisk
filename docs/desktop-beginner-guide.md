# Desktop Beginner Guide

This guide is for someone who wants to use the Basilisk desktop app as an operator console without digging through the backend code first.

Use Basilisk only on systems you own or are explicitly authorized to test.

## What the Desktop App Is

The desktop app is an Electron shell backed by the same Basilisk scan runtime used by the CLI. It is not a separate scanner with separate logic. That matters because:

- findings come from the same orchestrator
- evidence policy is the same as CLI
- reports come from the same report generator
- session history is stored locally on the workstation

## First Launch

When the app starts successfully, you should see:

- a title bar with window controls
- a top navigation row
- a connection indicator in the top right
- the `Dashboard` tab open by default

If the backend is healthy, the status changes to `Connected`.

## Main Tabs You Will Use First

- `New Scan`
- `Sessions`
- `Findings`
- `Reports`
- `Modules`
- `Settings`

You do not need every tab on day one. Start with `New Scan`.

## First Scan in the Desktop App

Open `New Scan` and fill in:

- `Endpoint URL`
- `Provider`
- `Model`
- `API Key`

For a first run, leave the rest simple:

- `Scan Mode`: `Standard`
- `Execution Mode`: `Validate`
- `Evidence Threshold`: `Strong`
- `Include research-tier modules`: unchecked

Then click `Start Scan`.

## What Happens During a Scan

While a scan is running, the desktop app shows:

- a timer
- current scan phase
- progress bar
- live findings
- severity counts
- telemetry in the log view

The UI polls the backend and updates:

- recon/profile information
- findings list
- evolution stats
- final scan status

## Reading the Result

### Dashboard

Use this for a fast summary:

- total findings
- severity breakdown
- recent findings
- live engine messages

### Findings

Use this for the flat list of findings discovered in the current session.

### Sessions

Use this for stored runs. When you click a session, you can inspect:

- campaign metadata
- policy summary
- evidence verdict counts
- exploit graph summary
- phase history
- findings table
- downgraded findings, if any

## Exporting a Report

Open `Reports` and choose:

- a session
- a format

Available exports include:

- HTML
- JSON
- SARIF
- PDF

The desktop app uses a save dialog for export rather than letting the backend write to arbitrary paths.

## Module Browser

Open `Modules` if you want to understand what Basilisk can run.

Each module card shows:

- module name
- OWASP-linked category
- trust tier
- default-on or default-off behavior

Click a module to expand:

- description
- success criteria
- required proof

That is the fastest way to understand why one module is safer to run by default than another.

## Secret Handling

You can enter provider API keys in the scan form, and the desktop app can also persist provider keys through the settings path.

The current build stores values in a Fernet-encrypted file. The encryption key is protected by the strongest backend available:

- Electron `safeStorage` on Windows, macOS, and Linux desktops with a real secret-service backend
- the operating-system keyring for CLI and backend-only use
- a permission-restricted local key file only when protected storage is unavailable

On headless Linux, Electron may report the `basic_text` backend. Basilisk rejects that backend as protected storage and lets the Python secret manager select the documented fallback instead. Existing local master keys are wrapped during the first supported desktop startup so stored values remain readable.

You can see the active secret-store status in `Settings`.

## Clearing Session History

If you want to remove local scan history:

1. stop any active scan
2. open `Sessions`
3. click `Clear`

This clears locally stored session metadata from the desktop workspace.

## Recommended First Workflow

1. Open `Modules` and skim the module tiers.
2. Run one `Validate` scan from `New Scan`.
3. Review `Sessions` to see campaign, evidence, and findings in one place.
4. Export an HTML report.
5. Move to the advanced guide when you want to use campaign controls, module allowlists, eval, or probes.

## Common Mistakes

### Starting with research modules enabled

Leave research modules off until you know why you want them.

### Treating scan mode and execution mode as the same thing

They are different:

- scan mode controls the runtime style
- execution mode controls operator policy

### Ignoring session detail for clean runs

Even if a scan finds nothing, the session detail still matters because it records:

- who ran the scan
- under which policy
- what execution mode was used
- what phase history occurred

## Where to Go Next

- [Desktop Advanced Guide](desktop-advanced-guide.md)
- [CLI Beginner Guide](cli-beginner-guide.md)
- [Eval, Probes, and Curiosity](eval-probes-curiosity.md)
