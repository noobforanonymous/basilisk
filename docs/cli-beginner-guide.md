# CLI Beginner Guide

This guide is for someone who wants to use Basilisk from a terminal for the first time and get a clean, understandable result without having to learn every command upfront.

Use Basilisk only on systems you own or are explicitly authorized to test.

## What You Need Before You Start

- Python 3.11 or newer
- a reachable target endpoint
- a provider and model, if the target is not a custom HTTP endpoint
- credentials in environment variables or a local key file

For provider-backed scans, Basilisk expects credentials through environment variables such as:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GOOGLE_API_KEY`
- `GH_MODELS_TOKEN`
- `GROQ_API_KEY`
- `XAI_API_KEY`
- `NVIDIA_API_KEY`

You can also pass a file path with `@/path/to/file` to `--api-key`. Inline secrets are intentionally rejected because they leak into shell history and process listings.

## Install Basilisk

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install basilisk-ai
```

If you want PDF reports, keyring-backed secrets, or multimodal support:

```bash
pip install "basilisk-ai[pdf,secrets,multimodal]"
```

## First Command to Run

Before you attack anything, look at the module catalog:

```bash
basilisk modules
```

That shows:

- module name
- trust tier
- category
- default severity
- short description

The trust tier matters:

- `production` means stricter evidence requirements
- `beta` means useful but less mature
- `research` means explicit opt-in only

## Your First Real Scan

Example with OpenAI:

```bash
export OPENAI_API_KEY="sk-..."

basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o
```

What this does:

1. builds a scan configuration
2. fingerprints the target unless you skip recon
3. selects attack modules based on trust tier and policy
4. runs attacks and optional evolution
5. writes a report to `./basilisk-reports`
6. stores session data in `./basilisk-sessions.db`

NVIDIA API Catalog uses its OpenAI-compatible endpoint directly:

```bash
export NVIDIA_API_KEY="nvapi-..."

basilisk scan \
  --target https://integrate.api.nvidia.com/v1 \
  --provider nvidia \
  --model openai/gpt-oss-20b
```

The key is read from `NVIDIA_API_KEY`; do not paste it into the command line.

The CLI launches the scan in a restricted worker process. The selected mode
sets its wall-time, CPU, memory, file-size, open-file, and child-process
ceilings. Target URLs are still checked by the outbound destination policy
inside the worker, including DNS and private-address restrictions.

## Choosing a Scan Mode

Start with one of these:

- `quick`: fastest first pass
- `standard`: best default starting point
- `deep`: more time, more generations, more coverage
- `stealth`: lower-rate probing
- `chaos`: highest aggression

Example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --mode standard
```

## Choosing an Execution Mode

This is a policy choice, not the same thing as scan mode.

- `recon`: learn the target, do not push exploitation
- `validate`: safest starting point for evidence-backed findings
- `exploit_chain`: more aggressive chained execution
- `research`: exploratory mode

Example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --execution-mode validate
```

For a first run, use `validate`.

## Running a Smaller Scope

### One module family

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --module injection.direct
```

### No research modules

That is already the default. Only opt into them when you mean to:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --include-research-modules
```

## Running Without Full Attacks

### Recon only

```bash
basilisk recon \
  --target https://example.test/v1/chat/completions \
  --provider openai
```

### Posture only

```bash
basilisk posture \
  --provider openai \
  --model gpt-4o
```

`posture` is useful when you want a quick safety profile without running the full attack path.

## Reading the Output

By default Basilisk writes reports to `./basilisk-reports`.

Most beginners should use:

- `html` for reading
- `json` for automation
- `sarif` for CI or security tooling

Example:

```bash
basilisk scan \
  --target https://example.test/v1/chat/completions \
  --provider openai \
  --model gpt-4o \
  --output html
```

## Finding Past Runs

List stored sessions:

```bash
basilisk sessions
```

Replay one:

```bash
basilisk replay BSLK-2026-ABC123
```

## Useful Beginner Commands

```bash
basilisk modules
basilisk probes --stats
basilisk posture --provider openai --model gpt-4o
basilisk sessions
basilisk help examples
```

## Common Mistakes

### Passing secrets inline

Do not pass API keys or bearer headers inline:

```bash
basilisk scan --api-key sk-...
basilisk scan --auth "Bearer token..."
```

Use an environment variable or a file reference:

```bash
basilisk scan --api-key @/path/to/key.txt
BASILISK_AUTH_HEADER="Bearer token..." basilisk scan --target https://example.test/v1/chat/completions --provider custom
```

### Mixing scan mode and execution mode

`--mode deep` does not mean the same thing as `--execution-mode exploit_chain`.

- scan mode controls runtime style
- execution mode controls operational policy

### Running research modules too early

Start with the default module set. Bring in research-tier modules only when you want broader exploratory behavior and you understand the trust tradeoff.

## Suggested First Workflow

1. Run `basilisk modules`.
2. Run a `posture` check.
3. Run a `standard` scan in `validate` execution mode.
4. Open the HTML report.
5. Review findings by module, evidence verdict, and downgrade state.
6. Re-run with narrower modules or stronger policy if needed.

## Where to Go Next

- [CLI Advanced Guide](cli-advanced-guide.md)
- [Eval, Probes, and Curiosity](eval-probes-curiosity.md)
- [CLI Reference](cli-reference.md)
