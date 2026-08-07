# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.0.x (latest) | ✅ Active support |
| 1.0.x | ⚠️ Security patches only |
| < 1.0.0 | ❌ No support |

## Reporting a Vulnerability

**DO NOT** open a public GitHub Issue for security vulnerabilities.

If you discover a security vulnerability in Basilisk (the framework itself, not in a target system you tested), please report it responsibly.

### How to Report

1. **Email**: Send a detailed report to **support@rothackers.com**
2. **Subject Line**: `[SECURITY] Basilisk — Brief Description`
3. **Encrypt** (optional): PGP key available upon request

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if you have one)
- Your name/handle for attribution (optional)

### What to Expect

| Timeline | Action |
|---|---|
| **24 hours** | Acknowledgement of your report |
| **72 hours** | Initial assessment and severity classification |
| **7 days** | Detailed response with remediation plan |
| **30 days** | Fix developed, tested, and released |
| **After fix** | Public disclosure with your attribution (if desired) |

## Scope

The following are **in scope** for security reports:

- Vulnerabilities in the Basilisk CLI, backend, or desktop application
- Supply chain issues (dependency vulnerabilities, compromised packages)
- Authentication or authorization bypasses in the desktop app's backend bridge
- Path traversal or arbitrary file access through report generation
- Code injection through crafted configuration files or scan inputs
- Insecure handling of API keys or credentials in local storage

The following are **out of scope**:

- Vulnerabilities in target LLM systems (report those to the LLM provider)
- Issues in third-party dependencies that are already publicly known
- Social engineering of project maintainers
- Denial of service against github.com or pypi.org

## Responsible Disclosure

We follow coordinated disclosure practices:

1. The reporter shares the vulnerability details privately with us
2. We validate and develop a fix
3. We release a patched version
4. We publicly disclose the vulnerability with credit to the reporter (unless they prefer anonymity)
5. We request a minimum **90-day embargo** before public disclosure to protect users

## Security Updates

Security patches are released as point releases (e.g., 1.0.2, 1.0.3). We recommend always running the latest version:

```bash
pip install --upgrade basilisk-ai
```

## Release Integrity

Tagged desktop releases require platform signing credentials and a separate
Ed25519 key for native-library manifests. The build stops if required trust
material is missing. Native libraries are checked against their signed
manifest before packaging and again before runtime loading.

The desktop process uses Electron `safeStorage` to wrap the Fernet master key
before starting the local backend. Linux `basic_text` storage is not accepted
as an OS-protected backend. CLI-only installations use the operating-system
keyring when available and otherwise fall back to a private local key file.
Secret values and unwrapped keys are never written to application logs.

CLI scans execute in a dedicated child interpreter by default. The supervisor
applies mode-specific wall-clock ceilings, and the child applies POSIX rlimits
or a Windows Job Object for CPU, memory, output-file, descriptor, and child-
process limits where the operating system supports them. The Electron backend
is already a separate sidecar process and receives the same memory/process
boundary. `BASILISK_DISABLE_PROCESS_ISOLATION=1` exists for controlled
diagnostics and unit tests; do not use it for untrusted targets.

Release assets include SHA-256 digests, a CycloneDX SBOM, SLSA provenance, and
Sigstore signatures. GitHub also publishes build-provenance and SBOM
attestations for every installer and archive. Verify the published digest and
attestation before running an installer obtained from a mirror.

`BASILISK_NATIVE_SIGNING_KEY` is a repository secret containing a
base64-encoded raw 32-byte Ed25519 private key. Its public key is derived during
the build and embedded into that release's desktop sidecar. The private key is
not written to the repository or packaged artifact.

## Hall of Fame

We maintain a list of security researchers who have responsibly disclosed vulnerabilities in Basilisk. If you report a valid security issue, you'll be credited here (with your permission).

*No reports yet — be the first!*

## Contact

- **Email**: support@rothackers.com
- **GitHub**: [@regaan](https://github.com/regaan)
- **Website**: [basilisk.rothackers.com](https://basilisk.rothackers.com)
