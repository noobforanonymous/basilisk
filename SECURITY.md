# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x (latest) | ✅ Active support |
| 0.1.x | ⚠️ Security patches only |
| < 0.1.0 | ❌ No support |

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

## Hall of Fame

We maintain a list of security researchers who have responsibly disclosed vulnerabilities in Basilisk. If you report a valid security issue, you'll be credited here (with your permission).

*No reports yet — be the first!*

## Contact

- **Email**: support@rothackers.com
- **GitHub**: [@noobforanonymous](https://github.com/noobforanonymous)
- **Website**: [basilisk.rothackers.com](https://basilisk.rothackers.com)
