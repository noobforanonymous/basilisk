# Contributing to Basilisk

Thank you for considering contributing to Basilisk! This document outlines how to contribute effectively.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Adding Attack Modules](#adding-attack-modules)
- [Reporting Bugs](#reporting-bugs)
- [Security Vulnerabilities](#security-vulnerabilities)

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/basilisk.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Push to your fork: `git push origin feature/your-feature-name`
6. Open a Pull Request

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 20+ (for Desktop app)
- Git
- An LLM API key (OpenAI, Anthropic, etc.) for testing

### Installation

```bash
# Clone the repository
git clone https://github.com/regaan/basilisk.git
cd basilisk

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

### Desktop App (Optional)

```bash
cd desktop
npm install
npm run dev
```

## Project Structure

```
basilisk/
├── basilisk/              # Core Python package
│   ├── attacks/           # Attack module implementations
│   ├── evolution/         # SPE-NL evolution engine
│   ├── providers/         # LLM provider integrations
│   ├── report/            # Report generators (SARIF, HTML, JSON, MD, PDF)
│   ├── cli/               # CLI interface (Click)
│   ├── core/              # Sessions, evidence, audit, config, and storage
│   └── runtime/           # Shared CLI/desktop scan orchestration
├── desktop/               # Electron desktop application
│   ├── src/               # Frontend source
│   └── bin/               # Backend sidecar binary
├── native/                # C and Go native extensions
├── tests/                 # Test suite
├── docs/                  # Documentation
└── .github/               # GitHub workflows and templates
```

## How to Contribute

### Types of Contributions We Welcome

| Type | Description |
|---|---|
| 🐛 **Bug Fixes** | Fix broken functionality in existing modules |
| ✨ **New Attack Modules** | Add new OWASP LLM Top 10 attack categories |
| 📝 **Documentation** | Improve docs, docstrings, or README |
| 🧪 **Tests** | Add or improve test coverage |
| 🎨 **Desktop UI** | Improve the Electron desktop application |
| ⚡ **Performance** | Optimize CLI speed, evolution engine, or native extensions |
| 🌍 **Provider Support** | Add new LLM provider integrations via LiteLLM |
| 📊 **Reporting** | New report formats or improved output |

### Things to Avoid

- Do not submit payloads derived from testing unauthorized systems
- Do not include API keys, tokens, or credentials in any commit
- Do not add dependencies without discussing first in an Issue

## Pull Request Process

1. **Open an Issue first** — For non-trivial changes, open an Issue to discuss the approach before writing code.

2. **One PR per feature** — Keep PRs focused. If you're fixing a bug AND adding a feature, split into two PRs.

3. **Write tests** — All new attack modules must include at least basic unit tests.

4. **Update documentation** — If your change adds or modifies functionality, update the relevant docs.

5. **Follow the template** — Use the PR template when opening your pull request.

6. **Keep it clean** — Squash commits before merge. Use clear, descriptive commit messages.

## Coding Standards

### Python

- Follow **PEP 8** style guidelines
- Use **type hints** for all function signatures
- Maximum line length: **120 characters**
- Use `"""docstrings"""` for all public functions and classes
- Use `snake_case` for functions and variables, `PascalCase` for classes

### Commit Messages

Use the conventional commit format:

```
type(scope): description

feat(attacks): add multi-turn social engineering module
fix(engine): correct fitness scoring in SPE-NL crossover
docs(readme): update installation instructions
test(reporting): add SARIF output validation tests
chore(ci): update Python version in build workflow
```

### Branch Naming

```
feature/short-description
fix/issue-number-description
docs/what-you-updated
test/what-you-tested
```

## Adding Attack Modules

To add a new attack module:

1. Create a new file in `basilisk/attacks/`
2. Implement the base attack interface
3. Register the module in the module registry
4. Add unit tests in `tests/`
5. Document the module in `docs/`

Each module should:
- Target a specific OWASP LLM Top 10 category
- Include at least 5 base payloads
- Support SPE-NL evolution (fitness function)
- Generate structured findings for SARIF output

## Reporting Bugs

Use the [Bug Report template](https://github.com/regaan/basilisk/issues/new?template=bug_report.md) and include:

- Basilisk version (`basilisk --version`)
- Python version
- OS and version
- Steps to reproduce
- Expected vs. actual behavior
- Relevant logs or error output

## Security Vulnerabilities

**DO NOT** open a public Issue for security vulnerabilities.

Instead, see our [Security Policy](SECURITY.md) for responsible disclosure instructions.

Report security issues to: **support@rothackers.com**

## License

By contributing to Basilisk, you agree that your contributions will be licensed under the [AGPL-3.0 License](LICENSE).

## Questions?

- Open a [Discussion](https://github.com/regaan/basilisk/discussions) on GitHub
- Email us at **support@rothackers.com**

Thank you for helping make AI systems more secure. 🐍
