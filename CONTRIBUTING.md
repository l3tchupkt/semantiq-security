# Contributing to Semantiq Security

Thank you for your interest in improving Semantiq Security!

## Code of Conduct

All contributors are expected to uphold the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Workflow

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/l3tchupkt/semantiq-security.git
   cd semantiq-security
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or .\venv\Scripts\Activate.ps1 on Windows
   pip install -e ".[all]"
   ```

3. Run the test suite:
   ```bash
   pytest
   ```

4. Run linting and type checking:
   ```bash
   ruff check .
   ruff format --check .
   mypy src/semantiq
   ```

## Development Principles

- **No False Claims:** Never commit mock implementations disguised as functional code or fabricate scan findings.
- **Safety First:** Never allow un-sandboxed execution of repository code during static scans. Always validate filesystem boundaries.
- **Strict Typing:** All new public APIs and functions must include type annotations.
- **Offline Reliability:** Core functionality must always operate without third-party API keys or internet access.
