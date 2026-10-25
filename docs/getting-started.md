# Getting Started with Semantiq Security

Semantiq Security is an independent, offline-first Python SDK and CLI designed for application security research, codebase threat modeling, and AI-assisted vulnerability discovery.

---

## 1. Installation

Install the base package via pip:

```bash
pip install semantiq
```

To enable optional AI providers (OpenAI, Anthropic):

```bash
pip install "semantiq[ai]"
```

For development and testing:

```bash
git clone https://github.com/l3tchupkt/semantiq-security.git
cd semantiq-security
pip install -e ".[dev]"
```

---

## 2. Command Line Quick Start

### 2.1 Verify your installation
```bash
semantiq doctor
```

### 2.2 Inspect a repository
```bash
semantiq inspect ./path/to/my-repo
```

### 2.3 Run a security scan
```bash
# General audit
semantiq scan ./path/to/my-repo

# Focus on specific vulnerability categories
semantiq scan ./path/to/my-repo --focus sql-injection,command-injection,ssrf

# Output SARIF format for CI/CD
semantiq scan ./path/to/my-repo --format sarif --output results.sarif
```

### 2.4 Generate codebase threat model
```bash
semantiq threat-model ./path/to/my-repo --output threatmodel.md
```

---

## 3. Python SDK Quick Start

```python
import asyncio
from semantiq import Semantiq

async def main():
    async with Semantiq() as security:
        # Run a scan
        result = await security.scan(
            target="./my-project",
            focus=["command-injection", "sql-injection", "path-traversal"],
        )

        print(f"Scan ID: {result.scan_id}")
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.title}")
            print(f"Location: {finding.file_path}:{finding.start_line}")
            print(f"Validation: {finding.validation_status}")

if __name__ == "__main__":
    asyncio.run(main())
```
