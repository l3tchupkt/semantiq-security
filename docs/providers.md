# AI Provider Integration Guide

Semantiq Security provides an extensible, provider-agnostic AI layer. While deterministic static analysis operates completely offline without models, AI providers can optionally be configured for deeper hypothesis investigation and threat model enrichment.

---

## 1. Supported Providers

### 1.1 OpenAI and Compatible Endpoints
Compatible with OpenAI (`gpt-4o`, `o3-mini`), vLLM, OpenRouter, and LocalAI.

Configuration:
```toml
[ai]
enabled = true
provider = "openai"
model = "gpt-4o"
api_key = "sk-..."
endpoint_url = "https://api.openai.com/v1/chat/completions" # or local endpoint
```

### 1.2 Anthropic Claude
Compatible with Anthropic Claude 3.5 Sonnet / Claude 3 Opus.

Configuration:
```toml
[ai]
enabled = true
provider = "anthropic"
model = "claude-3-5-sonnet-20241022"
api_key = "sk-ant-..."
```

### 1.3 Ollama (Local & Private)
Runs models locally on your workstation with zero cloud connectivity.

Configuration:
```toml
[ai]
enabled = true
provider = "ollama"
model = "deepseek-r1"
endpoint_url = "http://localhost:11434/api/generate"
```

### 1.4 Mock Provider (Testing / Offline Evaluation)
Generates deterministic structured mock evaluations without external network dependencies.

Configuration:
```toml
[ai]
enabled = true
provider = "mock"
```

---

## 2. Citation Verification Guardrail

LLMs are prone to hallucinating line numbers and phantom functions. Semantiq enforces strict **Source Citation Verification**:
- Every file path cited by the model must exist in the local repository.
- Every start and end line must fall within the physical line bounds of the file.
- The cited snippet must match the actual content at that location.

Any candidate that fails verification is rejected before being presented to the user.
