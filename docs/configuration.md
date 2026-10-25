# Configuration Reference

Semantiq Security can be configured via a `.semantiq.toml` file in your repository root, a custom file passed to `Semantiq(config_path="...")`, or environment variables.

---

## 1. Configuration Sections

### `[scan]`
- `mode`: Scan mode (`"standard"`, `"deep"`, or `"diff"`). Default: `"standard"`.
- `max_file_size_bytes`: Maximum allowed size for individual files before skipping. Default: `2097152` (2 MB).
- `max_files`: Maximum total files to include in a single scan inventory. Default: `50000`.
- `include_patterns`: List of glob patterns to explicitly include.
- `exclude_patterns`: List of glob patterns to exclude from analysis (e.g. `["**/.git/**", "**/venv/**"]`).
- `focus`: Optional list of vulnerability categories to restrict findings to (e.g. `["sql-injection", "ssrf"]`).

### `[validation]`
- `default_mode`: Default validation strategy (`"static"`, `"test_based"`, `"dynamic_sandbox"`, `"manual_plan"`). Default: `"static"`.
- `allow_execution`: Boolean flag explicitly opting into dynamic process execution. Default: `false`.
- `timeout_seconds`: Execution timeout for dynamic tests in seconds. Default: `30`.
- `max_output_bytes`: Maximum stdout/stderr buffer ceiling. Default: `102400` (100 KB).

### `[storage]`
- `database_path`: Path to SQLite state database file or `":memory:"`. Default: `"~/.semantiq/semantiq.db"`.

### `[ai]`
- `enabled`: Enable optional AI provider. Default: `false`.
- `provider`: Provider type (`"openai"`, `"anthropic"`, `"ollama"`, or `"mock"`). Default: `"ollama"`.
- `model`: Target model identifier. Default: `"deepseek-r1"`.
- `api_key`: API key for remote providers.
- `endpoint_url`: Custom base URL for inference endpoints.
- `temperature`: Model temperature. Default: `0.0`.
- `timeout_seconds`: Request timeout. Default: `60.0`.
- `verify_citations`: Cryptographically verify line numbers and code excerpts cited by model against local disk. Default: `true`.

---

## 2. Environment Variables

- `SEMANTIQ_ALLOW_EXECUTION`: Set to `true` or `1` to enable dynamic sandbox execution.
- `SEMANTIQ_AI_ENABLED`: Set to `true` or `1` to enable AI enrichment.
- `OPENAI_API_KEY`: Automatically configures OpenAI provider.
- `ANTHROPIC_API_KEY`: Automatically configures Anthropic provider.
- `SEMANTIQ_DB_PATH`: Custom path to SQLite database.
