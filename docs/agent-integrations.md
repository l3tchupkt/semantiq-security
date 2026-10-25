# Agent and Model Context Protocol (MCP) Integrations

Semantiq Security is built from the ground up for autonomous AI agents and security assistants. It provides a native Model Context Protocol (MCP) server over stdio as well as a direct Python async API.

---

## 1. Model Context Protocol (MCP) Server

Semantiq exposes 10 high-value security tools:
1. `semantiq_inspect_repository`
2. `semantiq_build_threat_model`
3. `semantiq_scan_repository`
4. `semantiq_scan_diff`
5. `semantiq_get_findings`
6. `semantiq_investigate_finding`
7. `semantiq_validate_finding`
8. `semantiq_propose_patch`
9. `semantiq_verify_patch`
10. `semantiq_export_report`

Launch the MCP server in stdio mode:
```bash
semantiq mcp
```

---

## 2. Claude Code Integration

To integrate Semantiq into Claude Code, add the MCP server to your Claude configuration (`~/.claude/mcp.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "semantiq": {
      "command": "semantiq",
      "args": ["mcp"]
    }
  }
}
```

Now you can instruct Claude Code:
> "Run a Semantiq security scan on this repository focusing on SQL injection and command injection. Retrieve the findings and generate a patch for any high severity issues."

---

## 3. OpenCode Integration

In OpenCode, configure Semantiq in your tool configuration:

```json
{
  "tools": {
    "semantiq": {
      "type": "mcp",
      "command": "semantiq",
      "args": ["mcp"]
    }
  }
}
```

---

## 4. Google Antigravity Integration

In Antigravity, add Semantiq to your active workspace `.mcp.json` or configuration:

```json
{
  "mcpServers": {
    "semantiq": {
      "command": "semantiq",
      "args": ["mcp"]
    }
  }
}
```

Antigravity agents can invoke `semantiq_scan_repository` or use the CLI via bash/pwsh to orchestrate automated bug bounty reviews and PR checks.

---

## 5. Custom Python Agent Loop (LangGraph / Autogen)

```python
import asyncio
from semantiq import Semantiq

async def autonomous_security_agent(target_repo: str):
    async with Semantiq() as security:
        # Step 1: Threat Model
        threat_model = await security.build_threat_model(target_repo)
        print(f"Mapped {len(threat_model.entry_points)} entry points.")

        # Step 2: Scan
        result = await security.scan(target_repo)

        # Step 3: Investigate & Patch
        for finding in result.findings:
            if finding.severity in ("critical", "high"):
                patch = await security.propose_patch(finding.finding_id)
                verification = await security.verify_patch(finding.finding_id, patch)
                print(f"Finding {finding.finding_id} patch status: {verification.status}")

asyncio.run(autonomous_security_agent("./my-project"))
```
