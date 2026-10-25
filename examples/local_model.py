"""Running Semantiq with a local private Ollama instance."""

import asyncio

from semantiq import Semantiq, SemantiqConfig


async def main():
    cfg = SemantiqConfig()
    cfg.ai.enabled = True
    cfg.ai.provider = "ollama"
    cfg.ai.model = "deepseek-r1"
    cfg.ai.endpoint_url = "http://localhost:11434/api/generate"

    async with Semantiq(config=cfg) as security:
        tm = await security.build_threat_model(".")
        print(f"Threat Model: {tm.application_name}")
        for assumption in tm.security_assumptions:
            print(f"- {assumption}")


if __name__ == "__main__":
    asyncio.run(main())
