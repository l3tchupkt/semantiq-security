"""Focused scan targeting specific vulnerability classes."""

import asyncio

from semantiq import Semantiq


async def main():
    async with Semantiq() as security:
        result = await security.scan(
            target=".",
            focus=["sql-injection", "command-injection", "ssrf"],
        )
        print(f"Focused findings: {len(result.findings)}")
        for f in result.findings:
            print(f"[{f.category.value}] {f.title}")


if __name__ == "__main__":
    asyncio.run(main())
