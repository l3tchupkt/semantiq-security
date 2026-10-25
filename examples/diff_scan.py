"""Git diff security scan for PR reviews."""

import asyncio

from semantiq import Semantiq


async def main():
    async with Semantiq() as security:
        result = await security.scan_diff(target=".", base="origin/main")
        print(f"Diff scan findings: {len(result.findings)}")


if __name__ == "__main__":
    asyncio.run(main())
