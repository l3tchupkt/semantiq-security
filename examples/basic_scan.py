"""Basic repository scan example using Semantiq Security."""

import asyncio

from semantiq import Semantiq


async def main():
    async with Semantiq() as security:
        result = await security.scan(target=".")
        print(f"Scan ID: {result.scan_id}")
        print(f"Total findings: {len(result.findings)}")

        for finding in result.findings:
            print(f"- [{finding.severity.upper()}] {finding.title} ({finding.file_path}:{finding.start_line})")


if __name__ == "__main__":
    asyncio.run(main())
