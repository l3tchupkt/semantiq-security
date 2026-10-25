"""Context extraction around vulnerability findings."""

from __future__ import annotations

from pathlib import Path


class ContextCollector:
    """Collects surrounding source context and symbol hierarchy for findings."""

    def __init__(self, repository_root: Path) -> None:
        self.repository_root = repository_root

    def get_surrounding_code(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        context_lines: int = 5,
    ) -> tuple[str, int, int]:
        """Extract surrounding source lines around a code snippet."""
        full_path = self.repository_root / file_path
        if not full_path.exists() or not full_path.is_file():
            return "", start_line, end_line

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except OSError:
            return "", start_line, end_line

        context_start = max(1, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines)

        formatted_lines: list[str] = []
        for line_num in range(context_start, context_end + 1):
            prefix = " >" if start_line <= line_num <= end_line else "  "
            line_content = lines[line_num - 1]
            formatted_lines.append(f"{prefix} {line_num:4d} | {line_content}")

        return "\n".join(formatted_lines), context_start, context_end
