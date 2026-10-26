"""Registry managing language frontends for the Semantic Program Graph."""

from __future__ import annotations

from semantiq.languages.base import FrontendCapabilities, LanguageFrontend
from semantiq.languages.javascript import JavaScriptFrontend
from semantiq.languages.python import PythonFrontend


class LanguageFrontendRegistry:
    """Registry managing language frontends and mapping file extensions to semantic parsers."""

    def __init__(self) -> None:
        self._frontends: dict[str, LanguageFrontend] = {}
        self._extension_map: dict[str, LanguageFrontend] = {}

        # Register default built-in frontends
        self.register(PythonFrontend())
        self.register(JavaScriptFrontend())

    def register(self, frontend: LanguageFrontend) -> None:
        """Register a language frontend for its declared file extensions."""
        self._frontends[frontend.language_id] = frontend
        for ext in frontend.file_extensions:
            self._extension_map[ext.lower()] = frontend

    def get_frontend_for_file(self, file_path: str) -> LanguageFrontend | None:
        """Lookup frontend capable of analyzing the given file."""
        clean = file_path.lower()
        for ext, frontend in self._extension_map.items():
            if clean.endswith(ext):
                return frontend
        return None

    def get_all_frontends(self) -> list[LanguageFrontend]:
        """Return all registered language frontends."""
        return list(self._frontends.values())

    def get_all_capabilities(self) -> list[FrontendCapabilities]:
        """Return capabilities for all registered frontends."""
        return [f.get_capabilities() for f in self._frontends.values()]


GLOBAL_FRONTEND_REGISTRY = LanguageFrontendRegistry()
