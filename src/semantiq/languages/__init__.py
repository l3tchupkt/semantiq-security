"""Language frontends for the Semantic Program Graph."""

from __future__ import annotations

from semantiq.languages.base import FrontendCapabilities, FrontendResult, LanguageFrontend
from semantiq.languages.javascript import JavaScriptFrontend
from semantiq.languages.python import PythonFrontend
from semantiq.languages.registry import GLOBAL_FRONTEND_REGISTRY, LanguageFrontendRegistry

__all__ = [
    "FrontendCapabilities",
    "FrontendResult",
    "GLOBAL_FRONTEND_REGISTRY",
    "JavaScriptFrontend",
    "LanguageFrontend",
    "LanguageFrontendRegistry",
    "PythonFrontend",
]
