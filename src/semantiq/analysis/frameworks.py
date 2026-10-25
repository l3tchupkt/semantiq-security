"""Framework-aware security analysis and model registry for Flask, FastAPI, and Django."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FrameworkModel:
    """Specification of framework-specific routes, request inputs, and security boundaries."""

    name: str
    route_decorators: set[str]
    auth_decorators: set[str]
    input_sources: set[str]
    template_sinks: set[str]
    redirect_sinks: set[str]
    raw_sql_sinks: set[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_route_decorator(self, decorator_name: str) -> bool:
        dec_clean = decorator_name.strip("@")
        return any(
            dec_clean.startswith(prefix) or dec_clean.endswith(suffix)
            for prefix in self.route_decorators
            for suffix in [".route", ".get", ".post", ".put", ".delete", ".patch"]
        ) or dec_clean in self.route_decorators

    def is_auth_decorator(self, decorator_name: str) -> bool:
        dec_clean = decorator_name.strip("@").lower()
        return any(auth.lower() in dec_clean for auth in self.auth_decorators)

    def is_input_source(self, expression: str) -> bool:
        expr_clean = expression.strip()
        return any(expr_clean.startswith(src) for src in self.input_sources)


# Built-in framework models

FLASK_MODEL = FrameworkModel(
    name="flask",
    route_decorators={
        "app.route",
        "bp.route",
        "blueprint.route",
        "api.route",
    },
    auth_decorators={
        "login_required",
        "roles_required",
        "fresh_login_required",
        "jwt_required",
    },
    input_sources={
        "request.args",
        "request.args.get",
        "request.form",
        "request.form.get",
        "request.values",
        "request.values.get",
        "request.json",
        "request.get_json",
        "request.data",
        "request.headers",
        "request.cookies",
        "request.files",
    },
    template_sinks={
        "render_template_string",
    },
    redirect_sinks={
        "redirect",
        "flask.redirect",
    },
    raw_sql_sinks={
        "db.session.execute",
        "cursor.execute",
    },
)

FASTAPI_MODEL = FrameworkModel(
    name="fastapi",
    route_decorators={
        "app.get",
        "app.post",
        "app.put",
        "app.delete",
        "app.patch",
        "router.get",
        "router.post",
        "router.put",
        "router.delete",
        "router.patch",
    },
    auth_decorators={
        "Depends",
        "Security",
        "oauth2_scheme",
    },
    input_sources={
        "request.query_params",
        "request.path_params",
        "request.headers",
        "request.cookies",
        "request.body",
        "request.json",
        "Query",
        "Path",
        "Body",
        "Header",
        "Cookie",
    },
    template_sinks={
        "templates.TemplateResponse",
    },
    redirect_sinks={
        "RedirectResponse",
    },
    raw_sql_sinks={
        "session.execute",
        "connection.execute",
    },
)

DJANGO_MODEL = FrameworkModel(
    name="django",
    route_decorators={
        "path",
        "re_path",
        "api_view",
        "action",
    },
    auth_decorators={
        "login_required",
        "permission_required",
        "user_passes_test",
    },
    input_sources={
        "request.GET",
        "request.GET.get",
        "request.POST",
        "request.POST.get",
        "request.body",
        "request.COOKIES",
        "request.META",
        "request.data",
        "request.query_params",
    },
    template_sinks={
        "Template",
    },
    redirect_sinks={
        "redirect",
        "HttpResponseRedirect",
    },
    raw_sql_sinks={
        "cursor.execute",
        "objects.raw",
        "objects.extra",
    },
)


class FrameworkRegistry:
    """Registry managing supported framework definitions."""

    def __init__(self) -> None:
        self.models: dict[str, FrameworkModel] = {
            "flask": FLASK_MODEL,
            "fastapi": FASTAPI_MODEL,
            "django": DJANGO_MODEL,
        }

    def register(self, model: FrameworkModel) -> None:
        self.models[model.name.lower()] = model

    def get(self, name: str) -> FrameworkModel | None:
        return self.models.get(name.lower())

    def get_all_input_sources(self) -> set[str]:
        sources: set[str] = set()
        for m in self.models.values():
            sources.update(m.input_sources)
        return sources

    def is_any_route_decorator(self, decorator_name: str) -> bool:
        return any(m.is_route_decorator(decorator_name) for m in self.models.values())

    def is_any_auth_decorator(self, decorator_name: str) -> bool:
        return any(m.is_auth_decorator(decorator_name) for m in self.models.values())

    def is_auth_decorator(self, decorator_name: str) -> bool:
        """Alias for is_any_auth_decorator."""
        return self.is_any_auth_decorator(decorator_name)


# Global framework registry singleton
GLOBAL_FRAMEWORK_REGISTRY = FrameworkRegistry()
