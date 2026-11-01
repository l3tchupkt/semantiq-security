"""Unit tests for the general security primitive analysis layer.

Verifies:
1. Detection of predictable CPython memory address session identifiers (str(id(self))) as PREDICTABLE_HEAP_ADDRESS.
2. Correlation with cookie security flags (httponly, samesite, secure).
3. Detection of cryptographically secure pseudo-random generators (secrets.token_hex, uuid4, os.urandom) as SECURE_CSPRNG.
4. Detection of weak PRNGs (random.randint) as WEAK_PRNG.
5. Detection of timestamp-based tokens (time.time()) as PREDICTABLE_TIME_STATE.
6. Detection of CSRF / Same-Origin request verification hooks.
7. SDK and InvestigationToolExecutor tool dispatch integration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from semantiq.analysis.security_primitives import (
    EntropyQuality,
    SecurityPrimitiveKind,
    SecurityPrimitivesAnalyzer,
)
from semantiq.client import Semantiq
from semantiq.discovery.investigation_tools import InvestigationToolExecutor
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.repository.intelligence import RepositoryIntelligence


@pytest.fixture
def mock_security_app(tmp_path: Path) -> Path:
    repo_root = tmp_path / "test_sec_app"
    repo_root.mkdir()

    # Create app module with diverse security primitives
    app_py = repo_root / "server.py"
    app_py.write_text(
        """import os
import random
import secrets
import time
import uuid

class Session:
    def __init__(self):
        self.data = {}

    @property
    def id(self):
        \"\"\"CPython heap object memory address session token.\"\"\"
        return str(id(self))

class TokenManager:
    def generate_api_key(self):
        \"\"\"Secure token generator.\"\"\"
        return secrets.token_hex(32)

    def generate_weak_pin(self):
        \"\"\"Insecure PRNG token.\"\"\"
        return str(random.randint(100000, 999999))

    def generate_timestamp_token(self):
        \"\"\"Predictable time-based session token.\"\"\"
        return f"sess_{int(time.time())}"

def set_auth_cookie(response, session):
    response.set_cookie("session_id", session.id, httponly=True, samesite="Strict", secure=True)

def enforce_same_origin(environ):
    \"\"\"Validate Origin and Referer headers against Host.\"\"\"
    origin = environ.get("HTTP_ORIGIN")
    host = environ.get("HTTP_HOST")
    if origin and host not in origin:
        return False
    return True
""",
        encoding="utf-8",
    )
    return repo_root


def test_predictable_heap_session_detection(mock_security_app: Path) -> None:
    analyzer = SecurityPrimitivesAnalyzer(mock_security_app)
    facts = analyzer.analyze_repository(["server.py"])

    heap_facts = [f for f in facts if f.entropy_quality == EntropyQuality.PREDICTABLE_HEAP_ADDRESS]
    assert len(heap_facts) == 1

    heap_fact = heap_facts[0]
    assert heap_fact.kind == SecurityPrimitiveKind.SESSION_IDENTIFIER
    assert "id(self)" in heap_fact.generation_expression
    assert heap_fact.is_weak_or_predictable is True
    assert "session_id" in str(heap_fact.exposure_channels)
    assert heap_fact.cookie_flags.get("httponly") is True
    assert heap_fact.cookie_flags.get("samesite") == "Strict"
    assert heap_fact.cookie_flags.get("secure") is True
    assert "memory address" in heap_fact.exploitability_assessment.lower()
    assert "str(id(self))" in heap_fact.exploitability_assessment


def test_csprng_and_weak_prng_classification(mock_security_app: Path) -> None:
    analyzer = SecurityPrimitivesAnalyzer(mock_security_app)
    facts = analyzer.analyze_repository(["server.py"])

    csprng_facts = [f for f in facts if f.entropy_quality == EntropyQuality.SECURE_CSPRNG]
    assert len(csprng_facts) == 1
    assert csprng_facts[0].is_weak_or_predictable is False
    assert "secrets.token_hex" in csprng_facts[0].generation_expression

    weak_facts = [f for f in facts if f.entropy_quality == EntropyQuality.WEAK_PRNG]
    assert len(weak_facts) == 1
    assert weak_facts[0].is_weak_or_predictable is True
    assert "random.randint" in weak_facts[0].generation_expression

    time_facts = [f for f in facts if f.entropy_quality == EntropyQuality.PREDICTABLE_TIME_STATE]
    assert len(time_facts) == 1
    assert time_facts[0].is_weak_or_predictable is True
    assert "time.time()" in time_facts[0].generation_expression


def test_csrf_origin_enforcement_detection(mock_security_app: Path) -> None:
    analyzer = SecurityPrimitivesAnalyzer(mock_security_app)
    facts = analyzer.analyze_repository(["server.py"])

    csrf_facts = [f for f in facts if f.kind == SecurityPrimitiveKind.CSRF_TOKEN]
    assert len(csrf_facts) == 1
    assert csrf_facts[0].symbol_name == "enforce_same_origin"
    assert csrf_facts[0].validation_mechanism == "same_origin_header_check"


@pytest.mark.anyio
async def test_security_primitives_client_and_executor(mock_security_app: Path) -> None:
    client = Semantiq()
    all_primitives = await client.query_security_primitives(mock_security_app)
    assert len(all_primitives) >= 4

    session_primitives = await client.query_security_primitives(mock_security_app, kind="session_identifier")
    assert len(session_primitives) >= 1
    assert any(p["entropy_quality"] == "predictable_heap_address" for p in session_primitives)

    # Test InvestigationToolExecutor dispatch
    intel = RepositoryIntelligence(mock_security_app)
    graph = SemanticProgramGraph()
    executor = InvestigationToolExecutor(mock_security_app, intel, graph)

    exec_res = executor.execute("query_security_primitives", {"kind": "session_identifier"})
    assert exec_res["status"] == "success"
    assert exec_res["total_primitives"] >= 1
    assert any(p["entropy_quality"] == "predictable_heap_address" for p in exec_res["primitives"])

