"""Phase 4 architecture rule, enforced by reading the source:

    Dashboard -> FastAPI -> existing services -> PostgreSQL

The dashboard never imports backend code or a database library, only the one client touches the network,
and the dashboard never handles the ingest API key.
"""
import ast
from pathlib import Path

DASHBOARD = Path(__file__).resolve().parents[1]
SOURCES = sorted(DASHBOARD.glob("ts_dashboard/*.py")) + [DASHBOARD / "app.py"]
FORBIDDEN_IMPORTS = {"app", "integrations", "sqlalchemy", "psycopg", "psycopg2", "sqlite3", "asyncpg"}
NETWORK_LIBRARIES = {"httpx", "requests", "urllib.request", "http.client", "socket", "aiohttp", "urllib3"}
ONLY_THE_CLIENT_MAY_USE_THE_NETWORK = "api_client.py"


def imported_modules(path: Path) -> set[str]:
    """Full dotted module names (urllib.parse is harmless, urllib.request is not)."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def top_level_imports(path: Path) -> set[str]:
    return {name.split(".")[0] for name in imported_modules(path)}


def test_the_sources_were_found():
    assert {p.name for p in SOURCES} == {"__init__.py", "api_client.py", "config.py", "models.py", "redact.py", "app.py"}


def test_no_backend_or_database_imports():
    for path in SOURCES:
        assert not top_level_imports(path) & FORBIDDEN_IMPORTS, path.name


def test_only_the_client_touches_the_network():
    for path in SOURCES:
        if path.name != ONLY_THE_CLIENT_MAY_USE_THE_NETWORK:
            assert not imported_modules(path) & NETWORK_LIBRARIES, path.name


def test_the_dashboard_never_handles_the_ingest_key():
    for path in SOURCES:
        code = "".join(line.split("#")[0] for line in path.read_text(encoding="utf-8").splitlines()).lower()
        assert "x-api-key" not in code and "ingest_api_key" not in code, path.name


def test_streamlit_is_only_used_by_the_entry_point():
    for path in SOURCES:
        if path.name != "app.py":
            assert "streamlit" not in top_level_imports(path), path.name  # keeps the logic testable without a browser


def test_streamlit_is_bound_to_loopback_only():
    config = (DASHBOARD / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    settings = "\n".join(line for line in config.splitlines() if not line.lstrip().startswith("#"))
    assert 'address = "127.0.0.1"' in settings and "0.0.0.0" not in settings
    assert "gatherUsageStats = false" in config
