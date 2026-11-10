"""Phase 4 architecture rule, enforced by reading the source:

    Dashboard -> FastAPI -> existing services -> PostgreSQL

The dashboard never imports backend code or a database library, only the one client touches the network,
and the dashboard never handles the ingest API key.
"""
import ast
from pathlib import Path

DASHBOARD = Path(__file__).resolve().parents[1]
SOURCES = sorted(DASHBOARD.glob("ts_dashboard/*.py")) + sorted(DASHBOARD.glob("views/*.py")) + [DASHBOARD / "app.py"]
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
    names = {p.relative_to(DASHBOARD).as_posix() for p in SOURCES}
    assert {"app.py", "ts_dashboard/api_client.py", "ts_dashboard/config.py", "ts_dashboard/models.py", "ts_dashboard/redact.py",
            "ts_dashboard/overview.py", "ts_dashboard/components.py", "ts_dashboard/charts.py", "ts_dashboard/theme.py",
            "ts_dashboard/paging.py", "views/overview.py", "views/common.py"} <= names


def test_no_backend_or_database_imports():
    for path in SOURCES:
        assert not top_level_imports(path) & FORBIDDEN_IMPORTS, path.name


def test_only_the_client_touches_the_network():
    for path in SOURCES:
        if path.name != ONLY_THE_CLIENT_MAY_USE_THE_NETWORK:
            assert not imported_modules(path) & NETWORK_LIBRARIES, path.name


KEY_HANDLERS = {"config.py", "api_client.py"}


def test_the_ingest_key_is_handled_only_by_the_settings_and_the_client():
    for path in SOURCES:
        code = "".join(line.split("#")[0] for line in path.read_text(encoding="utf-8").splitlines()).lower()
        if path.name not in KEY_HANDLERS:
            assert "x-api-key" not in code and "ingest_api_key" not in code and "get_secret_value" not in code, path.name


def test_the_header_is_set_in_exactly_one_place():
    code = (DASHBOARD / "ts_dashboard" / "api_client.py").read_text(encoding="utf-8")
    assert code.count('"X-API-Key"') == 1


def test_streamlit_is_only_used_by_the_entry_point_and_the_views():
    for path in SOURCES:
        if path.name != "app.py" and path.parent.name != "views":
            assert "streamlit" not in top_level_imports(path), path.name  # keeps the logic testable without a browser


def test_plotly_is_only_used_by_the_chart_module():
    for path in SOURCES:
        if path.name != "charts.py":
            assert "plotly" not in top_level_imports(path), path.name


def test_streamlit_is_bound_to_loopback_only():
    config = (DASHBOARD / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    settings = "\n".join(line for line in config.splitlines() if not line.lstrip().startswith("#"))
    assert 'address = "127.0.0.1"' in settings and "0.0.0.0" not in settings
    assert "gatherUsageStats = false" in config


COMPOSE = DASHBOARD.parent / "docker-compose.yml"
LOOPBACK = "127.0.0.1:"


def published_ports(compose_text: str) -> list[str]:
    """Every list entry under any `ports:` key, comments dropped and quotes stripped.
    shortcut: text-based (no PyYAML), so it assumes block-style lists, as docker-compose.yml uses."""
    found, in_ports, indent = [], False, 0
    for raw in compose_text.splitlines():
        line = raw.split(" #")[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip())
        if line.strip() == "ports:":
            in_ports, indent = True, depth
        elif in_ports and line.lstrip().startswith("- ") and depth >= indent:
            found.append(line.lstrip()[2:].strip().strip("\"'"))
        elif in_ports and depth <= indent:
            in_ports = False
    return found


def test_every_published_port_is_loopback_only():
    ports = published_ports(COMPOSE.read_text(encoding="utf-8"))
    assert ports, "docker-compose.yml publishes no ports - the parser or the file changed"
    assert [p for p in ports if not p.startswith(LOOPBACK)] == []


def test_the_port_check_catches_a_public_binding():
    public = 'services:\n  db:\n    ports:\n      # never 0.0.0.0\n      - "5432:5432"\n      - \'0.0.0.0:8000:8000\'\n'
    ports = published_ports(public)
    assert ports == ["5432:5432", "0.0.0.0:8000:8000"]       # the comment line is not a port
    assert [p for p in ports if not p.startswith(LOOPBACK)] == ports
    assert published_ports('ports:\n  - "127.0.0.1:8000:8000"  # local\n  - 127.0.0.1:5432:5432\nvolumes:\n  - ./x:/y\n') == [
        "127.0.0.1:8000:8000", "127.0.0.1:5432:5432"]
