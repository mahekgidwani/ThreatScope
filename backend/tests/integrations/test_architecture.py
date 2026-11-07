"""Phase 3 architecture rules, enforced by reading the source:

    Source -> Adapter -> ThreatScope API -> Validation -> Indicator extraction -> Risk scoring -> PostgreSQL

Adapters never touch the database, never run what they analyse, and reach the network only through
the one shared client.
"""
import ast
from pathlib import Path

import pytest

INTEGRATIONS = Path(__file__).resolve().parents[2] / "integrations"
MODULES = sorted(p for p in INTEGRATIONS.glob("*.py"))

# The only parts of the backend an adapter may import. They are pure functions (no database, no settings
# needed): the API's own domain/IP normalisation, and its log-redaction setup.
ALLOWED_APP_IMPORTS = {"app.schemas.event", "app.logging_config"}
DATABASE_LIBRARIES = {"sqlalchemy", "psycopg", "psycopg2", "sqlite3", "asyncpg", "pymongo"}
EXECUTION_TOOLS = {"subprocess", "ctypes", "pickle", "marshal", "importlib", "runpy", "multiprocessing"}
NETWORK_LIBRARIES = {"httpx", "requests", "urllib.request", "http.client", "socket", "aiohttp", "urllib3"}


def imported_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names |= {f"{node.module}.{alias.name}" for alias in node.names}
    return names


def top(name: str) -> str:
    return name.split(".")[0]


def test_the_adapter_modules_were_found():
    expected = {"client", "config", "cli_common", "textutil", "file_analyser", "file_formats", "analyse_file",
                "opensquat_detector", "opensquat_adapter", "modsec_parser", "modsec_adapter"}
    assert expected <= {p.stem for p in MODULES}


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_no_adapter_touches_the_database(path):
    names = imported_names(path)
    assert not {top(n) for n in names} & DATABASE_LIBRARIES
    for name in names:
        if name == "app" or name.startswith("app."):
            assert any(name == ok or name.startswith(ok + ".") or ok.startswith(name + ".")
                       for ok in ALLOWED_APP_IMPORTS) or name == "app" or name in {"app.schemas", "app.logging_config"}, \
                f"{path.name} imports {name}, which is not on the allow-list"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_nothing_is_executed_or_loaded_dynamically(path):
    assert not {top(n) for n in imported_names(path)} & EXECUTION_TOOLS
    calls = {node.func.id for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not calls & {"eval", "exec", "compile", "__import__"}
    attribute_calls = {f"{node.func.value.id}.{node.func.attr}"
                       for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and isinstance(node.func.value, ast.Name)}
    assert not attribute_calls & {"os.system", "os.popen", "os.exec", "os.spawn", "os.startfile"}


@pytest.mark.parametrize("path", [p for p in MODULES if p.name != "client.py"], ids=lambda p: p.name)
def test_only_the_shared_client_talks_to_the_network(path):
    names = imported_names(path)
    assert not {n for n in names if n in NETWORK_LIBRARIES or top(n) in {"httpx", "requests", "socket", "aiohttp"}}


def test_the_client_posts_to_exactly_one_endpoint():
    tree = ast.parse((INTEGRATIONS / "client.py").read_text(encoding="utf-8"))
    paths = {node.value for node in ast.walk(tree)
             if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("/api/")}
    assert paths == {"/api/v1/events"}


def test_no_adapter_contains_a_hard_coded_secret_or_reads_reference_key_files():
    for path in MODULES:
        text = path.read_text(encoding="utf-8").lower()
        assert "api_key.txt" not in text and "vt_key.txt" not in text, path.name
