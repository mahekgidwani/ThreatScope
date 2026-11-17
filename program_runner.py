"""Start ThreatScope: PostgreSQL + API in Docker, then the Streamlit dashboard.

Usage (from any folder):  python program_runner.py
Press Ctrl+C to stop the dashboard. The Docker containers keep running;
stop them with:  docker compose down   (run in the project folder)
"""
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
DASHBOARD = ROOT / "dashboard"
HEALTH_URL = "http://127.0.0.1:8000/health"


def run(cmd, cwd=ROOT):
    print(f"> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        sys.exit(f"Command failed (exit {result.returncode}): {' '.join(cmd)}")


def ensure_env():
    """Create .env from .env.example with random secrets, only if it does not exist."""
    if ENV.exists():
        return
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    text = text.replace("INGEST_API_KEY=change-me", f"INGEST_API_KEY={secrets.token_hex(24)}")
    text = text.replace("POSTGRES_PASSWORD=change-me", f"POSTGRES_PASSWORD={secrets.token_hex(16)}")
    ENV.write_text(text, encoding="utf-8")
    print("Created .env with random secrets.")


def wait_for_api(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=3) as response:
                if response.status == 200:
                    print("API is ready.")
                    return
        except OSError:  # not up yet, or database still starting (503)
            pass
        time.sleep(2)
    sys.exit("API did not become ready. Check the logs with: docker compose logs backend")


def main():
    if shutil.which("docker") is None:
        sys.exit("Docker not found. Install and start Docker Desktop first.")
    ensure_env()
    run(["docker", "compose", "up", "-d", "--build"])
    wait_for_api()
    run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=DASHBOARD)
    print("Dashboard: http://127.0.0.1:8501  (Ctrl+C to stop it)")
    try:
        run([sys.executable, "-m", "streamlit", "run", "app.py"], cwd=DASHBOARD)
    except KeyboardInterrupt:
        print("\nDashboard stopped. API containers are still running.")


if __name__ == "__main__":
    main()
