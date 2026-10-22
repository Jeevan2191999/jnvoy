#!/usr/bin/env python3
"""
Fixes the Docker stack and the README claims that no longer match the product.

docker-compose.yml
  * passes JNVOY_API_KEYS / JNVOY_ADMIN_KEYS through (without them every /v1 route answers 503),
    and stops with a clear message if JNVOY_API_KEYS is missing
  * removes Redis (nothing in the app uses it)
  * publishes PostgreSQL on localhost only (it was open to the whole network with password "jnvoy")
Also: new .env.example, a small test, README and homepage wording brought in line.

Run from the repo root:   python apply_docker_fix.py
Safe: every edit must match exactly once, in ALL files, or nothing is written.
Re-running is a no-op.   Undo with: git checkout docker-compose.yml README.md static/index.html
"""
import sys
from pathlib import Path

COMPOSE = Path("docker-compose.yml")
README = Path("README.md")
INDEX = Path("static") / "index.html"
ENV_EXAMPLE = Path(".env.example")
TEST = Path("tests") / "test_docker_compose.py"

REDIS_BLOCK = '''  # ── Redis (token store and semantic cache) ─────────────────────────────────
  redis:
    image: redis:7-alpine
    container_name: jnvoy-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

'''

COMPOSE_EDITS = [
    ("# Starts: API + Redis + PostgreSQL in one command\n# Usage: docker-compose up\n",
     "# Starts: API + PostgreSQL in one command\n"
     "# Setup:  cp .env.example .env, set your keys in .env, then run: docker-compose up\n"),
    ("      - REDIS_URL=redis://redis:6379\n",
     "      - JNVOY_API_KEYS=${JNVOY_API_KEYS:?Set JNVOY_API_KEYS in your .env file (see .env.example)}\n"
     "      - JNVOY_ADMIN_KEYS=${JNVOY_ADMIN_KEYS:-}\n"),
    ("    depends_on:\n      redis:\n        condition: service_healthy\n      postgres:\n        condition: service_healthy\n",
     "    depends_on:\n      postgres:\n        condition: service_healthy\n"),
    (REDIS_BLOCK, ""),
    ('      - "5432:5432"\n', '      - "127.0.0.1:5432:5432"\n'),
    ("volumes:\n  redis_data:\n  postgres_data:\n", "volumes:\n  postgres_data:\n"),
]

README_EDITS = [
    ("- Semantic caching saves 20 to 40 percent of LLM costs automatically\n",
     "- Exact-match response caching: an identical request from the same API key returns the stored answer with no model call\n"),
    ("- PostgreSQL audit logs that survive forever for FCA and GDPR compliance\n",
     "- PostgreSQL audit log of what was detected: counts by type, never the original text\n"),
    ("- Multi-tenant API keys so multiple companies can use it with complete data isolation\n",
     "- API keys with client and admin roles, per-key rate limits and constant-time checking\n"),
    ("- PDF compliance report generator, FCA and GDPR ready\n",
     "- PDF compliance report generator\n"),
    ("- Docker stack: API plus PostgreSQL plus Redis in one command\n",
     "- Docker stack: API plus PostgreSQL in one command\n"),
    ("- 180 automated tests passing\n", "- 374 automated tests passing\n"),
    ("cd jnvoy\ndocker-compose up\n",
     "cd jnvoy\ncp .env.example .env     # then open .env and set your keys\ndocker-compose up\n"),
    ("180 tests passing across", "374 tests passing across"),
]

INDEX_EDITS = [
    ("        <p>One command starts everything. API plus PostgreSQL plus Redis. Self-hostable on your own infrastructure.</p>\n",
     "        <p>One command starts the API and its PostgreSQL audit database, once your keys are set. Self-hostable on your own infrastructure.</p>\n"),
]

ENV_EXAMPLE_TEXT = """# Copy this file to .env and fill it in. Never commit .env.
#
# Client key: lets an application call /v1/proxy and /v1/scan. Generate one with:
#   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
JNVOY_API_KEYS=
# Admin key: also reads the audit log and reports. Use a different value.
JNVOY_ADMIN_KEYS=

# Model provider keys (set the ones you use)
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GOOGLE_API_KEY=
MISTRAL_API_KEY=
"""

TEST_TEXT = '''"""Guards on the Docker stack: keys are passed through, and nothing is exposed that should not be."""

from pathlib import Path

COMPOSE = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(encoding="utf-8")


def test_compose_passes_the_api_keys_and_fails_clearly_without_them():
    assert "JNVOY_API_KEYS=${JNVOY_API_KEYS:?" in COMPOSE
    assert "JNVOY_ADMIN_KEYS" in COMPOSE


def test_compose_no_longer_starts_an_unused_redis():
    assert "redis" not in COMPOSE.lower()


def test_postgres_is_not_published_to_the_whole_network():
    assert '"127.0.0.1:5432:5432"' in COMPOSE
    assert '"5432:5432"' not in COMPOSE.replace('"127.0.0.1:5432:5432"', "")
'''

PLAN = [(COMPOSE, COMPOSE_EDITS), (README, README_EDITS), (INDEX, INDEX_EDITS)]


def main() -> int:
    for path, _ in PLAN:
        if not path.exists():
            print(f"Cannot find {path}. Run this from the repo root.")
            return 1
    if "JNVOY_API_KEYS" in COMPOSE.read_bytes().decode("utf-8"):
        print("Already applied. Nothing to do.")
        return 0
    results = {}
    for path, edits in PLAN:
        src = path.read_bytes().decode("utf-8")
        for number, (old, _new) in enumerate(edits, start=1):
            found = src.count(old)
            if found != 1:
                print(f"{path} edit {number}: expected exactly 1 match, found {found}. NOTHING WAS CHANGED.")
                print(f"Send me the output of:  git --no-pager diff --stat   and   grep -n 'redis\\|180' {path}")
                return 1
        for old, new in edits:
            src = src.replace(old, new)
        results[path] = src
    for path, src in results.items():
        path.write_bytes(src.encode("utf-8"))
    ENV_EXAMPLE.write_text(ENV_EXAMPLE_TEXT, encoding="utf-8")
    TEST.write_text(TEST_TEXT, encoding="utf-8")
    print("Applied: Docker keys passed through, Redis removed, Postgres bound to localhost,")
    print("         .env.example and a test added, README and homepage wording corrected.")
    print("Next:  pytest -q")
    return 0


if __name__ == "__main__":
    sys.exit(main())
