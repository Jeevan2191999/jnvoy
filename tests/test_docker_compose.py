"""Guards on the Docker stack: keys are passed through, and nothing is exposed that should not be."""

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
