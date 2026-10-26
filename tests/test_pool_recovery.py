"""The pool survives a database restart. Needs PostgreSQL (DATABASE_URL); skipped otherwise."""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

psycopg2 = pytest.importorskip("psycopg2")
from core import database as db  # noqa: E402


def _ready():
    try:
        db.init_pool()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="PostgreSQL not available")


def _kill_all_connections():
    admin = psycopg2.connect(db.get_database_url())
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid()"
        )
    admin.close()
    time.sleep(0.3)


def test_pool_recovers_after_every_connection_is_killed():
    assert db.health_check_db()["status"] == "healthy"
    _kill_all_connections()
    assert db.health_check_db()["status"] == "healthy"   # first call after the restart
    assert db.health_check_db()["status"] == "healthy"


def test_every_pooled_connection_is_replaced_not_just_one():
    pool = db.get_pool()
    held = [pool.getconn() for _ in range(5)]
    for c in held:
        pool.putconn(c)
    _kill_all_connections()
    for _ in range(8):                                    # more calls than connections held
        assert db.health_check_db()["status"] == "healthy"


def test_a_connection_is_clean_when_handed_out():
    pool = db.get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")                       # leaves a transaction open
    finally:
        pool.putconn(conn)
    again = pool.getconn()
    try:
        assert again.get_transaction_status() == psycopg2.extensions.TRANSACTION_STATUS_IDLE
    finally:
        pool.putconn(again)
