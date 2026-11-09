"""Tiny DB abstraction: SQLite by default, Postgres when DATABASE_URL is set.

Render's free web services have an ephemeral filesystem, so SQLite data is
lost on every redeploy, restart, or spin-down from idle. Point DATABASE_URL
at a free Postgres instance (Neon, Supabase, or Render's own 90-day-trial
Postgres) to keep accounts and scan history across restarts.
"""
import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL")
BACKEND = "postgres" if DATABASE_URL else "sqlite"
SQLITE_PATH = os.environ.get("DB_PATH", "sitescan.db")

if BACKEND == "postgres":
    import psycopg
    from psycopg.rows import dict_row

    if DATABASE_URL.startswith("postgres://"):  # psycopg wants postgresql://
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
elif os.environ.get("VERCEL"):
    # Vercel's filesystem is read-only outside /tmp, and /tmp doesn't persist between
    # requests, so a SQLite file silently loses all data constantly. Fail loudly instead.
    raise RuntimeError("DATABASE_URL must be set on Vercel - SQLite cannot persist there. "
                       "Point it at a free Postgres instance (e.g. Neon or Supabase).")

SQLITE_SCHEMA = """
create table if not exists users(id integer primary key, email text unique, pw text, created_at text);
create table if not exists domains(id integer primary key, user_id integer, domain text, created_at text,
  unique(user_id, domain));
create table if not exists scans(id integer primary key, domain_id integer, created_at text,
  status text, score integer, result text, deep integer default 0, authorized_at text);
"""
PG_SCHEMA = """
create table if not exists users(id serial primary key, email text unique, pw text, created_at text);
create table if not exists domains(id serial primary key, user_id integer references users(id) on delete cascade,
  domain text, created_at text, unique(user_id, domain));
create table if not exists scans(id serial primary key, domain_id integer references domains(id) on delete cascade,
  created_at text, status text, score integer, result text, deep integer default 0, authorized_at text);
"""


def _pg():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def _adapt(sql):
    return sql.replace("?", "%s") if BACKEND == "postgres" else sql


def init_schema():
    if BACKEND == "postgres":
        with _pg() as c, c.cursor() as cur:
            cur.execute(PG_SCHEMA)
        return
    c = sqlite3.connect(SQLITE_PATH)
    c.executescript(SQLITE_SCHEMA)
    for col in ("deep integer default 0", "authorized_at text"):
        try:
            c.execute("alter table scans add column " + col)
        except sqlite3.OperationalError:
            pass  # column already exists, from an older SQLite database file
    c.commit()
    c.close()


def q(sql, args=(), one=False):
    if BACKEND == "postgres":
        with _pg() as c, c.cursor() as cur:
            cur.execute(_adapt(sql), args)
            rows = cur.fetchall() if cur.description else []
    else:
        c = sqlite3.connect(SQLITE_PATH, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            rows = c.execute(sql, args).fetchall()
            c.commit()
        finally:
            c.close()
    return (rows[0] if rows else None) if one else rows


def ins(sql, args):
    if BACKEND == "postgres":
        stmt = sql.rstrip().rstrip(";") + " returning id"
        with _pg() as c, c.cursor() as cur:
            cur.execute(_adapt(stmt), args)
            return cur.fetchone()["id"]
    c = sqlite3.connect(SQLITE_PATH, timeout=30)
    try:
        i = c.execute(sql, args).lastrowid
        c.commit()
        return i
    finally:
        c.close()
