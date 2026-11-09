"""Vercel entrypoint. Vercel's Python runtime looks for a FastAPI instance named
`app` and wraps it to handle requests; this file just re-exports the real app."""
from app.main import app  # noqa: F401
