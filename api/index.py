"""Vercel serverless entrypoint.

Exposes the FastAPI dashboard app at the function root. Vercel's
@vercel/python runtime looks for an ``app`` variable in this module.

The repo-root path is added to sys.path so ``dashboard.app`` resolves:
the function bundles the whole repository, but the function's own
directory (api/) is what's on sys.path by default.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.append(REPO_ROOT)

from dashboard.app import app as _app

app = _app
