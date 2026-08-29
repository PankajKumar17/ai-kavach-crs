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

try:
    from dashboard.app import app as _app
    app = _app
except Exception as e:
    import traceback
    err = traceback.format_exc()
    async def app(scope, receive, send):
        assert scope['type'] == 'http'
        await send({
            'type': 'http.response.start',
            'status': 500,
            'headers': [[b'content-type', b'text/plain']],
        })
        await send({
            'type': 'http.response.body',
            'body': err.encode('utf-8'),
        })
