"""One reviewed Python guard for every reference-patch handoff."""
import ast
import difflib


def python_guard(endpoint="/api/v1/voucher/claim"):
    # Endpoints are literals, never executable source.
    code = '''"""Reference mitigation only; DB constraints are still required.
Requires: fastapi, redis>=5,<7, authenticated scope.state.user_id.
The lease is not a durable idempotency guarantee. No client fingerprint is trusted.
"""
import os
import secrets
from fastapi.responses import JSONResponse

_RELEASE = 'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) end return 0'

class RedisIdempotencyMiddleware:
    def __init__(self, app, redis_client=None, lock_ttl_sec=3):
        self.app = app
        if redis_client is None:
            import redis.asyncio as aioredis
            redis_client = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        self.redis = redis_client
        self.ttl_ms = max(1, int(lock_ttl_sec * 1000))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != ENDPOINT or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        user_id = (scope.get("state") or {}).get("user_id")
        if not user_id:
            return await JSONResponse({"error": "Unauthenticated"}, status_code=401)(scope, receive, send)
        key = "aigis:lock:claim:" + str(user_id)
        owner = secrets.token_hex(16)
        try:
            acquired = await self.redis.set(key, owner, nx=True, px=self.ttl_ms)
        except Exception:
            return await JSONResponse({"error": "Guard unavailable"}, status_code=503)(scope, receive, send)
        if not acquired:
            return await JSONResponse({"error": "Concurrent claim blocked"}, status_code=429)(scope, receive, send)
        try:
            return await self.app(scope, receive, send)
        finally:
            try:
                await self.redis.eval(_RELEASE, 1, key, owner)
            except Exception:
                # The owner-token lease expires; never delete a successor's lock.
                pass
'''.replace("ENDPOINT", repr(endpoint))
    ast.parse(code)
    return code


def reference_diff(endpoint="/api/v1/voucher/claim"):
    return "".join(difflib.unified_diff([], python_guard(endpoint).splitlines(keepends=True),
                                       fromfile="/dev/null", tofile="b/app/middleware/idempotency.py"))


def metadata():
    return {"template_id": "authenticated-owner-lock-v1", "applicability": ["TOCTOU_RACE_CONDITION"],
            "dependencies": ["fastapi", "redis>=5,<7"],
            "assumptions": ["Upstream authentication sets scope.state.user_id", "Database-level claim and budget constraints"],
            "limitations": ["Lease expiry permits overlap during long requests", "Not durable request idempotency",
                            "Does not remediate BOLA, amount tampering, or workflow bypass"],
            "validation": "PYTHON_SYNTAX_AND_PROTOCOL_DOUBLE_TESTS", "production_verified": False}
