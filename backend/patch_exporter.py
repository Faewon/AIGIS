"""
Pillar 3: Multi-Target Language & 0-Day Edge WAF Patch Exporter
Tự động tổng hợp bản vá đa ngôn ngữ và quy tắc WAF tại biên mạng (Edge)
- Python (FastAPI Async)
- Java (Spring Boot + Redisson)
- Go (Golang Gin + Redsync)
- Cloudflare WAF Expression Rules
- NGINX OpenResty Lua WAF
- AWS WAF JSON Custom Rule
"""

import re
from typing import Dict, Any

class MultiTargetPatchExporter:

    @classmethod
    def generate_all_patches(cls, vulnerability_type: str = "TOCTOU_RACE_CONDITION", endpoint: str = "/api/v1/voucher/claim") -> Dict[str, Any]:
        # Sanitize values before interpolating them into generated code/rules.
        safe_endpoint = endpoint.strip() if isinstance(endpoint, str) else ""
        if not re.fullmatch(r"/[A-Za-z0-9_./:-]{1,120}", safe_endpoint):
            safe_endpoint = "/api/v1/voucher/claim"
        endpoint = safe_endpoint

        safe_vuln = vulnerability_type.strip().upper() if isinstance(vulnerability_type, str) else ""
        if not re.fullmatch(r"[A-Z0-9_]{1,80}", safe_vuln):
            safe_vuln = "TOCTOU_RACE_CONDITION"
        vulnerability_type = safe_vuln

        # 0. ROOT-CAUSE FIX: DB-LEVEL ATOMICITY (preferred over any mutex)
        sql_patch = f"""-- ==============================================================================
-- AIGIS ROOT-CAUSE FIX — DATABASE-LEVEL ATOMICITY (REFERENCE TEMPLATE, PostgreSQL)
-- Vulnerability: {vulnerability_type} on {endpoint}
-- A mutex only narrows the race; these constraints close it, including Sybil swarms
-- that rotate user IDs (the budget check is global and atomic).
-- ==============================================================================

-- 1. One claim per (user, voucher), enforced by the database.
ALTER TABLE voucher_claims
    ADD CONSTRAINT uq_voucher_claim_user UNIQUE (user_id, voucher_code);

-- 2. Claim + budget debit in ONE transaction; both statements are atomic.
BEGIN;

-- Debit the campaign budget only if enough remains (conditional UPDATE).
UPDATE voucher_campaigns
   SET budget_remaining = budget_remaining - $3
 WHERE voucher_code = $2
   AND budget_remaining >= $3;
-- If 0 rows were updated: ROLLBACK and return 409 "budget exhausted".

-- Record the claim; a duplicate is a no-op instead of a second payout.
INSERT INTO voucher_claims (user_id, voucher_code, amount, claimed_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (user_id, voucher_code) DO NOTHING;
-- If 0 rows were inserted: ROLLBACK (restores the budget) and return 409 "already claimed".

COMMIT;
"""

        # 1. PYTHON FASTAPI PATCH
        python_patch = f"""# ==============================================================================
# AIGIS BLUE TEAM — PYTHON FASTAPI IDEMPOTENCY MIDDLEWARE (REFERENCE TEMPLATE)
# Vulnerability: {vulnerability_type} on {endpoint}
# Requires an upstream authentication middleware that sets request.state.user_id.
# ==============================================================================
import os
import secrets
from fastapi import Request
from fastapi.responses import JSONResponse
import redis.asyncio as aioredis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = aioredis.from_url(REDIS_URL)

_RELEASE_LOCK_LUA = '''
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
end
return 0
'''

async def aigis_concurrency_guard_middleware(request: Request, call_next):
    if request.url.path == "{endpoint}" and request.method == "POST":
        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            return JSONResponse(status_code=401, content={{"success": False, "error": "Unauthenticated"}})

        lock_key = f"aigis:lock:claim:{{user_id}}"
        lock_value = secrets.token_hex(16)

        # Atomic SET NX with a short lease. Never trust a client-supplied X-User-ID.
        acquired = await redis_client.set(lock_key, lock_value, nx=True, ex=3)
        if not acquired:
            return JSONResponse(
                status_code=429,
                content={{"success": False, "error": "Too Many Requests: concurrent claim blocked by AIGIS."}}
            )
        try:
            return await call_next(request)
        finally:
            await redis_client.eval(_RELEASE_LOCK_LUA, 1, lock_key, lock_value)
    return await call_next(request)
"""

        # 2. JAVA SPRING BOOT PATCH (Core Banking standard: Vietcombank / BIDV / Techcombank)
        java_patch = f"""// ==============================================================================
// AIGIS BLUE TEAM — SPRING BOOT & REDISSON DISTRIBUTED LOCK (REFERENCE TEMPLATE)
// Target: {endpoint}
// Wire `userId` from the authenticated SecurityContext, never from a request header.
// ==============================================================================
package com.bank.security.aigis;

import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.concurrent.TimeUnit;

@FunctionalInterface
interface BusinessAction<T> {{
    T execute() throws Exception;
}}

class ConcurrencyBreachException extends RuntimeException {{
    public ConcurrencyBreachException(String message) {{
        super(message);
    }}
}}

@Component
public class AigisDistributedLockAspect {{

    @Autowired
    private RedissonClient redissonClient;

    // NOT @Transactional: the lock must wrap the whole transaction so that the
    // commit happens BEFORE unlock(). Put @Transactional on the business method
    // invoked by `action` (in a separate Spring bean so the proxy applies).
    public <T> T executeWithLock(String userId, BusinessAction<T> action) throws Exception {{
        String lockKey = "aigis:lock:claim:" + userId;
        RLock lock = redissonClient.getLock(lockKey);

        boolean isAcquired = lock.tryLock(0, 3000, TimeUnit.MILLISECONDS);
        if (!isAcquired) {{
            throw new ConcurrencyBreachException("HTTP 429: Concurrent transaction rejected by AIGIS Core Guard.");
        }}
        try {{
            return action.execute();  // action runs a @Transactional method that commits before returning
        }} finally {{
            if (lock.isHeldByCurrentThread()) {{
                lock.unlock();
            }}
        }}
    }}
}}
"""

        # 3. GOLANG GIN/FIBER PATCH (High-Performance Microservices)
        go_patch = f"""// ==============================================================================
// AIGIS BLUE TEAM — GOLANG GIN IDEMPOTENCY REDSYNC MIDDLEWARE (REFERENCE TEMPLATE)
// Target: {endpoint}
// `user_id` must be populated by authenticated middleware, not by a client header.
// ==============================================================================
package middleware

import (
    "net/http"
    "time"
    "github.com/gin-gonic/gin"
    "github.com/go-redsync/redsync/v4"
)

func AigisConcurrencyGuard(rs *redsync.Redsync) gin.HandlerFunc {{
    return func(c *gin.Context) {{
        if c.Request.URL.Path == "{endpoint}" && c.Request.Method == "POST" {{
            userID := c.GetString("user_id")
            if userID == "" {{
                c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{{
                    "success": false,
                    "error":   "Unauthenticated",
                }})
                return
            }}

            // WithTries(1): fail fast instead of redsync's default retry loop.
            mutex := rs.NewMutex("aigis:lock:claim:"+userID, redsync.WithExpiry(3*time.Second), redsync.WithTries(1))
            if err := mutex.Lock(); err != nil {{
                c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{{
                    "success": false,
                    "error":   "Too Many Requests: Concurrency breach blocked by AIGIS Go-Guard",
                }})
                return
            }}
            defer func() {{
                _, _ = mutex.Unlock()
            }}()
        }}
        c.Next()
    }}
}}
"""

        # 4. CLOUDFLARE RATE LIMITING RULE (Edge coarse throttle)
        # Note: rate() is not part of the Cloudflare Rules language. Rate limiting is
        # configured as a separate Rate Limiting Rule with a matching expression plus
        # characteristics/period/threshold fields.
        cloudflare_rule = f"""# ==============================================================================
# CLOUDFLARE RATE LIMITING RULE (EDGE COARSE THROTTLE) — REFERENCE TEMPLATE
# Dashboard -> Security -> WAF -> Rate limiting rules -> Create rule
# Edge rate limits cannot enforce sub-second atomicity; the DB-level fix is required.
# Verify field names against current Cloudflare docs before deploying.
# ==============================================================================
Expression:      (http.request.uri.path eq "{endpoint}" and http.request.method eq "POST")
Characteristics: ip.src
Period:          10 seconds
Requests:        5
Action:          Block (HTTP 429), mitigation timeout 10 seconds
"""

        # 5. NGINX OPENRESTY LUA SCRIPT (Reverse Proxy)
        nginx_lua = f"""# ==============================================================================
# NGINX OPENRESTY LUA ACCESS FILTER (/etc/nginx/conf.d/aigis_guard.conf)
# Reference template. Uses the edge-observed source IP, not a spoofable header.
# Fails CLOSED (503) if Redis is unreachable and returns connections to the pool.
# ==============================================================================
location {endpoint} {{
    access_by_lua_block {{
        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeout(100)
        local ok, err = red:connect("127.0.0.1", 6379)
        if not ok then
            ngx.log(ngx.ERR, "aigis guard: redis unavailable: ", err)
            return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
        end
        local client_ip = ngx.var.remote_addr or "unknown"
        local lock_key = "aigis:lock:claim:" .. client_ip
        local res, set_err = red:set(lock_key, "1", "NX", "EX", 3)
        red:set_keepalive(10000, 100)
        if not res then
            ngx.log(ngx.ERR, "aigis guard: redis SET failed: ", set_err)
            return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
        end
        if res == ngx.null then
            ngx.status = 429
            ngx.header.content_type = "application/json"
            ngx.say('{{"error": "Too Many Requests: Blocked by AIGIS Edge Guard"}}')
            return ngx.exit(429)
        end
    }}
    proxy_pass http://backend_upstream;
}}
"""

        # 6. AWS WAF JSON CUSTOM RULE
        # Rate-based rules aggregate over >=60s windows; they throttle volume but
        # cannot enforce sub-second atomicity. Use alongside the DB-level fix.
        aws_waf_rule = f"""{{
  "Name": "Aigis-Mitigate-{vulnerability_type}",
  "Priority": 1,
  "Action": {{ "Block": {{ "CustomResponse": {{ "ResponseCode": 429 }} }} }},
  "Statement": {{
    "RateBasedStatement": {{
      "Limit": 10,
      "EvaluationWindowSec": 60,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {{
        "AndStatement": {{
          "Statements": [
            {{
              "ByteMatchStatement": {{
                "SearchString": "{endpoint}",
                "FieldToMatch": {{ "UriPath": {{}} }},
                "TextTransformations": [{{ "Type": "NONE", "Priority": 0 }}],
                "PositionalConstraint": "EXACTLY"
              }}
            }},
            {{
              "ByteMatchStatement": {{
                "SearchString": "POST",
                "FieldToMatch": {{ "Method": {{}} }},
                "TextTransformations": [{{ "Type": "NONE", "Priority": 0 }}],
                "PositionalConstraint": "EXACTLY"
              }}
            }}
          ]
        }}
      }}
    }}
  }},
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AigisRateGuardMetric"
  }}
}}"""

        return {
            "vulnerability_type": vulnerability_type,
            "target_endpoint": endpoint,
            "languages": {
                "sql": {"name": "SQL Root-Cause Fix (PostgreSQL)", "filename": "voucher_atomic_claim.sql", "code": sql_patch},
                "python": {"name": "Python (FastAPI)", "filename": "idempotency_middleware.py", "code": python_patch},
                "java": {"name": "Java (Spring Boot + Redisson)", "filename": "AigisDistributedLockAspect.java", "code": java_patch},
                "golang": {"name": "Go (Gin + Redsync)", "filename": "aigis_guard.go", "code": go_patch}
            },
            "waf_rules": {
                "cloudflare": {"name": "Cloudflare WAF Expression", "filename": "cloudflare_rule.txt", "code": cloudflare_rule},
                "nginx_lua": {"name": "NGINX OpenResty Lua", "filename": "aigis_nginx.conf", "code": nginx_lua},
                "aws_waf": {"name": "AWS WAF Custom Rule JSON", "filename": "aws_waf_rule.json", "code": aws_waf_rule}
            }
        }

global_patch_exporter = MultiTargetPatchExporter()
