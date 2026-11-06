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

from typing import Dict, Any

class MultiTargetPatchExporter:

    @classmethod
    def generate_all_patches(cls, vulnerability_type: str = "TOCTOU_RACE_CONDITION", endpoint: str = "/api/v1/voucher/claim") -> Dict[str, Any]:
        
        # 1. PYTHON FASTAPI PATCH
        python_patch = f"""# ==============================================================================
# AIGIS BLUE TEAM — AUTONOMOUS PYTHON FASTAPI IDEMPOTENCY MIDDLEWARE
# Vulnerability: {vulnerability_type} on {endpoint}
# ==============================================================================
from fastapi import Request
from fastapi.responses import JSONResponse
import redis.asyncio as aioredis
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = aioredis.from_url(REDIS_URL)

async def aigis_concurrency_guard_middleware(request: Request, call_next):
    if request.url.path == "{endpoint}" and request.method == "POST":
        user_id = request.headers.get("X-User-ID", "anonymous")
        lock_key = f"aigis:lock:claim:{{user_id}}"
        
        # Atomic SET with NX (Not Exists) and 3.0s lease TTL
        acquired = await redis_client.set(lock_key, "locked", nx=True, ex=3)
        if not acquired:
            return JSONResponse(
                status_code=429,
                content={{"success": False, "error": "Too Many Requests: Sub-millisecond race condition blocked by AIGIS."}}
            )
    return await call_next(request)
"""

        # 2. JAVA SPRING BOOT PATCH (Core Banking standard: Vietcombank / BIDV / Techcombank)
        java_patch = f"""// ==============================================================================
// AIGIS BLUE TEAM — SPRING BOOT & REDISSON DISTRIBUTED LOCK ASPECT
// Standard: State Bank of Vietnam Circular 09 & PCI-DSS v4.0 Req 6.5.10
// Target: {endpoint}
// ==============================================================================
package com.bank.security.aigis;

import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import java.util.concurrent.TimeUnit;

@Component
public class AigisDistributedLockAspect {{

    @Autowired
    private RedissonClient redissonClient;

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public <T> T executeWithLock(String userId, BusinessAction<T> action) throws Exception {{
        String lockKey = "aigis:lock:claim:" + userId;
        RLock lock = redissonClient.getLock(lockKey);

        // Try lock: 0ms wait, 3000ms lease time
        boolean isAcquired = lock.tryLock(0, 3000, TimeUnit.MILLISECONDS);
        if (!isAcquired) {{
            throw new ConcurrencyBreachException("HTTP 429: Concurrent transaction rejected by AIGIS Core Guard.");
        }}
        try {{
            return action.execute();
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
// AIGIS BLUE TEAM — GOLANG GIN IDEMPOTENCY REDSYNC MIDDLEWARE
// Target: {endpoint}
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
            userID := c.GetHeader("X-User-ID")
            if userID == "" {{
                userID = "anonymous"
            }}
            
            mutex := rs.NewMutex("aigis:lock:claim:" + userID, redsync.WithExpiry(3*time.Second))
            if err := mutex.Lock(); err != nil {{
                c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{{
                    "success": false,
                    "error":   "Too Many Requests: Concurrency breach blocked by AIGIS Go-Guard",
                }})
                return
            }}
            defer mutex.Unlock()
        }}
        c.Next()
    }}
}}
"""

        # 4. CLOUDFLARE WAF EXPRESSION RULE (Edge 0-Day Defense)
        cloudflare_rule = f"""# ==============================================================================
# CLOUDFLARE WAF CUSTOM EXPRESSION RULE (EDGE RATE LIMITING)
# Deploy directly via Cloudflare Dashboard -> Security -> WAF -> Custom Rules
# Action: Block (HTTP 429) | Rate limit: 1 request per 3 seconds per IP/User
# ==============================================================================
(http.request.uri.path eq "{endpoint}" and http.request.method eq "POST" and rate(http.request.headers["x-user-id"][0], 3s) gt 1)
"""

        # 5. NGINX OPENRESTY LUA SCRIPT (Zero-Latency Reverse Proxy)
        nginx_lua = f"""# ==============================================================================
# NGINX OPENRESTY LUA ACCESS FILTER (/etc/nginx/conf.d/aigis_guard.conf)
# Deploys directly in reverse-proxy with zero application downtime
# ==============================================================================
location {endpoint} {{
    access_by_lua_block {{
        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeout(100)
        local ok, err = red:connect("127.0.0.1", 6379)
        if ok then
            local user_id = ngx.req.get_headers()["x-user-id"] or "anon"
            local lock_key = "aigis:lock:" .. user_id
            local res, err = red:set(lock_key, "1", "NX", "EX", 3)
            if not res or res == ngx.null then
                ngx.status = 429
                ngx.header.content_type = "application/json"
                ngx.say('{{\"error\": \"Too Many Requests: Blocked by AIGIS Edge WAF\"}}')
                ngx.exit(429)
            end
        end
    }}
    proxy_pass http://backend_upstream;
}}
"""

        # 6. AWS WAF JSON CUSTOM RULE
        aws_waf_rule = f"""{{
  "Name": "Aigis-Mitigate-{vulnerability_type}",
  "Priority": 1,
  "Action": {{ "Block": {{ "CustomResponse": {{ "ResponseCode": 429 }} }} }},
  "Statement": {{
    "RateBasedStatement": {{
      "Limit": 100,
      "AggregateKeyType": "CUSTOM_KEYS",
      "CustomKeys": [
        {{ "Header": {{ "Name": "x-user-id", "TextTransformations": [{{ "Type": "NONE", "Priority": 0 }}] }} }}
      ],
      "ScopeDownStatement": {{
        "ByteMatchStatement": {{
          "SearchString": "{endpoint}",
          "FieldToMatch": {{ "UriPath": {{}} }},
          "TextTransformations": [{{ "Type": "LOWERCASE", "Priority": 0 }}],
          "PositionalConstraint": "EXACTLY"
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
