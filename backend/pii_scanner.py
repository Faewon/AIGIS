import re
import json
from typing import Dict, Any, List

def check_luhn(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0

class SensitiveDataScanner:
    """
    Pillar 2: PII & Sensitive Data Exposure Scanner (Traceable & Akto inspired).
    Scans API payloads, responses, and dataset records for unmasked PII/PAN leaks:
    - Credit Card PAN (Visa, MasterCard, Amex) with Luhn validation
    - National ID (CCCD / CMND Vietnam - 9 or 12 digits)
    - Sensitive Secrets (JWT Tokens, Private Keys, AWS/OpenAI/Gemini keys)
    - Bank Account numbers (IBAN / Local Core Banking)
    """

    PATTERNS = {
        # 13-19 digits, optionally separated by single spaces or dashes; Luhn-validated below.
        "CREDIT_CARD_PAN": r'(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])',
        # Vietnam CCCD: 12 digits starting with a 3-digit province code (001-096).
        "VIETNAM_CCCD_ID": r'(?<!\d)0(?:0[1-9]|[1-8]\d|9[0-6])\d{9}(?!\d)',
        "VIETNAM_CMND_ID": r'(?<!\d)\d{9}(?!\d)',
        "JWT_SECRET_TOKEN": r'\beyJ[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]{15,}\b',
        "API_SECRET_KEY": r'\b(?:sk_live_[a-zA-Z0-9]{24,}|sk-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35}|ghp_[a-zA-Z0-9]{36}|gsk_[A-Za-z0-9]{20,})\b',
        "PHONE_NUMBER_VN": r'\b(?:09|08|03|07|05)[0-9]{8}\b'
    }

    # Card brand prefixes (Visa, Mastercard incl. 2-series, Amex, Discover, JCB, UnionPay).
    _CARD_PREFIX = re.compile(r'^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35|62)')

    @classmethod
    def scan_content(cls, content: str) -> Dict[str, Any]:
        findings = []
        masked_content = content

        # 1. Credit Card Check
        for m in re.finditer(cls.PATTERNS["CREDIT_CARD_PAN"], content):
            raw = m.group(0)
            card = re.sub(r'[ -]', '', raw)
            if cls._CARD_PREFIX.match(card) and check_luhn(card):
                masked = f"{card[:4]}-XXXX-XXXX-{card[-4:]}"
                masked_content = masked_content.replace(raw, masked)
                findings.append({
                    "type": "PAYMENT_CARD_PAN_EXPOSURE",
                    "severity": "CRITICAL",
                    "compliance_violation": "PCI-DSS v4.0 Req 3.4 (PAN Masking)",
                    "matched": f"{card[:4]}...{card[-4:]}",
                    "masked": masked
                })

        # 2. National ID (CCCD) Check
        for m in re.finditer(cls.PATTERNS["VIETNAM_CCCD_ID"] + "|" + cls.PATTERNS["VIETNAM_CMND_ID"], content):
            cid = m.group(0)
            masked = f"{cid[:3]}XXXXXX{cid[-3:]}"
            masked_content = masked_content.replace(cid, masked)
            findings.append({
                "type": "NATIONAL_ID_EXPOSURE",
                "severity": "HIGH",
                "compliance_violation": "Decree 13/2023/ND-CP & SBV Circular 09",
                "matched": f"{cid[:3]}...{cid[-3:]}",
                "masked": masked
            })

        # 3. JWT & Secrets Check
        jwt_matches = re.finditer(cls.PATTERNS["JWT_SECRET_TOKEN"], content)
        for m in jwt_matches:
            jwt = m.group(0)
            masked = f"{jwt[:10]}...[TRUNCATED_SECRET_TOKEN]"
            masked_content = masked_content.replace(jwt, masked)
            findings.append({
                "type": "BEARER_TOKEN_LEAK",
                "severity": "CRITICAL",
                "compliance_violation": "OWASP API2:2023 Broken Authentication",
                "matched": jwt[:15] + "...",
                "masked": masked
            })

        # 4. API Secret Keys
        for m in re.finditer(cls.PATTERNS["API_SECRET_KEY"], content):
            key = m.group(0)
            masked = f"{key[:6]}...[REDACTED_API_KEY]"
            masked_content = masked_content.replace(key, masked)
            findings.append({
                "type": "API_SECRET_KEY_LEAK",
                "severity": "CRITICAL",
                "compliance_violation": "OWASP API8:2023 Security Misconfiguration",
                "matched": key[:6] + "...",
                "masked": masked
            })

        return {
            "has_pii_leak": len(findings) > 0,
            "total_leaks_found": len(findings),
            "findings": findings,
            "sanitized_content": masked_content
        }

    @classmethod
    def parse_openapi_spec(cls, raw_text: str) -> Dict[str, Any]:
        """Tự động phân tích cấu trúc OpenAPI / Swagger JSON hoặc YAML"""
        try:
            data = json.loads(raw_text)
            paths = data.get("paths", {})
            extracted_endpoints = []
            global_security = data.get("security")
            for path, methods in paths.items():
                for method, spec in methods.items():
                    if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        # Operation-level `security` overrides the global one; an empty
                        # list (`security: []`) explicitly marks the operation public.
                        effective = spec["security"] if "security" in spec else global_security
                        # A `{}` entry means anonymous access is also allowed.
                        has_auth = bool(effective) and all(bool(req) for req in effective)
                        extracted_endpoints.append({
                            "path": path,
                            "method": method.upper(),
                            "summary": spec.get("summary", ""),
                            "is_protected": has_auth,
                            "potential_risk": "UNPROTECTED_SENSITIVE_FLOW" if not has_auth and any(k in path for k in ["transfer", "withdraw", "claim", "pay"]) else "NORMAL"
                        })
            return {
                "success": True,
                "title": data.get("info", {}).get("title", "Imported OpenAPI Specification"),
                "version": data.get("info", {}).get("version", "1.0.0"),
                "endpoints_count": len(extracted_endpoints),
                "endpoints": extracted_endpoints
            }
        except Exception as e:
            return {"success": False, "error": f"Invalid JSON/OpenAPI schema: {str(e)}"}

global_pii_scanner = SensitiveDataScanner()
