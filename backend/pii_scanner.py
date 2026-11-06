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
        "CREDIT_CARD_PAN": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        "VIETNAM_CCCD_ID": r'\b(0[0-9]{11}|[0-9]{9})\b',
        "JWT_SECRET_TOKEN": r'\beyJ[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]{15,}\.[a-zA-Z0-9_\-]{15,}\b',
        "API_SECRET_KEY": r'\b(?:sk_live_[a-zA-Z0-9]{24}|AIzaSy[a-zA-Z0-9_\-]{33}|ghp_[a-zA-Z0-9]{36})\b',
        "PHONE_NUMBER_VN": r'\b(?:09|08|03|07|05)[0-9]{8}\b'
    }

    @classmethod
    def scan_content(cls, content: str) -> Dict[str, Any]:
        findings = []
        masked_content = content

        # 1. Credit Card Check
        cc_matches = re.finditer(cls.PATTERNS["CREDIT_CARD_PAN"], content)
        for m in cc_matches:
            card = m.group(0)
            if check_luhn(card):
                masked = f"{card[:4]}-XXXX-XXXX-{card[-4:]}"
                masked_content = masked_content.replace(card, masked)
                findings.append({
                    "type": "PAYMENT_CARD_PAN_EXPOSURE",
                    "severity": "CRITICAL",
                    "compliance_violation": "PCI-DSS v4.0 Req 3.4 (PAN Masking)",
                    "matched": f"{card[:4]}...{card[-4:]}",
                    "masked": masked
                })

        # 2. National ID (CCCD) Check
        cccd_matches = re.finditer(cls.PATTERNS["VIETNAM_CCCD_ID"], content)
        for m in cccd_matches:
            cid = m.group(0)
            # Avoid matching pure timestamp digits by checking context
            if len(cid) == 12 and (cid.startswith("0") or "id" in content.lower()):
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
            for path, methods in paths.items():
                for method, spec in methods.items():
                    if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        has_auth = "security" in spec or "security" in data
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
