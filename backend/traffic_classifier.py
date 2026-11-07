import os
import sqlite3
import time
from typing import Dict, Any, List, Optional
from .database import get_connection, get_db_tables, get_active_db_info


def _quote_table(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _label_to_bool(value: Any) -> Optional[bool]:
    if value in (1, "1", True, "true", "True"):
        return True
    if value in (0, "0", False, "false", "False"):
        return False
    return None

def _pct(num: int, den: int) -> Optional[float]:
    return round(num / den * 100, 2) if den else None


def _evaluation_metrics(tp: int, fp: int, tn: int, fn: int,
                        bursts: Dict[str, List[Optional[int]]]) -> Dict[str, Any]:
    """Confusion-matrix metrics against the ground-truth label, plus per-burst time-to-detect."""
    if not (tp + fp + tn + fn):
        return {"status": "NOT_EVALUATED", "reason": "No ground-truth is_attack labels in the sample."}

    precision = _pct(tp, tp + fp)
    recall = _pct(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 2) if precision and recall else None

    delays = sorted(b[1] - b[0] for b in bursts.values() if b[1] is not None)
    missed_bursts = sum(1 for b in bursts.values() if b[1] is None)
    ttd = {
        "bursts_seen": len(bursts),
        "bursts_detected": len(delays),
        "bursts_missed": missed_bursts,
        "median_ms": delays[len(delays) // 2] if delays else None,
        "p95_ms": delays[min(len(delays) - 1, int(len(delays) * 0.95))] if delays else None,
        "definition": "Per attack burst: first flagged event time minus first event time.",
    }

    return {
        "status": "EVALUATED_ON_SYNTHETIC_LABELS",
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision_pct": precision,
        "recall_pct": recall,
        "false_positive_rate_pct": _pct(fp, fp + tn),
        "false_negative_rate_pct": _pct(fn, fn + tp),
        "f1_pct": f1,
        "time_to_detect": ttd,
        "caveat": "Labels come from the project's own simulator; this is a sanity check, not a held-out evaluation.",
    }


def classify_traffic_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Hệ thống AI Tự xác định Traffic của AIGIS:
    Phân tích đa chiều các vector an ninh viễn trắc để tự động xác định
    và phân loại chính xác ATTACK EVENT vs BENIGN TRAFFIC.
    """
    # Classification uses observable telemetry features only. The ground-truth
    # `is_attack` column is reserved for offline accuracy evaluation below.
    score = 0.0
    reasons = []

    # Vector 1: Concurrency Velocity / Packet Alignment
    burst_id = str(row.get("burst_stream_id", "") or "").strip()
    burst_rank = str(row.get("burst_concurrency_rank", "") or "").strip()

    is_burst = False
    if burst_id and burst_id not in ("NONE", "null", "", "None"):
        is_burst = True
    if burst_rank and burst_rank not in ("1/1", "NONE", "null", "", "-"):
        is_burst = True

    if is_burst:
        score += 0.55
        reasons.append(f"Sub-millisecond packet concurrency ({burst_rank or burst_id})")

    # Vector 2: Datacenter Hosting / Proxy ASN
    is_proxy = row.get("is_datacenter_proxy")
    if is_proxy in (1, "1", True, "true"):
        score += 0.25
        reasons.append("Datacenter proxy infrastructure (AWS/Hetzner/OVH)")

    isp = str(row.get("ip_isp", "") or "").lower()
    if any(k in isp for k in ["amazon", "digitalocean", "hetzner", "ovh", "linode", "vultr"]):
        if not any("proxy" in r.lower() for r in reasons):
            score += 0.20
            reasons.append(f"Cloud hosting ASN: {row.get('ip_isp')}")

    # Vector 3: Bot User-Agent Fingerprint
    ua = str(row.get("user_agent", "") or "").lower()
    is_bot_ua = any(bot in ua for bot in ["httpx", "curl", "python", "go-http-client", "fuzzer", "cerebrus", "bot_worker"])
    if is_bot_ua:
        score += 0.35
        reasons.append("Automated attack engine User-Agent signature")

    # Vector 4: Sensitive Endpoint & Missing Idempotency Key
    endpoint = str(row.get("api_endpoint", "") or row.get("endpoint", "") or row.get("path", "") or "").lower()
    if any(crit in endpoint for crit in ["/voucher/claim", "/claim", "/checkout/direct", "/transfer"]):
        has_idem = row.get("has_idempotency_key")
        if has_idem in (0, "0", False, "false"):
            score += 0.20
            reasons.append("Unprotected state mutation: Missing Idempotency Key")

    # user_id is deliberately NOT a feature: the simulator names attackers
    # "usr_botnet_*", so matching on it would leak the ground-truth label.

    score = min(1.0, round(score, 3))
    is_attack = score >= 0.45

    if is_attack:
        if is_burst:
            attack_type = "HTTP/2_RACE_CONDITION"
        elif is_bot_ua or is_proxy in (1, "1", True, "true"):
            attack_type = "DATACENTER_PROXY_BOT"
        elif "/checkout/direct" in endpoint:
            attack_type = "SHADOW_API_HARVEST"
        else:
            attack_type = "ANOMALOUS_VELOCITY_BURST"
    else:
        attack_type = "BENIGN"
        reasons = ["Normal consumer browsing & legitimate purchase flow"]

    return {
        "is_attack": is_attack,
        "label": "ATTACK" if is_attack else "BENIGN",
        "attack_type": attack_type,
        "anomaly_score": score,
        "confidence_pct": None,
        "confidence_method": "NOT_CALIBRATED",
        "reasons": reasons
    }

def run_autonomous_dataset_classification(sample_limit: int = 5000) -> Dict[str, Any]:
    """
    Quét cơ sở dữ liệu hiện hành và tự động xác định Benign vs Attack
    kèm báo cáo phân bổ và độ tin cậy của mô hình AI.
    """
    db_info = get_active_db_info()
    active_path = db_info.get("active_db_path")
    if not active_path or not os.path.exists(active_path):
        return {"success": False, "error": f"Database not found: {active_path}"}

    sample_limit = max(1, min(int(sample_limit), 50000))
    conn = get_connection()
    cur = conn.cursor()

    try:
        tables = get_db_tables()
        if not tables:
            return {"success": False, "error": "No tables found in database."}

        target_table = "telemetry" if "telemetry" in tables else tables[0]
        quoted_table = _quote_table(target_table)

        # Count total rows
        cur.execute(f"SELECT COUNT(*) FROM {quoted_table}")
        total_in_db = cur.fetchone()[0]

        # Fetch sample
        cur.execute(f"SELECT * FROM {quoted_table} LIMIT ?", (sample_limit,))
        rows = [dict(r) for r in cur.fetchall()]

        if not rows:
            return {"success": False, "error": "Table has no records to classify."}

        t0 = time.time()
        benign_count = 0
        attack_count = 0
        attack_types: Dict[str, int] = {}
        flagged_users: Dict[str, int] = {}
        flagged_ips: Dict[str, int] = {}
        tp = fp = tn = fn = 0
        # burst_stream_id -> [first event ms, first flagged event ms]
        bursts: Dict[str, List[Optional[int]]] = {}

        for r in rows:
            res = classify_traffic_row(r)
            if res["is_attack"]:
                attack_count += 1
                at = res["attack_type"]
                attack_types[at] = attack_types.get(at, 0) + 1

                u = r.get("user_id")
                if u:
                    flagged_users[u] = flagged_users.get(u, 0) + 1
                ip = r.get("client_ip")
                if ip:
                    flagged_ips[ip] = flagged_ips.get(ip, 0) + 1
            else:
                benign_count += 1

            actual = _label_to_bool(r.get("is_attack"))
            if actual is True:
                if res["is_attack"]:
                    tp += 1
                else:
                    fn += 1
            elif actual is False:
                if res["is_attack"]:
                    fp += 1
                else:
                    tn += 1

            burst_id = str(r.get("burst_stream_id") or "").strip()
            epoch = r.get("epoch_ms")
            if actual is True and burst_id not in ("", "NONE", "None", "null") and isinstance(epoch, (int, float)):
                b = bursts.setdefault(burst_id, [None, None])
                if b[0] is None or epoch < b[0]:
                    b[0] = epoch
                if res["is_attack"] and (b[1] is None or epoch < b[1]):
                    b[1] = epoch

        elapsed = round((time.time() - t0) * 1000, 2)
        sample_size = len(rows)
        attack_ratio = attack_count / sample_size if sample_size else 0.0

        projected_attacks = int(total_in_db * attack_ratio)
        projected_benign = total_in_db - projected_attacks

        top_ips = sorted(flagged_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        top_users = sorted(flagged_users.items(), key=lambda x: x[1], reverse=True)[:5]

        labeled_count = tp + fp + tn + fn
        evaluation = _evaluation_metrics(tp, fp, tn, fn, bursts)
        if labeled_count:
            classification_accuracy = f"{round((tp + tn) / labeled_count * 100, 2)}%"
        else:
            classification_accuracy = "NOT_EVALUATED"

        return {
            "success": True,
            "database_name": db_info.get("active_db_name"),
            "target_table": target_table,
            "total_records_in_db": total_in_db,
            "sample_analyzed": sample_size,
            "classified_benign_sample": benign_count,
            "classified_attacks_sample": attack_count,
            "attack_percentage": round(attack_ratio * 100, 2),
            "projected_benign_total": projected_benign,
            "projected_attack_total": projected_attacks,
            "classification_accuracy": classification_accuracy,
            "accuracy_evaluated_on": labeled_count,
            "evaluation": evaluation,
            "processing_time_ms": elapsed,
            "attack_type_breakdown": attack_types,
            "top_flagged_ips": [{"ip": item[0], "count": item[1]} for item in top_ips],
            "top_flagged_users": [{"user_id": item[0], "count": item[1]} for item in top_users],
            "verdict": (
                f"Heuristic classifier analyzed {sample_size:,} sampled records in {elapsed}ms. "
                f"It flagged {attack_count:,} events ({round(attack_ratio*100, 2)}%) as attack-like and "
                f"{benign_count:,} as benign. Accuracy is only reported when ground-truth labels are present."
            )
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


async def run_deep_dive_traffic_classification(sample_limit: int = 10000, enable_llm: bool = True) -> Dict[str, Any]:
    """
    Hệ thống AI Deep-Dive Traffic Forensics của AIGIS:
    Thực hiện phân tích đa tầng (Multi-Stage Deep Forensics):
    - Giai đoạn 1: Trích xuất chuỗi thời gian & ma trận vận tốc đồng bộ (Sub-ms Concurrency Matrix)
    - Giai đoạn 2: Lập hồ sơ thực thể (JA3 TLS, Datacenter ASN, User-Agent Entropy)
    - Giai đoạn 3: Đối chiếu heuristic với khung MITRE ATT&CK (không phải chẩn đoán chính thức)
    - Giai đoạn 4: Tổng hợp báo cáo điều tra số (Forensic Intelligence Dossier) & Playbook vá lỗi
    """
    db_info = get_active_db_info()
    active_path = db_info.get("active_db_path")
    if not active_path or not os.path.exists(active_path):
        return {"success": False, "error": f"Database not found: {active_path}"}

    sample_limit = max(1, min(int(sample_limit), 50000))
    t_start = time.time()
    conn = get_connection()
    cur = conn.cursor()

    try:
        tables = get_db_tables()
        target_table = "telemetry" if "telemetry" in tables else tables[0]
        quoted_table = _quote_table(target_table)

        cur.execute(f"SELECT COUNT(*) FROM {quoted_table}")
        total_in_db = cur.fetchone()[0]

        cur.execute(f"SELECT * FROM {quoted_table} LIMIT ?", (sample_limit,))
        rows = [dict(r) for r in cur.fetchall()]

        if not rows:
            return {"success": False, "error": "No records available for deep dive."}

        # Multi-stage analysis simulation with realistic forensic computation
        benign_count = 0
        attack_count = 0
        attack_types: Dict[str, int] = {}
        rogue_ips: Dict[str, Dict[str, Any]] = {}
        rogue_users: Dict[str, int] = {}
        burst_clusters: Dict[str, int] = {}
        datacenter_asn_count: Dict[str, int] = {}

        for r in rows:
            res = classify_traffic_row(r)
            if res["is_attack"]:
                attack_count += 1
                at = res["attack_type"]
                attack_types[at] = attack_types.get(at, 0) + 1

                # IP Profiling
                ip = r.get("client_ip", "UNKNOWN")
                isp = r.get("ip_isp", "Unknown ASN")
                if ip not in rogue_ips:
                    rogue_ips[ip] = {"ip": ip, "isp": isp, "count": 0, "endpoints": set()}
                rogue_ips[ip]["count"] += 1
                rogue_ips[ip]["endpoints"].add(r.get("api_endpoint", "/"))

                # User profiling
                u = r.get("user_id")
                if u:
                    rogue_users[u] = rogue_users.get(u, 0) + 1

                # Burst Clustering
                b_id = r.get("burst_stream_id")
                if b_id and b_id != "NONE":
                    burst_clusters[b_id] = burst_clusters.get(b_id, 0) + 1

                # ASN
                if r.get("is_datacenter_proxy"):
                    datacenter_asn_count[isp] = datacenter_asn_count.get(isp, 0) + 1
            else:
                benign_count += 1

        sample_size = len(rows)
        attack_ratio = attack_count / sample_size if sample_size else 0.0
        projected_attacks = int(total_in_db * attack_ratio)
        projected_benign = total_in_db - projected_attacks

        # Top actors
        sorted_rogue_ips = sorted(
            [{"ip": v["ip"], "isp": v["isp"], "count": v["count"], "endpoints": list(v["endpoints"])} for v in rogue_ips.values()],
            key=lambda x: x["count"],
            reverse=True
        )[:5]

        # Heuristic MITRE ATT&CK mapping. These are suggested categories, not a
        # validated attribution or vulnerability assessment.
        mitre_mappings = [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "severity": "INFO",
                "detected_events": attack_types.get("HTTP/2_RACE_CONDITION", 0),
                "description": "Concurrent requests target a state-changing voucher endpoint. Mapping is heuristic."
            },
            {
                "technique_id": "T1585",
                "technique_name": "Establish Accounts",
                "severity": "INFO",
                "detected_events": attack_types.get("DATACENTER_PROXY_BOT", 0),
                "description": "Multiple identities appear to originate from hosting infrastructure. Mapping is heuristic."
            },
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "severity": "INFO",
                "detected_events": attack_types.get("SHADOW_API_HARVEST", 0),
                "description": "Requests hit an unlisted checkout route. Mapping is heuristic."
            }
        ]

        # Prescriptive Hardening Playbook
        hardening_playbook = [
            {
                "layer": "API Gateway / NGINX",
                "rule": "limit_req_zone $binary_remote_addr zone=voucher_burst:10m rate=5r/s; limit_req zone=voucher_burst burst=5 nodelay;",
                "target": "Reduces burst throughput; tune against legitimate traffic and monitor false positives."
            },
            {
                "layer": "Application Middleware (Aegis)",
                "rule": "Redis SET NX (lock:claim:{user_id}) with 3.0s lease TTL & atomic idempotency token validation.",
                "target": "Serializes concurrent claims for the same authenticated user; it does not replace transaction-level constraints."
            },
            {
                "layer": "Infrastructure Firewall",
                "rule": "Flag ingress traffic from hosting ASNs (for example Linode ASN 63949, Hetzner ASN 24940) targeting payment routes for review.",
                "target": "Reduces some bot traffic but can affect legitimate cloud users; use as a signal, not a blanket block."
            }
        ]

        # Forensic Narrative (measured sample, no invented certainty)
        narrative = (
            f"AIGIS Deep-Dive Forensics examined a sample of {sample_size:,} telemetry records. "
            f"The heuristic classifier flagged {attack_count:,} events ({round(attack_ratio * 100, 2)}%) "
            f"as attack-like across {len(rogue_ips)} distinct client IPs. This is a demo classification, "
            f"not a statistical certainty or a confirmed attribution."
        )

        elapsed_ms = round((time.time() - t_start) * 1000, 2)

        return {
            "success": True,
            "mode": "DEEP_DIVE_FORENSICS",
            "total_records_in_db": total_in_db,
            "sample_analyzed": sample_size,
            "classified_attacks": attack_count,
            "classified_benign": benign_count,
            "attack_percentage": round(attack_ratio * 100, 2),
            "projected_attack_total": projected_attacks,
            "projected_benign_total": projected_benign,
            "threat_posture_score": None,
            "posture_rating": "DEMO_ONLY",
            "processing_time_ms": elapsed_ms,
            "mitre_mappings": mitre_mappings,
            "top_rogue_ips": sorted_rogue_ips,
            "hardening_playbook": hardening_playbook,
            "executive_narrative": narrative
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()
