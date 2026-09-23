#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT / "config" / "config.yml"
HISTORY_FILE = ROOT / "data" / "ip_history.json"
OUT = ROOT / "output"
OUT.mkdir(parents=True, exist_ok=True)
HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

CFG = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}

MAX_FAILURES = int(CFG.get("history", {}).get("max_failures", 3))
MAX_HISTORY_DEFAULT = 5000


def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# 地区识别
# ============================================================

DEFAULT_REGION_ALIASES = {
    "HK": ["HK", "HKG", "Hong Kong", "香港"],
    "JP": ["JP", "JPN", "NRT", "HND", "TYO", "KIX", "OSA", "Japan", "日本"],
    "SG": ["SG", "SGP", "SIN", "Singapore", "新加坡"],
    "KR": ["KR", "KOR", "ICN", "SEL", "GMP", "Korea", "韩国"],
    "TW": ["TW", "TWN", "TPE", "Taiwan", "台湾"],
    "US": [
        "US", "USA", "LAX", "SFO", "SEA", "ORD", "DFW", "ATL", "IAD",
        "EWR", "JFK", "MIA", "DEN", "PHX", "LAS", "PDX", "United States", "美国",
    ],
    "DE": ["DE", "DEU", "FRA", "BER", "MUC", "DUS", "HAM", "Germany", "德国"],
    "CN": ["CN", "CHN", "China", "中国"],
}


def _build_region_patterns():
    configured = CFG.get("region_aliases") or {}
    merged = {k: list(v) for k, v in DEFAULT_REGION_ALIASES.items()}
    for region, aliases in configured.items():
        merged[region.upper()] = list(dict.fromkeys(
            merged.get(region.upper(), []) + [str(x) for x in (aliases or [])]
        ))

    patterns = []
    for region, aliases in merged.items():
        for alias in sorted(set(aliases), key=len, reverse=True):
            if alias:
                patterns.append((
                    region,
                    re.compile(
                        r"(?<![A-Za-z0-9])" + re.escape(alias) +
                        r"(?![A-Za-z0-9])",
                        re.I,
                    ),
                ))
    return patterns


REGION_PATTERNS = _build_region_patterns()


def region_from_comment(comment: str, source_name: str = "") -> str:
    text = str(comment or "").strip()
    for region, pattern in REGION_PATTERNS:
        if pattern.search(text):
            return region
    return "OTHER"


# ============================================================
# 运营商识别
# ============================================================

ISP_ALIASES = {
    "中国移动": "CMCC", "移动": "CMCC", "mobile": "CMCC", "cmcc": "CMCC",
    "中国联通": "CU", "联通": "CU", "unicom": "CU", "cucc": "CU",
    "中国电信": "CT", "电信": "CT", "telecom": "CT", "ctcc": "CT",
}
ISP_CODE_RE = re.compile(r"\b(CMCC|CUCC|CU|CTCC|CT)\b", re.I)
ISP_CODE_MAP = {"CMCC": "CMCC", "CUCC": "CU", "CU": "CU", "CTCC": "CT", "CT": "CT"}


def isp_from_comment(comment: str) -> str:
    m = ISP_CODE_RE.search(comment or "")
    if m:
        return ISP_CODE_MAP[m.group(1).upper()]
    text = (comment or "").lower()
    for key, value in ISP_ALIASES.items():
        if key in text:
            return value
    return "OTHER"


# ============================================================
# 地址 / 解析
# ============================================================

IP_PORT_RE = re.compile(
    r"^\s*(\[[0-9a-fA-F:]+\]|[^:\s#]+)\s*:\s*(\d{1,5})\s*(?:#(.*))?$"
)


def normalize_address(raw: str):
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        ip = ipaddress.ip_address(raw)
        return str(ip), "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        if re.fullmatch(r"[A-Za-z0-9.-]+", raw) and "." in raw:
            return raw.lower(), "domain"
    return None, None


def item_key(item) -> str:
    return f"{item['address']}:{item['port']}"


def parse_line(line: str, source_name: str, kind: str):
    line = line.strip()
    if not line or line.startswith(("#", ";", "//")):
        return None

    m = IP_PORT_RE.match(line)
    if not m:
        return None

    address, port_s, comment = m.groups()
    try:
        port = int(port_s)
    except ValueError:
        return None

    if not (1 <= port <= 65535):
        return None

    address, addr_type = normalize_address(address)
    if not address:
        return None

    if kind == "ip" and addr_type not in ("ipv4", "ipv6"):
        return None
    if kind == "domain" and addr_type != "domain":
        return None

    comment = comment or ""

    return {
        "address": address,
        "port": port,
        "region": region_from_comment(comment, source_name),
        "isp": isp_from_comment(comment),
        "comment": comment,
        "source": source_name,
        "type": addr_type,
    }


# ============================================================
# 下载源
# ============================================================

def fetch_source(source):
    req = Request(
        source["url"],
        headers={"User-Agent": "CF-IP-VLESS-Generator/3.0"},
    )
    with urlopen(req, timeout=20) as response:
        return response.read().decode("utf-8", "replace")


def parse_sources():
    all_items = []
    source_status = {}

    for source in CFG.get("sources", []):
        name = source["name"]
        source_status[name] = {"ok": False, "parsed": 0, "error": ""}

        try:
            text = fetch_source(source)
            count = 0

            for line in text.splitlines():
                item = parse_line(line, name, source["kind"])
                if item:
                    all_items.append(item)
                    count += 1

            source_status[name]["ok"] = True
            source_status[name]["parsed"] = count

            if count:
                print(f"[OK] {name}: {count} parsed")
            else:
                print(f"[WARN] {name}: download succeeded but parsed 0 candidates")

        except Exception as e:
            source_status[name]["error"] = str(e)
            print(f"[WARN] {name}: source unavailable: {e}")

    seen = set()
    result = []

    for item in all_items:
        key = item_key(item)
        if key not in seen:
            seen.add(key)
            result.append(item)

    print(f"[INFO] current-source unique candidates: {len(result)}")
    return result, source_status


# ============================================================
# 历史池
# ============================================================

def load_history():
    if not HISTORY_FILE.exists():
        print("[INFO] history file not found; starting with empty history")
        return {}

    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))

        if not isinstance(data, dict):
            return {}

        clean = {}

        for key, item in data.items():
            if not isinstance(item, dict):
                continue

            address = item.get("address")
            port = item.get("port")

            if not address or not port:
                continue

            try:
                port = int(port)
            except (TypeError, ValueError):
                continue

            comment = str(item.get("comment", ""))
            old_region = str(item.get("region", "OTHER")).upper()

            detected = region_from_comment(
                comment,
                item.get("source", "HISTORY"),
            )

            if detected != "OTHER":
                old_region = detected

            clean[str(key)] = {
                "address": str(address),
                "port": port,
                "region": old_region,
                "isp": (
                    item.get("isp")
                    or item.get("operator")
                    or isp_from_comment(comment)
                ),
                "comment": comment,
                "source": item.get("source", "HISTORY"),
                "type": item.get("type", "ipv4"),
                "failures": max(
                    0,
                    int(item.get("failures", 0)),
                ),
                "first_seen": item.get("first_seen", utc_now()),
                "last_seen": item.get("last_seen", ""),
                "last_success": item.get("last_success", ""),
                "last_failure": item.get("last_failure", ""),
                "last_error": item.get("last_error", ""),
            }

        print(f"[HISTORY] loaded: {len(clean)}")
        return clean

    except Exception as e:
        print(f"[WARN] unable to load history: {e}")
        return {}


def merge_candidates(current_items, history):
    merged = {}

    for key, old in history.items():
        item = dict(old)
        item["source_current"] = False
        item["history_key"] = key
        merged[key] = item

    for item in current_items:
        key = item_key(item)
        old = merged.get(key)

        if old:
            item["failures"] = old.get("failures", 0)
            item["first_seen"] = old.get("first_seen", utc_now())
            item["last_seen"] = old.get("last_seen", "")
            item["last_success"] = old.get("last_success", "")
            item["last_failure"] = old.get("last_failure", "")
            item["last_error"] = old.get("last_error", "")

            if (
                item.get("region") == "OTHER"
                and old.get("region") not in (None, "OTHER")
            ):
                item["region"] = old["region"]

            if (
                item.get("isp") == "OTHER"
                and old.get("isp") not in (None, "OTHER")
            ):
                item["isp"] = old["isp"]

        else:
            item["failures"] = 0
            item["first_seen"] = utc_now()
            item["last_seen"] = ""
            item["last_success"] = ""
            item["last_failure"] = ""
            item["last_error"] = ""

        item["source_current"] = True
        item["history_key"] = key
        merged[key] = item

    result = list(merged.values())
    print(f"[HISTORY] merged candidates: {len(result)}")
    return result


# ============================================================
# TLS / WS / gRPC 健康检查（含 TCP 延迟测量）
# ============================================================

def grpc_upgrade_check(ssock, timeout: float) -> str:
    import h2.connection
    import h2.events

    t = CFG["template"]
    service_name = t.get("serviceName", "") or "grpc"

    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send())

    stream_id = conn.get_next_available_stream_id()

    headers = [
        (":method", "POST"),
        (":path", f"/{service_name}/Ping"),
        (":scheme", "https"),
        (":authority", t["host"]),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
    ]

    conn.send_headers(
        stream_id,
        headers,
        end_stream=True,
    )

    ssock.sendall(conn.data_to_send())
    ssock.settimeout(timeout)

    status = ""
    deadline = time.monotonic() + timeout

    while not status and time.monotonic() < deadline:
        try:
            data = ssock.recv(65536)
        except socket.timeout:
            break

        if not data:
            break

        events = conn.receive_data(data)
        outbound = conn.data_to_send()

        if outbound:
            ssock.sendall(outbound)

        for event in events:
            if isinstance(
                event,
                (
                    h2.events.ResponseReceived,
                    h2.events.TrailersReceived,
                ),
            ):
                for name, value in event.headers:
                    key = (
                        name.decode()
                        if isinstance(name, bytes)
                        else name
                    )
                    val = (
                        value.decode()
                        if isinstance(value, bytes)
                        else value
                    )

                    if key == ":status":
                        status = val

    return status


def ws_upgrade_check(ssock, timeout: float) -> str:
    t = CFG["template"]

    key = base64.b64encode(
        os.urandom(16)
    ).decode()

    request = (
        f"GET {t['path']} HTTP/1.1\r\n"
        f"Host: {t['host']}\r\n"
        f"Connection: Upgrade\r\n"
        f"Upgrade: websocket\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"\r\n"
    )

    ssock.settimeout(timeout)
    ssock.sendall(request.encode())

    data = ssock.recv(4096)

    if not data:
        return ""

    return data.split(
        b"\r\n",
        1,
    )[0].decode(
        "ascii",
        "replace",
    )


def tcp_tls_test(item):
    host = item["address"]
    port = item["port"]

    timeout = float(
        CFG["test"]["connect_timeout"]
    )

    tls_timeout = float(
        CFG["test"]["tls_timeout"]
    )

    latency_ms = 9999.0

    try:
        start_time = time.monotonic()
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as sock:
            latency_ms = (time.monotonic() - start_time) * 1000

            sock.settimeout(tls_timeout)

            ctx = ssl.create_default_context()

            verify = bool(
                CFG["test"].get(
                    "tls_verify",
                    False,
                )
            )

            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            if str(
                CFG["template"].get(
                    "type",
                    "",
                )
            ).lower() == "grpc":
                alpn_offer = ["h2"]
            else:
                alpn_offer = ["http/1.1"]

            try:
                ctx.set_alpn_protocols(alpn_offer)
            except NotImplementedError:
                pass

            with ctx.wrap_socket(
                sock,
                server_hostname=CFG["template"]["sni"],
            ) as ssock:

                tls_version = ssock.version() or ""

                real_check = bool(
                    CFG["test"].get(
                        "real_check",
                        False,
                    )
                )

                transport_type = str(
                    CFG["template"].get(
                        "type",
                        "",
                    )
                ).lower()

                if (
                    not real_check
                    or transport_type not in ("ws", "grpc")
                ):
                    return True, tls_version, latency_ms

                real_timeout = float(
                    CFG["test"].get(
                        "real_check_timeout",
                        tls_timeout,
                    )
                )

                if transport_type == "ws":
                    try:
                        status_line = ws_upgrade_check(
                            ssock,
                            real_timeout,
                        )
                    except Exception as e:
                        return (
                            False,
                            f"ws-check-error: {e}",
                            latency_ms,
                        )

                    if "101" in status_line:
                        return (
                            True,
                            f"{tls_version} | {status_line}",
                            latency_ms,
                        )

                    return (
                        False,
                        f"ws-check-rejected: "
                        f"{status_line or '(no response)'}",
                        latency_ms,
                    )

                alpn = ssock.selected_alpn_protocol()

                if alpn != "h2":
                    return (
                        False,
                        f"grpc-check-rejected: "
                        f"ALPN negotiated '{alpn}', expected h2",
                        latency_ms,
                    )

                try:
                    status = grpc_upgrade_check(
                        ssock,
                        real_timeout,
                    )
                except ImportError:
                    return (
                        False,
                        "grpc-check-error: "
                        "h2 library not installed",
                        latency_ms,
                    )
                except Exception as e:
                    return (
                        False,
                        f"grpc-check-error: {e}",
                        latency_ms,
                    )

                if status:
                    return (
                        True,
                        f"{tls_version} | grpc:{status}",
                        latency_ms,
                    )

                return (
                    False,
                    "grpc-check-rejected: (no response)",
                    latency_ms,
                )

    except Exception as e:
        return False, str(e), latency_ms


# ============================================================
# 健康检查
# ============================================================

def test_candidates(items):
    now = utc_now()

    if not CFG["test"].get(
        "enabled",
        True,
    ):
        for item in items:
            item["health_ok"] = True
            item["tls"] = ""
            item["test_error"] = ""
            item["tested"] = False
            item["test_time"] = now
            item["latency_ms"] = 9999.0

        print(
            "[INFO] health testing disabled; "
            "all candidates treated as healthy"
        )

        return items

    skip_ipv6 = bool(
        CFG["test"].get(
            "skip_ipv6_test",
            False,
        )
    )

    to_test = []
    skipped = 0

    for item in items:
        if (
            skip_ipv6
            and item.get("type") == "ipv6"
        ):
            item["health_ok"] = True
            item["tls"] = ""
            item["test_error"] = ""
            item["tested"] = False
            item["test_time"] = now
            item["latency_ms"] = 9999.0
            skipped += 1
        else:
            to_test.append(item)

    if skipped:
        print(
            f"[INFO] skip_ipv6_test=true: "
            f"{skipped} IPv6 candidates "
            f"trusted without testing"
        )

    workers = max(
        1,
        int(
            CFG["test"].get(
                "concurrency",
                40,
            )
        ),
    )

    passed = 0
    failed = 0

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
    ) as executor:

        futures = {
            executor.submit(
                tcp_tls_test,
                item,
            ): item
            for item in to_test
        }

        for future in concurrent.futures.as_completed(
            futures
        ):
            item = futures[future]

            try:
                ok, detail, latency = future.result()
            except Exception as e:
                ok, detail, latency = False, str(e), 9999.0

            item["tested"] = True
            item["test_time"] = now
            item["latency_ms"] = latency

            if ok:
                item["health_ok"] = True
                item["tls"] = detail
                item["test_error"] = ""
                passed += 1
            else:
                item["health_ok"] = False
                item["tls"] = ""
                item["test_error"] = detail
                failed += 1

    print(
        f"[HEALTH] passed={passed}, "
        f"failed={failed}, "
        f"total={len(to_test)}"
    )

    if failed:
        reject_count = 0
        other_count = 0
        samples = []

        for item in to_test:
            if item.get("health_ok"):
                continue

            err = item.get(
                "test_error",
                "",
            )

            if (
                "ws-check-rejected" in err
                or "grpc-check-rejected" in err
            ):
                reject_count += 1
            else:
                other_count += 1

            if (
                err
                and err not in samples
                and len(samples) < 5
            ):
                samples.append(err)

        print(
            f"[HEALTH] failure breakdown: "
            f"real-check-rejected={reject_count}, "
            f"other-errors={other_count}"
        )

        for err in samples:
            print(
                f"[HEALTH]   sample error: {err}"
            )

    return items


# ============================================================
# 历史更新
# ============================================================

def update_history(
    candidates,
    old_history,
):
    now = utc_now()

    new_history = {}

    stats = {
        "loaded": len(old_history),
        "new": 0,
        "success": 0,
        "failed": 0,
        "retained_failed": 0,
        "removed": 0,
    }

    for item in candidates:
        key = item_key(item)
        old = old_history.get(key)

        if old is None:
            record = {
                "address": item["address"],
                "port": item["port"],
                "region": item.get(
                    "region",
                    "OTHER",
                ),
                "isp": item.get(
                    "isp",
                    "OTHER",
                ),
                "comment": item.get(
                    "comment",
                    "",
                ),
                "source": item.get(
                    "source",
                    "HISTORY",
                ),
                "type": item.get(
                    "type",
                    "ipv4",
                ),
                "failures": 0,
                "first_seen": now,
                "last_seen": "",
                "last_success": "",
                "last_failure": "",
                "last_error": "",
            }

            stats["new"] += 1

        else:
            record = dict(old)

            if item.get(
                "source_current",
                False,
            ):
                if (
                    item.get("region") != "OTHER"
                    or record.get("region")
                    in (None, "OTHER")
                ):
                    record["region"] = item.get(
                        "region",
                        record.get(
                            "region",
                            "OTHER",
                        ),
                    )

                if (
                    item.get("isp") != "OTHER"
                    or record.get("isp")
                    in (None, "OTHER")
                ):
                    record["isp"] = item.get(
                        "isp",
                        record.get(
                            "isp",
                            "OTHER",
                        ),
                    )

                record["comment"] = item.get(
                    "comment",
                    record.get(
                        "comment",
                        "",
                    ),
                )

                record["source"] = item.get(
                    "source",
                    record.get(
                        "source",
                        "HISTORY",
                    ),
                )

                record["type"] = item.get(
                    "type",
                    record.get(
                        "type",
                        "ipv4",
                    ),
                )

        record["address"] = item["address"]
        record["port"] = item["port"]
        record["last_seen"] = now

        if item.get("health_ok"):
            record["failures"] = 0
            record["last_success"] = now
            record["last_error"] = ""

            stats["success"] += 1
            new_history[key] = record

        elif not item.get(
            "tested",
            False,
        ):
            new_history[key] = record

        else:
            failures = int(
                record.get(
                    "failures",
                    0,
                )
            ) + 1

            record["failures"] = failures
            record["last_failure"] = now
            record["last_error"] = item.get(
                "test_error",
                "",
            )

            stats["failed"] += 1

            if failures >= MAX_FAILURES:
                stats["removed"] += 1
                continue

            stats["retained_failed"] += 1
            new_history[key] = record

    return new_history, stats


def history_sort_key(item):
    return (
        1
        if item.get(
            "failures",
            0,
        ) == 0
        else 0,
        1
        if item.get(
            "last_success",
            "",
        )
        else 0,
        item.get(
            "last_success",
            "",
        ),
        item.get(
            "last_seen",
            "",
        ),
        item.get(
            "first_seen",
            "",
        ),
    )


def limit_history(history):
    hcfg = CFG.get(
        "history",
        {},
    )

    max_history = int(
        hcfg.get(
            "max_pool_size",
            MAX_HISTORY_DEFAULT,
        )
    )

    if len(history) <= max_history:
        return history, 0

    records = list(
        history.items()
    )

    records.sort(
        key=lambda x: history_sort_key(
            x[1]
        ),
        reverse=True,
    )

    reserve_cfg = hcfg.get(
        "min_nodes_per_region",
        {},
    )

    selected = []
    selected_keys = set()

    if isinstance(
        reserve_cfg,
        dict,
    ):
        for region, minimum in reserve_cfg.items():
            region = str(region).upper()

            need = max(
                0,
                int(minimum),
            )

            pool = [
                (key, value)
                for key, value in records
                if (
                    key not in selected_keys
                    and str(
                        value.get(
                            "region",
                            "OTHER",
                        )
                    ).upper()
                    == region
                )
            ]

            pool.sort(
                key=lambda x: history_sort_key(
                    x[1]
                ),
                reverse=True,
            )

            for key, value in pool[:need]:
                selected.append(
                    (key, value)
                )
                selected_keys.add(key)

    for key, value in records:
        if len(selected) >= max_history:
            break

        if key in selected_keys:
            continue

        selected.append(
            (key, value)
        )
        selected_keys.add(key)

    kept = dict(
        selected[:max_history]
    )

    removed = len(history) - len(kept)

    print(
        f"[HISTORY] limit {max_history}: "
        f"removed {removed} oldest/weak entries"
    )

    return kept, removed


# ============================================================
# VLESS / Mihomo 输出
# ============================================================

def vless_node(
    item,
    index,
    group=None,
):
    t = CFG["template"]

    name = CFG["output"]["naming"].format(
        REGION=group or item["region"],
        INDEX=index,
    )

    address = item["address"]

    if item["type"] == "ipv6":
        address = f"[{address}]"

    transport_type = str(
        t.get(
            "type",
            "",
        )
    ).lower()

    query = {
        "security": t["security"],
        "alpn": t["alpn"],
        "encryption": t["encryption"],
        "insecure": t["insecure"],
        "fp": t["fp"],
        "type": t["type"],
        "allowInsecure": t["allowInsecure"],
        "sni": t["sni"],
    }

    if transport_type == "ws":
        query["path"] = t["path"]
        query["host"] = t["host"]

    elif transport_type == "grpc":
        query["serviceName"] = t.get(
            "serviceName",
            "",
        )

    params = "&".join(
        f"{key}={quote(str(value), safe='')}"
        for key, value in query.items()
    )

    return (
        f"vless://"
        f"{t['uuid']}@"
        f"{address}:"
        f"{item['port']}?"
        f"{params}"
        f"#{quote(name, safe='-._')}"
    )


def write_subscription(
    path: Path,
    nodes,
):
    payload = "\n".join(nodes)

    if nodes:
        payload += "\n"

    encoded = base64.b64encode(
        payload.encode()
    ).decode()

    path.write_text(
        encoded + "\n",
        encoding="utf-8",
    )


def clash_proxy(
    item,
    index,
    group=None,
):
    t = CFG["template"]

    name = CFG["output"]["naming"].format(
        REGION=group or item["region"],
        INDEX=index,
    )

    proxy = {
        "name": name,
        "type": "vless",
        "server": item["address"],
        "port": item["port"],
        "uuid": t["uuid"],
        "udp": True,
        "tls": str(
            t["security"]
        ).lower() == "tls",
        "servername": t["sni"],
        "client-fingerprint": t["fp"],
        "skip-cert-verify": bool(
            t["allowInsecure"]
        ),
    }

    alpn = t.get("alpn")

    if alpn:
        if isinstance(
            alpn,
            str,
        ):
            proxy["alpn"] = [
                x.strip()
                for x in alpn.split(",")
                if x.strip()
            ]
        elif isinstance(
            alpn,
            list,
        ):
            proxy["alpn"] = alpn

    transport_type = str(
        t.get(
            "type",
            "",
        )
    ).lower()

    if transport_type == "ws":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {
            "path": t["path"],
            "headers": {
                "Host": t["host"]
            },
        }

    elif transport_type == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {
            "grpc-service-name": t.get(
                "serviceName",
                "",
            )
        }

    elif transport_type:
        proxy["network"] = transport_type

    return proxy


def write_clash_yaml(
    path: Path,
    items,
):
    proxies = [
        clash_proxy(
            item,
            item["_index"],
            group=item.get("_group"),
        )
        for item in items
    ]

    data = {
        "proxies": proxies
    }

    path.write_text(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )


# ============================================================
# 首页
# ============================================================

def write_index(
    history_stats=None,
):
    region_names = CFG.get(
        "output",
        {},
    ).get(
        "regions",
        {},
    )

    isp_names = CFG.get(
        "output",
        {},
    ).get(
        "isp_names",
        {},
    )

    links = []

    for p in sorted(
        OUT.glob("*")
    ):
        if p.suffix.lower() not in (
            ".txt",
            ".yaml",
        ):
            continue

        code = p.stem.upper()
        label = p.name

        if code in region_names:
            label += (
                f"（{region_names[code]}）"
            )

        elif code in isp_names:
            label += (
                f"（{isp_names[code]}）"
            )

        links.append(
            f"<li>"
            f"<a href='{p.name}'>"
            f"{label}"
            f"</a>"
            f"</li>"
        )

    extra_html = ""

    if (
        CFG.get(
            "output",
            {},
        ).get(
            "keep_failed",
            False,
        )
        and history_stats
    ):
        extra_html = (
            "<p>观察中（未连续失败 3 次）的历史 IP："
            f"{history_stats.get('retained_failed', 0)}"
            " 个，未包含在订阅内。</p>"
        )

    html = (
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' "
        "content='width=device-width,initial-scale=1'>"
        "<title>CF VLESS subscriptions</title>"
        "</head>"
        "<body>"
        "<h1>CF VLESS subscriptions</h1>"
        "<ul>"
        + "".join(links)
        + "</ul>"
        + extra_html
        + "</body>"
        "</html>"
    )

    (
        OUT / "index.html"
    ).write_text(
        html,
        encoding="utf-8",
    )


def save_history(
    history,
):
    temp_file = HISTORY_FILE.with_suffix(
        ".json.tmp"
    )

    text = (
        json.dumps(
            history,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    temp_file.write_text(
        text,
        encoding="utf-8",
    )

    os.replace(
        temp_file,
        HISTORY_FILE,
    )


def clean_output():
    for p in OUT.glob("*"):
        if p.is_file():
            p.unlink()


# ============================================================
# 地区选择（新节点 > 健康度 > 低延迟）
# ============================================================

def select_region_items(
    good,
):
    maxn = int(
        CFG["output"].get(
            "max_nodes_per_region",
            100,
        )
    )

    reserve_cfg = CFG.get(
        "history",
        {},
    ).get(
        "min_nodes_per_region",
        {},
    )

    if not isinstance(
        reserve_cfg,
        dict,
    ):
        reserve_cfg = {}

    grouped = {}

    for item in good:
        grouped.setdefault(
            str(
                item.get(
                    "region",
                    "OTHER",
                )
            ).upper(),
            [],
        ).append(item)

    selected = {}

    for region, items in grouped.items():
        items = sorted(
            items,
            key=lambda x: (
                0 if x.get("source_current") is True else 1,
                0 if x.get("failures", 0) == 0 else 1,
                x.get("latency_ms", 9999.0),
                x.get("address", ""),
            ),
        )

        selected[region] = items[:maxn]

    for region in reserve_cfg:
        selected.setdefault(
            str(region).upper(),
            [],
        )

    return selected


def write_region_outputs(
    grouped,
):
    maxn = int(
        CFG["output"].get(
            "max_nodes_per_region",
            100,
        )
    )

    all_items = []

    configured_regions = list(
        (
            CFG["output"].get(
                "regions",
                {},
            )
        ).keys()
    )

    regions = sorted(
        set(configured_regions)
        | set(grouped.keys())
    )

    for region in regions:
        items = list(
            grouped.get(
                region,
                [],
            )
        )[:maxn]

        for index, item in enumerate(
            items,
            1,
        ):
            item["_index"] = index

        all_items.extend(items)

        nodes = [
            vless_node(
                item,
                item["_index"],
            )
            for item in items
        ]

        region_name = region.lower()

        write_subscription(
            OUT / f"{region_name}.txt",
            nodes,
        )

        write_clash_yaml(
            OUT / f"{region_name}.yaml",
            items,
        )

        print(
            f"[INFO] Region {region}: "
            f"{len(items)} nodes -> "
            f"{region_name}.txt / "
            f"{region_name}.yaml"
        )

    return all_items


def write_isp_outputs(
    good,
    maxn,
):
    grouped = {}

    for item in good:
        isp = item.get(
            "isp",
            "OTHER",
        )

        if isp in (
            "CMCC",
            "CU",
            "CT",
        ):
            grouped.setdefault(
                isp,
                [],
            ).append(item)

    selected_all = []
    selected_ids = set()

    for isp, items in sorted(
        grouped.items()
    ):
        items = sorted(
            items,
            key=lambda x: (
                0 if x.get("source_current") is True else 1,
                0 if x.get("failures", 0) == 0 else 1,
                x.get("latency_ms", 9999.0),
                x.get("address", ""),
            ),
        )[:maxn]

        temp_items = []

        for index, item in enumerate(
            items,
            1,
        ):
            temp = dict(item)
            temp["_index"] = index
            temp["_group"] = isp

            temp_items.append(temp)

            selected_ids.add(
                id(item)
            )

        write_subscription(
            OUT / f"{isp.lower()}.txt",
            [
                vless_node(
                    item,
                    item["_index"],
                    group=isp,
                )
                for item in temp_items
            ],
        )

        write_clash_yaml(
            OUT / f"{isp.lower()}.yaml",
            temp_items,
        )

        selected_all.extend(
            temp_items
        )

        print(
            f"[INFO] ISP group {isp}: "
            f"{len(temp_items)} nodes "
            f"(capped at {maxn}) -> "
            f"{isp.lower()}.txt / "
            f"{isp.lower()}.yaml"
        )

    return selected_all, selected_ids


# ============================================================
# MAIN
# ============================================================

def main():
    print(
        "============================================================"
    )
    print(
        "CF-IP VLESS Generator"
    )
    print(
        "Regional Alias Mapping + "
        "Regional History Reserve + Health Check"
    )
    print(
        "============================================================"
    )

    clean_output()

    old_history = load_history()

    current_items, source_status = parse_sources()

    if not CFG.get(
        "output",
        {},
    ).get(
        "include_domain_source",
        True,
    ):
        before = len(current_items)

        current_items = [
            item
            for item in current_items
            if item["type"] != "domain"
        ]

        print(
            f"[INFO] include_domain_source=false: "
            f"dropped {before - len(current_items)} "
            f"domain candidates"
        )

    source_total = len(source_status)

    source_ok_count = sum(
        1
        for status in source_status.values()
        if status["ok"]
    )

    print(
        f"[SOURCE] available="
        f"{source_ok_count}/{source_total}"
    )

    if (
        source_total > 0
        and source_ok_count == 0
        and not old_history
    ):
        print(
            "[ERROR] all configured sources are unavailable "
            "and history is empty"
        )
        sys.exit(1)

    if (
        source_total > 0
        and source_ok_count == 0
    ):
        print(
            "[WARN] ALL configured sources are unavailable; "
            "existing history will be used."
        )

    candidates = merge_candidates(
        current_items,
        old_history,
    )

    if not candidates:
        print(
            "[ERROR] no candidates available"
        )
        sys.exit(1)

    candidates = test_candidates(
        candidates
    )

    good = [
        item
        for item in candidates
        if item.get(
            "health_ok",
            False,
        )
    ]

    if not good:
        print(
            "[ERROR] zero healthy nodes remain."
        )
        sys.exit(1)

    print(
        f"[INFO] final healthy candidates: "
        f"{len(good)}"
    )

    grouped = select_region_items(
        good
    )

    all_items = write_region_outputs(
        grouped
    )

    maxn = int(
        CFG["output"].get(
            "max_nodes_per_region",
            100,
        )
    )

    isp_items, isp_selected_ids = (
        write_isp_outputs(
            good,
            maxn,
        )
    )

    all_final = [
        item
        for item in all_items
        if id(item) not in isp_selected_ids
    ] + isp_items

    max_total = int(
        CFG["output"].get(
            "max_nodes_total",
            0,
        )
        or 0
    )

    if (
        max_total > 0
        and len(all_final) > max_total
    ):
        print(
            f"[INFO] max_nodes_total="
            f"{max_total}: trimming all "
            f"{len(all_final)} -> "
            f"{max_total}"
        )

        all_final = all_final[:max_total]

    if not all_final:
        print(
            "[ERROR] final node selection is empty"
        )
        sys.exit(1)

    write_subscription(
        OUT / "all.txt",
        [
            vless_node(
                item,
                item["_index"],
                group=item.get("_group"),
            )
            for item in all_final
        ],
    )

    write_clash_yaml(
        OUT / "all.yaml",
        all_final,
    )

    new_history, history_stats = update_history(
        candidates,
        old_history,
    )

    new_history, limit_removed = limit_history(
        new_history
    )

    history_stats["removed"] += limit_removed

    save_history(
        new_history
    )

    print("")
    print(
        "================ HISTORY ================="
    )
    print(
        f"[HISTORY] loaded: "
        f"{history_stats['loaded']}"
    )
    print(
        f"[HISTORY] new: "
        f"{history_stats['new']}"
    )
    print(
        f"[HISTORY] health success: "
        f"{history_stats['success']}"
    )
    print(
        f"[HISTORY] health failed: "
        f"{history_stats['failed']}"
    )
    print(
        f"[HISTORY] retained failed: "
        f"{history_stats['retained_failed']}"
    )
    print(
        f"[HISTORY] removed: "
        f"{history_stats['removed']}"
    )
    print(
        f"[HISTORY] final pool: "
        f"{len(new_history)}"
    )
    print(
        "==========================================="
    )

    write_index(
        history_stats
    )

    print("")
    print(
        "============================================================"
    )
    print(
        f"[DONE] generated "
        f"{len(all_final)} VLESS nodes"
    )
    print(
        f"[DONE] generated "
        f"{len(all_final)} Mihomo proxies"
    )
    print(
        f"[DONE] history pool "
        f"{len(new_history)}/"
        f"{CFG.get('history', {}).get('max_pool_size', MAX_HISTORY_DEFAULT)}"
    )
    print(
        "============================================================"
    )


if __name__ == "__main__":
    main()
