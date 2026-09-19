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
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml


# ============================================================
# 基础路径
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

CONFIG_FILE = ROOT / "config" / "config.yml"
HISTORY_FILE = ROOT / "data" / "ip_history.json"
OUT = ROOT / "output"

OUT.mkdir(parents=True, exist_ok=True)
HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 配置
# ============================================================

CFG = yaml.safe_load(
    CONFIG_FILE.read_text(encoding="utf-8")
)

MAX_FAILURES = 3
MAX_HISTORY = 5000


# ============================================================
# 正则
# ============================================================

# 地区识别
REGION_RE = re.compile(
    r"\b(HK|JP|SG|KR|TW|US|DE|CN)\b",
    re.I
)

# 运营商识别
OPERATOR_RE = re.compile(
    r"\b(CU|CT|CMCC)\b",
    re.I
)

IP_PORT_RE = re.compile(
    r"^\s*(\[[0-9a-fA-F:]+\]|[^:\s#]+)"
    r"\s*:\s*(\d{1,5})\s*(?:#(.*))?$"
)


# ============================================================
# 时间
# ============================================================

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

def region_from_comment(
    comment: str,
    source_name: str
) -> str:

    m = REGION_RE.search(comment or "")

    if m:
        return m.group(1).upper()

    text = (comment or "").lower()

    aliases = {
        "香港": "HK",
        "hong kong": "HK",

        "日本": "JP",
        "japan": "JP",

        "新加坡": "SG",
        "singapore": "SG",

        "韩国": "KR",
        "korea": "KR",

        "台湾": "TW",
        "taiwan": "TW",

        "美国": "US",
        "united states": "US",

        "德国": "DE",
        "germany": "DE",

        "中国": "CN",
        "china": "CN",
    }

    for key, value in aliases.items():
        if key in text:
            return value

    return "OTHER"


# ============================================================
# 运营商识别
#
# 支持：
#   CU / CT / CMCC
#   联通 / 电信 / 移动
#   中国联通 / 中国电信 / 中国移动
#   China Unicom / China Telecom / China Mobile
#
# 无法识别时：
#   OTHER
# ============================================================

def operator_from_comment(
    comment: str,
    source_name: str
) -> str:

    m = OPERATOR_RE.search(comment or "")

    if m:
        return m.group(1).upper()

    text = (comment or "").lower()

    aliases = {
        # 联通
        "联通": "CU",
        "中国联通": "CU",
        "china unicom": "CU",
        "unicom": "CU",

        # 电信
        "电信": "CT",
        "中国电信": "CT",
        "china telecom": "CT",
        "telecom": "CT",

        # 移动
        "移动": "CMCC",
        "中国移动": "CMCC",
        "china mobile": "CMCC",
        "mobile": "CMCC",
    }

    for key, value in aliases.items():
        if key in text:
            return value

    return "OTHER"


# ============================================================
# 地址标准化
# ============================================================

def normalize_address(raw: str):

    raw = raw.strip()

    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]

    try:
        ip = ipaddress.ip_address(raw)

        return str(ip), (
            "ipv6"
            if ip.version == 6
            else "ipv4"
        )

    except ValueError:
        # 允许域名
        if re.fullmatch(
            r"[A-Za-z0-9.-]+",
            raw
        ) and "." in raw:
            return raw.lower(), "domain"

    return None, None


# ============================================================
# 候选 Key
# ============================================================

def item_key(item) -> str:
    return f"{item['address']}:{item['port']}"


# ============================================================
# 解析单行
# ============================================================

def parse_line(
    line: str,
    source_name: str,
    kind: str
):

    line = line.strip()

    if not line or line.startswith(
        ("#", ";", "//")
    ):
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

    if kind == "ip" and addr_type not in (
        "ipv4",
        "ipv6"
    ):
        return None

    if kind == "domain" and addr_type != "domain":
        return None

    # --------------------------------------------------------
    # 地区
    # --------------------------------------------------------

    region = region_from_comment(
        comment or "",
        source_name
    )

    # --------------------------------------------------------
    # 运营商
    # --------------------------------------------------------

    operator = operator_from_comment(
        comment or "",
        source_name
    )

    return {
        "address": address,
        "port": port,
        "region": region,
        "operator": operator,
        "comment": comment or "",
        "source": source_name,
        "type": addr_type,
    }


# ============================================================
# 下载源
# ============================================================

def fetch_source(source):

    req = Request(
        source["url"],
        headers={
            "User-Agent": "CF-IP-VLESS-Generator/2.0"
        }
    )

    with urlopen(
        req,
        timeout=20
    ) as response:

        return response.read().decode(
            "utf-8",
            "replace"
        )


# ============================================================
# 读取所有源
#
# 返回：
#   candidates
#   source_status
#
# source_status 用于区分：
#   1. 正常下载
#   2. 下载失败
#   3. 下载成功但解析为 0
#
# 这样不会因为源站临时故障误删历史 IP。
# ============================================================

def parse_sources():

    all_items = []

    source_status = {}

    for source in CFG.get("sources", []):

        source_name = source["name"]

        source_status[source_name] = {
            "ok": False,
            "parsed": 0,
            "error": "",
        }

        try:

            text = fetch_source(source)

            count = 0

            for line in text.splitlines():

                item = parse_line(
                    line,
                    source_name,
                    source["kind"]
                )

                if item:

                    all_items.append(item)
                    count += 1

            source_status[source_name]["ok"] = True
            source_status[source_name]["parsed"] = count

            if count == 0:

                print(
                    f"[WARN] {source_name}: "
                    f"download succeeded but parsed 0 candidates"
                )

            else:

                print(
                    f"[OK] {source_name}: "
                    f"{count} parsed"
                )

        except Exception as e:

            source_status[source_name]["error"] = str(e)

            print(
                f"[WARN] {source_name}: "
                f"source unavailable: {e}"
            )

    # ========================================================
    # 去重
    # ========================================================

    seen = set()
    result = []

    for item in all_items:

        key = item_key(item)

        if key not in seen:

            seen.add(key)
            result.append(item)

    print(
        f"[INFO] current-source unique candidates: "
        f"{len(result)}"
    )

    return result, source_status


# ============================================================
# 历史池读取
# ============================================================

def load_history():

    if not HISTORY_FILE.exists():

        print(
            "[INFO] history file not found; "
            "starting with empty history"
        )

        return {}

    try:

        data = json.loads(
            HISTORY_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(data, dict):

            print(
                "[WARN] invalid history format; "
                "starting with empty history"
            )

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

            clean[str(key)] = {
                "address": str(address),
                "port": port,

                "region": item.get(
                    "region",
                    "OTHER"
                ),

                "operator": item.get(
                    "operator",
                    "OTHER"
                ),

                "comment": item.get(
                    "comment",
                    ""
                ),

                "source": item.get(
                    "source",
                    "HISTORY"
                ),

                "type": item.get(
                    "type",
                    "ipv4"
                ),

                "failures": max(
                    0,
                    int(item.get(
                        "failures",
                        0
                    ))
                ),

                "first_seen": item.get(
                    "first_seen",
                    utc_now()
                ),

                "last_seen": item.get(
                    "last_seen",
                    ""
                ),

                "last_success": item.get(
                    "last_success",
                    ""
                ),

                "last_failure": item.get(
                    "last_failure",
                    ""
                ),

                "last_error": item.get(
                    "last_error",
                    ""
                ),
            }

        print(
            f"[HISTORY] loaded: {len(clean)}"
        )

        return clean

    except Exception as e:

        print(
            f"[WARN] unable to load history: {e}"
        )

        return {}


# ============================================================
# 合并当前源 + 历史
#
# current-source IP：
#   source_current = True
#
# 历史 IP：
#   source_current = False
#
# 如果历史 IP 又出现在当前源：
#   更新 source / comment / region / operator
# ============================================================

def merge_candidates(
    current_items,
    history
):

    merged = {}

    # --------------------------------------------------------
    # 先放历史
    # --------------------------------------------------------

    for key, old in history.items():

        item = dict(old)

        item["source_current"] = False
        item["history_key"] = key

        merged[key] = item

    # --------------------------------------------------------
    # 当前源覆盖历史
    # --------------------------------------------------------

    for item in current_items:

        key = item_key(item)

        if key in merged:

            old = merged[key]

            item["failures"] = old.get(
                "failures",
                0
            )

            item["first_seen"] = old.get(
                "first_seen",
                utc_now()
            )

            item["last_seen"] = old.get(
                "last_seen",
                ""
            )

            item["last_success"] = old.get(
                "last_success",
                ""
            )

            item["last_failure"] = old.get(
                "last_failure",
                ""
            )

            item["last_error"] = old.get(
                "last_error",
                ""
            )

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

    print(
        f"[HISTORY] merged candidates: "
        f"{len(result)}"
    )

    return result


# ============================================================
# TCP + TLS 测试
# ============================================================

def tcp_tls_test(item):

    host = item["address"]
    port = item["port"]

    timeout = float(
        CFG["test"]["connect_timeout"]
    )

    tls_timeout = float(
        CFG["test"]["tls_timeout"]
    )

    try:

        with socket.create_connection(
            (host, port),
            timeout=timeout
        ) as sock:

            sock.settimeout(tls_timeout)

            ctx = ssl.create_default_context()

            # 是否校验证书由 config.yml 的 test.tls_verify 控制
            # 默认 False：只验证 TLS 握手是否成功（CF 边缘 IP 场景常见做法）
            verify = bool(
                CFG["test"].get(
                    "tls_verify",
                    False
                )
            )

            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(
                sock,
                server_hostname=CFG[
                    "template"
                ]["sni"]
            ) as ssock:

                return (
                    True,
                    ssock.version() or ""
                )

    except Exception as e:

        return False, str(e)


# ============================================================
# 健康检查
#
# 注意：
# 每次运行都主动测试当前源 + 历史池。
#
# 因此：
#   源站消失但 IP 仍可用 -> 保留
#   连续失败 1 次 -> 保留
#   连续失败 2 次 -> 保留
#   连续失败 3 次 -> 淘汰
# ============================================================

def test_candidates(items):

    now = utc_now()

    if not CFG["test"].get(
        "enabled",
        True
    ):

        for item in items:

            item["health_ok"] = True
            item["tls"] = ""
            item["test_error"] = ""
            item["tested"] = False
            item["test_time"] = now

        print(
            "[INFO] health testing disabled; "
            "all candidates treated as healthy"
        )

        return items

    # ========================================================
    # test.skip_ipv6_test
    #
    # 很多 CI Runner（包括 GitHub 托管的 ubuntu-latest）
    # 默认没有公网 IPv6 出网能力，导致 IPv6 候选在这里
    # 100% 测试失败，进而永远无法进入最终订阅。
    #
    # 打开这个开关后，IPv6 候选会跳过真实连接测试，
    # 直接信任源站数据、标记为健康。
    #
    # 注意：这样做意味着 IPv6 节点完全没有被验证过，
    # 如果源站数据本身质量不高，可能会包含失效 IP。
    # ========================================================

    skip_ipv6 = bool(
        CFG["test"].get(
            "skip_ipv6_test",
            False
        )
    )

    if skip_ipv6:

        to_test = []
        skipped = 0

        for item in items:

            if item.get("type") == "ipv6":

                item["health_ok"] = True
                item["tls"] = ""
                item["test_error"] = ""
                item["tested"] = False
                item["test_time"] = now

                skipped += 1

            else:

                to_test.append(item)

        if skipped:

            print(
                f"[INFO] skip_ipv6_test=true: "
                f"{skipped} IPv6 candidates "
                f"trusted without testing"
            )

    else:

        to_test = items

    workers = max(
        1,
        int(
            CFG["test"].get(
                "concurrency",
                40
            )
        )
    )

    passed = 0
    failed = 0

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                tcp_tls_test,
                item
            ): item
            for item in to_test
        }

        for future in concurrent.futures.as_completed(
            futures
        ):

            item = futures[future]

            try:

                ok, detail = future.result()

            except Exception as e:

                ok = False
                detail = str(e)

            item["tested"] = True
            item["test_time"] = now

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

    return items


# ============================================================
# 更新历史池
#
# 返回：
#   new_history
#   stats
#
# 只有真正参与健康检查的 IP 才会增加失败次数。
# ============================================================

def update_history(
    candidates,
    old_history
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
        "current_source": 0,
        "history_only": 0,
    }

    for item in candidates:

        key = item_key(item)

        old = old_history.get(key)

        was_new = old is None

        if was_new:

            record = {
                "address": item["address"],
                "port": item["port"],

                "region": item.get(
                    "region",
                    "OTHER"
                ),

                "operator": item.get(
                    "operator",
                    "OTHER"
                ),

                "comment": item.get(
                    "comment",
                    ""
                ),

                "source": item.get(
                    "source",
                    "HISTORY"
                ),

                "type": item.get(
                    "type",
                    "ipv4"
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

            # ------------------------------------------------
            # 当前源出现时更新元数据
            # ------------------------------------------------

            if item.get(
                "source_current",
                False
            ):

                record["region"] = item.get(
                    "region",
                    record.get(
                        "region",
                        "OTHER"
                    )
                )

                record["operator"] = item.get(
                    "operator",
                    record.get(
                        "operator",
                        "OTHER"
                    )
                )

                record["comment"] = item.get(
                    "comment",
                    record.get(
                        "comment",
                        ""
                    )
                )

                record["source"] = item.get(
                    "source",
                    record.get(
                        "source",
                        "HISTORY"
                    )
                )

                record["type"] = item.get(
                    "type",
                    record.get(
                        "type",
                        "ipv4"
                    )
                )

        # ----------------------------------------------------
        # 当前源中出现
        # ----------------------------------------------------

        if item.get(
            "source_current",
            False
        ):

            record["last_seen"] = now
            stats["current_source"] += 1

        else:

            stats["history_only"] += 1

        # ----------------------------------------------------
        # 健康检查成功
        # ----------------------------------------------------

        if item.get(
            "health_ok",
            False
        ):

            record["failures"] = 0

            record["last_success"] = now
            record["last_error"] = ""

            stats["success"] += 1

            new_history[key] = record

        # ----------------------------------------------------
        # 健康检查失败
        # ----------------------------------------------------

        else:

            # 未参与测试时，不增加失败次数
            if not item.get(
                "tested",
                False
            ):

                new_history[key] = record
                continue

            failures = int(
                record.get(
                    "failures",
                    0
                )
            )

            failures += 1

            record["failures"] = failures
            record["last_failure"] = now
            record["last_error"] = item.get(
                "test_error",
                ""
            )

            stats["failed"] += 1

            # 连续 3 次失败才淘汰
            if failures >= MAX_FAILURES:

                stats["removed"] += 1

                print(
                    f"[HISTORY] remove after "
                    f"{failures} failures: "
                    f"{key}"
                )

                continue

            stats["retained_failed"] += 1

            new_history[key] = record

    return new_history, stats


# ============================================================
# 历史池排序
#
# 保留优先级：
#
# 1. 当前源仍存在
# 2. 当前健康
# 3. 失败次数少
# 4. 最近成功
# 5. 最近出现
#
# 这样达到 5000 上限时，
# 优先留下真正有价值的历史 IP。
# ============================================================

def history_sort_key(item):

    return (
        1 if item.get(
            "failures",
            0
        ) == 0 else 0,

        1 if item.get(
            "last_success",
            ""
        ) else 0,

        item.get(
            "last_success",
            ""
        ),

        item.get(
            "last_seen",
            ""
        ),

        item.get(
            "first_seen",
            ""
        ),
    )


def limit_history(history):

    if len(history) <= MAX_HISTORY:

        return history, 0

    records = list(
        history.items()
    )

    records.sort(
        key=lambda x: history_sort_key(
            x[1]
        ),
        reverse=True
    )

    kept = dict(
        records[:MAX_HISTORY]
    )

    removed = len(history) - len(kept)

    print(
        f"[HISTORY] limit {MAX_HISTORY}: "
        f"removed {removed} oldest/weak entries"
    )

    return kept, removed


# ============================================================
# 生成 VLESS URI
# ============================================================

def vless_node(
    item,
    index,
    group=None
):

    t = CFG["template"]

    # --------------------------------------------------------
    # group 未指定时，继续使用原来的地区
    # --------------------------------------------------------

    group = group or item["region"]

    name = CFG["output"]["naming"].format(
        REGION=group,
        INDEX=index
    )

    address = item["address"]

    # IPv6 必须使用 []
    if item["type"] == "ipv6":
        address = f"[{address}]"

    transport_type = str(
        t.get("type", "")
    ).lower()

    # ========================================================
    # 通用参数（与传输方式无关）
    # ========================================================

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

    # ========================================================
    # WebSocket 专属参数
    # ========================================================

    if transport_type == "ws":

        query["path"] = t["path"]
        query["host"] = t["host"]

    # ========================================================
    # gRPC 专属参数
    #
    # 注意：与 clash_proxy() 保持一致，不再把 WS 的
    # path/host 塞进 gRPC 链接里。
    # ========================================================

    elif transport_type == "grpc":

        query["serviceName"] = t.get(
            "serviceName",
            ""
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


# ============================================================
# TXT：Base64 VLESS Subscription
# ============================================================

def write_subscription(
    path: Path,
    nodes
):

    payload = "\n".join(nodes)

    if nodes:
        payload += "\n"

    encoded = base64.b64encode(
        payload.encode()
    ).decode()

    path.write_text(
        encoded + "\n",
        encoding="utf-8"
    )


# ============================================================
# Mihomo / Clash Proxy
# ============================================================

def clash_proxy(
    item,
    index,
    group=None
):

    t = CFG["template"]

    # --------------------------------------------------------
    # group 未指定时，继续使用原来的地区
    # --------------------------------------------------------

    group = group or item["region"]

    name = CFG["output"]["naming"].format(
        REGION=group,
        INDEX=index
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

    # ========================================================
    # ALPN
    # ========================================================

    alpn = t.get("alpn")

    if alpn:

        if isinstance(
            alpn,
            str
        ):

            alpn_list = [
                x.strip()
                for x in alpn.split(",")
                if x.strip()
            ]

        elif isinstance(
            alpn,
            list
        ):

            alpn_list = alpn

        else:

            alpn_list = []

        if alpn_list:
            proxy["alpn"] = alpn_list

    # ========================================================
    # WebSocket
    # ========================================================

    transport_type = str(
        t.get(
            "type",
            ""
        )
    ).lower()

    if transport_type == "ws":

        proxy["network"] = "ws"

        proxy["ws-opts"] = {
            "path": t["path"],
            "headers": {
                "Host": t["host"]
            }
        }

    # ========================================================
    # gRPC
    # ========================================================

    elif transport_type == "grpc":

        proxy["network"] = "grpc"

        service_name = t.get(
            "serviceName",
            ""
        )

        proxy["grpc-opts"] = {
            "grpc-service-name": service_name
        }

    # ========================================================
    # 其他传输
    # ========================================================

    else:

        if transport_type:
            proxy["network"] = transport_type

    return proxy


# ============================================================
# YAML：Mihomo / Clash
# ============================================================

def write_clash_yaml(
    path: Path,
    items,
    group=None
):

    proxies = [
        clash_proxy(
            item,
            item["_index"],
            group=group
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
            default_flow_style=False
        ),
        encoding="utf-8"
    )


# ============================================================
# 生成首页
# ============================================================

def write_index(history_stats=None):

    files = sorted(
        OUT.glob("*")
    )

    # 使用 config.yml 的 output.regions 中文对照表美化文件名
    region_names = CFG.get(
        "output",
        {}
    ).get(
        "regions",
        {}
    )

    links = []

    for p in files:

        if p.suffix.lower() in (
            ".txt",
            ".yaml"
        ):

            code = p.stem.upper()

            label = p.name

            if code in region_names:

                label = (
                    f"{p.name}"
                    f"（{region_names[code]}）"
                )

            links.append(
                f"<li>"
                f"<a href='{p.name}'>"
                f"{label}"
                f"</a>"
                f"</li>"
            )

    # ========================================================
    # output.keep_failed
    #
    # 打开后，在首页额外展示"仍在观察中、未连续失败 3 次"的
    # 历史 IP 数量，仅供参考——这些 IP 不会进入任何订阅文件。
    # ========================================================

    extra_html = ""

    if CFG.get("output", {}).get(
        "keep_failed",
        False
    ) and history_stats:

        retained = history_stats.get(
            "retained_failed",
            0
        )

        extra_html = (
            "<p>观察中（未连续失败 3 次）的历史 IP："
            f"{retained} 个，未包含在订阅内。</p>"
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
        + "</html>"
    )

    (
        OUT / "index.html"
    ).write_text(
        html,
        encoding="utf-8"
    )


# ============================================================
# 原子写入历史文件
# ============================================================

def save_history(history):

    temp_file = HISTORY_FILE.with_suffix(
        ".json.tmp"
    )

    text = json.dumps(
        history,
        ensure_ascii=False,
        indent=2,
        sort_keys=True
    ) + "\n"

    temp_file.write_text(
        text,
        encoding="utf-8"
    )

    os.replace(
        temp_file,
        HISTORY_FILE
    )


# ============================================================
# 清理输出
# ============================================================

def clean_output():

    for p in OUT.glob("*"):

        if p.is_file():
            p.unlink()


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
        "Persistent IP History + Health Check"
    )
    print(
        "============================================================"
    )

    # ========================================================
    # 清理旧输出
    # ========================================================

    clean_output()

    # ========================================================
    # 读取历史
    # ========================================================

    old_history = load_history()

    # ========================================================
    # 获取当前源
    # ========================================================

    current_items, source_status = parse_sources()

    # ========================================================
    # output.include_domain_source
    #
    # 全局开关：即使某个源以 kind: domain 提供候选，
    # 也可以在这里一键关闭域名类候选的使用。
    # ========================================================

    if not CFG.get("output", {}).get(
        "include_domain_source",
        True
    ):

        before = len(current_items)

        current_items = [
            item
            for item in current_items
            if item["type"] != "domain"
        ]

        removed = before - len(current_items)

        if removed:

            print(
                f"[INFO] include_domain_source=false: "
                f"dropped {removed} domain candidates"
            )

    # ========================================================
    # 源站状态统计
    # ========================================================

    source_ok_count = sum(
        1
        for status in source_status.values()
        if status["ok"]
    )

    source_total = len(
        source_status
    )

    source_failed_count = (
        source_total -
        source_ok_count
    )

    print(
        f"[SOURCE] available="
        f"{source_ok_count}/{source_total}"
    )

    # ========================================================
    # 如果所有源都失败
    #
    # 有历史：
    #   继续测试历史 IP
    #
    # 没历史：
    #   无法安全生成订阅，直接失败
    # ========================================================

    if (
        source_total > 0
        and source_failed_count == source_total
        and not old_history
    ):

        print(
            "[ERROR] all configured sources are unavailable "
            "and history is empty"
        )

        sys.exit(1)

    if (
        source_total > 0
        and source_failed_count == source_total
    ):

        print(
            "[WARN] ALL configured sources are unavailable."
        )

        print(
            "[WARN] Existing history will be tested and retained."
        )

    # ========================================================
    # 合并当前源 + 历史
    # ========================================================

    candidates = merge_candidates(
        current_items,
        old_history
    )

    if not candidates:

        print(
            "[ERROR] no candidates available"
        )

        sys.exit(1)

    # ========================================================
    # 健康检测
    # ========================================================

    candidates = test_candidates(
        candidates
    )

    # ========================================================
    # 更新历史
    # ========================================================

    new_history, history_stats = update_history(
        candidates,
        old_history
    )

    # ========================================================
    # 历史池限制 5000
    # ========================================================

    new_history, limit_removed = limit_history(
        new_history
    )

    history_stats["removed"] += (
        limit_removed
    )

    # ========================================================
    # 保存历史
    # ========================================================

    save_history(
        new_history
    )

    # ========================================================
    # 输出历史统计
    # ========================================================

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

    # ========================================================
    # 最终健康节点
    #
    # 注意：
    # candidates 中仍保留连续失败 < 3 的历史记录，
    # 但它们不能进入最终订阅。
    # ========================================================

    good = [
        item
        for item in candidates
        if item.get(
            "health_ok",
            False
        )
    ]

    # ========================================================
    # 如果最终没有健康节点
    #
    # 防止 GitHub Pages 发布空订阅。
    # ========================================================

    if not good:

        print(
            "[ERROR] zero healthy nodes remain."
        )

        sys.exit(1)

    print(
        f"[INFO] final healthy candidates: "
        f"{len(good)}"
    )

    # ========================================================
    # 排序
    #
    # 历史中已经成功过的 IP 优先，
    # 其次当前源中新发现的 IP。
    #
    # 这样历史 IP 不会因为新源数据刷新而频繁被替换。
    # ========================================================

    good.sort(
        key=lambda item: (
            0
            if item.get(
                "history_key"
            ) in old_history
            else 1,

            item.get(
                "region",
                "OTHER"
            ),

            item.get(
                "address",
                ""
            ),

            item.get(
                "port",
                0
            ),
        )
    )

    # ========================================================
    # 按地区分组
    #
    # 原有逻辑保持不变：
    #
    # HK / JP / SG / KR / TW / US / DE / CN / OTHER
    #
    # 运营商分组是额外输出，不替代这里。
    # ========================================================

    grouped = {}

    for item in good:

        grouped.setdefault(
            item["region"],
            []
        ).append(item)

    # ========================================================
    # 按运营商分组
    #
    # 这是新增功能：
    #
    # CU   = 联通
    # CT   = 电信
    # CMCC = 移动
    #
    # 注意：
    # 一个节点可以同时出现在：
    #
    #   other.yaml
    #   cmcc.yaml
    #
    # 但 all.yaml 只出现一次。
    # ========================================================

    operator_grouped = {}

    for item in good:

        operator = item.get(
            "operator",
            "OTHER"
        )

        if operator in (
            "CU",
            "CT",
            "CMCC"
        ):

            operator_grouped.setdefault(
                operator,
                []
            ).append(item)

    # ========================================================
    # 最终节点
    # ========================================================

    all_items = []

    maxn = int(
        CFG["output"].get(
            "max_nodes_per_region",
            100
        )
    )

    # ========================================================
    # 按地区生成 TXT + YAML
    # ========================================================

    for region, items in sorted(
        grouped.items()
    ):

        # 每个地区最多 max_nodes_per_region
        items = items[:maxn]

        if not items:
            continue

        # ----------------------------------------------------
        # 固定编号
        #
        # 这里给每个节点定下唯一的编号，后面 all.txt / all.yaml
        # 复用同一个编号，避免同一节点在分地区文件和汇总文件里
        # 显示成两个不同的名字。
        # ----------------------------------------------------

        for index, item in enumerate(
            items,
            1
        ):
            item["_index"] = index

        # 保存最终选中的 IP
        all_items.extend(
            items
        )

        # ----------------------------------------------------
        # VLESS URI
        # ----------------------------------------------------

        nodes = [
            vless_node(
                item,
                item["_index"]
            )
            for item in items
        ]

        region_name = region.lower()

        # ----------------------------------------------------
        # TXT
        # ----------------------------------------------------

        write_subscription(
            OUT / f"{region_name}.txt",
            nodes
        )

        # ----------------------------------------------------
        # YAML
        # ----------------------------------------------------

        write_clash_yaml(
            OUT / f"{region_name}.yaml",
            items
        )

    # ========================================================
    # 按运营商生成 CU / CT / CMCC TXT + YAML
    #
    # 运营商文件是额外筛选订阅：
    #
    #   cu.txt
    #   cu.yaml
    #
    #   ct.txt
    #   ct.yaml
    #
    #   cmcc.txt
    #   cmcc.yaml
    #
    # 不加入 all_items，避免 all.txt / all.yaml 重复。
    # ========================================================

    for operator, items in sorted(
        operator_grouped.items()
    ):

        # 每个运营商最多 max_nodes_per_region
        items = items[:maxn]

        if not items:
            continue

        nodes = [
            vless_node(
                item,
                index,
                group=operator
            )
            for index, item in enumerate(
                items,
                1
            )
        ]

        operator_name = operator.lower()

        # ----------------------------------------------------
        # TXT
        # ----------------------------------------------------

        write_subscription(
            OUT / f"{operator_name}.txt",
            nodes
        )

        # ----------------------------------------------------
        # YAML
        # ----------------------------------------------------

        # 这里不能使用地区生成时留下的 _index，
        # 运营商文件自己从 1 开始编号。
        #
        # clash_proxy() 使用 group=operator，
        # 所以名称会是：
        #
        #   CU-1
        #   CT-1
        #   CMCC-1
        #
        operator_items = []

        for index, item in enumerate(
            items,
            1
        ):

            temp_item = dict(item)
            temp_item["_index"] = index
            operator_items.append(
                temp_item
            )

        write_clash_yaml(
            OUT / f"{operator_name}.yaml",
            operator_items,
            group=operator
        )

    # ========================================================
    # ALL TXT + ALL YAML
    #
    # 两者严格使用同一个 all_items。
    #
    # 注意：
    # 这里仍然保持原有逻辑，
    # 不会因为新增运营商分组而重复加入节点。
    # ========================================================

    all_nodes = [
        vless_node(
            item,
            item["_index"]
        )
        for item in all_items
    ]

    if not all_nodes:

        print(
            "[ERROR] final node selection is empty"
        )

        sys.exit(1)

    write_subscription(
        OUT / "all.txt",
        all_nodes
    )

    write_clash_yaml(
        OUT / "all.yaml",
        all_items
    )

    # ========================================================
    # 生成首页
    # ========================================================

    write_index(history_stats)

    # ========================================================
    # 最终统计
    # ========================================================

    print("")
    print(
        "============================================================"
    )

    print(
        f"[DONE] generated "
        f"{len(all_nodes)} VLESS nodes"
    )

    print(
        f"[DONE] generated "
        f"{len(all_items)} Mihomo proxies"
    )

    print(
        f"[DONE] history pool "
        f"{len(new_history)}/{MAX_HISTORY}"
    )

    # --------------------------------------------------------
    # 运营商统计
    # --------------------------------------------------------

    for operator in (
        "CU",
        "CT",
        "CMCC"
    ):

        count = len(
            operator_grouped.get(
                operator,
                []
            )
        )

        print(
            f"[DONE] {operator}: "
            f"{count} healthy nodes"
        )

    print(
        "============================================================"
    )


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    main()
