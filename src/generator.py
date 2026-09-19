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
# Paths
# ============================================================

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "config.yml"
HISTORY_FILE = ROOT / "history.json"
OUT = ROOT / "output"


# ============================================================
# Config
# ============================================================

if not CONFIG_FILE.exists():
    raise FileNotFoundError(f"Config file not found: {CONFIG_FILE}")

with CONFIG_FILE.open("r", encoding="utf-8") as f:
    CFG = yaml.safe_load(f) or {}


MAX_FAILURES = int(CFG.get("history", {}).get("max_failures", 3))
MAX_HISTORY = int(CFG.get("history", {}).get("max_history", 5000))


# ============================================================
# Region / Carrier definitions
# ============================================================

REGION_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(HK|JP|SG|KR|TW|US|DE|CN)"
    r"(?![A-Za-z0-9])",
    re.I,
)


# 中国运营商
#
# 优先识别运营商。
# 这样即使注释中同时出现“中国”和“移动”，
# 也会优先归类为 CMCC。
#
CARRIER_ALIASES = {
    "联通": "CU",
    "中国联通": "CU",
    "China Unicom": "CU",

    "电信": "CT",
    "中国电信": "CT",
    "China Telecom": "CT",

    "移动": "CMCC",
    "中国移动": "CMCC",
    "China Mobile": "CMCC",
}


REGION_ALIASES = {
    "香港": "HK",
    "Hong Kong": "HK",

    "日本": "JP",
    "Japan": "JP",

    "新加坡": "SG",
    "Singapore": "SG",

    "韩国": "KR",
    "Korea": "KR",
    "South Korea": "KR",

    "台湾": "TW",
    "Taiwan": "TW",

    "美国": "US",
    "United States": "US",
    "United States of America": "US",

    "德国": "DE",
    "Germany": "DE",

    "中国": "CN",
    "China": "CN",
}


DEFAULT_REGION_NAMES = {
    "HK": "香港",
    "JP": "日本",
    "SG": "新加坡",
    "KR": "韩国",
    "TW": "台湾",
    "US": "美国",
    "DE": "德国",
    "CN": "中国",

    "CU": "联通",
    "CT": "电信",
    "CMCC": "移动",

    "OTHER": "其他",
}


# ============================================================
# IP:PORT parser
# ============================================================

IP_PORT_RE = re.compile(
    r"^\s*"
    r"(\[[0-9a-fA-F:]+\]|[^:\s#]+)"
    r"\s*:\s*"
    r"(\d{1,5})"
    r"\s*(?:#(.*))?$"
)


# ============================================================
# Time
# ============================================================

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ============================================================
# Carrier detection
# ============================================================

def carrier_from_comment(comment):
    """
    根据注释判断中国运营商。

    优先级：
        联通 -> CU
        电信 -> CT
        移动 -> CMCC

    只识别明确的运营商名称，避免普通单词
    mobile / telecom / unicom 产生误判。
    """

    if not comment:
        return None

    text = str(comment)

    # 中文 / 英文明确名称
    for alias, code in CARRIER_ALIASES.items():
        if alias.lower() in text.lower():
            return code

    return None


# ============================================================
# Region detection
# ============================================================

def region_from_comment(comment, source_name=""):
    """
    根据注释判断节点所属分组。

    优先级：
        1. 中国运营商
        2. 地区代码
        3. 地区中文 / 英文名称
        4. OTHER
    """

    comment = comment or ""
    source_name = source_name or ""

    text = f"{comment} {source_name}"

    # --------------------------------------------------------
    # 1. 中国运营商
    # --------------------------------------------------------

    carrier = carrier_from_comment(text)

    if carrier:
        return carrier

    # --------------------------------------------------------
    # 2. 地区代码
    # --------------------------------------------------------

    m = REGION_RE.search(text)

    if m:
        return m.group(1).upper()

    # --------------------------------------------------------
    # 3. 地区名称
    # --------------------------------------------------------

    lower_text = text.lower()

    # 长名称优先
    aliases = sorted(
        REGION_ALIASES.items(),
        key=lambda x: len(x[0]),
        reverse=True,
    )

    for alias, code in aliases:
        if alias.lower() in lower_text:
            return code

    # --------------------------------------------------------
    # 4. OTHER
    # --------------------------------------------------------

    return "OTHER"


# ============================================================
# Address normalization
# ============================================================

def normalize_address(address):
    address = str(address).strip()

    # IPv6 [xxxx]
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]

    try:
        ip = ipaddress.ip_address(address)

        if ip.version == 6:
            return str(ip), "ipv6"

        return str(ip), "ipv4"

    except ValueError:
        # 域名
        return address, "domain"


# ============================================================
# Item key
# ============================================================

def item_key(item):
    """
    生成节点唯一键。

    对普通节点：
        address:port

    对 CMCC/CU/CT：
        address:port:region

    这样可以允许同一个 IP:PORT 同时存在：
        CU
        CT
        CMCC

    例如：

        2606:4700:54::8422:962c:443:CU
        2606:4700:54::8422:962c:443:CT

    两者都会保留。
    """

    address = str(item.get("address", ""))
    port = int(item.get("port", 443))
    region = str(item.get("region", "OTHER")).upper()

    if region in ("CMCC", "CU", "CT"):
        return f"{address}:{port}:{region}"

    return f"{address}:{port}"


# ============================================================
# Parse line
# ============================================================

def parse_line(line, source_name="", kind="ip"):
    """
    解析：

    1.2.3.4:443#comment

    [2606:4700::1]:443#comment
    """

    if not line:
        return None

    line = str(line).strip()

    if not line:
        return None

    # 忽略纯注释
    if line.startswith("#"):
        return None

    m = IP_PORT_RE.match(line)

    if not m:
        return None

    raw_address = m.group(1)
    raw_port = m.group(2)
    comment = m.group(3) or ""

    try:
        port = int(raw_port)
    except ValueError:
        return None

    if port < 1 or port > 65535:
        return None

    address, ip_type = normalize_address(raw_address)

    # kind 过滤
    if kind == "ipv4" and ip_type != "ipv4":
        return None

    if kind == "ipv6" and ip_type != "ipv6":
        return None

    region = region_from_comment(
        comment,
        source_name,
    )

    return {
        "address": address,
        "port": port,
        "region": region,
        "comment": comment,
        "source": source_name,
        "type": ip_type,
    }


# ============================================================
# Fetch source
# ============================================================

def fetch_source(url, timeout=30):
    req = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 CF-IP-Generator",
        },
    )

    with urlopen(req, timeout=timeout) as response:
        data = response.read()

    return data.decode(
        "utf-8",
        errors="ignore",
    )


# ============================================================
# Parse sources
# ============================================================

def parse_sources():
    sources = CFG.get("sources", [])

    all_items = []
    source_status = []

    for source in sources:

        name = str(source.get("name", "UNKNOWN"))
        url = str(source.get("url", ""))
        kind = str(source.get("kind", "ip")).lower()

        try:
            content = fetch_source(url)

            items = []

            for line in content.splitlines():
                item = parse_line(
                    line,
                    source_name=name,
                    kind=kind,
                )

                if item:
                    items.append(item)

            source_status.append({
                "name": name,
                "url": url,
                "ok": True,
                "count": len(items),
            })

            all_items.extend(items)

            print(
                f"[SOURCE] {name}: "
                f"{len(items)} nodes"
            )

        except Exception as e:

            source_status.append({
                "name": name,
                "url": url,
                "ok": False,
                "count": 0,
                "error": str(e),
            })

            print(
                f"[SOURCE] {name}: FAILED - {e}"
            )

    # --------------------------------------------------------
    # Deduplication
    #
    # 注意：
    # CMCC/CU/CT 使用 region-aware key，
    # 所以同一个 IP 可以分别存在于不同运营商分组。
    # --------------------------------------------------------

    unique = {}

    for item in all_items:
        key = item_key(item)

        if key not in unique:
            unique[key] = item

    return list(unique.values()), source_status


# ============================================================
# History
# ============================================================

def load_history():
    if not HISTORY_FILE.exists():
        return {}

    try:
        with HISTORY_FILE.open(
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    result = {}

    # --------------------------------------------------------
    # 兼容旧 history.json
    #
    # 不直接相信 JSON 中原来的 key，
    # 根据节点自身信息重新生成 canonical key。
    # --------------------------------------------------------

    for _, item in data.items():

        if not isinstance(item, dict):
            continue

        if not item.get("address"):
            continue

        try:
            item["port"] = int(
                item.get("port", 443)
            )
        except Exception:
            continue

        item["region"] = str(
            item.get("region", "OTHER")
        ).upper()

        item.setdefault(
            "comment",
            "",
        )

        item.setdefault(
            "source",
            "",
        )

        item.setdefault(
            "type",
            "ipv4",
        )

        item.setdefault(
            "failures",
            0,
        )

        item.setdefault(
            "last_seen",
            "",
        )

        item.setdefault(
            "last_test",
            "",
        )

        item.setdefault(
            "healthy",
            False,
        )

        key = item_key(item)

        # 如果重复，优先保留健康节点
        if key not in result:
            result[key] = item

        else:
            old = result[key]

            old_score = (
                int(old.get("healthy", False)),
                -int(old.get("failures", 0)),
            )

            new_score = (
                int(item.get("healthy", False)),
                -int(item.get("failures", 0)),
            )

            if new_score > old_score:
                result[key] = item

    return result


# ============================================================
# Merge candidates
# ============================================================

def merge_candidates(history, current):
    merged = {}

    # history first
    for key, item in history.items():
        merged[key] = item

    # current overrides history
    for item in current:
        key = item_key(item)

        if key in merged:
            old = merged[key]

            # 保留历史健康状态
            item["failures"] = old.get(
                "failures",
                0,
            )

            item["healthy"] = old.get(
                "healthy",
                False,
            )

            item["last_test"] = old.get(
                "last_test",
                "",
            )

        merged[key] = item

    return list(merged.values())


# ============================================================
# TCP / TLS test
# ============================================================

def tcp_tls_test(
    address,
    port,
    timeout=5,
    server_hostname=None,
    skip_cert_verify=True,
):
    context = ssl.create_default_context()

    if skip_cert_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    sock = None

    try:

        sock = socket.create_connection(
            (address, port),
            timeout=timeout,
        )

        tls_sock = context.wrap_socket(
            sock,
            server_hostname=server_hostname,
        )

        tls_sock.close()

        return True

    except Exception:
        return False

    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================
# Test candidates
# ============================================================

def test_candidates(items):
    health_cfg = CFG.get(
        "health_check",
        {},
    )

    enabled = bool(
        health_cfg.get(
            "enabled",
            True,
        )
    )

    timeout = int(
        health_cfg.get(
            "timeout",
            5,
        )
    )

    workers = int(
        health_cfg.get(
            "workers",
            32,
        )
    )

    skip_ipv6_test = bool(
        health_cfg.get(
            "skip_ipv6_test",
            False,
        )
    )

    if not enabled:

        for item in items:
            item["healthy"] = True
            item["last_test"] = utc_now()

        return items

    output_cfg = CFG.get(
        "output",
        {},
    )

    sni = output_cfg.get(
        "sni",
        "",
    )

    skip_cert_verify = bool(
        output_cfg.get(
            "skip_cert_verify",
            True,
        )
    )

    def test_one(item):

        if (
            item.get("type") == "ipv6"
            and skip_ipv6_test
        ):
            return True

        return tcp_tls_test(
            item["address"],
            int(item["port"]),
            timeout=timeout,
            server_hostname=sni or None,
            skip_cert_verify=skip_cert_verify,
        )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                test_one,
                item,
            ): item
            for item in items
        }

        for future in concurrent.futures.as_completed(
            futures
        ):

            item = futures[future]

            try:
                healthy = bool(
                    future.result()
                )
            except Exception:
                healthy = False

            item["healthy"] = healthy
            item["last_test"] = utc_now()

    return items


# ============================================================
# Update history
# ============================================================

def update_history(history, items):
    now = utc_now()

    updated = {}

    for item in items:

        key = item_key(item)

        old = history.get(
            key,
            {},
        )

        failures = int(
            old.get(
                "failures",
                0,
            )
        )

        if item.get("healthy"):
            failures = 0
        else:
            failures += 1

        item["failures"] = failures

        item["last_seen"] = now

        # 达到最大失败次数后删除
        if failures >= MAX_FAILURES:
            continue

        updated[key] = item

    return updated


# ============================================================
# History sorting
# ============================================================

def history_sort_key(item):
    return (
        -int(item.get("healthy", False)),
        int(item.get("failures", 0)),
        str(item.get("address", "")),
        int(item.get("port", 443)),
    )


# ============================================================
# Limit history
# ============================================================

def limit_history(history):
    items = list(history.values())

    items.sort(
        key=history_sort_key
    )

    return {
        item_key(item): item
        for item in items[:MAX_HISTORY]
    }


# ============================================================
# VLESS node
# ============================================================

def vless_node(item, index=None):

    region = str(
        item.get(
            "region",
            "OTHER",
        )
    ).upper()

    if index is None:
        index = item.get(
            "_index",
            1,
        )

    naming = CFG.get(
        "output",
        {}
    ).get(
        "naming",
        "{REGION}-{INDEX:03d}",
    )

    try:
        name = naming.format(
            REGION=region,
            INDEX=int(index),
        )
    except Exception:
        name = f"{region}-{int(index):03d}"

    address = item["address"]
    port = int(item["port"])

    # IPv6
    if ":" in address:
        server = f"[{address}]"
    else:
        server = address

    params = []

    params.append("encryption=none")

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    params.append("security=tls")

    output_cfg = CFG.get(
        "output",
        {}
    )

    sni = output_cfg.get(
        "sni",
        "",
    )

    if sni:
        params.append(
            f"sni={quote(str(sni))}"
        )

    fingerprint = output_cfg.get(
        "client_fingerprint",
        "",
    )

    if fingerprint:
        params.append(
            f"fp={quote(str(fingerprint))}"
        )

    if output_cfg.get(
        "skip_cert_verify",
        False,
    ):
        params.append(
            "allowInsecure=1"
        )

    # --------------------------------------------------------
    # Transport
    # --------------------------------------------------------

    transport = str(
        output_cfg.get(
            "transport",
            "ws",
        )
    ).lower()

    if transport == "ws":

        ws_path = output_cfg.get(
            "ws_path",
            "/",
        )

        ws_host = output_cfg.get(
            "ws_host",
            "",
        )

        params.append(
            "type=ws"
        )

        params.append(
            "path="
            + quote(
                str(ws_path),
                safe="/",
            )
        )

        if ws_host:
            params.append(
                "host="
                + quote(
                    str(ws_host)
                )
            )

    elif transport == "grpc":

        service_name = output_cfg.get(
            "grpc_service_name",
            "",
        )

        params.append(
            "type=grpc"
        )

        if service_name:
            params.append(
                "serviceName="
                + quote(
                    str(service_name)
                )
            )

    query = "&".join(params)

    return (
        f"vless://"
        f"{item['uuid']}@"
        f"{server}:"
        f"{port}"
        f"?{query}"
        f"#{quote(name)}"
    )


# ============================================================
# Write subscription
# ============================================================

def write_subscription(path, nodes):

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    text = "\n".join(nodes)

    path.write_text(
        text + ("\n" if text else ""),
        encoding="utf-8",
    )


# ============================================================
# Clash proxy
# ============================================================

def clash_proxy(item, index=None):

    region = str(
        item.get(
            "region",
            "OTHER",
        )
    ).upper()

    if index is None:
        index = item.get(
            "_index",
            1,
        )

    naming = CFG.get(
        "output",
        {}
    ).get(
        "naming",
        "{REGION}-{INDEX:03d}",
    )

    try:
        name = naming.format(
            REGION=region,
            INDEX=int(index),
        )
    except Exception:
        name = f"{region}-{int(index):03d}"

    proxy = {
        "name": name,
        "type": "vless",
        "server": item["address"],
        "port": int(item["port"]),
        "uuid": item["uuid"],
        "udp": True,
        "tls": True,
    }

    output_cfg = CFG.get(
        "output",
        {}
    )

    sni = output_cfg.get(
        "sni",
        "",
    )

    if sni:
        proxy["servername"] = sni

    fingerprint = output_cfg.get(
        "client_fingerprint",
        "",
    )

    if fingerprint:
        proxy["client-fingerprint"] = fingerprint

    if output_cfg.get(
        "skip_cert_verify",
        False,
    ):
        proxy["skip-cert-verify"] = True

    alpn = output_cfg.get(
        "alpn",
        None,
    )

    if alpn:
        proxy["alpn"] = alpn

    # --------------------------------------------------------
    # Transport
    # --------------------------------------------------------

    transport = str(
        output_cfg.get(
            "transport",
            "ws",
        )
    ).lower()

    if transport == "ws":

        ws_path = output_cfg.get(
            "ws_path",
            "/",
        )

        ws_host = output_cfg.get(
            "ws_host",
            "",
        )

        proxy["network"] = "ws"

        proxy["ws-opts"] = {
            "path": ws_path,
        }

        if ws_host:
            proxy["ws-opts"]["headers"] = {
                "Host": ws_host,
            }

    elif transport == "grpc":

        service_name = output_cfg.get(
            "grpc_service_name",
            "",
        )

        proxy["network"] = "grpc"

        proxy["grpc-opts"] = {}

        if service_name:
            proxy["grpc-opts"][
                "grpc-service-name"
            ] = service_name

    return proxy


# ============================================================
# Write Clash YAML
# ============================================================

def write_clash_yaml(path, proxies):

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = {
        "proxies": proxies,
    }

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:

        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
        )


# ============================================================
# Write index
# ============================================================

def write_index(files):

    output_cfg = CFG.get(
        "output",
        {}
    )

    configured_regions = output_cfg.get(
        "regions",
        {},
    )

    region_names = dict(
        DEFAULT_REGION_NAMES
    )

    if isinstance(
        configured_regions,
        dict,
    ):
        region_names.update(
            configured_regions
        )

    lines = [
        "# CF-IP generated files",
        "",
        f"Generated: {utc_now()}",
        "",
    ]

    for filename in sorted(files):

        stem = Path(filename).stem.upper()

        label = region_names.get(
            stem,
            stem,
        )

        lines.append(
            f"- {label}: {filename}"
        )

    (OUT / "index.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


# ============================================================
# Save history
# ============================================================

def save_history(history):

    HISTORY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with HISTORY_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            history,
            f,
            ensure_ascii=False,
            indent=2,
        )


# ============================================================
# Clean output
# ============================================================

def clean_output():

    OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    for path in OUT.iterdir():

        if path.is_file():

            try:
                path.unlink()
            except Exception:
                pass


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 60)
    print("CF-IP Generator")
    print("=" * 60)

    clean_output()

    # --------------------------------------------------------
    # Load history
    # --------------------------------------------------------

    history = load_history()

    print(
        f"[HISTORY] loaded: {len(history)}"
    )

    # --------------------------------------------------------
    # Fetch and parse sources
    # --------------------------------------------------------

    current, source_status = parse_sources()

    available_sources = [
        x for x in source_status
        if x.get("ok")
    ]

    # --------------------------------------------------------
    # Optional domain handling
    # --------------------------------------------------------

    drop_domains = bool(
        CFG.get(
            "input",
            {}
        ).get(
            "drop_domains",
            False,
        )
    )

    if drop_domains:

        current = [
            item
            for item in current
            if item.get("type")
            != "domain"
        ]

    # --------------------------------------------------------
    # Source statistics
    # --------------------------------------------------------

    print()
    print("[SOURCE STATUS]")

    for source in source_status:

        if source.get("ok"):
            print(
                f"  OK   "
                f"{source['name']}: "
                f"{source['count']}"
            )
        else:
            print(
                f"  FAIL "
                f"{source['name']}: "
                f"{source.get('error', '')}"
            )

    # --------------------------------------------------------
    # If all sources failed and no history
    # --------------------------------------------------------

    if not available_sources and not history:

        raise RuntimeError(
            "All sources unavailable and history is empty."
        )

    # --------------------------------------------------------
    # Merge
    # --------------------------------------------------------

    candidates = merge_candidates(
        history,
        current,
    )

    print()
    print(
        f"[MERGE] candidates: "
        f"{len(candidates)}"
    )

    # --------------------------------------------------------
    # Health test
    # --------------------------------------------------------

    candidates = test_candidates(
        candidates
    )

    # --------------------------------------------------------
    # Update history
    # --------------------------------------------------------

    history = update_history(
        history,
        candidates,
    )

    history = limit_history(
        history
    )

    # --------------------------------------------------------
    # Save history
    # --------------------------------------------------------

    save_history(
        history
    )

    # --------------------------------------------------------
    # Only healthy nodes
    # --------------------------------------------------------

    good = [
        item
        for item in history.values()
        if item.get("healthy")
    ]

    print()
    print(
        f"[RESULT] healthy: "
        f"{len(good)}"
    )

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    good.sort(
        key=lambda item: (
            str(
                item.get(
                    "region",
                    "OTHER",
                )
            ),
            str(
                item.get(
                    "address",
                    "",
                )
            ),
            int(
                item.get(
                    "port",
                    443,
                )
            ),
        )
    )

    # ========================================================
    # IMPORTANT
    #
    # Group nodes by their actual region.
    #
    # CMCC / CU / CT are independent groups.
    # OTHER only contains real OTHER nodes.
    # ========================================================

    grouped = {}

    for item in good:

        region = str(
            item.get(
                "region",
                "OTHER",
            )
        ).upper()

        # 防止异常 region
        if not region:
            region = "OTHER"

        if region not in grouped:
            grouped[region] = []

        grouped[region].append(item)

    # --------------------------------------------------------
    # Make sure all known groups exist if needed
    # --------------------------------------------------------

    for region in (
        "CMCC",
        "CU",
        "CT",
        "OTHER",
    ):

        if region not in grouped:
            grouped[region] = []

    # ========================================================
    # Number every region independently
    #
    # CMCC:
    #   CMCC-001
    #   CMCC-002
    #
    # CU:
    #   CU-001
    #
    # CT:
    #   CT-001
    #
    # OTHER:
    #   OTHER-001
    #
    # These indexes are stored on the actual item.
    # ========================================================

    for region, region_items in grouped.items():

        for idx, item in enumerate(
            region_items,
            1,
        ):

            item["_index"] = idx

    # ========================================================
    # Generate individual region files
    #
    # IMPORTANT:
    #
    # other.yaml contains ONLY OTHER.
    #
    # Therefore CMCC/CU/CT are automatically excluded.
    # ========================================================

    generated_files = []

    for region, region_items in grouped.items():

        # 不生成空文件
        if not region_items:
            continue

        txt_nodes = [
            vless_node(
                item,
                item["_index"],
            )
            for item in region_items
        ]

        yaml_nodes = [
            clash_proxy(
                item,
                item["_index"],
            )
            for item in region_items
        ]

        region_lower = region.lower()

        txt_path = (
            OUT
            / f"{region_lower}.txt"
        )

        yaml_path = (
            OUT
            / f"{region_lower}.yaml"
        )

        write_subscription(
            txt_path,
            txt_nodes,
        )

        write_clash_yaml(
            yaml_path,
            yaml_nodes,
        )

        generated_files.append(
            txt_path.name
        )

        generated_files.append(
            yaml_path.name
        )

        print(
            f"[GROUP] "
            f"{region}: "
            f"{len(region_items)}"
        )

    # ========================================================
    # Generate ALL YAML
    #
    # VERY IMPORTANT:
    #
    # Do NOT do:
    #
    #   enumerate(good, 1)
    #
    # because that would make all nodes use a global index.
    #
    # Instead, reuse item["_index"] from its own group.
    #
    # Therefore:
    #
    # CMCC-001 remains CMCC-001
    # CU-001   remains CU-001
    # CT-001   remains CT-001
    # OTHER-001 remains OTHER-001
    # ========================================================

    all_nodes = [
        clash_proxy(
            item,
            item["_index"],
        )
        for item in good
    ]

    write_clash_yaml(
        OUT / "all.yaml",
        all_nodes,
    )

    generated_files.append(
        "all.yaml"
    )

    # ========================================================
    # Generate ALL TXT
    #
    # Same naming rule as all.yaml.
    # ========================================================

    all_txt_nodes = [
        vless_node(
            item,
            item["_index"],
        )
        for item in good
    ]

    write_subscription(
        OUT / "all.txt",
        all_txt_nodes,
    )

    generated_files.append(
        "all.txt"
    )

    # ========================================================
    # Index
    # ========================================================

    write_index(
        generated_files
    )

    # ========================================================
    # Statistics
    # ========================================================

    stats = {}

    for item in good:

        region = str(
            item.get(
                "region",
                "OTHER",
            )
        ).upper()

        stats[region] = (
            stats.get(region, 0)
            + 1
        )

    print()
    print("=" * 60)
    print("FINAL STATISTICS")
    print("=" * 60)

    for region in sorted(stats):

        label = DEFAULT_REGION_NAMES.get(
            region,
            region,
        )

        print(
            f"{region:<6} "
            f"{label:<8} "
            f"{stats[region]}"
        )

    print()
    print(
        f"TOTAL: {len(good)}"
    )

    print()
    print(
        f"Output directory: {OUT}"
    )

    print("=" * 60)


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            "\nInterrupted."
        )
        sys.exit(130)
    except Exception as e:
        print(
            f"\nERROR: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
