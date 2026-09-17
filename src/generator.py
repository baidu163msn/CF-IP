#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import quote

import yaml


ROOT = Path(__file__).resolve().parents[1]
CFG = yaml.safe_load(
    (ROOT / "config/config.yml").read_text(encoding="utf-8")
)

OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

REGION_RE = re.compile(
    r"\b(HK|JP|SG|KR|TW|US|DE|CN)\b",
    re.I
)

IP_PORT_RE = re.compile(
    r"^\s*(\[[0-9a-fA-F:]+\]|[^:\s#]+)"
    r"\s*:\s*(\d{1,5})\s*(?:#(.*))?$"
)


# ============================================================
# 地区识别
# ============================================================

def region_from_comment(comment: str, source_name: str) -> str:
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
        if re.fullmatch(r"[A-Za-z0-9.-]+", raw) and "." in raw:
            return raw.lower(), "domain"

    return None, None


# ============================================================
# 解析源文件
# ============================================================

def parse_line(
    line: str,
    source_name: str,
    kind: str
):
    line = line.strip()

    if not line or line.startswith(("#", ";", "//")):
        return None

    m = IP_PORT_RE.match(line)

    if not m:
        return None

    address, port_s, comment = m.groups()

    port = int(port_s)

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

    region = region_from_comment(
        comment or "",
        source_name
    )

    return {
        "address": address,
        "port": port,
        "region": region,
        "comment": comment or "",
        "source": source_name,
        "type": addr_type,
    }


# ============================================================
# 下载源
# ============================================================

def fetch_source(source):
    import urllib.request

    req = urllib.request.Request(
        source["url"],
        headers={
            "User-Agent": "cf-vless-generator/1.0"
        }
    )

    with urllib.request.urlopen(
        req,
        timeout=20
    ) as response:

        return response.read().decode(
            "utf-8",
            "replace"
        )


# ============================================================
# 解析所有源
# ============================================================

def parse_sources():

    all_items = []

    for source in CFG["sources"]:

        try:

            text = fetch_source(source)

            count = 0

            for line in text.splitlines():

                item = parse_line(
                    line,
                    source["name"],
                    source["kind"]
                )

                if item:
                    all_items.append(item)
                    count += 1

            print(
                f"[OK] {source['name']}: "
                f"{count} parsed"
            )

        except Exception as e:

            print(
                f"[WARN] {source['name']}: {e}"
            )

    # ========================================================
    # 去重
    # ========================================================

    seen = set()
    result = []

    for item in all_items:

        key = (
            item["address"],
            item["port"]
        )

        if key not in seen:

            seen.add(key)
            result.append(item)

    print(
        f"[INFO] unique candidates: "
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

            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(
                sock,
                server_hostname=CFG["template"]["sni"]
            ) as ssock:

                return (
                    True,
                    ssock.version() or ""
                )

    except Exception as e:

        return False, str(e)


# ============================================================
# 测试所有候选 IP
# ============================================================

def test_candidates(items):

    if not CFG["test"]["enabled"]:
        return items

    good = []

    workers = int(
        CFG["test"]["concurrency"]
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                tcp_tls_test,
                item
            ): item
            for item in items
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

            if ok:

                item["tls"] = detail
                good.append(item)

    print(
        f"[INFO] health passed: "
        f"{len(good)}/{len(items)}"
    )

    return good


# ============================================================
# 生成 VLESS URI
# ============================================================

def vless_node(item, index):

    t = CFG["template"]

    name = CFG["output"]["naming"].format(
        REGION=item["region"],
        INDEX=index
    )

    # IPv6 必须使用 []
    address = item["address"]

    if item["type"] == "ipv6":
        address = f"[{address}]"

    params = (
        f"path={quote(t['path'], safe='')}"
        f"&security={quote(str(t['security']), safe='')}"
        f"&alpn={quote(str(t['alpn']), safe='')}"
        f"&encryption={quote(str(t['encryption']), safe='')}"
        f"&insecure={t['insecure']}"
        f"&host={quote(t['host'], safe='')}"
        f"&fp={quote(t['fp'], safe='')}"
        f"&type={quote(t['type'], safe='')}"
        f"&allowInsecure={t['allowInsecure']}"
        f"&sni={quote(t['sni'], safe='')}"
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
    index
):

    t = CFG["template"]

    name = CFG["output"]["naming"].format(
        REGION=item["region"],
        INDEX=index
    )

    proxy = {
        "name": name,
        "type": "vless",
        "server": item["address"],
        "port": item["port"],
        "uuid": t["uuid"],
        "udp": True,
        "tls": str(t["security"]).lower() == "tls",
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

        if isinstance(alpn, str):

            alpn_list = [
                x.strip()
                for x in alpn.split(",")
                if x.strip()
            ]

        elif isinstance(alpn, list):

            alpn_list = alpn

        else:

            alpn_list = []

        if alpn_list:
            proxy["alpn"] = alpn_list

    # ========================================================
    # WebSocket
    # ========================================================

    transport_type = str(
        t.get("type", "")
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
# YAML：Mihomo / Clash 配置
# ============================================================

def write_clash_yaml(
    path: Path,
    items
):

    proxies = [
        clash_proxy(
            item,
            index
        )
        for index, item in enumerate(
            items,
            1
        )
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

def write_index():

    files = sorted(
        OUT.glob("*")
    )

    links = []

    for p in files:

        if p.suffix.lower() in (
            ".txt",
            ".yaml"
        ):

            links.append(
                f"<li>"
                f"<a href='{p.name}'>"
                f"{p.name}"
                f"</a>"
                f"</li>"
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
        "</body>"
        "</html>"
    )

    (OUT / "index.html").write_text(
        html,
        encoding="utf-8"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # 清理旧输出
    # ========================================================

    for p in OUT.glob("*"):

        if p.is_file():
            p.unlink()

    # ========================================================
    # 获取候选 IP
    # ========================================================

    candidates = parse_sources()

    # ========================================================
    # 健康检测
    # ========================================================

    good = test_candidates(
        candidates
    )

    # ========================================================
    # 按地区分组
    # ========================================================

    grouped = {}

    for item in good:

        grouped.setdefault(
            item["region"],
            []
        ).append(item)

    # ========================================================
    # 最终节点
    # ========================================================

    all_nodes = []

    all_items = []

    maxn = int(
        CFG["output"]["max_nodes_per_region"]
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

        # 保存最终选中的 IP
        all_items.extend(items)

        # 生成 VLESS URI
        nodes = [
            vless_node(
                item,
                index
            )
            for index, item in enumerate(
                items,
                1
            )
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

        all_nodes.extend(nodes)

    # ========================================================
    # ALL TXT + ALL YAML
    # ========================================================

    if all_nodes:

        # Base64 VLESS
        write_subscription(
            OUT / "all.txt",
            all_nodes
        )

        # Mihomo / Clash
        write_clash_yaml(
            OUT / "all.yaml",
            all_items
        )

    # ========================================================
    # 输出统计
    # ========================================================

    print(
        f"[DONE] generated "
        f"{len(all_nodes)} VLESS nodes"
    )

    print(
        f"[DONE] generated "
        f"{len(all_items)} Mihomo proxies"
    )

    # ========================================================
    # 生成首页
    # ========================================================

    write_index()


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    main()
