```python
#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import yaml


ROOT = Path(__file__).resolve().parents[1]

CFG = yaml.safe_load(
    (ROOT / "config/config.yml").read_text(
        encoding="utf-8"
    )
)

OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

HISTORY_FILE = DATA / "ip_history.json"

# ============================================================
# 历史池参数
# ============================================================

MAX_FAILURES = 3
MAX_HISTORY = 5000

# ============================================================
# 正则
# ============================================================

REGION_RE = re.compile(
    r"\b(HK|JP|SG|KR|TW|US|DE|CN)\b",
    re.I
)

IP_PORT_RE = re.compile(
    r"^\s*(\[[0-9a-fA-F:]+\]|[^:\s#]+)"
    r"\s*:\s*(\d{1,5})\s*(?:#(.*))?$"
)


# ============================================================
# 时间
# ============================================================

def now_iso():
    return datetime.now(
        timezone.utc
    ).replace(
        microsecond=0
    ).isoformat()


# ============================================================
# 地区识别
# ============================================================

def region_from_comment(
    comment: str,
    source_name: str
) -> str:

    m = REGION_RE.search(
        comment or ""
    )

    if m:
        return m.group(1).upper()

    text = (
        comment or ""
    ).lower()

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

    if (
        raw.startswith("[")
        and raw.endswith("]")
    ):
        raw = raw[1:-1]

    try:

        ip = ipaddress.ip_address(
            raw
        )

        return str(ip), (
            "ipv6"
            if ip.version == 6
            else "ipv4"
        )

    except ValueError:

        if (
            re.fullmatch(
                r"[A-Za-z0-9.-]+",
                raw
            )
            and "." in raw
        ):
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

    if (
        not line
        or line.startswith(
            ("#", ";", "//")
        )
    ):
        return None

    m = IP_PORT_RE.match(line)

    if not m:
        return None

    address, port_s, comment = (
        m.groups()
    )

    port = int(port_s)

    if not (
        1 <= port <= 65535
    ):
        return None

    address, addr_type = (
        normalize_address(address)
    )

    if not address:
        return None

    if (
        kind == "ip"
        and addr_type not in (
            "ipv4",
            "ipv6"
        )
    ):
        return None

    if (
        kind == "domain"
        and addr_type != "domain"
    ):
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
            "User-Agent":
                "cf-vless-generator/1.0"
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
# 当前数据源
# ============================================================

def parse_sources():

    all_items = []

    source_success = 0
    source_failed = 0

    for source in CFG["sources"]:

        try:

            text = fetch_source(
                source
            )

            count = 0

            for line in text.splitlines():

                item = parse_line(
                    line,
                    source["name"],
                    source["kind"]
                )

                if item:

                    all_items.append(
                        item
                    )

                    count += 1

            source_success += 1

            print(
                f"[OK] {source['name']}: "
                f"{count} parsed"
            )

        except Exception as e:

            source_failed += 1

            print(
                f"[WARN] "
                f"{source['name']}: {e}"
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

            result.append(
                item
            )

    print(
        f"[INFO] source success: "
        f"{source_success}"
    )

    print(
        f"[INFO] source failed: "
        f"{source_failed}"
    )

    print(
        f"[INFO] current unique candidates: "
        f"{len(result)}"
    )

    return result


# ============================================================
# 历史池读取
# ============================================================

def load_history():

    if not HISTORY_FILE.exists():

        print(
            "[INFO] history: "
            "no previous history"
        )

        return {}

    try:

        data = json.loads(
            HISTORY_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(
            data,
            dict
        ):
            return {}

        print(
            f"[INFO] history loaded: "
            f"{len(data)}"
        )

        return data

    except Exception as e:

        print(
            f"[WARN] history load failed: "
            f"{e}"
        )

        return {}


# ============================================================
# 历史池保存
# ============================================================

def save_history(history):

    HISTORY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    tmp = HISTORY_FILE.with_suffix(
        ".tmp"
    )

    tmp.write_text(
        json.dumps(
            history,
            ensure_ascii=False,
            indent=2,
            sort_keys=True
        ) + "\n",
        encoding="utf-8"
    )

    tmp.replace(
        HISTORY_FILE
    )


# ============================================================
# 历史 IP Key
# ============================================================

def item_key(item):

    return (
        f"{item['address']}:"
        f"{item['port']}"
    )


# ============================================================
# 历史池 + 当前数据源
# ============================================================

def merge_history(
    current_items,
    history
):

    merged = {}

    current_keys = set()

    # --------------------------------------------------------
    # 先放当前数据源
    # 当前源拥有最高优先级
    # --------------------------------------------------------

    for item in current_items:

        key = item_key(item)

        current_keys.add(key)

        old = history.get(
            key,
            {}
        )

        item["history"] = True
        item["source_current"] = True
        item["failures"] = int(
            old.get(
                "failures",
                0
            )
        )

        item["first_seen"] = (
            old.get(
                "first_seen",
                now_iso()
            )
        )

        item["last_seen"] = now_iso()

        merged[key] = item

    # --------------------------------------------------------
    # 再加入历史中已经消失的数据源 IP
    # --------------------------------------------------------

    for key, old in history.items():

        if key in merged:
            continue

        try:

            address = old["address"]
            port = int(old["port"])

        except Exception:
            continue

        item = {
            "address": address,
            "port": port,
            "region": old.get(
                "region",
                "OTHER"
            ),
            "comment": old.get(
                "comment",
                ""
            ),
            "source": old.get(
                "source",
                "HISTORY"
            ),
            "type": old.get(
                "type",
                "ipv4"
            ),
            "history": True,
            "source_current": False,
            "failures": int(
                old.get(
                    "failures",
                    0
                )
            ),
            "first_seen": old.get(
                "first_seen",
                now_iso()
            ),
            "last_seen": old.get(
                "last_seen",
                ""
            ),
        }

        merged[key] = item

    history_only = (
        len(merged)
        - len(current_keys)
    )

    print(
        f"[INFO] merged candidates: "
        f"{len(merged)}"
    )

    print(
        f"[INFO] historical candidates: "
        f"{history_only}"
    )

    return list(
        merged.values()
    )


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

            sock.settimeout(
                tls_timeout
            )

            ctx = (
                ssl.create_default_context()
            )

            ctx.check_hostname = False

            ctx.verify_mode = (
                ssl.CERT_NONE
            )

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
# 测试所有候选 IP
# ============================================================

def test_candidates(items):

    if not CFG["test"]["enabled"]:

        for item in items:
            item["health_ok"] = True

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

                ok, detail = (
                    future.result()
                )

            except Exception as e:

                ok = False
                detail = str(e)

            key = item_key(item)

            if ok:

                item["tls"] = detail
                item["health_ok"] = True
                item["failures"] = 0
                item["last_success"] = (
                    now_iso()
                )

                good.append(item)

            else:

                item["health_ok"] = False

                old_failures = int(
                    item.get(
                        "failures",
                        0
                    )
                )

                item["failures"] = (
                    old_failures + 1
                )

                item["last_failure"] = (
                    now_iso()
                )

                item["last_error"] = (
                    detail
                )

    passed = len(good)

    failed = (
        len(items)
        - passed
    )

    print(
        f"[INFO] health passed: "
        f"{passed}/{len(items)}"
    )

    print(
        f"[INFO] health failed: "
        f"{failed}"
    )

    return good


# ============================================================
# 更新历史池
# ============================================================

def update_history(
    tested_items,
    history
):

    new_history = {}

    new_count = 0
    retained_count = 0
    failed_count = 0
    removed_count = 0

    for item in tested_items:

        key = item_key(item)

        was_history = (
            key in history
        )

        if item.get(
            "health_ok",
            False
        ):

            if was_history:
                retained_count += 1
            else:
                new_count += 1

            new_history[key] = {
                "address": item[
                    "address"
                ],
                "port": item[
                    "port"
                ],
                "region": item[
                    "region"
                ],
                "comment": item[
                    "comment"
                ],
                "source": item[
                    "source"
                ],
                "type": item[
                    "type"
                ],
                "failures": 0,
                "first_seen": item.get(
                    "first_seen",
                    now_iso()
                ),
                "last_seen": now_iso(),
                "last_success": item.get(
                    "last_success",
                    now_iso()
                ),
            }

        else:

            failures = int(
                item.get(
                    "failures",
                    0
                )
            )

            if failures < MAX_FAILURES:

                failed_count += 1

                new_history[key] = {
                    "address": item[
                        "address"
                    ],
                    "port": item[
                        "port"
                    ],
                    "region": item[
                        "region"
                    ],
                    "comment": item[
                        "comment"
                    ],
                    "source": item[
                        "source"
                    ],
                    "type": item[
                        "type"
                    ],
                    "failures": failures,
                    "first_seen": item.get(
                        "first_seen",
                        now_iso()
                    ),
                    "last_seen": item.get(
                        "last_seen",
                        ""
                    ),
                    "last_failure": item.get(
                        "last_failure",
                        now_iso()
                    ),
                    "last_error": item.get(
                        "last_error",
                        ""
                    ),
                }

            else:

                removed_count += 1

    # --------------------------------------------------------
    # 历史池最大容量
    # --------------------------------------------------------

    if len(new_history) > MAX_HISTORY:

        def sort_key(pair):

            value = pair[1]

            return (
                int(
                    value.get(
                        "failures",
                        0
                    )
                ),
                value.get(
                    "last_success",
                    ""
                ),
            )

        sorted_history = sorted(
            new_history.items(),
            key=sort_key,
            reverse=True
        )

        new_history = dict(
            sorted_history[
                :MAX_HISTORY
            ]
        )

    save_history(
        new_history
    )

    print(
        f"[HISTORY] new: "
        f"{new_count}"
    )

    print(
        f"[HISTORY] retained: "
        f"{retained_count}"
    )

    print(
        f"[HISTORY] temporary failed: "
        f"{failed_count}"
    )

    print(
        f"[HISTORY] removed: "
        f"{removed_count}"
    )

    print(
        f"[HISTORY] total: "
        f"{len(new_history)}"
    )

    return new_history


# ============================================================
# 生成 VLESS URI
# ============================================================

def vless_node(
    item,
    index
):

    t = CFG["template"]

    name = CFG["output"][
        "naming"
    ].format(
        REGION=item["region"],
        INDEX=index
    )

    address = item[
        "address"
    ]

    if item["type"] == "ipv6":

        address = (
            f"[{address}]"
        )

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
# TXT
# ============================================================

def write_subscription(
    path: Path,
    nodes
):

    payload = "\n".join(
        nodes
    )

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
# Mihomo Proxy
# ============================================================

def clash_proxy(
    item,
    index
):

    t = CFG["template"]

    name = CFG["output"][
        "naming"
    ].format(
        REGION=item["region"],
        INDEX=index
    )

    proxy = {
        "name": name,
        "type": "vless",
        "server": item[
            "address"
        ],
        "port": item[
            "port"
        ],
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

    alpn = t.get(
        "alpn"
    )

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
            proxy["alpn"] = (
                alpn_list
            )

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

    elif transport_type == "grpc":

        proxy["network"] = "grpc"

        service_name = t.get(
            "serviceName",
            ""
        )

        proxy["grpc-opts"] = {
            "grpc-service-name":
                service_name
        }

    else:

        if transport_type:
            proxy["network"] = (
                transport_type
            )

    return proxy


# ============================================================
# YAML
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
# 首页
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

    (
        OUT / "index.html"
    ).write_text(
        html,
        encoding="utf-8"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # 清理旧输出
    # 注意：只清理 output，不碰 data/history
    # ========================================================

    for p in OUT.glob("*"):

        if p.is_file():
            p.unlink()

    # ========================================================
    # 当前数据源
    # ========================================================

    current_items = (
        parse_sources()
    )

    # ========================================================
    # 历史池
    # ========================================================

    history = load_history()

    candidates = merge_history(
        current_items,
        history
    )

    # ========================================================
    # 健康检测
    # ========================================================

    tested = test_candidates(
        candidates
    )

    # ========================================================
    # 更新历史池
    # ========================================================

    updated_history = (
        update_history(
            candidates,
            history
        )
    )

    # ========================================================
    # 只使用本轮健康通过的节点
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
    # 统计当前源 / 历史保留
    # ========================================================

    current_good = [
        item
        for item in good
        if item.get(
            "source_current",
            False
        )
    ]

    retained_good = [
        item
        for item in good
        if not item.get(
            "source_current",
            False
        )
    ]

    print(
        f"[INFO] healthy current-source: "
        f"{len(current_good)}"
    )

    print(
        f"[INFO] healthy historical-retained: "
        f"{len(retained_good)}"
    )

    print(
        f"[INFO] healthy total: "
        f"{len(good)}"
    )

    # ========================================================
    # 历史有效 IP 优先
    #
    # 这样数据源发生变化时，
    # 已经验证过的旧 IP 不会轻易被新 IP 顶掉。
    # ========================================================

    good = (
        retained_good
        + current_good
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
        CFG["output"][
            "max_nodes_per_region"
        ]
    )

    # ========================================================
    # 地区 TXT + YAML
    # ========================================================

    for region, items in sorted(
        grouped.items()
    ):

        items = items[
            :maxn
        ]

        if not items:
            continue

        all_items.extend(
            items
        )

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

        region_name = (
            region.lower()
        )

        write_subscription(
            OUT / f"{region_name}.txt",
            nodes
        )

        write_clash_yaml(
            OUT / f"{region_name}.yaml",
            items
        )

        all_nodes.extend(
            nodes
        )

    # ========================================================
    # ALL
    # ========================================================

    if all_nodes:

        write_subscription(
            OUT / "all.txt",
            all_nodes
        )

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

    print(
        f"[DONE] history file: "
        f"{HISTORY_FILE}"
    )

    # ========================================================
    # 首页
    # ========================================================

    write_index()


if __name__ == "__main__":
    main()
```
