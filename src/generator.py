import concurrent.futures
import datetime
import ipaddress
import json
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

SRC_DIR = Path(__file__).resolve().parent
ROOT = SRC_DIR.parent

CONFIG_FILE = ROOT / "config" / "config.yml"
HISTORY_FILE = ROOT / "data" / "ip_history.json"
OUT = ROOT / "output"


# ============================================================
# Config
# ============================================================

if not CONFIG_FILE.exists():
    raise FileNotFoundError(f"Config file not found: {CONFIG_FILE}")

with CONFIG_FILE.open("r", encoding="utf-8") as f:
    CFG = yaml.safe_load(f) or {}

SOURCE_CFG = CFG.get("sources", [])
TEMPLATE_CFG = CFG.get("template", {})
TEST_CFG = CFG.get("test", {})
OUTPUT_CFG = CFG.get("output", {})

MAX_FAILURES = 3
MAX_HISTORY = 1000

HISTORY_CFG = CFG.get("history", {})
if isinstance(HISTORY_CFG, dict):
    MAX_FAILURES = int(HISTORY_CFG.get("max_failures", MAX_FAILURES))
    MAX_HISTORY = int(HISTORY_CFG.get("max_history", MAX_HISTORY))


# ============================================================
# Carrier / Region
# ============================================================

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


REGION_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(HK|JP|SG|KR|TW|US|DE|CN)"
    r"(?![A-Za-z0-9])",
    re.I,
)


IP_PORT_RE = re.compile(
    r"^\s*"
    r"(?:"
    r"\[([0-9A-Fa-f:.]+)\]"
    r"|"
    r"([0-9A-Fa-f:.]+)"
    r"|"
    r"([A-Za-z0-9.-]+)"
    r")"
    r":(\d+)"
    r"(?:#(.*))?"
    r"\s*$"
)


# ============================================================
# Utility
# ============================================================

def detect_carrier(comment):
    """
    Carrier detection has priority over region detection.

    Important:
    Do not independently match generic words such as
    mobile / telecom / unicom because they may create false
    positives.
    """
    text = str(comment or "")

    for alias, carrier in CARRIER_ALIASES.items():
        if alias.lower() in text.lower():
            return carrier

    return None


def detect_region(comment):
    text = str(comment or "")

    # Carrier first
    carrier = detect_carrier(text)
    if carrier:
        return carrier

    # Long aliases first
    for alias, region in sorted(
        REGION_ALIASES.items(),
        key=lambda x: len(x[0]),
        reverse=True,
    ):
        if alias.lower() in text.lower():
            return region

    # Short region code
    m = REGION_RE.search(text)
    if m:
        return m.group(1).upper()

    return "OTHER"


def normalize_address(address):
    address = str(address).strip()

    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]

    try:
        ip = ipaddress.ip_address(address)
        if ip.version == 4:
            return str(ip), "ipv4"
        return str(ip), "ipv6"
    except ValueError:
        return address, "domain"


def item_key(item):
    """
    Carrier-aware deduplication.

    CMCC/CU/CT are allowed to share the same IP:port because
    the same IP can appear in multiple source comments with
    different carrier labels.

    Other regions keep the traditional address:port key.
    """
    address = str(item.get("address", ""))
    port = int(item.get("port", 443))
    region = str(item.get("region", "OTHER")).upper()

    if region in ("CMCC", "CU", "CT"):
        return f"{address}:{port}:{region}"

    return f"{address}:{port}"


# ============================================================
# Parse source
# ============================================================

def parse_line(line, source):
    line = line.strip()

    if not line:
        return None

    m = IP_PORT_RE.match(line)
    if not m:
        return None

    ipv6_addr = m.group(1)
    normal_addr = m.group(2)
    domain_addr = m.group(3)
    port = int(m.group(4))
    comment = m.group(5) or ""

    raw_address = ipv6_addr or normal_addr or domain_addr

    address, ip_type = normalize_address(raw_address)

    kind = str(source.get("kind", "ip")).lower()

    if kind == "ip" and ip_type == "domain":
        return None

    if kind == "domain" and ip_type != "domain":
        return None

    region = detect_region(comment)

    return {
        "address": address,
        "port": port,
        "region": region,
        "comment": comment,
        "source": source.get("name", "UNKNOWN"),
        "type": ip_type,
    }


def fetch_source(source):
    name = source.get("name", "UNKNOWN")
    url = source.get("url", "")

    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/130.0 Safari/537.36"
            )
        },
    )

    with urlopen(req, timeout=20) as response:
        data = response.read()

    text = data.decode("utf-8", errors="ignore")

    result = []
    seen = set()

    for line in text.splitlines():
        item = parse_line(line, source)

        if not item:
            continue

        key = item_key(item)

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


def parse_sources():
    all_items = []
    source_status = []

    for source in SOURCE_CFG:
        name = source.get("name", "UNKNOWN")

        try:
            items = fetch_source(source)
            all_items.extend(items)

            source_status.append((name, True, len(items)))

            print(f"[SOURCE] {name}: {len(items)} nodes")

        except Exception as e:
            source_status.append((name, False, 0))

            print(f"[SOURCE] {name}: ERROR: {e}")

    print("[SOURCE STATUS]")

    for name, ok, count in source_status:
        if ok:
            print(f"  OK   {name}: {count}")
        else:
            print(f"  FAIL {name}")

    # Global dedup
    unique = {}

    for item in all_items:
        unique[item_key(item)] = item

    return list(unique.values()), source_status


# ============================================================
# History
# ============================================================

def load_history():
    if not HISTORY_FILE.exists():
        return {}

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            raw = json.load(f)

        if not isinstance(raw, dict):
            return {}

        history = {}

        for _, item in raw.items():
            if not isinstance(item, dict):
                continue

            key = item_key(item)
            history[key] = item

        print(f"[HISTORY] loaded: {len(history)}")

        return history

    except Exception as e:
        print(f"[HISTORY] load error: {e}")
        return {}


def save_history(history):
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

    with HISTORY_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            history,
            f,
            ensure_ascii=False,
            indent=2,
        )


def merge_candidates(current, history):
    merged = dict(history)

    for item in current:
        key = item_key(item)

        old = merged.get(key)

        if old:
            item["failures"] = int(old.get("failures", 0))
            item["last_seen"] = old.get("last_seen")

        merged[key] = item

    print(f"[MERGE] candidates: {len(merged)}")

    return merged


# ============================================================
# Health check
# ============================================================

def tcp_tls_test(item):
    address = item["address"]
    port = int(item.get("port", 443))

    connect_timeout = float(
        TEST_CFG.get("connect_timeout", 3.0)
    )

    tls_timeout = float(
        TEST_CFG.get("tls_timeout", 4.0)
    )

    tls_verify = bool(
        TEST_CFG.get("tls_verify", False)
    )

    sni = TEMPLATE_CFG.get("sni", "")

    sock = None

    try:
        sock = socket.create_connection(
            (address, port),
            timeout=connect_timeout,
        )

        sock.settimeout(tls_timeout)

        if tls_verify:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()

        with context.wrap_socket(
            sock,
            server_hostname=sni or None,
        ):
            pass

        return True

    except Exception:
        return False

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_candidates(candidates):
    if not TEST_CFG.get("enabled", True):
        print("[TEST] disabled")

        for item in candidates:
            item["_healthy"] = True

        return

    skip_ipv6_test = bool(
        TEST_CFG.get("skip_ipv6_test", False)
    )

    concurrency = int(
        TEST_CFG.get("concurrency", 40)
    )

    def check(item):
        if (
            item.get("type") == "ipv6"
            and skip_ipv6_test
        ):
            return True

        return tcp_tls_test(item)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=concurrency
    ) as executor:

        futures = {
            executor.submit(check, item): item
            for item in candidates.values()
        }

        for future in concurrent.futures.as_completed(futures):
            item = futures[future]

            try:
                item["_healthy"] = bool(
                    future.result()
                )
            except Exception:
                item["_healthy"] = False


def update_history(history):
    now = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()

    updated = {}

    for key, item in history.items():
        healthy = bool(item.get("_healthy", False))

        if healthy:
            item["failures"] = 0
            item["last_seen"] = now

        else:
            item["failures"] = (
                int(item.get("failures", 0)) + 1
            )

        item.pop("_healthy", None)

        if item["failures"] < MAX_FAILURES:
            updated[key] = item

    return updated


def limit_history(history):
    if len(history) <= MAX_HISTORY:
        return history

    items = list(history.items())

    items.sort(
        key=lambda kv: kv[1].get("last_seen", ""),
        reverse=True,
    )

    return dict(items[:MAX_HISTORY])


# ============================================================
# VLESS
# ============================================================

def template_uuid():
    return str(
        TEMPLATE_CFG.get(
            "uuid",
            "",
        )
    )


def vless_node(item, index):
    region = str(
        item.get("region", "OTHER")
    ).upper()

    naming = OUTPUT_CFG.get(
        "naming",
        "{REGION}-{INDEX:03d}",
    )

    name = naming.format(
        REGION=region,
        INDEX=index,
    )

    uuid = template_uuid()

    address = item["address"]
    port = int(item.get("port", 443))

    path = TEMPLATE_CFG.get(
        "path",
        "/",
    )

    security = TEMPLATE_CFG.get(
        "security",
        "tls",
    )

    encryption = TEMPLATE_CFG.get(
        "encryption",
        "none",
    )

    params = {
        "encryption": encryption,
        "security": security,
    }

    sni = TEMPLATE_CFG.get("sni", "")
    fp = TEMPLATE_CFG.get("fp", "")

    if sni:
        params["sni"] = sni

    if fp:
        params["fp"] = fp

    host = TEMPLATE_CFG.get("host", "")

    node_type = str(
        TEMPLATE_CFG.get("type", "ws")
    ).lower()

    if node_type == "ws":
        params["type"] = "ws"
        params["host"] = host
        params["path"] = path

    elif node_type == "grpc":
        params["type"] = "grpc"

        service_name = TEMPLATE_CFG.get(
            "serviceName",
            "",
        )

        if service_name:
            params["serviceName"] = service_name

    query = "&".join(
        f"{quote(str(k))}={quote(str(v))}"
        for k, v in params.items()
        if v != ""
    )

    return (
        f"vless://{uuid}@"
        f"{address}:{port}"
        f"?{query}"
        f"#{quote(name)}"
    )


# ============================================================
# Mihomo / Clash
# ============================================================

def clash_proxy(item, index):
    region = str(
        item.get("region", "OTHER")
    ).upper()

    naming = OUTPUT_CFG.get(
        "naming",
        "{REGION}-{INDEX:03d}",
    )

    name = naming.format(
        REGION=region,
        INDEX=index,
    )

    proxy = {
        "name": name,
        "type": "vless",
        "server": item["address"],
        "port": int(item.get("port", 443)),
        "uuid": template_uuid(),
        "udp": True,
    }

    security = TEMPLATE_CFG.get(
        "security",
        "tls",
    )

    if security == "tls":
        proxy["tls"] = True

        sni = TEMPLATE_CFG.get("sni", "")

        if sni:
            proxy["servername"] = sni

        fp = TEMPLATE_CFG.get("fp", "")

        if fp:
            proxy["client-fingerprint"] = fp

        allow_insecure = bool(
            TEMPLATE_CFG.get(
                "allowInsecure",
                0,
            )
        )

        proxy["skip-cert-verify"] = allow_insecure

    node_type = str(
        TEMPLATE_CFG.get(
            "type",
            "ws",
        )
    ).lower()

    if node_type == "ws":
        proxy["network"] = "ws"

        ws_opts = {}

        path = TEMPLATE_CFG.get(
            "path",
            "/",
        )

        if path:
            ws_opts["path"] = path

        host = TEMPLATE_CFG.get(
            "host",
            "",
        )

        if host:
            ws_opts["headers"] = {
                "Host": host
            }

        if ws_opts:
            proxy["ws-opts"] = ws_opts

    elif node_type == "grpc":
        proxy["network"] = "grpc"

        service_name = TEMPLATE_CFG.get(
            "serviceName",
            "",
        )

        if service_name:
            proxy["grpc-opts"] = {
                "grpc-service-name": service_name
            }

    return proxy


def write_clash_yaml(path, proxies):
    data = {
        "proxies": proxies
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
# Output
# ============================================================

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


def write_index(grouped):
    regions = dict(DEFAULT_REGION_NAMES)

    configured = OUTPUT_CFG.get(
        "regions",
        {},
    )

    if isinstance(configured, dict):
        regions.update(configured)

    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        '<meta charset="utf-8">',
        "<title>CF-IP</title>",
        "</head>",
        "<body>",
        "<h1>CF-IP</h1>",
        "<ul>",
    ]

    for region, items in grouped.items():
        display = regions.get(
            region,
            region,
        )

        lines.append(
            f"<li>{display} ({region}): "
            f"{len(items)}</li>"
        )

    lines.extend([
        "</ul>",
        "</body>",
        "</html>",
    ])

    OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    with (OUT / "index.html").open(
        "w",
        encoding="utf-8",
    ) as f:
        f.write("\n".join(lines))


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

    history = load_history()

    current, source_status = parse_sources()

    # --------------------------------------------------------
    # If all sources failed and there is no history,
    # abort instead of generating empty output.
    # --------------------------------------------------------

    successful_sources = any(
        ok
        for _, ok, _ in source_status
    )

    if (
        not successful_sources
        and not history
    ):
        raise RuntimeError(
            "All sources failed and history is empty."
        )

    # --------------------------------------------------------
    # Merge current candidates with history
    # --------------------------------------------------------

    candidates = merge_candidates(
        current,
        history,
    )

    # --------------------------------------------------------
    # Health test
    # --------------------------------------------------------

    test_candidates(candidates)

    healthy = [
        item
        for item in candidates.values()
        if item.get("_healthy", False)
    ]

    print(
        f"[RESULT] healthy: {len(healthy)}"
    )

    # --------------------------------------------------------
    # Update / save history
    # --------------------------------------------------------

    updated_history = update_history(
        candidates
    )

    updated_history = limit_history(
        updated_history
    )

    save_history(updated_history)

    # --------------------------------------------------------
    # Only healthy nodes enter subscriptions
    # --------------------------------------------------------

    good = healthy

    # Remove internal state
    for item in good:
        item.pop("_healthy", None)

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    good.sort(
        key=lambda x: (
            str(x.get("region", "OTHER")),
            str(x.get("address", "")),
            int(x.get("port", 443)),
        )
    )

    # --------------------------------------------------------
    # Group
    # --------------------------------------------------------

    grouped = {}

    for item in good:
        region = str(
            item.get(
                "region",
                "OTHER",
            )
        ).upper()

        grouped.setdefault(
            region,
            [],
        ).append(item)

    # Ensure required groups exist
    for region in (
        "CMCC",
        "CU",
        "CT",
        "OTHER",
    ):
        grouped.setdefault(
            region,
            [],
        )

    # --------------------------------------------------------
    # Number nodes independently inside each group.
    #
    # This is important:
    #
    # CMCC:
    #   CMCC-001
    #   CMCC-002
    #
    # CU:
    #   CU-001
    #   CU-002
    #
    # CT:
    #   CT-001
    #
    # OTHER:
    #   OTHER-001
    #
    # all.yaml reuses these same names.
    # --------------------------------------------------------

    for region, items in grouped.items():
        max_nodes = int(
            OUTPUT_CFG.get(
                "max_nodes_per_region",
                100,
            )
        )

        if max_nodes > 0:
            items = items[:max_nodes]
            grouped[region] = items

        for idx, item in enumerate(
            items,
            1,
        ):
            item["_index"] = idx

    # --------------------------------------------------------
    # Per-region outputs
    # --------------------------------------------------------

    for region, items in grouped.items():
        if not items:
            continue

        txt_lines = [
            vless_node(
                item,
                item["_index"],
            )
            for item in items
        ]

        proxies = [
            clash_proxy(
                item,
                item["_index"],
            )
            for item in items
        ]

        region_lower = region.lower()

        with (
            OUT / f"{region_lower}.txt"
        ).open(
            "w",
            encoding="utf-8",
        ) as f:
            f.write(
                "\n".join(txt_lines)
            )

        write_clash_yaml(
            OUT / f"{region_lower}.yaml",
            proxies,
        )

    # --------------------------------------------------------
    # all.txt
    #
    # Keep the original per-region node names.
    # --------------------------------------------------------

    all_txt = [
        vless_node(
            item,
            item["_index"],
        )
        for item in good
        if item.get("_index")
    ]

    with (
        OUT / "all.txt"
    ).open(
        "w",
        encoding="utf-8",
    ) as f:
        f.write(
            "\n".join(all_txt)
        )

    # --------------------------------------------------------
    # all.yaml
    #
    # CMCC nodes remain CMCC-xxx
    # CU nodes remain CU-xxx
    # CT nodes remain CT-xxx
    # OTHER nodes remain OTHER-xxx
    #
    # No global renumbering.
    # --------------------------------------------------------

    all_proxies = [
        clash_proxy(
            item,
            item["_index"],
        )
        for item in good
        if item.get("_index")
    ]

    write_clash_yaml(
        OUT / "all.yaml",
        all_proxies,
    )

    # --------------------------------------------------------
    # Index
    # --------------------------------------------------------

    write_index(grouped)

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print("=" * 60)
    print("OUTPUT")
    print("=" * 60)

    for region in sorted(grouped):
        count = len(
            grouped[region]
        )

        if count:
            print(
                f"  {region}: {count}"
            )

    print(
        f"  ALL: {len(all_proxies)}"
    )

    print("=" * 60)
    print("DONE")
    print("=" * 60)


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            "\nInterrupted.",
            file=sys.stderr,
        )
        sys.exit(130)

    except Exception as e:
        print(
            f"ERROR: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
