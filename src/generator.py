#!/usr/bin/env python3
from __future__ import annotations
import base64, concurrent.futures, ipaddress, re, socket, ssl
from pathlib import Path
from urllib.parse import quote
import yaml

ROOT = Path(__file__).resolve().parents[1]
CFG = yaml.safe_load((ROOT / "config/config.yml").read_text(encoding="utf-8"))
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

REGION_RE = re.compile(r"\b(HK|JP|SG|KR|TW|US|DE|CN)\b", re.I)
IP_PORT_RE = re.compile(r"^\s*(\[[0-9a-fA-F:]+\]|[^:\s#]+)\s*:\s*(\d{1,5})\s*(?:#(.*))?$")

def region_from_comment(comment: str, source_name: str) -> str:
    m = REGION_RE.search(comment or "")
    if m:
        return m.group(1).upper()
    # Common Chinese/English names as fallback.
    text = (comment or "").lower()
    aliases = {
        "香港":"HK", "hong kong":"HK", "日本":"JP", "japan":"JP",
        "新加坡":"SG", "singapore":"SG", "韩国":"KR", "korea":"KR",
        "台湾":"TW", "taiwan":"TW", "美国":"US", "united states":"US",
        "德国":"DE", "germany":"DE", "中国":"CN", "china":"CN",
    }
    for k, v in aliases.items():
        if k in text:
            return v
    return "OTHER"

def normalize_address(raw: str):
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        ip = ipaddress.ip_address(raw)
        return str(ip), ("ipv6" if ip.version == 6 else "ipv4")
    except ValueError:
        # Permit domain source separately.
        if re.fullmatch(r"[A-Za-z0-9.-]+", raw) and "." in raw:
            return raw.lower(), "domain"
    return None, None

def parse_line(line: str, source_name: str, kind: str):
    line = line.strip()
    if not line or line.startswith(("#",";","//")):
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
    if kind == "ip" and addr_type not in ("ipv4","ipv6"):
        return None
    if kind == "domain" and addr_type != "domain":
        return None
    region = region_from_comment(comment or "", source_name)
    return {
        "address": address, "port": port, "region": region,
        "comment": comment or "", "source": source_name, "type": addr_type
    }

def fetch_source(source):
    import urllib.request
    req = urllib.request.Request(source["url"], headers={"User-Agent":"cf-vless-generator/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")

def parse_sources():
    all_items = []
    for source in CFG["sources"]:
        try:
            text = fetch_source(source)
            count = 0
            for line in text.splitlines():
                item = parse_line(line, source["name"], source["kind"])
                if item:
                    all_items.append(item)
                    count += 1
            print(f"[OK] {source['name']}: {count} parsed")
        except Exception as e:
            print(f"[WARN] {source['name']}: {e}")
    # Deduplicate by address + port, preserving first occurrence.
    seen, result = set(), []
    for item in all_items:
        key = (item["address"], item["port"])
        if key not in seen:
            seen.add(key); result.append(item)
    print(f"[INFO] unique candidates: {len(result)}")
    return result

def tcp_tls_test(item):
    host = item["address"]
    port = item["port"]
    timeout = float(CFG["test"]["connect_timeout"])
    tls_timeout = float(CFG["test"]["tls_timeout"])
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(tls_timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # IPv6 / domain both work through socket.create_connection.
            with ctx.wrap_socket(sock, server_hostname=CFG["template"]["sni"]) as ssock:
                return True, ssock.version() or ""
    except Exception as e:
        return False, str(e)

def test_candidates(items):
    if not CFG["test"]["enabled"]:
        return items
    good = []
    workers = int(CFG["test"]["concurrency"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(tcp_tls_test, item): item for item in items}
        for fut in concurrent.futures.as_completed(futures):
            item = futures[fut]
            try:
                ok, detail = fut.result()
            except Exception as e:
                ok, detail = False, str(e)
            if ok:
                item["tls"] = detail
                good.append(item)
    print(f"[INFO] health passed: {len(good)}/{len(items)}")
    return good

def vless_node(item, index):
    t = CFG["template"]
    name = CFG["output"]["naming"].format(REGION=item["region"], INDEX=index)
    # VLESS URI requires brackets around IPv6 literals.
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
    return f"vless://{t['uuid']}@{address}:{item['port']}?{params}#{quote(name, safe='-._') }"

def write_subscription(path: Path, nodes):
    # Base64 VLESS subscription, compatible with common Clash/OpenClash
    # HTTP providers that accept VLESS URI lists.
    payload = "\n".join(nodes) + ("\n" if nodes else "")
    encoded = base64.b64encode(payload.encode()).decode()
    path.write_text(encoded + "\n", encoding="utf-8")

def main():
    for p in OUT.glob("*"):
        if p.is_file():
            p.unlink()
    candidates = parse_sources()
    good = test_candidates(candidates)

    grouped = {}
    for item in good:
        grouped.setdefault(item["region"], []).append(item)

    all_nodes = []
    maxn = int(CFG["output"]["max_nodes_per_region"])
    for region, items in sorted(grouped.items()):
        items = items[:maxn]
        nodes = [vless_node(x, i) for i, x in enumerate(items, 1)]
        if nodes:
            write_subscription(OUT / f"{region.lower()}.txt", nodes)
            all_nodes.extend(nodes)

    if all_nodes:
        write_subscription(OUT / "all.txt", all_nodes)

    # Domain source is intentionally separate so it can be enabled/disabled
    # independently without mixing domain candidates into IP pools.
    print(f"[DONE] generated {len(all_nodes)} VLESS nodes")
    (OUT / "index.html").write_text(
        "<meta charset='utf-8'><title>CF VLESS subscriptions</title>"
        "<h1>CF VLESS subscriptions</h1>"
        "<ul>" + "".join(
            f"<li><a href='{p.name}'>{p.name}</a></li>"
            for p in sorted(OUT.glob("*.txt"))
        ) + "</ul>", encoding="utf-8"
    )

if __name__ == "__main__":
    main()
