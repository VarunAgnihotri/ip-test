# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""
Figures out what is in front of it, resolves the client IP accordingly,
and shows its work.

    uv run https://raw.githubusercontent.com/VarunAgnihotri/ip-test/main/ip_server.py
    uvx --from git+https://github.com/VarunAgnihotri/ip-test ip-server

    GET /        HTML in a browser, plain text to curl (Accept negotiated)
    GET /ip      plain text
    GET /json    always JSON  (add ?full=1 for every candidate)
    GET /debug   everything, including raw headers
"""

import argparse
import errno
import ipaddress
import json
import os
import re
import signal
import socket
import sys
from collections.abc import Callable, Mapping
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import monotonic
from typing import Any
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"

type Headers = Mapping[str, list[str]]
type Json = dict[str, Any]


# Address normalization + scope

_BRACKETED = re.compile(r"^\[([^\]]+)\](?::\d+)?$")  # [2001:db8::1]:443
_V4_WITH_PORT = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$")  # 1.2.3.4:443
_V4_MAPPED = re.compile(r"^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$", re.IGNORECASE)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_ip(raw: str | None) -> str | None:
    """Strip ports, brackets, zone ids and v4-mapped prefixes. None if unusable."""
    if not isinstance(raw, str):
        return None
    ip = raw.strip().strip('"')
    if not ip:
        return None

    bracketed = _BRACKETED.match(ip)
    if bracketed:
        ip = bracketed.group(1)

    if _V4_WITH_PORT.match(ip):
        ip = ip.split(":")[0]

    # Bare IPv6 with a trailing port (CloudFront does this): 2001:db8::1:52011
    if not _is_ip(ip) and ":" in ip:
        head = ip[: ip.rindex(":")]
        if _is_ip(head):
            ip = head

    ip = ip.split("%")[0]  # fe80::1%eth0

    mapped = _V4_MAPPED.match(ip)
    if mapped:
        ip = mapped.group(1)

    ip = ip.lower()
    return ip if _is_ip(ip) else None


_NON_PUBLIC = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",  # unique local
        "fe80::/10",  # link local
        "ff00::/8",  # multicast
        "2001:db8::/32",  # documentation
    )
]


def is_non_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr.version == net.version and addr in net for net in _NON_PUBLIC)


def scope_of(ip: str | None) -> str | None:
    if not ip:
        return None
    return "private" if is_non_public(ip) else "public"


def ip_version(ip: str) -> str:
    return f"IPv{ipaddress.ip_address(ip).version}"


# Header inventory

SINGLE_IP_HEADERS = (
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-pseudo-ipv4",
    "true-client-ip",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
    "fly-client-ip",
    "do-connecting-ip",
    "oxygen-buyer-ip",
    "x-appengine-user-ip",
    "x-azure-clientip",
    "x-azure-socketip",
    "x-vercel-forwarded-for",
    "x-nf-client-connection-ip",
    "cloudfront-viewer-address",
    "x-envoy-external-address",
    "client-ip",
    "proxy-client-ip",
    "wl-proxy-client-ip",
    "x-coming-from",
    "remote-addr",
    "z-forwarded-for",
    "http-x-cluster-client-ip",
    "x-original-remote-addr",
)

CHAIN_HEADERS = (
    "x-forwarded-for",
    "x-original-forwarded-for",
    "x-forwarded",
    "forwarded-for",
    "x-http-forwarded-for",
    "x-vercel-proxied-for",
)


def collect_headers(message: Message) -> Headers:
    """Lowercase name -> every value sent under it, repeats kept."""
    headers: dict[str, list[str]] = {}
    for name, value in message.items():
        headers.setdefault(name.lower(), []).append(value)
    return headers


def header_values(headers: Headers, name: str) -> list[str]:
    return headers.get(name, [])


_FORWARDED_FOR = re.compile(r'for\s*=\s*("[^"]*"|[^;,\s]+)', re.IGNORECASE)


def parse_forwarded(value: str) -> list[str]:
    """RFC 7239: Forwarded: for=1.2.3.4;proto=https, for="[2001:db8::1]:8080" """
    ips = []
    for element in value.split(","):
        match = _FORWARDED_FOR.search(element)
        if not match:
            continue
        ip = normalize_ip(match.group(1))
        if ip:
            ips.append(ip)
    return ips


def chain_from(headers: Headers) -> dict[str, Any] | None:
    for name in CHAIN_HEADERS:
        values = header_values(headers, name)
        if not values:
            continue
        ips = [ip for part in ",".join(values).split(",") if (ip := normalize_ip(part))]
        if ips:
            return {"header": name, "ips": ips}

    forwarded = [ip for v in header_values(headers, "forwarded") for ip in parse_forwarded(v)]
    if forwarded:
        return {"header": "forwarded", "ips": forwarded}
    return None


# Edge detection
#
# Each edge is identified by a *fingerprint* header it stamps on every
# request, not by the IP header itself. Once we know the edge, we know
# exactly which header (or which position in the XFF chain) holds the client.
#
# pick:
#   leftmost          first entry in the chain
#   rightmost         last entry, because the edge appended the real peer
#   second_from_right edge appended two entries (client, own LB address)

type Fingerprint = tuple[str, ...] | Callable[[Headers], bool]


def _via_matches(pattern: str) -> Callable[[Headers], bool]:
    probe = re.compile(pattern, re.IGNORECASE)

    def check(headers: Headers) -> bool:
        return any(probe.search(v) for v in header_values(headers, "via"))

    return check


def _is_heroku(headers: Headers) -> bool:
    return _via_matches("vegur")(headers) or "x-request-start" in headers


EDGES: tuple[dict[str, Any], ...] = (
    {
        "id": "cloudflare",
        "name": "Cloudflare",
        "fingerprint": ("cf-ray",),
        "headers": ("cf-connecting-ip", "true-client-ip"),
        "trusted_hops": 1,
    },
    {
        "id": "cloudfront",
        "name": "AWS CloudFront",
        "fingerprint": ("x-amz-cf-id",),
        "headers": ("cloudfront-viewer-address",),
        "pick": "leftmost",
        "trusted_hops": 1,
    },
    {
        "id": "aws-elb",
        "name": "AWS ALB / ELB",
        "fingerprint": ("x-amzn-trace-id",),
        "pick": "leftmost",
        "trusted_hops": 1,
    },
    {
        "id": "fastly",
        "name": "Fastly",
        "fingerprint": ("fastly-client-ip", "x-served-by"),
        "headers": ("fastly-client-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "akamai",
        "name": "Akamai",
        "fingerprint": ("akamai-origin-hop", "x-akamai-request-id"),
        "headers": ("true-client-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "vercel",
        "name": "Vercel",
        "fingerprint": ("x-vercel-id", "x-vercel-deployment-url"),
        "headers": ("x-vercel-forwarded-for", "x-real-ip"),
        "trusted_hops": 1,
    },
    {
        "id": "netlify",
        "name": "Netlify",
        "fingerprint": ("x-nf-request-id",),
        "headers": ("x-nf-client-connection-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "fly",
        "name": "Fly.io",
        "fingerprint": ("fly-request-id",),
        "headers": ("fly-client-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "azure-fd",
        "name": "Azure Front Door",
        "fingerprint": ("x-azure-ref",),
        "headers": ("x-azure-clientip", "x-azure-socketip"),
        "trusted_hops": 1,
    },
    {
        "id": "gclb",
        "name": "Google Cloud Load Balancer",
        "fingerprint": _via_matches(r"\bgoogle\b"),
        "pick": "second_from_right",
        "trusted_hops": 2,
    },
    {
        "id": "appengine",
        "name": "Google App Engine",
        "fingerprint": ("x-appengine-city", "x-appengine-request-log-id"),
        "headers": ("x-appengine-user-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "heroku",
        "name": "Heroku Router",
        "fingerprint": _is_heroku,
        "pick": "rightmost",
        "trusted_hops": 1,
    },
    {
        "id": "digitalocean",
        "name": "DigitalOcean App Platform",
        "fingerprint": ("do-connecting-ip",),
        "headers": ("do-connecting-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "oxygen",
        "name": "Shopify Oxygen",
        "fingerprint": ("oxygen-buyer-ip",),
        "headers": ("oxygen-buyer-ip",),
        "trusted_hops": 1,
    },
    {
        "id": "render",
        "name": "Render",
        "fingerprint": ("render-proxy-ttl", "rndr-id"),
        "headers": ("true-client-ip", "x-real-ip"),
        "trusted_hops": 1,
    },
    {
        "id": "envoy",
        "name": "Envoy / Istio",
        "fingerprint": ("x-envoy-external-address", "x-envoy-attempt-count"),
        "headers": ("x-envoy-external-address",),
        "trusted_hops": 1,
    },
)


def detect_edge(headers: Headers) -> dict[str, Any] | None:
    for edge in EDGES:
        fingerprint: Fingerprint = edge["fingerprint"]
        if callable(fingerprint):
            evidence = ["via"] if fingerprint(headers) else []
        else:
            evidence = [name for name in fingerprint if name in headers]
        if evidence:
            return {**edge, "evidence": evidence}
    return None


def pick_from_chain(ips: list[str], rule: str) -> str | None:
    if not ips:
        return None
    if rule == "rightmost":
        return ips[-1]
    if rule == "second_from_right":
        return ips[-2] if len(ips) >= 2 else ips[0]
    return next((ip for ip in ips if not is_non_public(ip)), ips[0])  # leftmost public


# Resolution


def _single_ip_candidates(headers: Headers) -> list[dict[str, str]]:
    singles = []
    for name in SINGLE_IP_HEADERS:
        values = header_values(headers, name)
        if not values:
            continue
        ip = normalize_ip(values[0])
        if ip:
            singles.append({"header": name, "ip": ip, "raw": values[0].strip()})
    return singles


def _from_edge(
    edge: dict[str, Any],
    singles: list[dict[str, str]],
    chain: dict[str, Any] | None,
) -> tuple[str, str] | None:
    """The address this edge documents, plus where it came from."""
    for name in edge.get("headers", ()):
        hit = next((s for s in singles if s["header"] == name), None)
        if hit:
            return hit["ip"], name
    if chain:
        pick = edge.get("pick", "leftmost")
        ip = pick_from_chain(chain["ips"], pick)
        if ip:
            suffix = f" ({pick})" if edge.get("pick") else ""
            return ip, f"{chain['header']}{suffix}"
    return None


def _first_claim(
    singles: list[dict[str, str]], chain: dict[str, Any] | None
) -> tuple[str, str] | None:
    if chain:
        ip = pick_from_chain(chain["ips"], "leftmost")
        if ip:
            return ip, chain["header"]
    if singles:
        return singles[0]["ip"], singles[0]["header"]
    return None


def _build_hops(
    chain: dict[str, Any] | None,
    singles: list[dict[str, str]],
    peer: str | None,
    resolved_ip: str | None,
) -> list[Json]:
    hops: list[Json] = []
    if chain:
        for index, hop_ip in enumerate(chain["ips"]):
            hops.append(
                {
                    "ip": hop_ip,
                    "label": "claimed origin" if index == 0 else f"hop {index}",
                    "role": "claim",
                    "scope": scope_of(hop_ip),
                }
            )
    elif singles:
        hops.append(
            {
                "ip": singles[0]["ip"],
                "label": singles[0]["header"],
                "role": "claim",
                "scope": scope_of(singles[0]["ip"]),
            }
        )
    if peer:
        hops.append({"ip": peer, "label": "tcp peer", "role": "peer", "scope": scope_of(peer)})
    hops.append({"ip": None, "label": "this server", "role": "server", "scope": None})

    marked = False
    for hop in hops:
        hop["resolved"] = not marked and bool(resolved_ip) and hop["ip"] == resolved_ip
        marked = marked or hop["resolved"]
    return hops


def _is_chain(header: str | None) -> bool:
    """Chain headers hold a comma-separated list, so a snippet has to index into it."""
    return header in CHAIN_HEADERS or header == "forwarded"


def _advice(
    edge: dict[str, Any] | None,
    forwarded: bool,
    peer_scope: str | None,
    chain: dict[str, Any] | None,
    singles: list[dict[str, str]],
) -> Json:
    if edge:
        header = (edge.get("headers") or (None,))[0] or (
            chain["header"] if chain else "x-forwarded-for"
        )
        return {
            "trusted_hops": edge["trusted_hops"],
            "header": header,
            "pick": edge.get("pick", "leftmost") if _is_chain(header) else None,
            "note": (
                f"Read only this header at the origin and drop the others, "
                f"so nothing but {edge['name']} can set it."
            ),
        }
    if forwarded and peer_scope == "private":
        fallback = singles[0]["header"] if singles else "x-real-ip"
        header = chain["header"] if chain else fallback
        return {
            "trusted_hops": 1,
            "header": header,
            "pick": "leftmost" if _is_chain(header) else None,
            "note": (
                "Set your reverse proxy to overwrite this header rather than append to it, "
                "then trust exactly one hop."
            ),
        }
    return {
        "trusted_hops": 0,
        "header": None,
        "pick": None,
        "note": "Nothing is proxying this server. Trust no hops and read the socket.",
    }


def resolve(headers: Headers, peer_address: str) -> Json:
    peer = normalize_ip(peer_address)
    peer_scope = scope_of(peer)
    chain = chain_from(headers)
    edge = detect_edge(headers)
    singles = _single_ip_candidates(headers)
    forwarded = bool(chain) or bool(singles)

    ip: str | None = None
    source: str | None = None
    confidence = "low"
    reason = ""

    if edge:
        # A recognized edge stamped this request. Use its documented position.
        found = _from_edge(edge, singles, chain)
        if found:
            ip, source = found
            confidence = "high"
            reason = (
                f"{edge['name']} is in front of this server, so the address it stamps "
                f"on the request is the one to use."
            )

    if not ip and not forwarded and peer:
        ip, source = peer, "socket peer"
        confidence = "high"
        reason = (
            "No proxy headers arrived, so the machine that opened the TCP connection is the client."
        )

    if not ip and forwarded:
        claim = _first_claim(singles, chain)
        if claim:
            ip, source = claim
            if peer_scope == "private":
                confidence = "medium"
                reason = (
                    "The connection came from a private address, so something local is proxying. "
                    "The forwarded header is believable, but nothing here proves it."
                )
            else:
                confidence = "low"
                reason = (
                    "Forwarding headers arrived over a direct connection from an unrecognized "
                    "public host. Any client can send these, so this is a claim rather than a fact."
                )

    if not ip and peer:
        ip, source = peer, "socket peer"
        confidence = "high"
        reason = "Nothing usable was forwarded, so this is the TCP peer address."

    return {
        "ip": ip,
        "version": ip_version(ip) if ip else None,
        "scope": scope_of(ip),
        "source": source,
        "confidence": confidence,
        "reason": reason,
        "spoofable": source != "socket peer",
        "edge": {"id": edge["id"], "name": edge["name"], "evidence": edge["evidence"]}
        if edge
        else None,
        "peer": peer,
        "hops": _build_hops(chain, singles, peer, ip),
        "advice": _advice(edge, forwarded, peer_scope, chain, singles),
        "chain": {"header": chain["header"], "ips": chain["ips"]} if chain else None,
    }


def trusted_hop_walk(headers: Headers, peer_address: str) -> str | None:
    """
    What Express's `req.ip` would be under `trust proxy: (addr) => isNonPublic(addr)`.

    Walk right to left starting at the socket peer, stepping over every hop that
    sits in a non-public range, and stop at the first address we did not put there.
    """
    chain = chain_from(headers)
    addresses = [normalize_ip(peer_address)] + list(reversed(chain["ips"] if chain else []))
    for address in addresses:
        if address and not is_non_public(address):
            return address
    return next((a for a in reversed(addresses) if a), None)


def candidate_table(headers: Headers, peer_address: str) -> list[Json]:
    rows: list[Json] = []

    def push(source: str, raw: str) -> None:
        ip = normalize_ip(raw)
        rows.append(
            {
                "source": source,
                "raw": raw.strip(),
                "ip": ip,
                "scope": scope_of(ip),
                "valid": bool(ip),
            }
        )

    for name in CHAIN_HEADERS:
        for value in header_values(headers, name):
            for part in value.split(","):
                push(name, part)
    for value in header_values(headers, "forwarded"):
        for part in parse_forwarded(value):
            push("forwarded", part)
    for name in SINGLE_IP_HEADERS:
        for value in header_values(headers, name):
            push(name, value)
    walked = trusted_hop_walk(headers, peer_address)
    if walked:
        push("trusted-hop walk", walked)
    if peer_address:
        push("socket peer", peer_address)
    return rows


# UI

PAGE = """<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Client address</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root{
                --bg:#DCDFE3; --surface:#FAFAFA; --ink:#0E1116; --muted:#656E78;
                --line:#C3C8CE; --signal:#1F3FD8; --warn:#A05505; --ok:#136B45; --bad:#8C1D18;
                --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
                --sans:"Archivo",system-ui,-apple-system,sans-serif;
            }
            *{box-sizing:border-box}
            body{
                margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
                -webkit-font-smoothing:antialiased;line-height:1.5;
                padding:clamp(22px,6vw,72px) clamp(18px,5vw,48px);
            }
            main{max-width:740px;margin:0 auto}
            .eyebrow{
                font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;
                color:var(--muted);margin:0 0 10px;
            }
            .addr{
                font-family:var(--mono);font-weight:700;
                font-size:clamp(28px,8vw,60px);letter-spacing:-.02em;
                margin:0;word-break:break-all;line-height:1.05;
            }
            .addr .dot{color:var(--muted);font-weight:400}
            .verdict{margin:14px 0 0;max-width:58ch;color:var(--muted);font-size:15px}
            .verdict.strong{color:var(--ink)}
            .tags{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0 0}
            .tag{
                font-family:var(--mono);font-size:11px;padding:4px 9px;
                border:1px solid var(--line);border-radius:2px;background:var(--surface);
                color:var(--muted);
            }
            .tag[data-level=high]{color:var(--ok);border-color:currentColor}
            .tag[data-level=medium]{color:var(--warn);border-color:currentColor}
            .tag[data-level=low]{color:var(--bad);border-color:currentColor}

            .wire{margin:14px 0 0;position:relative}
            .wire::before{content:"";position:absolute;left:7px;top:10px;bottom:14px;width:1px;background:var(--line)}
            .hop{position:relative;padding:0 0 20px 34px}
            .hop:last-child{padding-bottom:0}
            .node{
                position:absolute;left:0;top:4px;width:15px;height:15px;border-radius:50%;
                border:1px solid var(--muted);background:var(--bg);
            }
            .hop[data-role=server] .node{border-style:dashed}
            .hop[data-resolved=true] .node{
                border-color:var(--signal);background:var(--signal);
                box-shadow:0 0 0 4px rgba(31,63,216,.16);
            }
            .hop-ip{font-family:var(--mono);font-size:14px;word-break:break-all}
            .hop[data-resolved=true] .hop-ip{color:var(--signal);font-weight:700}
            .hop-label{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-top:3px}
            .hop-label em{font-style:normal;color:var(--warn)}

            section{margin:42px 0 0;border-top:1px solid var(--line);padding-top:22px}
            pre{
                font-family:var(--mono);font-size:13px;background:var(--surface);
                border:1px solid var(--line);border-radius:3px;padding:12px 14px;
                overflow-x:auto;margin:14px 0 0;
            }
            table{width:100%;border-collapse:collapse;font-size:13px;margin-top:14px}
            th{
                text-align:left;font-size:10px;letter-spacing:.14em;text-transform:uppercase;
                color:var(--muted);font-weight:700;padding:0 10px 8px 0;border-bottom:1px solid var(--line);
            }
            td{padding:8px 10px;border-bottom:1px solid var(--line);font-family:var(--mono);word-break:break-all;vertical-align:top}
            td:first-child,th:first-child{padding-left:0}
            td.dim{color:var(--muted)}
            details summary{
                cursor:pointer;font-size:11px;font-weight:700;letter-spacing:.18em;
                text-transform:uppercase;color:var(--muted);
            }
            summary:focus-visible,button:focus-visible{outline:2px solid var(--signal);outline-offset:3px}
            button{
                font-family:var(--sans);font-size:12px;font-weight:500;cursor:pointer;
                background:var(--surface);border:1px solid var(--line);border-radius:2px;
                padding:7px 13px;color:var(--ink);
            }
            button:hover{border-color:var(--ink)}
            .row{display:flex;gap:8px;margin-top:28px;flex-wrap:wrap}
            .tabs{display:flex;flex-wrap:wrap;gap:0;margin:18px 0 0;border-bottom:1px solid var(--line)}
            .tab{
                font-family:var(--mono);font-size:11px;letter-spacing:.06em;
                background:none;border:none;border-bottom:2px solid transparent;
                border-radius:0;padding:7px 11px;color:var(--muted);
            }
            .tab:hover{color:var(--ink)}
            .tab[aria-selected=true]{color:var(--signal);border-bottom-color:var(--signal);font-weight:700}
            .tabs + pre{margin-top:0;border-top:none;border-radius:0 0 3px 3px}
            .loading{color:var(--muted);font-family:var(--mono);font-size:14px}
            @media (prefers-reduced-motion:no-preference){
                .hop{animation:in .3s ease both}
                @keyframes in{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
            }
        </style>
    </head>
    <body>
        <main id="app"><p class="loading">Resolving&hellip;</p></main>
        <script type="module">
            function esc(s){
                return String(s == null ? "" : s).replace(/[&<>"']/g, function(c){
                    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
                });
            }
            function splitAddr(ip){
                if(!ip) return "unknown";
                var sep = ip.indexOf(":") > -1 ? ":" : ".";
                return ip.split(sep).map(esc).join('<span class="dot">' + sep + "</span>");
            }

            /**
             * Same advice, written out for whatever is terminating the connection.
             * Each builder gets the header to trust (null when nothing is proxying),
             * how many hops sit in front, and which entry to take when the header
             * carries a list rather than one address.
             */
            var PICK_WORDS = {
                leftmost: "the leftmost entry",
                rightmost: "the rightmost entry",
                second_from_right: "the entry second from the right"
            };

            /** Comment that goes above a chain snippet, so the indexing is not a mystery. */
            function chainNote(hdr, pick, marker){
                return [marker + " " + hdr + " holds a list, take " + (PICK_WORDS[pick] || "the leftmost entry")];
            }

            /**
             * RFC 7239 elements look like for="[2001:db8::1]:8080", which needs a real
             * parser rather than a one-liner. Point people at the header their stack
             * can actually read instead of handing them a broken split.
             */
            var FORWARDED_NOTE = [
                "forwarded is RFC 7239, and almost nothing parses it out of the box",
                "have the proxy set x-forwarded-for as well, then read that"
            ];

            var SNIPPETS = [
                { id: "python", label: "Python", marker: "#", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        "# http.server",
                        "ip = self.client_address[0]",
                        "",
                        "# flask",
                        "ip = request.remote_addr"
                    ];
                    if(pick){
                        var at = { leftmost: "[0]", rightmost: "[-1]", second_from_right: "[-2]" }[pick];
                        var enough = pick === "second_from_right" ? "len(chain) >= 2" : "chain";
                        return chainNote(hdr, pick, "#").concat([
                            'raw = self.headers.get("' + hdr + '", "")',
                            'chain = [p.strip() for p in raw.split(",") if p.strip()]',
                            "ip = chain" + at + " if " + enough + " else self.client_address[0]"
                        ]);
                    }
                    return [
                        "# http.server",
                        'ip = self.headers.get("' + hdr + '", self.client_address[0])',
                        "",
                        "# flask",
                        'ip = request.headers.get("' + hdr + '", request.remote_addr)',
                        "",
                        "# fastapi / starlette",
                        'ip = request.headers.get("' + hdr + '") or request.client.host'
                    ];
                }},
                { id: "node", label: "Node", marker: "//", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        'app.set("trust proxy", false)',
                        "const ip = req.socket.remoteAddress"
                    ];
                    var head = ['app.set("trust proxy", ' + hops + ")", ""];
                    if(pick){
                        var at = { leftmost: "[0]", rightmost: ".at(-1)", second_from_right: ".at(-2)" }[pick];
                        return head.concat(chainNote(hdr, pick, "//")).concat([
                            'const raw = String(req.headers["' + hdr + '"] ?? "")',
                            'const chain = raw.split(",").map(s => s.trim()).filter(Boolean)',
                            "const ip = chain" + at + " ?? req.socket.remoteAddress"
                        ]);
                    }
                    return head.concat([
                        "// read the one header the edge controls, ignore the rest",
                        'const ip = req.headers["' + hdr + '"] ?? req.socket.remoteAddress'
                    ]);
                }},
                { id: "go", label: "Go", marker: "//", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        "ip, _, _ := net.SplitHostPort(r.RemoteAddr)"
                    ];
                    if(pick){
                        var at = {
                            leftmost: "parts[0]",
                            rightmost: "parts[len(parts)-1]",
                            second_from_right: "parts[len(parts)-2]"
                        }[pick];
                        var lines = chainNote(hdr, pick, "//").concat([
                            'parts := strings.Split(r.Header.Get("' + hdr + '"), ",")'
                        ]);
                        if(pick === "second_from_right"){
                            return lines.concat([
                                "ip, _, _ := net.SplitHostPort(r.RemoteAddr)",
                                "if len(parts) >= 2 {",
                                "    ip = strings.TrimSpace(" + at + ")",
                                "}"
                            ]);
                        }
                        return lines.concat(["ip := strings.TrimSpace(" + at + ")"]);
                    }
                    return [
                        'ip := r.Header.Get("' + hdr + '")',
                        'if ip == "" {',
                        "    ip, _, _ = net.SplitHostPort(r.RemoteAddr)",
                        "}"
                    ];
                }},
                { id: "rust", label: "Rust", marker: "//", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        "// axum: ConnectInfo<SocketAddr> extractor",
                        "let ip = addr.ip().to_string();"
                    ];
                    if(pick){
                        var at = {
                            leftmost: ".next()",
                            rightmost: ".rev().nth(0)",
                            second_from_right: ".rev().nth(1)"
                        }[pick];
                        return chainNote(hdr, pick, "//").concat([
                            'let raw = headers.get("' + hdr + '")',
                            "    .and_then(|v| v.to_str().ok())",
                            '    .unwrap_or("");',
                            "let ip = raw.split(',').map(str::trim)" + at,
                            "    .map(str::to_owned)",
                            "    .unwrap_or_else(|| addr.ip().to_string());"
                        ]);
                    }
                    return [
                        "// axum: HeaderMap + ConnectInfo<SocketAddr> extractors",
                        "let ip = headers",
                        '    .get("' + hdr + '")',
                        "    .and_then(|v| v.to_str().ok())",
                        "    .map(str::to_owned)",
                        "    .unwrap_or_else(|| addr.ip().to_string());"
                    ];
                }},
                { id: "php", label: "PHP", marker: "//", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        "$ip = $_SERVER['REMOTE_ADDR'];"
                    ];
                    var key = "HTTP_" + hdr.toUpperCase().replace(/-/g, "_");
                    if(pick){
                        var at = {
                            leftmost: "$chain[0] ??",
                            rightmost: "end($chain) ?:",
                            second_from_right: "$chain[count($chain) - 2] ??"
                        }[pick];
                        return chainNote(hdr, pick, "//").concat([
                            "$raw = $_SERVER['" + key + "'] ?? '';",
                            "$chain = array_values(array_filter(array_map('trim', explode(',', $raw))));",
                            "$ip = " + at + " $_SERVER['REMOTE_ADDR'];"
                        ]);
                    }
                    return [
                        "$ip = $_SERVER['" + key + "'] ?? $_SERVER['REMOTE_ADDR'];"
                    ];
                }},
                { id: "nginx", label: "nginx", marker: "#", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        "# nothing in front, $remote_addr is already the client",
                        "# leave real_ip_header unset"
                    ];
                    var lines = [
                        "# replace with the edge's published ranges, never 0.0.0.0/0",
                        "set_real_ip_from 0.0.0.0/0;",
                        "real_ip_header " + hdr + ";"
                    ];
                    if(pick === "rightmost" || !pick) lines.push("real_ip_recursive off;");
                    else lines.push(
                        "# recursive walks right to left past every trusted range above",
                        "real_ip_recursive on;"
                    );
                    return lines;
                }},
                { id: "caddy", label: "Caddy", marker: "#", build: function(hdr, hops, pick){
                    if(!hdr) return [
                        "# nothing in front, no trusted_proxies needed"
                    ];
                    var lines = [
                        "servers {",
                        "    # replace with the edge's published ranges",
                        "    trusted_proxies static 0.0.0.0/0",
                        "    client_ip_headers " + hdr
                    ];
                    if(pick) lines.push("    # caddy walks the list right to left, skipping trusted ranges");
                    lines.push("}");
                    return lines;
                }}
            ];

            var activeSnippet = SNIPPETS[0].id;

            function snippetBlock(advice){
                var chosen = SNIPPETS.filter(function(s){ return s.id === activeSnippet; })[0] || SNIPPETS[0];
                var h = '<div class="tabs" role="tablist">';
                SNIPPETS.forEach(function(s){
                    h += '<button class="tab" role="tab" data-snippet="' + s.id +
                        '" aria-selected="' + (s.id === chosen.id ? "true" : "false") + '">' +
                        esc(s.label) + "</button>";
                });
                var hdr = advice.header;
                var lead = [];
                if(hdr === "forwarded"){
                    lead = FORWARDED_NOTE.map(function(line){ return chosen.marker + " " + line; });
                    hdr = "x-forwarded-for";
                }
                var body = lead.concat(chosen.build(hdr, advice.trusted_hops, advice.pick));
                h += "</div><pre>" + esc(body.join("\\n")) + "</pre>";
                return h;
            }

            function render(d){
                var h = "";
                h += '<p class="eyebrow">Your address, as this server sees it</p>';
                h += '<h1 class="addr">' + splitAddr(d.ip) + "</h1>";
                h += '<p class="verdict strong">' + esc(d.reason) + "</p>";

                h += '<div class="tags">';
                h += '<span class="tag" data-level="' + esc(d.confidence) + '">' + esc(d.confidence) + " confidence</span>";
                if(d.version) h += '<span class="tag">' + esc(d.version) + "</span>";
                if(d.scope) h += '<span class="tag">' + esc(d.scope) + "</span>";
                h += '<span class="tag">from ' + esc(d.source) + "</span>";
                if(d.edge) h += '<span class="tag">' + esc(d.edge.name) + "</span>";
                h += '<span class="tag">' + (d.spoofable ? "spoofable" : "verified at socket") + "</span>";
                h += "</div>";

                h += '<section><p class="eyebrow">Request path</p><div class="wire">';
                d.hops.forEach(function(hop){
                    h += '<div class="hop" data-role="' + esc(hop.role) + '" data-resolved="' + (hop.resolved ? "true" : "false") + '">';
                    h += '<span class="node"></span>';
                    h += '<div class="hop-ip">' + (hop.ip ? esc(hop.ip) : "&mdash;") + "</div>";
                    h += '<div class="hop-label">' + esc(hop.label);
                    if(hop.scope === "private") h += " &middot; <em>private range</em>";
                    if(hop.resolved) h += " &middot; picked";
                    h += "</div></div>";
                });
                h += "</div></section>";

                h += '<section><p class="eyebrow">Lock it down</p>';
                h += '<p class="verdict">' + esc(d.advice.note) + "</p>";
                h += snippetBlock(d.advice);
                h += "</section>";

                if(d.candidates && d.candidates.length){
                    h += "<section><details><summary>All " + d.candidates.length + " sources seen</summary>";
                    h += "<table><thead><tr><th>Source</th><th>Value</th><th>Scope</th></tr></thead><tbody>";
                    d.candidates.forEach(function(c){
                        h += "<tr><td>" + esc(c.source) + "</td><td>" + esc(c.ip || c.raw) +
                        '</td><td class="dim">' + esc(c.valid ? c.scope : "unparseable") + "</td></tr>";
                    });
                    h += "</tbody></table></details></section>";
                }

                h += '<div class="row"><button id="copy">Copy address</button><button id="again">Check again</button></div>';
                document.getElementById("app").innerHTML = h;

                var copy = document.getElementById("copy");
                copy.addEventListener("click", function(){
                    navigator.clipboard.writeText(d.ip || "").then(function(){
                        copy.textContent = "Copied";
                        setTimeout(function(){ copy.textContent = "Copy address"; }, 1400);
                    });
                });
                document.getElementById("again").addEventListener("click", load);

                Array.prototype.forEach.call(document.querySelectorAll(".tab"), function(tab){
                    tab.addEventListener("click", function(){
                        activeSnippet = tab.getAttribute("data-snippet");
                        render(d);  // cheap enough, and it keeps one code path
                    });
                });
            }

            function load(){
                fetch("/json?full=1", { headers: { Accept: "application/json" }, cache: "no-store" })
                    .then(function(r){ return r.json(); })
                    .then(render)
                    .catch(function(){
                        document.getElementById("app").innerHTML =
                            '<p class="eyebrow">No answer from the server</p>' +
                            '<p class="verdict strong">The page loaded but /json did not respond. Check the process is still running, then reload.</p>';
                    });
            }
            load();
        </script>
    </body>
</html>"""


# Routes


class Handler(BaseHTTPRequestHandler):
    server_version: str = f"ip-server/{VERSION}"
    sys_version: str = ""
    protocol_version: str = "HTTP/1.1"

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        headers = collect_headers(self.headers)
        peer_address = self.client_address[0]
        result = resolve(headers, peer_address)

        if url.path == "/ip":
            self._send_text(f"{result['ip'] or 'unknown'}\n")
        elif url.path == "/json":
            body = dict(result)
            if parse_qs(url.query).get("full"):
                body["candidates"] = candidate_table(headers, peer_address)
            self._send_json(body)
        elif url.path == "/debug":
            self._send_json(
                {
                    **result,
                    "candidates": candidate_table(headers, peer_address),
                    "headers": {
                        name: values[0] if len(values) == 1 else values
                        for name, values in headers.items()
                    },
                }
            )
        elif url.path == "/":
            accept = ",".join(header_values(headers, "accept"))
            if "text/html" in accept:
                self._send_body(PAGE.encode(), "text/html; charset=utf-8")
            elif "application/json" in accept:
                self._send_json(result)
            else:
                self._send_text(f"{result['ip'] or 'unknown'}\n")
        else:
            self._send_json({"error": "not found", "routes": ["/", "/ip", "/json", "/debug"]}, 404)

    def do_HEAD(self) -> None:
        self.do_GET()

    def _send_body(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_text(self, text: str, status: int = 200) -> None:
        self._send_body(text.encode(), "text/plain; charset=utf-8", status)

    def _send_json(self, payload: Json, status: int = 200) -> None:
        body = json.dumps(payload, indent=2, sort_keys=False).encode()
        self._send_body(body, "application/json; charset=utf-8", status)

    def log_message(self, fmt: str, *args: object) -> None:
        """Quiet by default; the banner is the only expected output."""
        if os.environ.get("IP_SERVER_LOG"):
            sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")


# Startup banner

_USE_COLOR = (
    sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
)


def paint(code: str) -> Callable[[object], str]:
    def apply(value: object) -> str:
        return f"\x1b[{code}m{value}\x1b[0m" if _USE_COLOR else str(value)

    return apply


bold = paint("1")
dim = paint("2")
green = paint("32")
yellow = paint("33")
cyan_bold = paint("1;36")


def lan_address() -> str | None:
    """First outward-facing IPv4 on this host, so the banner can show a LAN URL."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("8.8.8.8", 53))  # no packets sent, just picks a route
        except OSError:
            return None
        address = probe.getsockname()[0]
    return address if address and not address.startswith("127.") else None


def banner(port: int, elapsed_ms: int) -> None:
    def row(label: str, value: str) -> str:
        return f"   {dim('-')} {label:<14}{value}"

    lines = [
        "",
        f"   {cyan_bold('▲')} {bold('ip-server')} {dim(VERSION)}",
        row("Local:", f"http://localhost:{port}"),
    ]
    lan = lan_address()
    if lan:
        lines.append(row("Network:", f"http://{lan}:{port}"))
    lines.append(row("Routes:", dim("/  /ip  /json  /debug")))
    lines.append(row("Trust proxy:", dim("auto, detected per request")))
    lines += ["", f" {green('✓')} Ready in {elapsed_ms}ms", ""]

    print("\n".join(lines), flush=True)


# Listen


class DualStackServer(ThreadingHTTPServer):
    """Accepts IPv4 and IPv6 on one socket, the way node's app.listen() does."""

    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class IPv4Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _open(host: str, port: int) -> ThreadingHTTPServer:
    """One bind attempt, dual-stack where the host means "everything"."""
    if host in ("", "::", "0.0.0.0"):
        try:
            return DualStackServer(("::", port), Handler)
        except OSError as exc:
            if exc.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.EPROTONOSUPPORT):
                raise
            return IPv4Server(("0.0.0.0", port), Handler)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    server_class = DualStackServer if family == socket.AF_INET6 else IPv4Server
    return server_class((host, port), Handler)


def bind(host: str, port: int, attempts: int = 10) -> ThreadingHTTPServer:
    """Bind to port, stepping up if it is taken. Raises OSError if it never lands."""
    for offset in range(attempts + 1):
        try:
            return _open(host, port + offset)
        except OSError as exc:
            if exc.errno == errno.EACCES:
                print(
                    f" {yellow('⚠')} Port {port + offset} needs elevated privileges. "
                    f"Pick a port above 1024 with PORT=8080.",
                    file=sys.stderr,
                    flush=True,
                )
                raise
            if exc.errno != errno.EADDRINUSE or offset == attempts:
                raise
            print(
                f" {yellow('⚠')} Port {port + offset} is in use, "
                f"trying {port + offset + 1} instead.",
                flush=True,
            )
    raise OSError(errno.EADDRINUSE, "no free port found")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ip-server",
        description="Resolve the client IP behind whatever proxy or CDN is in front of this server.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "::"),
        help="interface to bind, :: means every IPv4 and IPv6 one (default: %(default)s, env HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "3000")),
        help="port to bind, steps up if taken (default: %(default)s, env PORT)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started_at = monotonic()

    try:
        httpd = bind(args.host, args.port)
    except OSError as exc:
        print(f" {yellow('⚠')} {exc.strerror or exc}", file=sys.stderr, flush=True)
        return 1

    banner(httpd.server_address[1], round((monotonic() - started_at) * 1000))

    def shutdown(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, shutdown)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
