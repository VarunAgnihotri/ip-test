/**
 * Figures out what is in front of it, resolves the client IP accordingly,
 * and shows its work.
 *
 *   npm i express
 *   node server.js
 *
 *   GET /        HTML in a browser, plain text to curl (Accept negotiated)
 *   GET /ip      plain text
 *   GET /json    always JSON  (add ?full=1 for every candidate)
 *   GET /debug   everything, including raw headers
 */

const express = require("express");
const net = require("net");
const os = require("os");

const VERSION = "1.0.0";

const app = express();
app.disable("x-powered-by");

// Address normalization + scope
function normalizeIp(input) {
    if (typeof input !== "string") return null;
    let ip = input.trim().replace(/^"+|"+$/g, "");
    if (!ip) return null;

    const bracketed = ip.match(/^\[([^\]]+)\](?::\d+)?$/); // [2001:db8::1]:443
    if (bracketed) ip = bracketed[1];

    if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.split(":")[0]; // 1.2.3.4:443

    // Bare IPv6 with a trailing port (CloudFront does this): 2001:db8::1:52011
    if (!net.isIP(ip) && ip.includes(":")) {
        const head = ip.slice(0, ip.lastIndexOf(":"));
        if (net.isIP(head)) ip = head;
    }

    const pct = ip.indexOf("%"); // fe80::1%eth0
    if (pct !== -1) ip = ip.slice(0, pct);

    const mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    if (mapped) ip = mapped[1];

    ip = ip.toLowerCase();
    return net.isIP(ip) ? ip : null;
}

const ipv4ToLong = (ip) =>
    ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;

function inV4Cidr(ip, cidr) {
    const [base, bits] = cidr.split("/");
    const mask = bits === "0" ? 0 : (~0 << (32 - Number(bits))) >>> 0;
    return (ipv4ToLong(ip) & mask) === (ipv4ToLong(base) & mask);
}

const V4_NON_PUBLIC = [
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
];

function isNonPublic(ip) {
    const v = net.isIP(ip);
    if (v === 4) return V4_NON_PUBLIC.some((c) => inV4Cidr(ip, c));
    if (v === 6) {
        if (ip === "::1" || ip === "::") return true;
        if (/^f[cd][0-9a-f]{2}:/.test(ip)) return true; // fc00::/7 ULA
        if (/^fe[89ab][0-9a-f]:/.test(ip)) return true; // fe80::/10 link-local
        if (/^ff[0-9a-f]{2}:/.test(ip)) return true; // multicast
        if (/^2001:0?db8:/.test(ip)) return true; // documentation
        return false;
    }
    return true;
}

const scopeOf = (ip) => (ip ? (isNonPublic(ip) ? "private" : "public") : null);

// Header inventory
const SINGLE_IP_HEADERS = [
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
];

const CHAIN_HEADERS = [
    "x-forwarded-for",
    "x-original-forwarded-for",
    "x-forwarded",
    "forwarded-for",
    "x-http-forwarded-for",
    "x-vercel-proxied-for",
];

function headerValues(req, name) {
    const raw = req.headers[name];
    if (raw === undefined) return [];
    return Array.isArray(raw) ? raw : [raw];
}

/** RFC 7239: Forwarded: for=1.2.3.4;proto=https, for="[2001:db8::1]:8080" */
function parseForwarded(value) {
    if (!value) return [];
    return value
        .split(",")
        .map((el) => {
            const m = el.match(/for\s*=\s*("[^"]*"|[^;,\s]+)/i);
            return m ? normalizeIp(m[1]) : null;
        })
        .filter(Boolean);
}

function chainFrom(req) {
    for (const h of CHAIN_HEADERS) {
        const values = headerValues(req, h);
        if (!values.length) continue;
        const ips = values
            .join(",")
            .split(",")
            .map(normalizeIp)
            .filter(Boolean);
        if (ips.length) return { header: h, ips };
    }
    const fwd = headerValues(req, "forwarded").flatMap(parseForwarded);
    if (fwd.length) return { header: "forwarded", ips: fwd };
    return null;
}

/**
 * Edge detection
 *
 * Each edge is identified by a *fingerprint* header it stamps on every
 * request, not by the IP header itself. Once we know the edge, we know
 * exactly which header (or which position in the XFF chain) holds the client.
 *
 * pick:
 *   leftmost         first entry in the chain
 *   rightmost        last entry, because the edge appended the real peer
 *   secondFromRight  edge appended two entries (client, own LB address)
 */
const EDGES = [
    {
        id: "cloudflare",
        name: "Cloudflare",
        fingerprint: ["cf-ray"],
        headers: ["cf-connecting-ip", "true-client-ip"],
        trustProxy: "cloudflare",
    },
    {
        id: "cloudfront",
        name: "AWS CloudFront",
        fingerprint: ["x-amz-cf-id"],
        headers: ["cloudfront-viewer-address"],
        pick: "leftmost",
        trustProxy: 1,
    },
    {
        id: "aws-elb",
        name: "AWS ALB / ELB",
        fingerprint: ["x-amzn-trace-id"],
        pick: "leftmost",
        trustProxy: 1,
    },
    {
        id: "fastly",
        name: "Fastly",
        fingerprint: ["fastly-client-ip", "x-served-by"],
        headers: ["fastly-client-ip"],
        trustProxy: 1,
    },
    {
        id: "akamai",
        name: "Akamai",
        fingerprint: ["akamai-origin-hop", "x-akamai-request-id"],
        headers: ["true-client-ip"],
        trustProxy: 1,
    },
    {
        id: "vercel",
        name: "Vercel",
        fingerprint: ["x-vercel-id", "x-vercel-deployment-url"],
        headers: ["x-vercel-forwarded-for", "x-real-ip"],
        trustProxy: 1,
    },
    {
        id: "netlify",
        name: "Netlify",
        fingerprint: ["x-nf-request-id"],
        headers: ["x-nf-client-connection-ip"],
        trustProxy: 1,
    },
    {
        id: "fly",
        name: "Fly.io",
        fingerprint: ["fly-request-id"],
        headers: ["fly-client-ip"],
        trustProxy: 1,
    },
    {
        id: "azure-fd",
        name: "Azure Front Door",
        fingerprint: ["x-azure-ref"],
        headers: ["x-azure-clientip", "x-azure-socketip"],
        trustProxy: 1,
    },
    {
        id: "gclb",
        name: "Google Cloud Load Balancer",
        fingerprint: (h) => /\bgoogle\b/i.test(h["via"] || ""),
        pick: "secondFromRight",
        trustProxy: 2,
    },
    {
        id: "appengine",
        name: "Google App Engine",
        fingerprint: ["x-appengine-city", "x-appengine-request-log-id"],
        headers: ["x-appengine-user-ip"],
        trustProxy: 1,
    },
    {
        id: "heroku",
        name: "Heroku Router",
        fingerprint: (h) =>
            /vegur/i.test(h["via"] || "") || "x-request-start" in h,
        pick: "rightmost",
        trustProxy: 1,
    },
    {
        id: "digitalocean",
        name: "DigitalOcean App Platform",
        fingerprint: ["do-connecting-ip"],
        headers: ["do-connecting-ip"],
        trustProxy: 1,
    },
    {
        id: "oxygen",
        name: "Shopify Oxygen",
        fingerprint: ["oxygen-buyer-ip"],
        headers: ["oxygen-buyer-ip"],
        trustProxy: 1,
    },
    {
        id: "render",
        name: "Render",
        fingerprint: ["render-proxy-ttl", "rndr-id"],
        headers: ["true-client-ip", "x-real-ip"],
        trustProxy: 1,
    },
    {
        id: "envoy",
        name: "Envoy / Istio",
        fingerprint: ["x-envoy-external-address", "x-envoy-attempt-count"],
        headers: ["x-envoy-external-address"],
        trustProxy: 1,
    },
];

function detectEdge(headers) {
    for (const edge of EDGES) {
        const evidence = [];
        if (typeof edge.fingerprint === "function") {
            if (edge.fingerprint(headers)) evidence.push("via");
        } else {
            for (const h of edge.fingerprint)
                if (h in headers) evidence.push(h);
        }
        if (evidence.length) return { ...edge, evidence };
    }
    return null;
}

function pickFromChain(ips, rule) {
    if (!ips.length) return null;
    if (rule === "rightmost") return ips[ips.length - 1];
    if (rule === "secondFromRight") return ips[ips.length - 2] ?? ips[0];
    return ips.find((ip) => !isNonPublic(ip)) ?? ips[0]; // leftmost public
}

/** Chain headers hold a comma-separated list, so a snippet has to index into it. */
const isChain = (header) =>
    CHAIN_HEADERS.includes(header) || header === "forwarded";

/**
 * What to read at the origin, and which entry of it.
 *
 * pick tells a reader which element of a chain header holds the client, and is
 * null whenever the header carries a single address.
 */
function adviceFor(edge, forwarded, peerScope, chain, singles) {
    if (edge) {
        const header =
            edge.headers?.[0] ?? chain?.header ?? "x-forwarded-for";
        return {
            trustProxy: edge.trustProxy,
            header,
            pick: isChain(header) ? (edge.pick ?? "leftmost") : null,
            note: `Read only this header at the origin and drop the others, so nothing but ${edge.name} can set it.`,
        };
    }
    if (forwarded && peerScope === "private") {
        const header = chain?.header ?? singles[0]?.header ?? "x-real-ip";
        return {
            trustProxy: 1,
            header,
            pick: isChain(header) ? "leftmost" : null,
            note: "Set your reverse proxy to overwrite this header rather than append to it, then trust exactly one hop.",
        };
    }
    return {
        trustProxy: false,
        header: null,
        pick: null,
        note: "Nothing is proxying this server. Leave trust proxy off and read the socket.",
    };
}

// Resolution
function resolve(req) {
    const headers = req.headers;
    const peer = normalizeIp(
        req.socket?.remoteAddress ?? req.connection?.remoteAddress ?? "",
    );
    const peerScope = scopeOf(peer);
    const chain = chainFrom(req);
    const edge = detectEdge(headers);

    const singles = SINGLE_IP_HEADERS.map((h) => {
        const v = headerValues(req, h)[0];
        const ip = v === undefined ? null : normalizeIp(v);
        return ip ? { header: h, ip, raw: String(v).trim() } : null;
    }).filter(Boolean);

    const forwarded = Boolean(chain) || singles.length > 0;

    let ip = null;
    let source = null;
    let confidence = "low";
    let reason = "";

    if (edge) {
        // A recognized edge stamped this request. Use its documented position.
        for (const h of edge.headers ?? []) {
            const hit = singles.find((s) => s.header === h);
            if (hit) {
                ip = hit.ip;
                source = h;
                break;
            }
        }
        if (!ip && chain) {
            ip = pickFromChain(chain.ips, edge.pick ?? "leftmost");
            source = chain.header + (edge.pick ? ` (${edge.pick})` : "");
        }
        if (ip) {
            confidence = "high";
            reason = `${edge.name} is in front of this server, so the address it stamps on the request is the one to use.`;
        }
    }

    if (!ip && !forwarded && peer) {
        ip = peer;
        source = "socket.remoteAddress";
        confidence = "high";
        reason =
            "No proxy headers arrived, so the machine that opened the TCP connection is the client.";
    }

    if (!ip && forwarded && peerScope === "private") {
        if (chain) {
            ip = pickFromChain(chain.ips, "leftmost");
            source = chain.header;
        } else {
            ip = singles[0].ip;
            source = singles[0].header;
        }
        confidence = "medium";
        reason =
            "The connection came from a private address, so something local is proxying. " +
            "The forwarded header is believable, but nothing here proves it.";
    }

    if (!ip && forwarded) {
        if (chain) {
            ip = pickFromChain(chain.ips, "leftmost");
            source = chain.header;
        } else {
            ip = singles[0].ip;
            source = singles[0].header;
        }
        confidence = "low";
        reason =
            "Forwarding headers arrived over a direct connection from an unrecognized public host. " +
            "Any client can send these, so this is a claim rather than a fact.";
    }

    if (!ip && peer) {
        ip = peer;
        source = "socket.remoteAddress";
        confidence = "high";
        reason =
            "Nothing usable was forwarded, so this is the TCP peer address.";
    }

    // The visible request path.
    const hops = [];
    if (chain) {
        chain.ips.forEach((hopIp, i) => {
            hops.push({
                ip: hopIp,
                label: i === 0 ? "claimed origin" : `hop ${i}`,
                role: "claim",
                scope: scopeOf(hopIp),
            });
        });
    } else if (singles.length) {
        hops.push({
            ip: singles[0].ip,
            label: singles[0].header,
            role: "claim",
            scope: scopeOf(singles[0].ip),
        });
    }
    if (peer)
        hops.push({
            ip: peer,
            label: "tcp peer",
            role: "peer",
            scope: peerScope,
        });
    hops.push({ ip: null, label: "this server", role: "server", scope: null });

    let marked = false;
    for (const hop of hops) {
        hop.resolved =
            !marked && Boolean(ip) && hop.ip === ip && hop.role !== "server";
        if (hop.resolved) marked = true;
    }

    const advice = adviceFor(edge, forwarded, peerScope, chain, singles);

    return {
        ip,
        version: ip ? `IPv${net.isIP(ip)}` : null,
        scope: scopeOf(ip),
        source,
        confidence,
        reason,
        spoofable: source !== "socket.remoteAddress",
        edge: edge
            ? { id: edge.id, name: edge.name, evidence: edge.evidence }
            : null,
        peer,
        hops,
        advice,
        chain: chain ? { header: chain.header, ips: chain.ips } : null,
    };
}

function candidateTable(req) {
    const rows = [];
    const push = (source, raw) => {
        const ip = normalizeIp(raw);
        rows.push({
            source,
            raw: String(raw).trim(),
            ip,
            scope: scopeOf(ip),
            valid: Boolean(ip),
        });
    };
    for (const h of CHAIN_HEADERS)
        for (const v of headerValues(req, h))
            v.split(",").forEach((p) => push(h, p));
    for (const v of headerValues(req, "forwarded"))
        parseForwarded(v).forEach((p) => push("forwarded", p));
    for (const h of SINGLE_IP_HEADERS)
        for (const v of headerValues(req, h)) push(h, v);
    if (req.ip) push("req.ip", req.ip);
    const peer = req.socket?.remoteAddress;
    if (peer) push("socket.remoteAddress", peer);
    return rows;
}

// UI
const PAGE = `<!doctype html>
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
                // trustProxy can be false or a preset name; a snippet needs a number
                var hops = typeof advice.trustProxy === "number" ? advice.trustProxy : 1;
                // this file spells the rule secondFromRight, the builders key on snake_case
                var pick = advice.pick
                    ? advice.pick.replace(/([A-Z])/g, function(c){ return "_" + c.toLowerCase(); })
                    : null;
                var body = lead.concat(chosen.build(hdr, hops, pick));
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
</html>`;

// Routes

// Keeps req.ip sane behind local proxies. Our own resolver does the real work.
app.set("trust proxy", (addr) => isNonPublic(addr));

app.use((req, _res, next) => {
    req.result = resolve(req);
    next();
});

app.get("/ip", (req, res) =>
    res.type("text/plain").send(`${req.result.ip ?? "unknown"}\n`),
);

app.get("/json", (req, res) => {
    const body = { ...req.result };
    if (req.query.full) body.candidates = candidateTable(req);
    res.json(body);
});

app.get("/debug", (req, res) =>
    res.json({
        ...req.result,
        candidates: candidateTable(req),
        headers: req.headers,
    }),
);

app.get("/", (req, res) => {
    const accept = req.headers.accept ?? "";
    if (accept.includes("text/html")) res.type("html").send(PAGE);
    else if (accept.includes("application/json")) res.json(req.result);
    else res.type("text/plain").send(`${req.result.ip ?? "unknown"}\n`);
});

// Startup banner
const useColor =
    process.stdout.isTTY &&
    !("NO_COLOR" in process.env) &&
    process.env.TERM !== "dumb";
const paint = (code) => (s) =>
    useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s);
const bold = paint(1);
const dim = paint(2);
const green = paint(32);
const yellow = paint(33);
const cyanBold = paint("1;36");

/** First non-internal IPv4 on this host, so the banner can show a LAN URL. */
function lanAddress() {
    for (const list of Object.values(os.networkInterfaces())) {
        for (const iface of list ?? []) {
            const family =
                typeof iface.family === "string"
                    ? iface.family
                    : `IPv${iface.family}`;
            if (family === "IPv4" && !iface.internal) return iface.address;
        }
    }
    return null;
}

function banner(actualPort, elapsedMs) {
    const lan = lanAddress();
    const row = (label, value) => `   ${dim("-")} ${label.padEnd(14)}${value}`;

    const out = [
        "",
        `   ${cyanBold("▲")} ${bold("ip-server")} ${dim(VERSION)}`,
        row("Local:", `http://localhost:${actualPort}`),
    ];
    if (lan) out.push(row("Network:", `http://${lan}:${actualPort}`));
    out.push(row("Routes:", dim("/  /ip  /json  /debug")));
    out.push(row("Trust proxy:", dim("auto, detected per request")));
    out.push("", ` ${green("✓")} Ready in ${elapsedMs}ms`, "");

    console.log(out.join("\n"));
}

// Listen
const startedAt = Date.now();
const basePort = Number(process.env.PORT ?? 3000);

function listen(port, attempt = 0) {
    const server = app.listen(port);

    server.once("listening", () => {
        banner(server.address().port, Date.now() - startedAt);
    });

    server.once("error", (err) => {
        if (err.code === "EADDRINUSE" && attempt < 10) {
            console.log(
                ` ${yellow("⚠")} Port ${port} is in use, trying ${port + 1} instead.`,
            );
            listen(port + 1, attempt + 1);
            return;
        }
        if (err.code === "EACCES") {
            console.error(
                ` ${yellow("⚠")} Port ${port} needs elevated privileges. Pick a port above 1024 with PORT=8080.`,
            );
            process.exit(1);
        }
        console.error(` ${yellow("⚠")} ${err.message}`);
        process.exit(1);
    });

    for (const signal of ["SIGINT", "SIGTERM"]) {
        process.once(signal, () => {
            server.close(() => process.exit(0));
        });
    }
}

listen(basePort);
