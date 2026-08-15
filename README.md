# ip-test

A tiny Express server that figures out what is in front of it, resolves the client IP
accordingly, and shows its work.

This is the Express branch. A dependency-free Python port lives on `main`, and it is the
one to use if you want to run this without cloning — see [below](#the-python-port).

## Run it

```bash
bun install     # or: npm install
npm start       # or: node server.js
```

Express 5 is the only dependency.

## Options

| Env    | Default | What it does                                 |
| ------ | ------- | -------------------------------------------- |
| `PORT` | `3000`  | Port to bind. Steps up if the port is taken. |

`NO_COLOR` (or `TERM=dumb`) turns off the colored startup banner.

## Routes

| Route    | Response                                                        |
| -------- | ---------------------------------------------------------------- |
| `/`      | HTML in a browser, plain text to curl (negotiated on `Accept`)   |
| `/ip`    | The resolved address, plain text                                 |
| `/json`  | Full resolution as JSON. `?full=1` adds every candidate it saw   |
| `/debug` | Everything, including the raw request headers                    |

```bash
curl localhost:3000/ip
curl -s 'localhost:3000/json?full=1' | jq
```

## How it decides

It identifies the edge by a *fingerprint* header the edge stamps on every request
(`cf-ray`, `x-amz-cf-id`, `fly-request-id`, `via: … google`, and so on), not by the IP
header itself. Once the edge is known, the header — or the position in the
`x-forwarded-for` chain — that holds the real client is known too.

Recognized: Cloudflare, AWS CloudFront, AWS ALB/ELB, Fastly, Akamai, Vercel, Netlify,
Fly.io, Azure Front Door, Google Cloud Load Balancer, Google App Engine, Heroku,
DigitalOcean App Platform, Shopify Oxygen, Render, Envoy/Istio.

With no recognized edge it falls back, and says so in `confidence` and `reason`:

- No forwarding headers at all → the TCP peer, `high` confidence.
- Forwarding headers over a private connection → the header, `medium`, since something
  local is clearly proxying but nothing proves the value.
- Forwarding headers straight from a public host → the header, `low`. Any client can
  send those, so it's a claim, not a fact.

`spoofable` says which of the two you got.

`app.set("trust proxy")` here is just `isNonPublic`, to keep `req.ip` sane behind local
proxies. The resolver above does the real work and ignores it.

## Lock it down

The HTML page ends with the config you actually need, for whatever is terminating the
connection: Python (`http.server`, Flask, FastAPI), Node/Express, Go, Rust/axum, PHP,
nginx and Caddy. Pick a tab and copy.

The snippets are generated from the resolution, not canned, so they name the one header
worth trusting and — when that header carries a list rather than a single address — index
into the right entry. `advice.pick` in the JSON carries that rule (`leftmost`,
`rightmost`, `secondFromRight`, or `null` for a single-value header).

Two things the snippets won't do for you: the `0.0.0.0/0` in the nginx and Caddy examples
is a placeholder for the edge's published ranges, and if the only chain header is RFC 7239
`Forwarded`, they tell you to have the proxy set `x-forwarded-for` too rather than pretend
a one-line split can parse `for="[2001:db8::1]:8080"`.

The Express tab shows `advice.trustProxy` as a hop count. The stored value is not always a
number — Cloudflare carries a preset name, and nothing-in-front carries `false` — so the
snippet coerces it rather than printing something `app.set` would reject.

## The Python port

`main` has the same server with no dependencies at all, which means it runs straight from
the repo:

```bash
uvx --from git+https://github.com/VarunAgnihotri/ip-test ip-server
uv run https://raw.githubusercontent.com/VarunAgnihotri/ip-test/main/ip_server.py
```

Same routes, same detection table, same resolution rules, same startup banner, same
snippet tabs. Three fields read differently there, because these ones name Node APIs:

| Express (here)                   | Python (`main`)              |
| -------------------------------- | ---------------------------- |
| `source: "socket.remoteAddress"` | `source: "socket peer"`      |
| `advice.trustProxy`              | `advice.trusted_hops`        |
| candidate `req.ip`               | candidate `trusted-hop walk` |

`advice.pick` is `secondFromRight` here and `second_from_right` there, each matching the
casing its own file already used.

## License

MIT
