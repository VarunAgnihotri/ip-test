# ip-test

A tiny server that figures out what is in front of it, resolves the client IP accordingly,
and shows its work. No dependencies, just the Python standard library.

## Run it without cloning

```bash
# as a command, straight from the repo
uvx --from git+https://github.com/VarunAgnihotri/ip-test ip-server

# or as a single script (PEP 723 header, nothing to install)
uv run https://raw.githubusercontent.com/VarunAgnihotri/ip-test/main/ip_server.py
```

Both need Python 3.12+, which `uv` fetches on its own if you don't have it.

Locally:

```bash
uv run ip_server.py --port 8080
```

## Options

| Flag     | Env    | Default | What it does                                        |
| -------- | ------ | ------- | --------------------------------------------------- |
| `--host` | `HOST` | `::`    | Interface to bind. `::` accepts IPv4 and IPv6 both. |
| `--port` | `PORT` | `3000`  | Port to bind. Steps up if the port is taken.        |

Set `IP_SERVER_LOG=1` for a per-request access log on stderr.

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

## Lock it down

The HTML page ends with the config you actually need, for whatever is terminating the
connection: Python (`http.server`, Flask, FastAPI), Node/Express, Go, Rust/axum, PHP,
nginx and Caddy. Pick a tab and copy.

The snippets are generated from the resolution, not canned, so they name the one header
worth trusting and — when that header carries a list rather than a single address — index
into the right entry. `advice.pick` in the JSON carries that rule (`leftmost`,
`rightmost`, `second_from_right`, or `null` for a single-value header).

Two things the snippets won't do for you: the `0.0.0.0/0` in the nginx and Caddy examples
is a placeholder for the edge's published ranges, and if the only chain header is RFC 7239
`Forwarded`, they tell you to have the proxy set `x-forwarded-for` too rather than pretend
a one-line split can parse `for="[2001:db8::1]:8080"`.

## Port of the Express version

The Express server lives on the `node-express` branch. Same routes, same detection
table, same resolution rules, same startup banner. Three things read differently in
the JSON, because they named Node APIs:

| Express                         | Python                     |
| ------------------------------- | -------------------------- |
| `source: "socket.remoteAddress"` | `source: "socket peer"`    |
| `advice.trustProxy`             | `advice.trusted_hops`      |
| candidate `req.ip`              | candidate `trusted-hop walk` |

`advice.pick` is new here, and the page's snippet section is new with it.

`trusted-hop walk` is the same right-to-left walk Express's `req.ip` does over the
chain, stopping at the first address the server didn't put there. It normalizes
IPv4-mapped addresses first, which Express's copy didn't, so behind a v6 socket it
reports the forwarded address where Express reported `127.0.0.1`.

The 404 body is JSON here rather than Express's HTML page.

## License

MIT
