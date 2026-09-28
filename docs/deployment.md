# Deployment guide

This guide covers running a WAP business agent in production. You host it, you choose
the infrastructure and you own the operational decisions. This page lists what matters
and how the library supports each item. Every setting is described in
[configuration.md](configuration.md).

## Checklist

- [ ] **Persistent signing key** loaded from a secret manager (`WAP_PRIVATE_KEY` or `private_key=`).
- [ ] **HTTPS** in front of the app. Clients refuse plain HTTP for public domains.
- [ ] **Shared store** (`RedisStore`) if you run more than one worker or machine.
- [ ] **Business data in your own database.** WAP keeps protocol state only; the example bakery's
      in-memory inventory is for demos.
- [ ] **Client IPs:** `trust_forwarded_for=True` only if a proxy you control sets `X-Forwarded-For`.
- [ ] **Limits and proof-of-work** chosen for your traffic; admission tiers for partners and logged-in users.
- [ ] **Effects declared honestly** on every action (`read`, `write`, `financial`).
- [ ] **Observer** wired to your metrics and logs.
- [ ] **Optional:** DNS TXT record for your key, and a key rotation plan.

## Keys

```bash
wap keygen --out bakery.key          # prints the public key, fingerprint and a DNS TXT record
```

Store the private key in your secret manager and pass it through the environment:

```python
wap = WAPServer(..., private_key=os.environ["WAP_PRIVATE_KEY"])
```

Every worker must use the same key. The proof-of-work secret is derived from it, so
challenges issued by one worker are accepted by all of them.

### DNS anchoring (optional)

Publish your key so that clients can check it independently of your web server:

```
_wap.bakery.example.  TXT  "v=wap1; k=<64-hex public key>"
```

Clients with `dns_key_policy="if-present"` or `"require"` reject manifests signed by any
other key. Use DNSSEC for full strength.

### Rotating keys

1. Generate a new key.
2. Deploy with `private_key=NEW, previous_keys=[OLD]`. The manifest now lists the old
   key and carries its endorsement of the new one. Clients that pinned the old key
   verify the endorsement and switch to the new key.
3. If you use DNS anchoring, publish TXT records for both keys during the transition.
4. After a few manifest lifetimes (hours to days), remove `previous_keys` and the old
   TXT record.

If the old key was **compromised**, an endorsement doesn't help, because the attacker
can endorse their own key. Announce the new key's fingerprint out of band, and ask
partners who pin keys to reset their pins.

## Processes, workers and Redis

A single uvicorn worker with the default `MemoryStore` is fine for small sites. With
more than one worker, per-process memory breaks the protections. The load test shows
it directly: with 4 workers and no shared store, a replayed message was accepted 4
times and a reused proof-of-work solution twice. With Redis, both were accepted once.

```python
from wap.storage import RedisStore

wap = WAPServer(..., store=RedisStore.from_url(os.environ["REDIS_URL"], prefix="bakery:"))
```

```bash
uvicorn myapp:app --host 0.0.0.0 --port 8000 --workers 4
# or: gunicorn -k uvicorn.workers.UvicornWorker -w 4 myapp:app
```

- **Redis setup:** use a dedicated database or `prefix` per deployment, and `rediss://`
  for TLS. Redis Cluster needs all of a request's keys in one slot, so use a single
  shard or a hash-tagged prefix such as `"{bakery}:"`.
- **Redis outages:** if Redis is unreachable, WAP requests fail with a server error.
  They fail closed rather than silently dropping protections, so monitor Redis like
  any other dependency.
- **ASGI lifespan:** the `/mcp` endpoint and `include_mcp()` imports start in the
  application's lifespan. uvicorn and gunicorn with uvicorn workers run it by default.
  Without it, `/mcp` answers `503` and says so.

## Reverse proxies and CDNs

- **HTTPS:** terminate TLS at the proxy and forward to the app.
- **Client IPs:** set `trust_forwarded_for=True` only if the proxy overwrites
  `X-Forwarded-For`. Otherwise clients can spoof their IP and dodge the per-IP limits.
- **Caching the manifest:** `/.well-known/wap.json` and the legacy
  `/.well-known/agent.json` can be cached; they send `Cache-Control` and `ETag`.
- **Don't cache interactions:** do not cache `/wap/v1/*` or `/mcp`, and allow
  streaming (`text/event-stream`) through without buffering. For nginx, use
  `proxy_buffering off` for `/wap/v1/interact`.
- **Body size:** keep request bodies up to 256 KiB.

## Choosing protections

| Traffic | Suggested settings |
|---|---|
| Public, anonymous agents | `require_pow=True, pow_difficulty=4`, default limits, `adaptive_pow=AdaptivePow()` |
| Your own logged-in users | `auth_handler=...` plus an admission tier with `require_pow=False` and higher limits |
| Known partner platforms | an admission tier keyed on their agent keys, no PoW, high limits, `conversation_policy=False` if they aggregate |
| Plain MCP clients on `/mcp` | `mcp_require_pow=False`, with IP limits doing the work |
| Internal or testing | `rate_limit=False, ip_rate_limit=False, conversation_policy=False` |

Declare `effects` truthfully. Clients use it to decide what to confirm with a human
and what is safe to retry. The default is `write`, so mark lookups as `read`.

## Capacity

Measurements from `python examples/load_test.py` on a 4-vCPU, 2.1 GHz Xeon. The load
generator shares the machine with the server, so these are lower bounds. Each request
includes a challenge fetch, a proof-of-work at difficulty 2, a signed request, and a
signed reply that the client verifies:

| Workers | Store | Load-generator processes | Requests/s | p50 | p95 | p99 | Errors |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | memory | 3 | ~580 | 51 ms | 74 ms | 104 ms | 0 |
| 2 | Redis | 2 | ~400 | 70 ms | 112 ms | 150 ms | 0 |
| 3 | Redis | 2 | ~425 | 68 ms | 99 ms | 135 ms | 0 |

On a machine this small, the Redis round trips and the shared CPU cancel out the
benefit of extra workers. Run the script on your own hardware (`--workers`,
`--redis-url`, `--users`, `--client-processes`) to size your deployment. The protocol
overhead itself is small: about 97 µs to verify a signature and about 40 µs to verify
a proof-of-work solution. Your actions (database calls, LLMs) will usually dominate.

## Monitoring

```python
from wap.server.observability import LoggingObserver, MetricsObserver, combine

metrics = MetricsObserver()
wap = WAPServer(..., observer=combine(LoggingObserver(), metrics))
```

Watch these:

- the rate of `request.rejected` by `code`: spikes in `rate_limited` or `pow_invalid`
  mean abuse, and `loop_detected` means misbehaving agents;
- latency percentiles of `request.completed` for each capability;
- the difficulty in `pow.issued` when `AdaptivePow` is on.

## What stays your responsibility

The library does not handle payments, user accounts, your business data, TLS
certificates, DDoS protection at the network layer, or hosting. It gives you signed,
abuse-resistant, loop-safe plumbing between agents. Everything behind your actions is
your application.
