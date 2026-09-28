## Context cost

| Representation | Bytes | ≈ Tokens | vs raw HTML |
|---|---:|---:|---:|
| Raw HTML storefront | 18,848 | 7,071 | 1.0× |
| Visible text (scripts/styles/tags stripped) | 1,456 | 419 | 16.9× |
| WAP: full manifest (4 capabilities) | 5,407 | 1,564 | 4.5× |
| WAP: one capability schema | 774 | 249 | 28.4× |
| WAP: signed reply on the wire (check_pastry_stock) | 704 | 300 | 23.6× |
| WAP: model-visible result (text + structured_data) | 158 | 57 | 124.1× |

WAP per-query model context (one schema + model-visible result): ≈306 tokens → 23.1× less than raw HTML

## Proof-of-work asymmetry

| Difficulty | Expected hashes | Client solve (mean of 20) | Server verify |
|---:|---:|---:|---:|
| 1 | 16 | 0.0 ms | 9.2 µs |
| 2 | 256 | 0.3 ms | 13.8 µs |
| 3 | 4,096 | 2.9 ms | 44.3 µs |
| 4 | 65,536 | 58.6 ms | 120.5 µs |
| 5 | 1,048,576 | 845.6 ms | 114.3 µs |

(difficulty 5 averaged over 5 trials)

## Signatures

Ed25519 sign (canonicalise + sign): 149.9 µs · verify: 276.3 µs

## In-process round trip (PoW d=3, signed request + signed reply, 30 calls)

p50 6.1 ms · p90 14.2 ms · max 19.8 ms
