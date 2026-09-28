# Evidence

Every number in [`docs/whitepaper.md`](../whitepaper.md) comes from a file in this folder. All of them were
produced by one command, in a Linux container, against the code at the commit in `environment.txt`:

```bash
docker build -f evals/Dockerfile -t wap-eval .
docker run --rm -v "$PWD/.env:/app/.env:ro" -v "$PWD/docs/evidence:/app/docs/evidence" \
    -e GIT_COMMIT=$(git rev-parse --short HEAD) wap-eval
```

`.env` needs `OPENAI_API_KEY` (and optionally `OPENAI_LLM`; the default is `gpt-6-luna`). The key is
mounted at run time and never copied into the image. A full run makes a few hundred model calls.

| File | What it is | Produced by |
|---|---|---|
| `environment.txt` | Date, commit, Python, kernel, CPU, memory, package versions | `evals/run.sh` |
| `benchmark.md` | Byte and approximate-token sizes, proof-of-work cost, signature cost, in-process latency | `examples/benchmark.py` |
| `load-test.md` | Throughput and latency of real uvicorn workers over HTTP, plus replay and proof-of-work reuse probes | `examples/load_test.py` |
| `agent-eval/summary.md` | Results of the real-agent evaluation | `evals/agent_eval.py` |
| `agent-eval/results.json` | The same results, machine-readable, with run metadata | `evals/agent_eval.py` |
| `agent-eval/transcripts.jsonl` | One line per agent run: every tool call with its arguments and result, the model's final answer, billed tokens, timing, and the server-side state that was checked | `evals/agent_eval.py` |

## What the agent evaluation does

A language model is given tools and a task, and runs until it answers. Nothing is mocked: the bakery is a
real HTTP server, every WAP call is signed and pays proof-of-work at difficulty 4, `wap-mcp` runs as a
separate process over stdio exactly as an MCP host would launch it, and token counts are the ones the
OpenAI API billed. Outcomes are checked against the server's own state, not against what the model says.

| Scenario | Tools the model gets | Checked against |
|---|---|---|
| `lookup_html` | `fetch_page` returning the storefront's raw HTML | live inventory |
| `lookup_text` | `fetch_page` returning the storefront's visible text | live inventory |
| `lookup_wap` | the bakery's WAP capabilities | live inventory |
| `reserve_approved` | WAP capabilities; the user approves the reservation | holds on the server |
| `reserve_declined` | WAP capabilities; the user declines (`WAPClient(confirm=...)`) | holds on the server |
| `bridge_declined` | `wap-mcp` tools; the user declines through MCP elicitation | holds on the server |
| `loop_firm` | `wap-mcp` tools; "my budget is firm at $3.60" | negotiations the bakery executed |
| `loop_adversarial` | `wap-mcp` tools; told to repeat the $3.60 offer at least 10 more times | negotiations the bakery executed |

The storefront page is rendered from the same live inventory the WAP tools read, so all three lookup
strategies see the same facts.

## Limits

- One model (`gpt-6-luna`), chosen for cost. Other models will spend different numbers of tokens and may
  behave differently at the edges (for example, whether they obey a loop-protection stop instruction).
- Small samples: 10 lookups per strategy and 5 runs of each other scenario. Treat rates as indicative.
- One synthetic storefront (18.8 KB of HTML). Real pages are usually larger, which favours WAP against raw
  HTML, and messier, which a stripped-text scraper may or may not survive.
- Everything runs on one machine, so network latency is near zero.
- The adversarial loop prompt is deliberately unrealistic; it exists to exercise loop protection.
