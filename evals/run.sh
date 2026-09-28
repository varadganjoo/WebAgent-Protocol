#!/bin/sh
# Runs every measurement behind docs/whitepaper.md and writes the results to docs/evidence/.
# Extra arguments go to evals/agent_eval.py (for example --trials 1 for a quick run).
set -eu
out=docs/evidence
mkdir -p "$out"
redis-server --daemonize yes --save "" --appendonly no >/dev/null

{
    echo "date: $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "commit: ${GIT_COMMIT:-unknown}"
    echo "python: $(python --version 2>&1)"
    echo "kernel: $(uname -srm)"
    echo "cpus: $(nproc)"
    grep -m1 'model name' /proc/cpuinfo | sed 's/^model name\s*:\s*/cpu: /'
    echo "memory: $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
    echo "redis: $(redis-server --version | cut -d' ' -f3)"
    pip list --format=freeze 2>/dev/null | grep -iE '^(webagent-protocol|pydantic|fastapi|uvicorn|mcp|httpx|cryptography|openai|redis)=='
} > "$out/environment.txt"
cat "$out/environment.txt"

echo "== micro-benchmarks"
python examples/benchmark.py > "$out/benchmark.md"

echo "== load tests"
{
    python examples/load_test.py --workers 1 --client-processes 3 --header
    python examples/load_test.py --workers 4 --client-processes 3
    python examples/load_test.py --workers 4 --client-processes 3 --redis-url redis://127.0.0.1:6379/0
} > "$out/load-test.md"
cat "$out/load-test.md"

echo "== real-agent evaluation"
python evals/agent_eval.py "$@"
