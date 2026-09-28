# Reproduces docs/evidence/: benchmarks, load tests and the real-agent evaluation on Linux.
# The OpenAI key is read from a mounted .env at run time; it is never copied into the image.
#
#   docker build -f evals/Dockerfile -t wap-eval .
#   docker run --rm -v "$PWD/.env:/app/.env:ro" -v "$PWD/docs/evidence:/app/docs/evidence" \
#       -e GIT_COMMIT=$(git rev-parse --short HEAD) wap-eval
FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends redis-server \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY wap wap
RUN pip install --no-cache-dir --root-user-action=ignore -e ".[all]" openai python-dotenv
COPY . .

CMD ["sh", "evals/run.sh"]
