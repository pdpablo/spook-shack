FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock README.md ./
COPY spook_shack ./spook_shack
COPY dashboard ./dashboard

RUN uv sync --frozen --no-dev --compile-bytecode

ENV PATH="/app/.venv/bin:${PATH}" \
    SPOOK_SHACK_HOME=/data

VOLUME ["/data"]
EXPOSE 8000

CMD ["spook-shack", "serve", "--host", "0.0.0.0", "--port", "8000"]
