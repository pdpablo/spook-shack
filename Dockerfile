FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SPOOK_SHACK_HOME=/data

WORKDIR /app

RUN mkdir -p /data

COPY pyproject.toml README.md ./
COPY app ./app
COPY spook_shack ./spook_shack
COPY dashboard ./dashboard
COPY dashboard/dist ./dashboard/dist
COPY templates ./templates
COPY static ./static

RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir .

EXPOSE 8000

CMD ["spook-shack", "serve", "--host", "0.0.0.0"]
