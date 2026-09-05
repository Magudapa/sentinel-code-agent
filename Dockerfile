FROM python:3.13-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY sentinel ./sentinel

RUN pip install --no-cache-dir . \
    && python -c "import sentinel; from sentinel.model import ModelClient; print('sentinel', sentinel.__version__)"

RUN useradd --create-home --shell /usr/sbin/nologin sentinel
USER sentinel
WORKDIR /work

ENTRYPOINT ["sentinel"]
CMD ["review", "--provider", "local", "--path", ".", "--no-explain"]