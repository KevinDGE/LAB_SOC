# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN useradd --create-home --uid 10001 soc
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY soc_lab ./soc_lab
RUN mkdir -p /app/data && chown soc:soc /app/data

# --- Imagen de pruebas: docker compose run --rm tests -----------------------
FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY pyproject.toml ./
COPY tests ./tests
COPY docs ./docs
COPY reports ./reports
USER soc
CMD ["python", "-m", "pytest", "-p", "no:cacheprovider"]

# --- Imagen de ejecución (por defecto) ---------------------------------------
FROM base AS runtime
COPY docker/entrypoint.sh /entrypoint.sh
USER soc
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
