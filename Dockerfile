FROM python:3.12-slim

# Pinned uv for reproducible builds; bump intentionally.
COPY --from=ghcr.io/astral-sh/uv:0.11.26 /uv /usr/local/bin/uv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app
COPY pyproject.toml README.md uv.lock ./
COPY src ./src
# --frozen installs exactly what uv.lock pins (no PyPI re-resolution).
# Root package stays editable so the compose dev service's --reload sees ./src mounts.
RUN uv sync --frozen --no-dev

EXPOSE 8000
CMD ["uvicorn", "palisade.main:app", "--host", "0.0.0.0", "--port", "8000"]
