FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY docs/README.md ./docs/README.md
COPY app ./app
COPY tests ./tests

RUN pip install --no-cache-dir uv && uv sync --all-groups

EXPOSE 8080

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
