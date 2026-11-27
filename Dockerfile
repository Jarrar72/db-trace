FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY dbtrace ./dbtrace

RUN pip install --no-cache-dir uv && \
    uv sync --no-dev --frozen

# Generate 100 environments and train model artifacts inside the container image
RUN .venv/bin/python -m dbtrace.generator --n 100 --seed 42 && \
    .venv/bin/python -m dbtrace.models.train

EXPOSE 7860
CMD [".venv/bin/uvicorn", "dbtrace.api.app:app", "--host", "0.0.0.0", "--port", "7860"]
