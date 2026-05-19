FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
COPY app ./app

RUN pip install --no-cache-dir --upgrade pip uv && \
    uv export --frozen --no-dev --no-hashes --no-emit-project -o requirements.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir --no-deps . && \
    pip uninstall -y uv && \
    adduser --disabled-password --no-create-home appuser

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
