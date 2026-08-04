FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY scanner ./scanner
COPY samples ./samples

RUN pip install --no-cache-dir ".[api]"

EXPOSE 8000

CMD ["uvicorn", "scanner.api:app", "--host", "0.0.0.0", "--port", "8000"]
