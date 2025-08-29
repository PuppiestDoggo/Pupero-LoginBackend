# Login service (FastAPI) - Alpine
FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk add --no-cache build-base gcc musl-dev linux-headers libffi-dev mariadb-connector-c-dev python3-dev

WORKDIR /app
COPY Login/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app and centralized schemas
COPY Login/app /app/app
COPY Login/.env /app/.env

EXPOSE 8001

CMD ["/bin/sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${LOGIN_PORT:-8001}"]
