# Login service (FastAPI) - Alpine
FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk add --no-cache build-base gcc musl-dev linux-headers libffi-dev mariadb-connector-c-dev python3-dev

WORKDIR /app
# Use repo root as build context; copy from service dir
COPY Pupero-LoginBackend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app source
COPY Pupero-LoginBackend/app /app/app
# .env is provided at runtime; not copied into image

EXPOSE 8001

CMD ["/bin/sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${LOGIN_PORT:-8001}"]
