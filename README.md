# Login (Auth Service)

FastAPI service handling user registration, login with JWT, profile management, and TOTP 2FA.

- Default port: 8001
- Backed by MariaDB; this service defines its own SQLModel models locally

## Main endpoints
- POST /register
- POST /login
- POST /refresh
- GET /user/profile
- PUT /user/update
- POST /password/reset (stub)
- TOTP:
  - POST /totp/enable/start
  - POST /totp/enable/confirm
  - POST /totp/disable
  - GET /totp/status

OpenAPI docs: /docs, /openapi.json

## Environment
`Login/.env`:
```
DATABASE_URL=mariadb+mariadbconnector://root:mypass@127.0.0.1:3306/pupero_auth
JWT_SECRET_KEY=your_super_secret_key_here
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_MINUTES=1440
ANTI_PHISHING_PHRASE_DEFAULT=Welcome to Pupero
LOGIN_PORT=8001
```

## Run locally
```
cd Login
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

## Docker
```
docker build -t pupero-login -f Login/Dockerfile .
docker run --rm -p 8001:8001 --env-file Login/.env pupero-login
```

## Notes
- Database tables are initialized by the DB service (MariaDB image) via init scripts.
- The service defines its own Pydantic schemas and SQLModel models; it does not import from other projects.
- Works best behind APIManager at /auth/*
