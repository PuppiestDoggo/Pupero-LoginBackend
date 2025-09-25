### Code Files

#### app/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    DATABASE_URL: str
    # Provide a development default so the service can start without env override.
    # In production, always set JWT_SECRET_KEY via environment variables.
    JWT_SECRET_KEY: str = "dev-secret-change-me"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    REMEMBER_ME_DAYS: int = 30
    ANTI_PHISHING_PHRASE_DEFAULT: str = "Welcome to Pupero"
    SQL_ECHO: bool = False
    MONERO_SERVICE_URL: str | None = None

    # Matrix integration (for auto account creation)
    MATRIX_ENABLED: bool = True
    MATRIX_HS_URL: str | None = "http://pupero-matrix-synapse:8008"
    MATRIX_SERVER_NAME: str = "localhost"
    MATRIX_USER_PREFIX: str = "u"
    MATRIX_DEFAULT_PASSWORD_SECRET: str = "change-me"

    # Accept extra env vars like LOGIN_PORT without failing
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
