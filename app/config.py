### Code Files

#### app/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET_KEY: str
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    REMEMBER_ME_DAYS: int = 30
    ANTI_PHISHING_PHRASE_DEFAULT: str = "Welcome to Pupero"
    SQL_ECHO: bool = False

    # Accept extra env vars like LOGIN_PORT without failing
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
