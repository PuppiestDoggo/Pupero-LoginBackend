### Code Files

#### app/config.py
from pydantic_settings import BaseSettings
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

    class Config:
        env_file = ".env"

settings = Settings()
