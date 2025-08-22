from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from app.config import settings

# Create engine
engine = create_engine(settings.DATABASE_URL, echo=True)

# Function to create database if it doesn't exist
def create_db_if_not_exists():
    db_name = "pupero_auth"  # Extract from URL or hardcode based on .env
    engine_no_db = create_engine(settings.DATABASE_URL.replace(f"/{db_name}", ""))
    with Session(engine_no_db) as session:
        try:
            session.exec(text(f"CREATE DATABASE IF NOT EXISTS {db_name}"))
            session.commit()
        except OperationalError:
            pass  # Database already exists

# Create tables
def create_db_and_tables():
    create_db_if_not_exists()
    SQLModel.metadata.create_all(engine)

# Dependency for getting DB session
def get_session():
    with Session(engine) as session:
        yield session
