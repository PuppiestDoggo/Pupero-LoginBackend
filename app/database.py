from sqlmodel import create_engine, Session
from app.config import settings

# Create engine (no schema creation here)
engine = create_engine(settings.DATABASE_URL, echo=settings.SQL_ECHO)

# Dependency for getting DB session
def get_session():
    with Session(engine) as session:
        yield session
