from sqlmodel import create_engine, Session
from app.config import settings

# Create engine (no schema creation here)
engine = create_engine(settings.DATABASE_URL, echo=settings.SQL_ECHO)

# Dependency for getting DB session
def get_session():
    with Session(engine) as session:
        yield session


def run_startup_migrations() -> None:
    """
    Idempotent, minimal migrations to ensure required columns exist on the `user` table.
    This is designed to work against existing MariaDB instances without dropping data.
    """
    ddl_statements = [
        # Add missing columns if they don't exist. MariaDB/MySQL accept IF NOT EXISTS in recent versions.
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS username VARCHAR(255) NULL",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS role VARCHAR(50) NOT NULL DEFAULT 'user'",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS is_disabled TINYINT(1) NOT NULL DEFAULT 0",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS force_logout_at DATETIME NULL",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(255) NULL",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS matrix_localpart VARCHAR(255) NULL",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS phrase VARCHAR(255) NOT NULL DEFAULT 'Welcome to Pupero'",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS successful_trades INT NOT NULL DEFAULT 0",
        "ALTER TABLE user ADD COLUMN IF NOT EXISTS created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        # Helpful indexes (idempotent in MariaDB 10.5+ with IF NOT EXISTS; wrap in try/except otherwise)
        "CREATE INDEX IF NOT EXISTS ix_user_email ON user (email)",
        "CREATE INDEX IF NOT EXISTS ix_user_username ON user (username)",
        "CREATE INDEX IF NOT EXISTS ix_user_is_disabled ON user (is_disabled)",
        "CREATE TABLE IF NOT EXISTS review ("
        "id BIGINT PRIMARY KEY AUTO_INCREMENT,"
        "trade_id VARCHAR(64) NOT NULL,"
        "reviewer_user_id BIGINT NOT NULL,"
        "reviewee_user_id BIGINT NOT NULL,"
        "rating TINYINT NOT NULL CHECK (rating BETWEEN 1 AND 5),"
        "comment TEXT NOT NULL,"
        "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE KEY uq_review_trade_reviewer (trade_id, reviewer_user_id),"
        "INDEX ix_review_reviewee (reviewee_user_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    ]
    try:
        with engine.connect() as conn:
            for stmt in ddl_statements:
                try:
                    conn.exec_driver_sql(stmt)
                except Exception:
                    # Older MariaDB/MySQL may not support IF NOT EXISTS for some operations.
                    # In that case, ignore errors like duplicate column/index.
                    pass
            conn.commit()
    except Exception:
        # Do not block service start if migrations fail; runtime may still work for fresh DBs.
        pass
