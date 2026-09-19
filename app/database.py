import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

IS_VERCEL = bool(os.getenv("VERCEL"))
DB_PATH = os.getenv(
    "DATABASE_URL",
    "sqlite:////tmp/email_threat_analyzer.db" if IS_VERCEL
    else "sqlite:///./email_threat_analyzer.db",
)

engine = create_engine(
    DB_PATH, 
    connect_args={"check_same_thread": False} if "sqlite" in DB_PATH else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency for obtaining database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)
