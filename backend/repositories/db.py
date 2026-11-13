import os
from dotenv import load_dotenv

load_dotenv()

# Optional direct-Postgres connection. The API itself talks to Supabase over its REST
# client (config/database.py), so a missing DATABASE_URL must not crash imports.
DATABASE_URL = os.getenv("DATABASE_URL")
engine = None
SessionLocal = None

if DATABASE_URL:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    if SessionLocal is None:
        raise RuntimeError("DATABASE_URL is not set in the .env file.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
