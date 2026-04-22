import os
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Get database URL directly
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("❌ DATABASE_URL not found in .env file")

# Schema name (default: cloud_schema)
SCHEMA_NAME = os.getenv("SCHEMA_NAME", "cloud_schema")

# Create engine
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Metadata and Base for ORM
metadata = MetaData(schema=SCHEMA_NAME)
Base = declarative_base(metadata=metadata)
