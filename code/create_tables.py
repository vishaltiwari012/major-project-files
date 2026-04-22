from sqlalchemy.exc import OperationalError
from database import engine, Base
from models import User, FileMetadata, ChunkMetadata  # import new models

try:
    Base.metadata.create_all(bind=engine)
    print("✅ Tables created successfully on Render DB!")
except OperationalError as e:
    print("❌ Error connecting to Render DB:")
    print(e)
