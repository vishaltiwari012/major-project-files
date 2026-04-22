from sqlalchemy import Column, Integer, String, Text, BigInteger, ForeignKey, TIMESTAMP, func
from database import Base

class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "cloud_schema"}

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())

class FileMetadata(Base):
    __tablename__ = "file_metadata"
    __table_args__ = {"schema": "cloud_schema"}

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    chunks_count = Column(Integer, default=0)
    chunk_size = Column(Integer, default=1024*1024)
    uploaded_by = Column(String(50), nullable=False)
    uploaded_at = Column(TIMESTAMP, server_default=func.now())

class ChunkMetadata(Base):
    __tablename__ = "chunk_metadata"
    __table_args__ = {"schema": "cloud_schema"}

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("cloud_schema.file_metadata.id", ondelete="CASCADE"))
    chunk_index = Column(Integer, nullable=False)
    lender_node = Column(String(50), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
