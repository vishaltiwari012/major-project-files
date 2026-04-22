# IMPORTS
import os
import psycopg2
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
import uvicorn
from models import Base
from database import engine
Base.metadata.create_all(bind=engine)

# AUTH / JWT HELPERS & ENDPOINTS 
import bcrypt
import jwt
from pydantic import BaseModel, EmailStr
from fastapi import HTTPException, Depends, Header


# CONFIGURATION
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("DATABASE_URL environment variable is not set!")

FRONTEND_URL = "https://rudravcloud.onrender.com"

KEY_FILE = "secret.key"
UPLOAD_DIR = "./chunks"
CHUNK_SIZE = 1024 * 1024  # 1 MB

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ENCRYPTION SETUP
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as keyfile:
        keyfile.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as keyfile:
    key = keyfile.read()

cipher = Fernet(key)


# DATABASE CONNECTION
try:
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cursor = conn.cursor()
    print("Database connected successfully!")
except Exception as e:
    raise Exception(f"Database connection failed: {e}")


app = FastAPI(title="Rudra Cloud API", version="1.0")
templates = Jinja2Templates(directory="templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# config
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_change_me")
JWT_ALGO = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

# pydantic models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

# helper: create JWT
def create_jwt(payload: dict, expire_seconds: int = JWT_EXPIRE_SECONDS):
    data = payload.copy()
    from datetime import datetime, timedelta
    exp = datetime.utcnow() + timedelta(seconds=expire_seconds)
    data.update({"exp": exp})
    token = jwt.encode(data, SECRET_KEY, algorithm=JWT_ALGO)
    return token

# helper: decode & validate JWT (returns payload)
def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# dependency to get current user from Authorization header
def get_current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    # Accept formats: "Bearer <token>" or just "<token>"
    parts = authorization.split()
    token = parts[-1]
    payload = decode_jwt(token)
    return payload  # contains user_id, username, exp

MAX_BCRYPT_BYTES = 72

def truncate_password_bytes(password: str, limit: int = MAX_BCRYPT_BYTES) -> bytes:
    """
    Return UTF-8 encoded bytes of password truncated to at most `limit` bytes,
    truncating at character boundaries (so no broken multibyte char).
    """
    if password is None:
        return b""
    out_bytes = bytearray()
    for ch in password:
        ch_b = ch.encode("utf-8")
        if len(out_bytes) + len(ch_b) > limit:
            break
        out_bytes.extend(ch_b)
    return bytes(out_bytes)



@app.post("/register")
def register_user(payload: UserRegister):
    try:
        if len(payload.password) < 6:
            raise HTTPException(status_code=400, detail="Password too short")

        # Username/email exists?
        cursor.execute(
            "SELECT id FROM users WHERE username=%s OR email=%s",
            (payload.username, payload.email)
        )
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username or email already exists")

        # Truncate to <= 72 bytes (bytes result)
        safe_password_bytes = truncate_password_bytes(payload.password)

        # Hash using native bcrypt (hashpw expects bytes)
        hashed = bcrypt.hashpw(safe_password_bytes, bcrypt.gensalt())  # returns bytes

        # Store hashed as bytes or decode to utf-8-safe form (e.g., store as base64 or decode)
        # Most people store it as bytes in BYTEA column or as its utf-8 repr:
        # If your DB column is text, decode to utf-8:
        hashed_str = hashed.decode("utf-8")

        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (payload.username, payload.email, hashed_str)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()

        return {"status": "ok", "user_id": user_id}

    except HTTPException:
        raise
    except Exception as e:
        print("Register error:", e)
        raise HTTPException(status_code=500, detail="Server error")



@app.post("/login")
def login_user(payload: UserLogin):
    try:
        cursor.execute("SELECT id, password_hash FROM users WHERE username=%s", (payload.username,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user_id, password_hash_db = row

        # DB value might be stored as str; convert to bytes
        if isinstance(password_hash_db, str):
            password_hash_bytes = password_hash_db.encode("utf-8")
        else:
            password_hash_bytes = password_hash_db

        # Truncate incoming password to same rule and get bytes
        safe_password_bytes = truncate_password_bytes(payload.password)

        # Verify with bcrypt.checkpw OR bcrypt.checkpw-like using hash
        if not bcrypt.checkpw(safe_password_bytes, password_hash_bytes):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_jwt({"user_id": user_id, "username": payload.username})
        return {"access_token": token, "token_type": "bearer"}

    except HTTPException:
        raise
    except Exception as e:
        print("Login error:", e)
        raise HTTPException(status_code=500, detail="Server error")


# Example protected route (usage)
@app.get("/me")
def me(user=Depends(get_current_user)):
    # user is JWT payload dict
    return {"user": user}
# end auth block 

# ROUTE
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Home page: fetch file list from DB and pass to template.
    Files will be a list of dicts: {"id": ..., "name": ...}
    """
    try:
        cursor.execute("SELECT id, filename FROM file_metadata ORDER BY uploaded_at DESC;")
        rows = cursor.fetchall()
        files = [{"id": r[0], "name": r[1]} for r in rows] if rows else []
    except Exception as e:
        print("Error in home():", e)
        files = []
    return templates.TemplateResponse("index.html", {"request": request, "files": files})


@app.get("/api/files", response_class=JSONResponse)
def list_files_api():
    try:
        cursor.execute("SELECT id, filename FROM file_metadata ORDER BY uploaded_at DESC;")
        rows = cursor.fetchall()

        files = [{"id": r[0], "name": r[1]} for r in rows] if rows else []
        return JSONResponse({"files": files})

    except Exception as e:
        print("Error in /api/files:", e)
        return JSONResponse({"files": []}, status_code=500)


@app.get("/health")
def health():
    return {"status": "running", "database_url": DATABASE_URL, "frontend": FRONTEND_URL}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), uploaded_by: str = "user1"):
    try:
        temp_path = os.path.join(UPLOAD_DIR, file.filename)
        content = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content)

        # Insert metadata into file_metadata
        cursor.execute(
            """
            INSERT INTO file_metadata (filename, chunks_count, chunk_size, uploaded_by)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (file.filename, 0, CHUNK_SIZE, uploaded_by)
        )
        file_id = cursor.fetchone()[0]

        # Encrypt and split into chunks
        chunks_count = 0
        with open(temp_path, "rb") as f:
            index = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = cipher.encrypt(chunk)
                # NOTE: your repo uses filename + "chunk" + index (no underscore)
                chunk_path = os.path.join(UPLOAD_DIR, f"{file.filename}chunk{index}")
                with open(chunk_path, "wb") as cf:
                    cf.write(encrypted_chunk)
                # Insert chunk metadata
                cursor.execute(
                    """
                    INSERT INTO chunk_metadata (file_id, chunk_index, lender_node)
                    VALUES (%s, %s, %s)
                    """,
                    (file_id, index, "node1")
                )
                index += 1
                chunks_count += 1

        # Update chunks count in file_metadata
        cursor.execute(
            "UPDATE file_metadata SET chunks_count=%s WHERE id=%s",
            (chunks_count, file_id)
        )

        os.remove(temp_path)

        return JSONResponse(content={"status": "success", "file_id": file_id, "chunks": chunks_count})

    except Exception as e:
        print("Error in upload_file:", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload_chunk/")
async def upload_chunk(file: UploadFile = File(...), uploaded_by: str = "user1"):
    print("Alias route called for:", file.filename)
    try:
        return await upload_file(file, uploaded_by)
    except Exception as e:
        print("Error in upload_chunk:", e)
        raise

@app.get("/download_by_name/{filename}")
def download_by_name(filename: str):
    try:
        cursor.execute("SELECT id FROM file_metadata WHERE filename=%s", (filename,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="File not found")
        return download_file(r[0])  # reuse existing function
    except HTTPException:
        raise
    except Exception as e:
        print("Error in download_by_name:", e)
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/download/{file_id}")
def download_file(file_id: int):
    try:
        cursor.execute(
            "SELECT filename, chunks_count FROM file_metadata WHERE id=%s",
            (file_id,)
        )
        file_meta = cursor.fetchone()
        if not file_meta:
            raise HTTPException(status_code=404, detail="File not found")

        filename, chunks_count = file_meta

        def iter_decrypted():
            for i in range(chunks_count):
                # use same naming as upload: filename + "chunk" + index
                chunk_path = os.path.join(UPLOAD_DIR, f"{filename}chunk{i}")
                if not os.path.exists(chunk_path):
                    # raise inside generator so StreamingResponse exposes error
                    raise HTTPException(status_code=404, detail=f"Chunk {i} missing")
                with open(chunk_path, "rb") as cf:
                    enc = cf.read()
                try:
                    dec = cipher.decrypt(enc)
                except Exception as ex:
                    print(f"Decrypt error for chunk {i}:", ex)
                    raise HTTPException(status_code=500, detail="Decryption failed")
                yield dec

        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return StreamingResponse(iter_decrypted(), media_type="application/octet-stream", headers=headers)

    except HTTPException:
        raise
    except Exception as e:
        print("Error in download_file:", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/download_chunk/{file_id}")
def download_chunk(file_id: int):
    return download_file(file_id)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
