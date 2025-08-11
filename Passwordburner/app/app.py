import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

#
# Simple one-time secret sharing service for testing.
#
# This FastAPI application stores ciphertext and nonce for a secret along
# with an identifier and HMAC of a token. The secret is never stored
# in plaintext. Retrieval is allowed only once via a POST request to
# /api/consume, which atomically deletes the record.
# Audit events are logged into a SQLite table with hashes of sensitive
# values. This implementation is self-contained and suitable for
# demonstration in a controlled environment.


########################
# Configuration
########################
# Data directory where SQLite database and static files reside.
DATA_DIR = Path(os.getenv("PWB_DATA_DIR", "./pwburner/app"))
# Directory containing static frontend files.
STATIC_DIR = Path(os.getenv("PWB_STATIC_DIR", "./pwburner/static"))
# SQLite database file path.
DB_PATH = DATA_DIR / "data.db"

# TTL configuration (in seconds)
DEFAULT_TTL = int(os.getenv("PWB_DEFAULT_TTL", "3600"))        # 1 hour
MAX_TTL = int(os.getenv("PWB_MAX_TTL", "604800"))              # 7 days
# Maximum allowed ciphertext size (roughly double plaintext size)
MAX_BYTES = int(os.getenv("PWB_MAX_SECRET_BYTES", "16384"))     # 16 KiB

# Secrets for HMAC hashing; must be base64 encoded; if not provided,
# random values are generated for demo usage. In production these
# should be set via environment variables and rotated regularly.
SERVER_HMAC_SECRET = base64.b64decode(os.getenv(
    "SERVER_HMAC_SECRET",
    base64.b64encode(secrets.token_bytes(32)).decode()
))
LOG_SALT = base64.b64decode(os.getenv(
    "LOG_SALT",
    base64.b64encode(secrets.token_bytes(32)).decode()
))
# Optional token for exporting audit logs; leave unset to disable.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", None)


########################
# Utility functions
########################
def now() -> int:
    """Return current Unix timestamp."""
    return int(time.time())


def b64url_bytes(data: bytes) -> str:
    """Return URL-safe base64 encoding of bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(data: str) -> bytes:
    """Decode URL-safe base64 string, adding padding if needed."""
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hmac_b64(key: bytes, data: str) -> str:
    """Compute HMAC-SHA256 of data using key and return base64url encoding."""
    return b64url_bytes(hmac.new(key, data.encode(), hashlib.sha256).digest())


def sha256_b64(data: str) -> str:
    """Compute SHA256 of string and return base64url encoding."""
    return b64url_bytes(hashlib.sha256(data.encode()).digest())


def client_ip(request: Request) -> str:
    """Determine client IP address from request headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


########################
# Database helpers
########################
def get_db() -> sqlite3.Connection:
    """Return a SQLite connection with reasonable pragmas."""
    conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Initialize database tables if they do not exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    # Table storing secrets; deletion occurs upon retrieval or expiry.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            token_hmac TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        """
    )
    # Table storing audit events; sensitive data is hashed.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            ts INTEGER NOT NULL,
            event TEXT NOT NULL,
            sid_hash TEXT NOT NULL,
            sid_prefix TEXT NOT NULL,
            ct_bytes INTEGER,
            ttl INTEGER,
            ip_hash TEXT NOT NULL,
            ua_hash TEXT NOT NULL
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_events(ts);")
    conn.close()


########################
# Pydantic models
########################
class CreateIn(BaseModel):
    ciphertext: str
    nonce: str
    ttl: Optional[int] = Field(DEFAULT_TTL, ge=60, le=MAX_TTL)

    @field_validator("ciphertext", "nonce")
    def validate_base64(cls, v: str) -> str:
        """Validate value is URL-safe base64."""
        try:
            unb64url(v)
        except Exception:
            raise ValueError("invalid base64url")
        return v


class CreateOut(BaseModel):
    id: str
    auth_token: str


class ConsumeIn(BaseModel):
    id: str
    token: str


class ConsumeOut(BaseModel):
    ciphertext: str
    nonce: str


########################
# FastAPI Application
########################
app = FastAPI(title="Password Burner", docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add strict security headers to responses."""
    response: Response = await call_next(request)
    response.headers.update({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'"
        ),
    })
    return response


########################
# Rate limiting
########################
# Simple in-memory rate limit dictionary; resets every RATE_LIMIT_WINDOW seconds.
_rate_limit_counter = {}
RATE_LIMIT_WINDOW = int(os.getenv("PWB_RL_WINDOW", "10"))
RATE_LIMIT_MAX = int(os.getenv("PWB_RL_MAX", "50"))


def rate_limit(request: Request):
    """Very simple token bucket rate limiting by IP."""
    ip = client_ip(request)
    current_window = now() // RATE_LIMIT_WINDOW
    key = (ip, current_window)
    _rate_limit_counter[key] = _rate_limit_counter.get(key, 0) + 1
    if _rate_limit_counter[key] > RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many requests")


########################
# Audit logging
########################
def audit(event: str, *, sid: str, ct_bytes: Optional[int] = None, ttl: Optional[int] = None, request: Optional[Request] = None):
    """Write an audit entry to the audit_events table."""
    ip = client_ip(request) if request else "0.0.0.0"
    ua = request.headers.get("user-agent", "") if request else ""
    # Build row data with hashed identifiers
    row = (
        now(),
        event,
        hmac_b64(LOG_SALT, sid),
        sid[:6],
        ct_bytes,
        ttl,
        hmac_b64(LOG_SALT, ip),
        sha256_b64(ua),
    )
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_events (ts, event, sid_hash, sid_prefix, ct_bytes, ttl, ip_hash, ua_hash) VALUES (?,?,?,?,?,?,?,?)",
        row
    )
    conn.close()


########################
# Static file routes
########################
@app.get("/", include_in_schema=False)
def index():
    """Serve the home page for creating secrets."""
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return Response(html, media_type="text/html")


@app.get("/s/{secret_id}", include_in_schema=False)
def view_page(secret_id: str):
    """Serve the page for viewing a secret."""
    html = (STATIC_DIR / "view.html").read_text(encoding="utf-8")
    return Response(html, media_type="text/html")


########################
# API endpoints
########################
@app.post("/api/secrets", response_model=CreateOut)
def create_secret(body: CreateIn, request: Request):
    """Store a ciphertext and return a secret ID and auth token."""
    # Rate limit check
    rate_limit(request)
    # Validate ciphertext length (some headroom for overhead vs plaintext)
    ct_len = len(unb64url(body.ciphertext))
    if ct_len > MAX_BYTES * 2:
        raise HTTPException(status_code=413, detail="Secret too large")
    # Generate secret id and token
    secret_id = b64url_bytes(secrets.token_bytes(16))
    auth_token = b64url_bytes(secrets.token_bytes(16))
    token_h = hmac_b64(SERVER_HMAC_SECRET, auth_token)
    expires_at = now() + int(body.ttl)
    # Store record in database
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO secrets (id, token_hmac, ciphertext, nonce, created_at, expires_at) VALUES (?,?,?,?,?,?)",
            (secret_id, token_h, unb64url(body.ciphertext), unb64url(body.nonce), now(), expires_at)
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=500, detail="ID collision, please retry")
    finally:
        conn.close()
    # Record audit event
    audit("create", sid=secret_id, ct_bytes=ct_len, ttl=int(body.ttl), request=request)
    return CreateOut(id=secret_id, auth_token=auth_token)


@app.post("/api/consume", response_model=ConsumeOut)
def consume_secret(body: ConsumeIn, request: Request):
    """Retrieve and delete a secret if the token matches and not expired."""
    rate_limit(request)
    # Compute token HMAC
    token_h = hmac_b64(SERVER_HMAC_SECRET, body.token)
    conn = get_db()
    # Delete row and get ciphertext and nonce atomically
    cursor = conn.execute(
        "DELETE FROM secrets WHERE id=? AND token_hmac=? AND expires_at > ? RETURNING ciphertext, nonce",
        (body.id, token_h, now())
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        # Failed retrieval: either not found, wrong token or expired
        audit("consume_fail", sid=body.id, request=request)
        raise HTTPException(status_code=404, detail="Not found or already consumed")
    # Successful retrieval
    audit("consume_ok", sid=body.id, request=request)
    return ConsumeOut(ciphertext=b64url_bytes(row["ciphertext"]), nonce=b64url_bytes(row["nonce"]))


@app.post("/api/burn")
def burn_secret(body: ConsumeIn, request: Request):
    """Manually burn (delete) a secret without retrieval."""
    rate_limit(request)
    token_h = hmac_b64(SERVER_HMAC_SECRET, body.token)
    conn = get_db()
    cursor = conn.execute(
        "DELETE FROM secrets WHERE id=? AND token_hmac=?",
        (body.id, token_h)
    )
    deleted = cursor.rowcount
    conn.close()
    if deleted == 0:
        audit("consume_fail", sid=body.id, request=request)
        raise HTTPException(status_code=404, detail="Not found or already consumed")
    audit("burn", sid=body.id, request=request)
    return {"status": "burned"}


########################
# Audit export endpoint
########################
@app.get("/admin/export", include_in_schema=False)
def export_audit(request: Request, since: Optional[int] = 0):
    """Export audit events as NDJSON. Requires ADMIN_TOKEN in Authorization header."""
    if ADMIN_TOKEN is None:
        raise HTTPException(status_code=404, detail="Audit export not enabled")
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    ts_from = int(since or 0)
    conn = get_db()
    cursor = conn.execute(
        "SELECT ts, event, sid_hash, sid_prefix, ct_bytes, ttl, ip_hash, ua_hash FROM audit_events WHERE ts >= ? ORDER BY ts ASC",
        (ts_from,)
    )
    lines = [json.dumps(dict(row)) for row in cursor.fetchall()]
    conn.close()
    # Compose NDJSON response
    return Response("\n".join(lines) + ("\n" if lines else ""), media_type="application/x-ndjson")


# Initialize DB tables on import
init_db()