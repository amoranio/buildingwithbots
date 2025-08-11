#!/usr/bin/env bash
set -euo pipefail

# ===== Args =====
DOMAIN=""
EMAIL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email)  EMAIL="$2";  shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ===== Constants =====
APP_USER="pwburner"
APP_GROUP=""                         # will default to APP_USER after creation
APP_DIR="/srv/pwburner"
APP_CODE_DIR="$APP_DIR/app"
APP_STATIC_DIR="$APP_DIR/static"
APP_VENV="$APP_DIR/venv"
ENV_DIR="/etc/pwburner"
ENV_FILE="$ENV_DIR/pwb.env"
SYSTEMD_UNIT="/etc/systemd/system/pwburner.service"
NGINX_SITE="/etc/nginx/sites-available/pwburner"
NGINX_LINK="/etc/nginx/sites-enabled/pwburner"

# ===== Helpers =====
is_debian_like() {
  [[ -r /etc/os-release ]] || return 1
  . /etc/os-release
  case "${ID_LIKE:-$ID}" in
    *debian*|debian|ubuntu) return 0 ;;
    *) return 1 ;;
  esac
}
has_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
in_container() { ! has_systemd || grep -qiE '(docker|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; }

# ===== OS check =====
echo "[0/10] OS check..."
if ! is_debian_like; then
  echo "This installer targets Debian/Ubuntu. Aborting."
  exit 1
fi

# ===== Install packages =====
echo "[1/10] Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release \
  python3 python3-venv python3-pip sqlite3 \
  nginx ufw openssl
if [[ -n "$DOMAIN" ]]; then
  apt-get install -y --no-install-recommends certbot python3-certbot-nginx
fi

# ===== Python version check =====
echo "[2/10] Checking Python version..."
PYV=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYMAJOR=${PYV%%.*}; PYMINOR=${PYV#*.}
if (( PYMAJOR < 3 || (PYMAJOR == 3 && PYMINOR < 10) )); then
  echo "Python 3.10+ required (found $PYV). Aborting."
  exit 1
fi

# ===== System user & dirs (robust on minimal Debian 13) =====
echo "[3/10] Creating user and directories..."
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  if command -v adduser >/dev/null 2>&1; then
    adduser --system --group --home "$APP_DIR" "$APP_USER"
  else
    # Ensure shadow tools exist, then create user and its group (-U)
    apt-get install -y -qq passwd adduser || true
    if command -v adduser >/dev/null 2>&1; then
      adduser --system --group --home "$APP_DIR" "$APP_USER"
    else
      useradd -r -m -d "$APP_DIR" -s /usr/sbin/nologin -U "$APP_USER"
    fi
  fi
fi
APP_GROUP="${APP_GROUP:-$APP_USER}"

mkdir -p "$APP_CODE_DIR" "$APP_STATIC_DIR" "$ENV_DIR"
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
chmod 750 "$APP_DIR" "$APP_CODE_DIR" "$APP_STATIC_DIR"
chmod 750 "$ENV_DIR"

# ===== Python venv + deps =====
echo "[4/10] Creating venv and installing deps..."
python3 -m venv "$APP_VENV"
# shellcheck disable=SC1091
source "$APP_VENV/bin/activate"
python -m pip install --upgrade pip
cat > "$APP_DIR/requirements.txt" <<'REQS'
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.8.2
REQS
pip install -r "$APP_DIR/requirements.txt"

# ===== Application code =====
echo "[5/10] Writing application code..."
# ----- app.py -----
cat > "$APP_CODE_DIR/app.py" <<'PY'
import base64, hashlib, hmac, json, os, secrets, sqlite3, time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

DATA_DIR   = Path(os.getenv("PWB_DATA_DIR", "/srv/pwburner/app"))
STATIC_DIR = Path(os.getenv("PWB_STATIC_DIR", "/srv/pwburner/static"))
DB_PATH    = DATA_DIR / "data.db"

DEFAULT_TTL = int(os.getenv("PWB_DEFAULT_TTL", "3600"))
MAX_TTL     = int(os.getenv("PWB_MAX_TTL", "604800"))
MAX_BYTES   = int(os.getenv("PWB_MAX_SECRET_BYTES", "16384"))
SERVER_HMAC_SECRET = base64.b64decode(os.environ["SERVER_HMAC_SECRET"])
LOG_SALT           = base64.b64decode(os.environ["LOG_SALT"])
ADMIN_TOKEN        = os.getenv("ADMIN_TOKEN", "")

now = lambda: int(time.time())
def b64url_bytes(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64url(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def hmac_b64(key: bytes, data: str) -> str: return b64url_bytes(hmac.new(key, data.encode(), "sha256").digest())
def sha256_b64(s: str) -> str: return b64url_bytes(hashlib.sha256(s.encode()).digest())

def client_ip(req: Request) -> str:
    xf = req.headers.get("x-forwarded-for")
    return xf.split(",")[0].strip() if xf else (req.client.host if req.client else "0.0.0.0")

def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA foreign_keys=ON;")
    con.execute("PRAGMA synchronous=NORMAL;")
    return con

def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = db()
    con.execute("""
    CREATE TABLE IF NOT EXISTS secrets(
      id TEXT PRIMARY KEY,
      token_hmac TEXT NOT NULL,
      ciphertext BLOB NOT NULL,
      nonce BLOB NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );""")
    con.execute("""
    CREATE TABLE IF NOT EXISTS audit_events(
      ts INTEGER NOT NULL,
      event TEXT NOT NULL,
      sid_hash TEXT NOT NULL,
      sid_prefix TEXT NOT NULL,
      ct_bytes INTEGER,
      ttl INTEGER,
      ip_hash TEXT NOT NULL,
      ua_hash TEXT NOT NULL
    );""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_events(ts);")
    con.close()
init_db()

class CreateIn(BaseModel):
    ciphertext: str
    nonce: str
    ttl: Optional[int] = Field(default=DEFAULT_TTL, ge=60, le=MAX_TTL)
    @field_validator("ciphertext","nonce")
    @classmethod
    def _b64(cls,v:str)->str:
        try: unb64url(v)
        except: raise ValueError("invalid base64url")
        return v

class CreateOut(BaseModel): id: str; auth_token: str
class ConsumeIn(BaseModel): id: str; token: str
class ConsumeOut(BaseModel): ciphertext: str; nonce: str

app = FastAPI(title="Password Burner", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.middleware("http")
async def sec_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers.update({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy":
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    })
    return resp

_RL = {}; RL_WIN=10; RL_MAX=50
def rate_limit(req: Request):
    t = now() // RL_WIN; key = (client_ip(req), t)
    _RL[key] = _RL.get(key,0)+1
    if _RL[key] > RL_MAX: raise HTTPException(429, "Too many requests")

def audit(event:str, *, sid:str, ct_bytes:int|None=None, ttl:int|None=None, req:Request|None=None):
    ip = client_ip(req) if req else "0.0.0.0"
    ua = req.headers.get("user-agent","") if req else ""
    row = ( now(), event,
            hmac_b64(LOG_SALT,sid), sid[:6], ct_bytes, ttl,
            hmac_b64(LOG_SALT,ip), sha256_b64(ua))
    c=db(); c.execute("INSERT INTO audit_events(ts,event,sid_hash,sid_prefix,ct_bytes,ttl,ip_hash,ua_hash) VALUES (?,?,?,?,?,?,?,?)", row); c.close()

@app.get("/", include_in_schema=False)
def index():
    return Response((STATIC_DIR/"index.html").read_text(encoding="utf-8"), media_type="text/html")

@app.get("/s/{secret_id}", include_in_schema=False)
def view(secret_id: str):
    return Response((STATIC_DIR/"view.html").read_text(encoding="utf-8"), media_type="text/html")

@app.post("/api/secrets", response_model=CreateOut)
def create_secret(body: CreateIn, request: Request):
    rate_limit(request)
    ct_len = len(unb64url(body.ciphertext))
    if ct_len > MAX_BYTES*2: raise HTTPException(413, "Secret too large")
    sid  = b64url_bytes(secrets.token_bytes(16))
    tok  = b64url_bytes(secrets.token_bytes(16))
    tokh = hmac_b64(SERVER_HMAC_SECRET, tok)
    exp  = now()+int(body.ttl)
    c=db()
    try:
        c.execute("INSERT INTO secrets(id,token_hmac,ciphertext,nonce,created_at,expires_at) VALUES (?,?,?,?,?,?)",
                  (sid, tokh, unb64url(body.ciphertext), unb64url(body.nonce), now(), exp))
    except sqlite3.IntegrityError:
        raise HTTPException(500, "Collision, retry")
    finally:
        c.close()
    audit("create", sid=sid, ct_bytes=ct_len, ttl=int(body.ttl), req=request)
    return CreateOut(id=sid, auth_token=tok)

@app.post("/api/consume", response_model=ConsumeOut)
def consume(body: ConsumeIn, request: Request):
    rate_limit(request)
    tokh = hmac_b64(SERVER_HMAC_SECRET, body.token)
    c=db()
    cur=c.execute("DELETE FROM secrets WHERE id=? AND token_hmac=? AND expires_at>? RETURNING ciphertext,nonce",
                  (body.id, tokh, now()))
    row=cur.fetchone(); c.close()
    if not row:
        audit("consume_fail", sid=body.id, req=request)
        raise HTTPException(404, "Not found or already consumed")
    audit("consume_ok", sid=body.id, req=request)
    return ConsumeOut(ciphertext=b64url_bytes(row["ciphertext"]), nonce=b64url_bytes(row["nonce"]))

@app.post("/api/burn")
def burn(body: ConsumeIn, request: Request):
    rate_limit(request)
    tokh = hmac_b64(SERVER_HMAC_SECRET, body.token)
    c=db(); cur=c.execute("DELETE FROM secrets WHERE id=? AND token_hmac=?", (body.id, tokh))
    deleted=cur.rowcount; c.close()
    if not deleted:
        audit("consume_fail", sid=body.id, req=request)
        raise HTTPException(404, "Not found or already consumed")
    audit("burn", sid=body.id, req=request)
    return {"status":"burned"}
PY

# ----- static files -----
cat > "$APP_STATIC_DIR/index.html" <<'HTML'
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Password Burner — Create</title><meta name="robots" content="noindex,nofollow">
<link rel="stylesheet" href="/static/styles.css"></head><body>
<main><h1>One-time Secret</h1>
<p>Enter a secret. It’s encrypted locally; the server never sees it. You’ll get a one-time link.</p>
<label for="secret">Secret</label>
<textarea id="secret" maxlength="16000" placeholder="Paste password, token…"></textarea>
<label for="ttl">Expires in</label>
<select id="ttl">
<option value="600">10 minutes</option>
<option value="3600" selected>1 hour</option>
<option value="86400">24 hours</option>
<option value="604800">7 days</option>
</select>
<button id="createBtn">Create one-time link</button>
<section id="result" hidden>
<h2>Your link</h2><input id="link" readonly>
<p class="hint">Share this link once. The decryption key lives in the <code>#fragment</code> and never reaches our server.</p>
</section>
<p id="error" class="error" hidden></p></main>
<script src="/static/create.js" defer></script></body></html>
HTML

cat > "$APP_STATIC_DIR/view.html" <<'HTML'
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Password Burner — View</title><meta name="robots" content="noindex,nofollow">
<link rel="stylesheet" href="/static/styles.css"></head><body>
<main><h1>One-time Secret</h1>
<div id="loading">Fetching…</div>
<pre id="secret" hidden></pre>
<p id="state" class="hint" hidden></p>
<p id="error" class="error" hidden></p>
<button id="burn" hidden>Burn now</button>
</main><script src="/static/view.js" defer></script></body></html>
HTML

cat > "$APP_STATIC_DIR/create.js" <<'JS'
async function genKey(){const k=await crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]);const raw=new Uint8Array(await crypto.subtle.exportKey("raw",k));return{key:k,raw}}
function b64url(b){return btoa(String.fromCharCode(...b)).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"")}
function u8(s){return new TextEncoder().encode(s)}
async function enc(text,key){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,u8(text)));return{iv,ct}}
document.getElementById("createBtn").addEventListener("click",async()=>{
 const secret=document.getElementById("secret").value;
 const ttl=parseInt(document.getElementById("ttl").value,10);
 const err=document.getElementById("error"); err.hidden=true;
 if(!secret.trim()){err.textContent="Please enter a secret."; err.hidden=false; return}
 if(secret.length>16000){err.textContent="Secret too large."; err.hidden=false; return}
 try{
  const {key,raw}=await genKey();
  const {iv,ct}=await enc(secret,key);
  const res=await fetch("/api/secrets",{method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({ciphertext:b64url(ct),nonce:b64url(iv),ttl})});
  if(!res.ok) throw new Error((await res.json()).detail||"Failed to create secret");
  const {id,auth_token}=await res.json();
  const link=`${location.origin}/s/${encodeURIComponent(id)}#${b64url(raw)}.${auth_token}`;
  document.getElementById("result").hidden=false; const l=document.getElementById("link"); l.value=link; l.select();
 }catch(e){err.textContent=e.message||String(e); err.hidden=false}
});
JS

cat > "$APP_STATIC_DIR/view.js" <<'JS'
function parseFrag(){const f=location.hash.slice(1); if(!f.includes(".")) return {}; const [k,t]=f.split(".",2); return{keyPart:k,token:t}}
function unb64(s){s=s.replaceAll("-","+").replaceAll("_","/"); while(s.length%4) s+="="; const bin=atob(s); const out=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out}
async function importKey(raw){return crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"])}
async function dec(ct,iv,key){const p=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct); return new TextDecoder().decode(new Uint8Array(p))}
(async()=>{
 const err=document.getElementById("error"); const state=document.getElementById("state");
 const pre=document.getElementById("secret"); const burn=document.getElementById("burn");
 const loading=document.getElementById("loading");
 try{
  const {keyPart,token}=parseFrag(); const id=decodeURIComponent(location.pathname.split("/").pop()||"");
  if(!keyPart||!token||!id) throw new Error("Invalid link.");
  const r=await fetch("/api/consume",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id,token})});
  if(!r.ok) throw new Error((await r.json()).detail||"Not found or already consumed.");
  const {ciphertext,nonce}=await r.json();
  const key=await importKey(unb64(keyPart));
  const txt=await dec(unb64(ciphertext),unb64(nonce),key);
  loading.hidden=true; pre.textContent=txt; pre.hidden=false;
  state.textContent="This secret is now burned. Copy it if you need it — it cannot be retrieved again."; state.hidden=false;
  window.addEventListener("beforeunload",()=>{try{navigator.sendBeacon("/api/burn",new Blob([JSON.stringify({id,token})],{type:"application/json"}))}catch{}});
  burn.hidden=false; burn.addEventListener("click",async()=>{await fetch("/api/burn",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id,token})}); state.textContent="Secret burned."; burn.disabled=true;});
 }catch(e){loading.hidden=true; err.textContent=e.message||String(e); err.hidden=false}
})();
JS

cat > "$APP_STATIC_DIR/styles.css" <<'CSS'
html,body{margin:0;font:16px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#111;background:#fff}
main{max-width:720px;margin:2rem auto;padding:0 1rem}
h1{margin-top:0}label{display:block;margin:.75rem 0 .25rem;font-weight:600}
textarea{width:100%;min-height:10rem}input#link{width:100%}
button{margin-top:1rem;padding:.6rem 1rem;cursor:pointer}.hint{color:#444}.error{color:#a00}
pre{background:#f6f6f6;padding:1rem;overflow:auto}
CSS

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

# ===== Secrets / env =====
echo "[6/10] Generating secrets & environment..."
if [[ ! -f "$ENV_FILE" ]]; then
  umask 077
  SERVER_HMAC_SECRET="$(openssl rand -base64 32)"
  LOG_SALT="$(openssl rand -base64 32)"
  ADMIN_TOKEN="$(openssl rand -hex 24)"
  cat > "$ENV_FILE" <<ENV
PWB_DATA_DIR=$APP_CODE_DIR
PWB_STATIC_DIR=$APP_STATIC_DIR
PWB_DEFAULT_TTL=3600
PWB_MAX_TTL=604800
PWB_MAX_SECRET_BYTES=16384
SERVER_HMAC_SECRET=$SERVER_HMAC_SECRET
LOG_SALT=$LOG_SALT
ADMIN_TOKEN=$ADMIN_TOKEN
ENV
  chown root:root "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

# ===== systemd unit =====
echo "[7/10] Configuring systemd service..."
cat > "$SYSTEMD_UNIT" <<SYSTEMD
[Unit]
Description=Password Burner (FastAPI)
After=network.target

[Service]
User=$APP_USER
Group=$APP_GROUP
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_DIR
ExecStart=$APP_VENV/bin/uvicorn app.app:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips="*" --access-log off
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SYSTEMD

if has_systemd && ! in_container; then
  systemctl daemon-reload
  systemctl enable --now pwburner
else
  echo "-> Skipping systemd start (container or no systemd). To run manually:"
  echo "   $APP_VENV/bin/uvicorn app.app:app --host 0.0.0.0 --port 8000"
fi

# ===== Nginx (and TLS) =====
echo "[8/10] Configuring Nginx..."
# Avoid default-site server_name '_' conflict on Debian
rm -f /etc/nginx/sites-enabled/default || true

cat > "$NGINX_SITE" <<NGINX
server {
    listen 80;
    server_name ${DOMAIN:-_};
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    # Certbot will insert HTTPS redirect if --domain is used
}
NGINX

ln -sf "$NGINX_SITE" "$NGINX_LINK"
nginx -t
if has_systemd && ! in_container; then
  systemctl reload nginx || true
else
  echo "-> In container/no systemd: start Nginx manually if needed: nginx"
fi

if [[ -n "$DOMAIN" ]] && has_systemd && ! in_container; then
  echo "[8b/10] Requesting Let's Encrypt certificate for $DOMAIN..."
  if [[ -n "$EMAIL" ]]; then
    certbot --nginx -d "$DOMAIN" --redirect --agree-tos -m "$EMAIL" --no-eff-email || true
  else
    certbot --nginx -d "$DOMAIN" --redirect --agree-tos --register-unsafely-without-email || true
  fi
else
  [[ -n "$DOMAIN" ]] && echo "-> Skipped certbot (container or no systemd)."
fi

# ===== Firewall =====
echo "[9/10] Configuring UFW..."
if command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH || true
  ufw allow 'Nginx Full' || true
  if has_systemd && ! in_container; then
    yes | ufw enable || true
  else
    echo "-> Skipping 'ufw enable' (container/no systemd)."
  fi
fi

echo "[10/10] Done."
if [[ -n "$DOMAIN" ]]; then
  echo "Open: https://${DOMAIN}/"
else
  ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "Open: http://${ip:-127.0.0.1}/  (Consider adding a domain + TLS later.)"
fi
echo "Admin audit export token is in $ENV_FILE (ADMIN_TOKEN)."
