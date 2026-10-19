"""Greekgodx-only, permission-gated Twitch highlights dashboard."""
import hashlib
import hmac
import html
import json
import logging
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ggx")
DATA = Path(os.environ.get("DATA_DIR", "/tmp/ggx")).resolve()
DB = DATA / "clips.sqlite3"
INTERVAL = max(600, int(os.environ.get("SCAN_INTERVAL_SECONDS", "7200")))
LOCK = threading.RLock()
STOP = threading.Event()
SCAN = {"running": False, "last_run": "Never", "message": "Scanning not configured"}
BASIC = HTTPBasic(auto_error=False)

def esc(value):
    return html.escape(str(value or ""), quote=True)

def auth(credentials: HTTPBasicCredentials | None = Depends(BASIC)):
    user = os.environ.get("DASHBOARD_USERNAME", "")
    password = os.environ.get("DASHBOARD_PASSWORD", "")
    if not user or len(password) < 16 or not credentials or not (
        hmac.compare_digest(credentials.username.encode(), user.encode()) and
        hmac.compare_digest(credentials.password.encode(), password.encode())
    ):
        raise HTTPException(401, "Login required", headers={"WWW-Authenticate": 'Basic realm="GGX Private"'})
    return user

def csrf(action, clipid=""):
    key = os.environ.get("DASHBOARD_PASSWORD", "").encode()
    return hmac.new(key, f"{action}:{clipid}".encode(), hashlib.sha256).hexdigest()

def verify_token(action, clipid, token):
    if not hmac.compare_digest(csrf(action, clipid), token):
        raise HTTPException(403, "Expired or invalid action token")

def db_connect():
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    DATA.mkdir(parents=True, exist_ok=True)
    with LOCK, db_connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS clips (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, url TEXT NOT NULL,
            views INTEGER NOT NULL, old_views INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL, checked TEXT NOT NULL,
            created TEXT NOT NULL, duration REAL NOT NULL DEFAULT 0,
            score INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'new',
            note TEXT NOT NULL DEFAULT ''
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS posts (
            clip_id TEXT NOT NULL, platform TEXT NOT NULL, url TEXT NOT NULL,
            PRIMARY KEY (clip_id,platform)
        )""")
        db.commit()

def rights():
    raw = os.environ.get("CREATOR_PERMISSION_JSON", "")
    if not raw:
        raise ValueError("Add documented Greekgodx permission before approving clips.")
    try:
        obj = json.loads(raw)
        valid = (obj.get("creator_login", "").lower() == "greekgodx"
            and obj.get("permission_status") == "approved"
            and bool(obj.get("signed_permission_reference"))
            and obj.get("allowed_editing") is True
            and {"youtube", "tiktok"}.issubset(set(obj.get("allowed_platforms", [])))
            and obj.get("revoked") is False
            and datetime.fromisoformat(obj["expires_on"]).date() >= datetime.now(timezone.utc).date())
    except (ValueError, TypeError, KeyError) as err:
        raise ValueError("Creator permission settings are invalid.") from err
    if not valid:
        raise ValueError("Explicit permission for editing and posting to both channels is not recorded or has expired.")
    return obj

def twitch_clips():
    client_id = os.environ.get("TWITCH_CLIENT_ID")
    client_secret = os.environ.get("TWITCH_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise ValueError("Add Twitch developer CLIENT_ID and CLIENT_SECRET in Render first.")
    with httpx.Client(timeout=30) as client:
        token_response = client.post(
            "https://id.twitch.tv/oauth2/token",
            params={"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"})
        token_response.raise_for_status()
        token = token_response.json()["access_token"]
        headers = {"Client-Id": client_id, "Authorization": f"Bearer {token}"}
        user_response = client.get("https://api.twitch.tv/helix/users", headers=headers, params={"login": "greekgodx"})
        user_response.raise_for_status()
        users = user_response.json().get("data", [])
        if not users or users[0].get("login", "").lower() != "greekgodx":
            raise ValueError("Greekgodx Twitch account not found")
        broadcaster = users[0]["id"]
        start = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat().replace("+00:00", "Z")
        end = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        clips = []
        cursor = None
        for _ in range(3):
            params = {"broadcaster_id": broadcaster, "first": 100, "started_at": start, "ended_at": end}
            if cursor:
                params["after"] = cursor
            response = client.get("https://api.twitch.tv/helix/clips", headers=headers, params=params)
            response.raise_for_status()
            payload = response.json()
            clips.extend(c for c in payload.get("data", []) if c.get("broadcaster_id") == broadcaster)
            cursor = payload.get("pagination", {}).get("cursor")
            if not cursor:
                break
        return clips

def do_scan():
    with LOCK:
        if SCAN["running"]:
            return
        SCAN["running"] = True
    try:
        clips = twitch_clips()
        now = datetime.now(timezone.utc)
        with LOCK, db_connect() as db:
            for clip in clips:
                if not clip.get("id") or not clip.get("url"):
                    continue
                views = int(clip.get("view_count", 0))
                duration = float(clip.get("duration", 0))
                if duration > 180:
                    continue
                old = db.execute("SELECT * FROM clips WHERE id=?", (clip["id"],)).fetchone()
                created_text = clip.get("created_at", now.isoformat())
                try:
                    created = datetime.fromisoformat(created_text.replace("Z", "+00:00"))
                    age_hours = max((now - created).total_seconds()/3600, 1)
                except ValueError:
                    age_hours = 24
                if old:
                    try:
                        elapsed = max((now - datetime.fromisoformat(old["checked"])).total_seconds()/3600, 0.25)
                    except ValueError:
                        elapsed = 2
                    velocity = max(0, views-old["views"])/elapsed
                else:
                    velocity = views/age_hours
                score = min(100, round(24 * math.log1p(max(0, velocity)) / math.log(101) + 12 * math.log1p(views) / math.log(10001)))
                values = (str(clip.get("title", ""))[:250], clip["url"], views, old["views"] if old else 0,
                          now.isoformat(), duration, score, clip["id"])
                if old:
                    db.execute("""UPDATE clips SET title=?,url=?,views=?,old_views=?,checked=?,
                                  duration=?,score=? WHERE id=?""", values)
                else:
                    db.execute("""INSERT INTO clips
                        (id,title,url,views,old_views,first_seen,checked,created,duration,score)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (clip["id"], values[0], values[1], views, 0, now.isoformat(),
                         now.isoformat(), created_text, duration, score))
            db.commit()
        SCAN["message"] = f"Checked {len(clips)} Greekgodx clips."
    except Exception as exc:
        logger.exception("Scan failed")
        SCAN["message"] = f"Scan unavailable: {str(exc)[:180]}"
    finally:
        SCAN["last_run"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        SCAN["running"] = False

def schedule_scans():
    if os.environ.get("SCAN_ENABLED") == "1":
        do_scan()
    while not STOP.wait(INTERVAL):
        if os.environ.get("SCAN_ENABLED") == "1":
            do_scan()

@asynccontextmanager
async def lifespan(app):
    if not os.environ.get("DASHBOARD_USERNAME") or len(os.environ.get("DASHBOARD_PASSWORD", "")) < 16:
        raise RuntimeError("Set DASHBOARD_USERNAME and a 16+ character DASHBOARD_PASSWORD")
    init_db()
    STOP.clear()
    worker = threading.Thread(target=schedule_scans, daemon=True)
    worker.start()
    try:
        yield
    finally:
        STOP.set()
        worker.join(timeout=2)

app = FastAPI(title="Greekgodx Highlights", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

@app.middleware("http")
async def secure_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return response

def page(content):
    style = """body{font-family:system-ui,Arial;background:#10141c;color:#f3f5f8;max-width:980px;margin:40px auto;padding:0 16px}
    h1{font-size:28px}p,small{color:#b8c7d5}a{color:#91c9ff}article{background:#1d2735;padding:18px;margin:12px 0;border:1px solid #35465b;border-radius:13px}
    button,input{font:inherit;border-radius:7px;padding:8px;background:#273c54;color:white;border:1px solid #576e86}
    button{cursor:pointer}form{display:inline-block;margin:5px 10px 3px 0} .pill{display:inline-block;padding:5px 10px;border-radius:20px;background:#354861;font-size:12px}
    .sub{font-size:13px;color:#b4c1d3}"""
    return HTMLResponse(f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Greekgodx Highlights</title><style>{style}</style></head><body><h1>Greekgodx Highlights</h1><p>Private Twitch discovery and review dashboard · <a href="https://www.twitch.tv/greekgodx/clips">Original Twitch clips</a></p>{content}<small>This service does not automatically download, edit or publish videos. Creator and third-party rights must be verified before republishing.</small></body></html>')

@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok"

@app.get("/", response_class=HTMLResponse)
def index(user=Depends(auth)):
    try:
        rights()
        permitted = "Creator permission recorded in configuration."
    except ValueError as err:
        permitted = str(err)
    ready = bool(os.environ.get("TWITCH_CLIENT_ID") and os.environ.get("TWITCH_CLIENT_SECRET"))
    notice = f"<article><b>Scanner:</b> {'enabled' if os.environ.get('SCAN_ENABLED') == '1' else 'disabled'} · Twitch credentials: {'configured' if ready else 'missing'}<p>{esc(SCAN['last_run'])} · {esc(SCAN['message'])}</p><p>{esc(permitted)}</p>"
    notice += f'<form action="/scan" method="post"><input type="hidden" name="token" value="{csrf("scan")}"><button>Scan Twitch now</button></form></article>'
    with LOCK, db_connect() as db:
        clips = db.execute("SELECT * FROM clips ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, score DESC,views DESC LIMIT 100").fetchall()
        posts = {(p["clip_id"], p["platform"]) for p in db.execute("SELECT clip_id,platform FROM posts")}
    blocks = ""
    for c in clips:
        cid = str(c["id"])
        token = csrf("review", cid)
        actions = ""
        if c["status"] == "new":
            actions = (f'<form method="post" action="/review/{quote(cid,safe="")}"><input type="hidden" name="token" value="{token}">'
                '<input type="hidden" name="decision" value="approved"><label><input type="checkbox" required name="checked" value="yes"> Rights and content checked</label> <button>Approve</button></form>'
                f'<form method="post" action="/review/{quote(cid,safe="")}"><input type="hidden" name="token" value="{token}">'
                '<input type="hidden" name="decision" value="rejected"><button>Reject</button></form>')
        elif c["status"] == "approved":
            actions = "<p>Approved for manual review/editing. Downloading and publishing integrations are not connected.</p>"
            for platform in ("youtube", "tiktok"):
                if (cid, platform) not in posts:
                    actions += (f'<form method="post" action="/record/{quote(cid,safe="")}/{platform}">'
                        f'<input type="hidden" name="token" value="{csrf("record:"+platform,cid)}">'
                        f'<input type="url" name="url" required placeholder="Published {platform} URL">'
                        f'<button>Record {platform} post</button></form>')
        blocks += f'<article><span class="pill">{esc(c["status"])}</span> <b>{esc(c["title"])}</b><p>{c["views"]:,} views · ranking {c["score"]}/100 · {c["duration"]:.0f}s · <a href="{esc(c["url"])}" target="_blank" rel="noreferrer">View original clip ↗</a></p>{actions}</article>'
    if not blocks:
        blocks = "<article>No Twitch clips collected yet. Add Twitch API credentials in Render's Environment section, then click Scan Twitch now.</article>"
    return page(notice + blocks)

@app.post("/scan")
def manual_scan(token: str=Form(""),user=Depends(auth)):
    verify_token("scan", "", token)
    threading.Thread(target=do_scan, daemon=True).start()
    return RedirectResponse("/", status_code=303)

@app.post("/review/{clip_id}")
def review(clip_id: str, token: str=Form(""),decision: str=Form(""),checked: str=Form(""),user=Depends(auth)):
    verify_token("review", clip_id, token)
    if decision not in ("approved", "rejected"):
        raise HTTPException(400, "Invalid decision")
    if decision == "approved":
        try:
            rights()
        except ValueError as err:
            raise HTTPException(403, str(err))
        if checked != "yes":
            raise HTTPException(400, "Review confirmation required")
    with LOCK, db_connect() as db:
        row = db.execute("SELECT status FROM clips WHERE id=?", (clip_id,)).fetchone()
        if not row or row["status"] != "new":
            raise HTTPException(404, "Unreviewed clip not found")
        db.execute("UPDATE clips SET status=? WHERE id=?", (decision, clip_id))
        db.commit()
    return RedirectResponse("/", status_code=303)

@app.post("/record/{clip_id}/{platform}")
def record(clip_id: str, platform: str, token: str=Form(""),url: str=Form(""), user=Depends(auth)):
    if platform not in ("youtube", "tiktok"):
        raise HTTPException(400, "Unknown platform")
    verify_token("record:"+platform, clip_id, token)
    try:
        rights()
    except ValueError as err:
        raise HTTPException(403, str(err))
    from urllib.parse import urlparse
    parsed = urlparse(url)
    allowed = {"youtube": ("youtube.com","youtu.be"),"tiktok": ("tiktok.com",)}[platform]
    if parsed.scheme != "https" or not any(parsed.hostname == host or (parsed.hostname or "").endswith("."+host) for host in allowed):
        raise HTTPException(400, "Use a valid platform HTTPS URL")
    with LOCK, db_connect() as db:
        row = db.execute("SELECT status FROM clips WHERE id=?", (clip_id,)).fetchone()
        if not row or row["status"] != "approved":
            raise HTTPException(404, "Approved clip not found")
        db.execute("INSERT OR REPLACE INTO posts(clip_id,platform,url) VALUES(?,?,?)", (clip_id,platform,url))
        db.commit()
    return RedirectResponse("/", status_code=303)
