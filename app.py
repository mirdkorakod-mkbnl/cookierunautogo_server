"""
License Server สำหรับระบบใบอนุญาต 2 แบบ: rental (เช่ามีวันหมดอายุ) และ permanent (ถาวร)

ฐานข้อมูล: PostgreSQL (ผ่าน environment variable DATABASE_URL) เพื่อให้ข้อมูล License
คงอยู่ถาวร ไม่หายเมื่อเซิร์ฟเวอร์ redeploy/restart/spin down (ต่างจาก SQLite ไฟล์เดี่ยว
ซึ่งจะหายไปทุกครั้งที่ instance เปลี่ยนบน Render Free tier)

Endpoints สำหรับผู้ใช้ปลายทาง (โปรแกรมบอทเรียกใช้):
    POST /activate   -> ผูก license key เข้ากับเครื่อง (ครั้งแรกที่ใช้คีย์)
    POST /validate    -> เช็คว่า license ยังใช้ได้อยู่ไหม (เรียกซ้ำเป็นระยะ)
    GET  /version      -> เช็คเวอร์ชันล่าสุดของโปรแกรม (สำหรับระบบแจ้งเตือนอัปเดต)

Endpoints สำหรับแอดมิน (ต้องแนบ header X-Admin-Token ให้ตรงกับ ADMIN_TOKEN):
    POST /admin/generate  -> สร้าง license key ใหม่ (rental หรือ permanent)
    POST /admin/revoke     -> เพิกถอน license key
    POST /admin/unbind      -> ปลดผูกเครื่องของ license key (ให้ย้ายเครื่องใหม่ได้)
    GET  /admin/licenses    -> ดูรายการ license ทั้งหมด (JSON)
    GET  /admin/dashboard   -> หน้าเว็บจัดการ License ทั้งหมดผ่านเบราว์เซอร์
"""

import os
import time
import hmac
import secrets
import string
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

DATABASE_URL = os.environ.get("DATABASE_URL")

# ⚠️ ห้ามตั้งค่า default ให้ ADMIN_TOKEN เด็ดขาด (เช่น os.environ.get("ADMIN_TOKEN",
# "some-default")) เพราะไฟล์นี้อยู่ใน repo Public บน GitHub - ค่า default ใดๆ ที่
# เขียนไว้ตรงนี้เท่ากับประกาศรหัสผ่านแอดมินให้ทุกคนที่เข้าถึง repo เห็นได้เลย
# ถ้าลืมตั้ง environment variable ต้อง "รันไม่ขึ้น" (fail-safe) ไม่ใช่ "เงียบๆ ใช้
# ค่า default ที่รู้กันแทน" (fail-open) - หลักการเดียวกับ DATABASE_URL ด้านล่าง
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

if not DATABASE_URL:
    raise RuntimeError(
        "ไม่พบ environment variable DATABASE_URL — ต้องตั้งค่า connection string ของ "
        "PostgreSQL ก่อนรันเซิร์ฟเวอร์ (เช่น จาก Supabase: Project Settings > Database > "
        "Connection string)"
    )

if not ADMIN_TOKEN:
    raise RuntimeError(
        "ไม่พบ environment variable ADMIN_TOKEN — ต้องตั้งค่านี้ก่อนรันเซิร์ฟเวอร์เสมอ "
        "(ห้ามใช้ค่า default เด็ดขาด เพราะไฟล์นี้เป็น public repo) ตั้งเป็นค่าสุ่มที่คาดเดา"
        "ยากอย่างน้อย 32 ตัวอักษร เช่นใช้คำสั่ง python -c \"import secrets; "
        "print(secrets.token_urlsafe(32))\" เพื่อสร้างค่าที่ปลอดภัย"
    )

app = FastAPI(title="AutoGo License Server")


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------
# ใช้ connection pool แทนการเปิด-ปิด connection ใหม่ทุกครั้ง เพื่อรองรับ
# หลาย request พร้อมกันได้อย่างมีประสิทธิภาพ (minconn=1, maxconn=10 เพียงพอ
# สำหรับปริมาณการใช้งานระดับนี้)
_pool = psycopg2.pool.SimpleConnectionPool(1, 10, dsn=DATABASE_URL)


@contextmanager
def get_db():
    conn = _pool.getconn()
    try:
        yield conn
    finally:
        _pool.putconn(conn)


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    license_key  TEXT PRIMARY KEY,
                    license_type TEXT NOT NULL,              -- 'rental' หรือ 'permanent'
                    created_at   TEXT NOT NULL,
                    expires_at   TEXT,                        -- NULL สำหรับ permanent
                    machine_id   TEXT,                         -- ผูกเครื่องตอน activate ครั้งแรก
                    status       TEXT NOT NULL DEFAULT 'active', -- 'active' หรือ 'revoked'
                    note         TEXT,
                    last_seen_at TEXT
                )
            """)
        conn.commit()


init_db()


def gen_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "-".join(parts)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


# ---------------------------------------------------------
# MODELS
# ---------------------------------------------------------
class ActivateRequest(BaseModel):
    license_key: str
    machine_id: str


class ValidateRequest(BaseModel):
    license_key: str
    machine_id: str


class GenerateRequest(BaseModel):
    license_type: str          # 'rental' หรือ 'permanent'
    days: Optional[int] = None  # จำเป็นสำหรับ rental
    count: int = 1
    note: Optional[str] = None


class RevokeRequest(BaseModel):
    license_key: str


def check_admin(token: Optional[str]):
    # ใช้ hmac.compare_digest() แทน != ธรรมดา เพราะ != เทียบทีละตัวอักษรแล้ว
    # คืนผลทันทีที่เจอตัวแรกที่ไม่ตรง - เวลาที่ใช้ตอบสนองจะสั้น/ยาวต่างกันตาม
    # จำนวนตัวอักษรที่ตรงกัน (มากตัวตรง = ใช้เวลานานกว่าเล็กน้อย) ผู้โจมตีที่
    # วัดเวลาตอบสนองอย่างละเอียดสามารถไล่เดา token ทีละตัวอักษรได้ (timing
    # attack) compare_digest() ใช้เวลาคงที่เสมอไม่ว่าจะตรงกี่ตัวอักษร จึงไม่รั่ว
    # ข้อมูลผ่านเวลาตอบสนอง - ต้องเช็ค token ไม่ใช่ None/ว่างเปล่าก่อนเสมอ เพราะ
    # compare_digest() โยน TypeError ถ้าได้ None เข้ามา
    if not ADMIN_TOKEN or not token or not hmac.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized: ADMIN_TOKEN ไม่ถูกต้อง")


# ---------------------------------------------------------
# RATE LIMITING
# ---------------------------------------------------------
# In-memory sliding-window rate limiter แบบง่าย ไม่ต้องพึ่ง library ภายนอก
# เพิ่ม (เช่น slowapi/redis) - เก็บ timestamp ของ request ล่าสุดแยกตาม
# (endpoint, IP) จำกัดจำนวน request ต่อช่วงเวลาที่กำหนด กันคนยิงรัวๆ เดา
# ADMIN_TOKEN หรือลอง license_key สุ่มๆ ซ้ำๆ
#
# ⚠️ ข้อจำกัด: state เก็บอยู่ใน memory ของ process เดียว ถ้า deploy แบบมีหลาย
# instance/worker พร้อมกัน แต่ละตัวจะนับแยกกันไม่ synced กัน (ทำให้ limit จริง
# สูงกว่าที่ตั้งไว้ N เท่า ตาม N instance) สำหรับปริมาณการใช้งานระดับนี้ (deploy
# บน Render แบบ instance เดียว) เพียงพอแล้ว ถ้าอนาคตขยายเป็นหลาย instance ค่อย
# ย้ายไปใช้ Redis-based rate limiter แทน
_rate_limit_buckets = defaultdict(deque)


def rate_limit(key_prefix: str, max_requests: int, window_seconds: int):
    """
    คืนค่าเป็น FastAPI dependency function - ใส่ใน dependencies=[...] ของแต่ละ
    endpoint ที่ต้องการจำกัดอัตรา ตัวอย่าง:
        @app.post("/activate", dependencies=[Depends(rate_limit("activate", 10, 60))])
    """

    def dependency(request: Request):
        client_ip = request.client.host if request.client else "unknown"
        bucket_key = f"{key_prefix}:{client_ip}"
        now = time.time()
        bucket = _rate_limit_buckets[bucket_key]

        # ทิ้ง timestamp ที่เก่าเกิน window ออกจากหน้าคิว (sliding window)
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

        if len(bucket) >= max_requests:
            raise HTTPException(
                status_code=429,
                detail=f"เรียกใช้งานถี่เกินไป กรุณาลองใหม่อีกครั้งภายใน {window_seconds} วินาที",
            )

        bucket.append(now)

    return dependency


# ---------------------------------------------------------
# ENDPOINTS: USER-FACING
# ---------------------------------------------------------
@app.post("/activate", dependencies=[Depends(rate_limit("activate", 10, 60))])
def activate(req: ActivateRequest):
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s", (req.license_key,))
            row = cur.fetchone()

            if row is None:
                raise HTTPException(status_code=404, detail="ไม่พบ License Key นี้ในระบบ")

            if row["status"] == "revoked":
                raise HTTPException(status_code=403, detail="License นี้ถูกเพิกถอนแล้ว")

            if row["license_type"] == "rental" and row["expires_at"]:
                if parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
                    raise HTTPException(status_code=403, detail="License นี้หมดอายุแล้ว")

            if row["machine_id"] is None:
                # activate ครั้งแรก -> ผูกกับเครื่องนี้เลย
                cur.execute(
                    "UPDATE licenses SET machine_id = %s, last_seen_at = %s WHERE license_key = %s",
                    (req.machine_id, now_iso(), req.license_key),
                )
                conn.commit()
            elif row["machine_id"] != req.machine_id:
                raise HTTPException(
                    status_code=403,
                    detail="License นี้ถูกใช้งานกับเครื่องอื่นไปแล้ว กรุณาติดต่อผู้ขายเพื่อย้ายเครื่อง",
                )
            else:
                cur.execute(
                    "UPDATE licenses SET last_seen_at = %s WHERE license_key = %s",
                    (now_iso(), req.license_key),
                )
                conn.commit()

            return {
                "valid": True,
                "license_type": row["license_type"],
                "expires_at": row["expires_at"],
            }


@app.post("/validate", dependencies=[Depends(rate_limit("validate", 30, 60))])
def validate(req: ValidateRequest):
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s", (req.license_key,))
            row = cur.fetchone()

            if row is None:
                return {"valid": False, "reason": "not_found"}

            if row["status"] == "revoked":
                return {"valid": False, "reason": "revoked"}

            if row["machine_id"] != req.machine_id:
                return {"valid": False, "reason": "machine_mismatch"}

            if row["license_type"] == "rental" and row["expires_at"]:
                if parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
                    return {"valid": False, "reason": "expired"}

            cur.execute(
                "UPDATE licenses SET last_seen_at = %s WHERE license_key = %s",
                (now_iso(), req.license_key),
            )
            conn.commit()

            return {
                "valid": True,
                "license_type": row["license_type"],
                "expires_at": row["expires_at"],
            }


# ---------------------------------------------------------
# ENDPOINTS: ADMIN
# ---------------------------------------------------------
@app.post("/admin/generate", dependencies=[Depends(rate_limit("admin", 20, 60))])
def admin_generate(req: GenerateRequest, x_admin_token: Optional[str] = Header(default=None)):
    check_admin(x_admin_token)

    if req.license_type not in ("rental", "permanent", "admin"):
        raise HTTPException(status_code=400, detail="license_type ต้องเป็น 'rental', 'permanent' หรือ 'admin'")

    if req.license_type == "rental" and not req.days:
        raise HTTPException(status_code=400, detail="ต้องระบุจำนวนวัน (days) สำหรับ rental")

    created = []

    with get_db() as conn:
        with conn.cursor() as cur:
            for _ in range(max(1, req.count)):
                key = gen_key()
                expires_at = None
                if req.license_type == "rental":
                    expires_at = (datetime.now(timezone.utc) + timedelta(days=req.days)).isoformat()

                cur.execute(
                    "INSERT INTO licenses (license_key, license_type, created_at, expires_at, note) "
                    "VALUES (%s,%s,%s,%s,%s)",
                    (key, req.license_type, now_iso(), expires_at, req.note),
                )
                created.append(
                    {"license_key": key, "license_type": req.license_type, "expires_at": expires_at}
                )
            conn.commit()

    return {"created": created}


@app.post("/admin/revoke", dependencies=[Depends(rate_limit("admin", 20, 60))])
def admin_revoke(req: RevokeRequest, x_admin_token: Optional[str] = Header(default=None)):
    check_admin(x_admin_token)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET status='revoked' WHERE license_key=%s", (req.license_key,))
            conn.commit()

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="ไม่พบ License Key นี้")

    return {"revoked": req.license_key}


@app.post("/admin/unbind", dependencies=[Depends(rate_limit("admin", 20, 60))])
def admin_unbind(req: RevokeRequest, x_admin_token: Optional[str] = Header(default=None)):
    """เคลียร์ machine_id ออก เผื่อลูกค้าต้องการย้ายไปใช้กับเครื่องใหม่"""
    check_admin(x_admin_token)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE licenses SET machine_id=NULL WHERE license_key=%s", (req.license_key,))
            conn.commit()

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="ไม่พบ License Key นี้")

    return {"unbound": req.license_key}


@app.get("/admin/licenses", dependencies=[Depends(rate_limit("admin_list", 40, 60))])
def admin_list(x_admin_token: Optional[str] = Header(default=None)):
    check_admin(x_admin_token)

    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
            rows = cur.fetchall()
            return [dict(r) for r in rows]


@app.get("/")
def root():
    return {"status": "ok", "service": "cookierun-bot-license-server"}


# ---------------------------------------------------------
# LANDING PAGE (หน้าขาย/ดาวน์โหลดสำหรับลูกค้า)
# ---------------------------------------------------------
# โลโก้โปรแกรม (CookieRunAutoGo) แปลงเป็น base64 ฝังตรงในหน้าเว็บเลย ไม่ต้องพึ่งไฟล์/hosting แยก
LOGO_BASE64 = "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"


SHOP_HTML = r"""
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<title>CookieRunAutoGo — ฟาร์มอัตโนมัติ ไม่ต้องนั่งเฝ้าจอ</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="โปรแกรมช่วยเล่นเกมมือถือแนววิ่งเก็บของอัตโนมัติ ตั้งค่า Boost, เก็บ Gift Box, ส่งหัวใจให้เพื่อน ทำงานต่อเนื่องโดยไม่ต้องนั่งเฝ้าจอ">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chonburi&family=Kanit:wght@500;600;700&family=Noto+Sans+Thai:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0B1326;
    --bg-panel: #141F35;
    --bg-panel-2: #1C2A45;
    --border: #2A3F5F;
    --text: #F0F4F8;
    --text-muted: #8FA3C4;
    --orange: #F0781A;
    --orange-dark: #C85F0A;
    --cyan: #3DE0E0;
    --red: #DC3C28;
  }

  * { box-sizing: border-box; }

  html { scroll-behavior: smooth; }

  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: "Noto Sans Thai", sans-serif;
    line-height: 1.6;
  }

  h1, h2, h3 { font-family: "Chonburi", cursive; font-weight: 400; margin: 0; }
  .eyebrow, .price, .btn, nav a, .badge { font-family: "Kanit", sans-serif; }

  a { color: inherit; }

  img, svg { max-width: 100%; }

  .wrap { max-width: 1080px; margin: 0 auto; padding: 0 24px; }

  /* ---------------- NAV ---------------- */
  nav {
    position: sticky; top: 0; z-index: 50;
    background: rgba(36, 24, 18, 0.92);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
  }
  nav .wrap { display: flex; align-items: center; justify-content: space-between; padding: 14px 24px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 18px; }
  .brand .logo-mark { width: 32px; height: 32px; border-radius: 50%; display: block; }
  nav .links { display: flex; gap: 22px; font-size: 14px; font-weight: 500; }
  nav .links a { text-decoration: none; color: var(--text-muted); transition: color 0.15s; }
  nav .links a:hover, nav .links a:focus-visible { color: var(--orange); }

  /* ---------------- HERO ---------------- */
  .hero { padding: 56px 0 40px; text-align: center; }
  .hero-logo {
    width: 120px; height: 120px; border-radius: 50%; margin-bottom: 20px;
    box-shadow: 0 0 0 3px var(--border), 0 8px 30px rgba(61, 224, 224, 0.15);
  }
  .product-tag {
    font-family: "Kanit", sans-serif; font-size: 13.5px; font-weight: 600;
    color: var(--text-muted); margin-bottom: 16px; letter-spacing: 0.02em;
  }
  .product-tag span { color: var(--orange); }
  .status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    background: var(--bg-panel); border: 1px solid var(--border);
    border-radius: 999px; padding: 7px 16px; font-size: 13px; color: var(--cyan);
    margin-bottom: 28px;
  }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%; background: var(--cyan);
    box-shadow: 0 0 0 0 rgba(61,224,224,0.6);
    animation: pulse 1.8s infinite;
  }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(61,224,224,0.55); }
    70% { box-shadow: 0 0 0 8px rgba(61,224,224,0); }
    100% { box-shadow: 0 0 0 0 rgba(61,224,224,0); }
  }

  .hero h1 {
    font-size: clamp(32px, 5.5vw, 56px);
    line-height: 1.25;
    color: var(--text);
  }
  .hero h1 span { color: var(--orange); }
  .hero p.sub {
    max-width: 560px; margin: 20px auto 0; color: var(--text-muted); font-size: 17px;
  }

  .cta-row { display: flex; gap: 14px; justify-content: center; margin-top: 32px; flex-wrap: wrap; }
  .btn {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 14px 28px; border-radius: 10px; font-weight: 600; font-size: 15px;
    text-decoration: none; border: none; cursor: pointer; transition: transform 0.12s, filter 0.12s;
  }
  .btn:hover { transform: translateY(-2px); filter: brightness(1.08); }
  .btn:focus-visible { outline: 3px solid var(--cyan); outline-offset: 2px; }
  .btn-primary { background: var(--orange); color: #241608; }
  .btn-secondary { background: transparent; color: var(--text); border: 1px solid var(--border); }

  @media (prefers-reduced-motion: reduce) {
    .status-dot { animation: none; }
  }

  /* ---------------- SECTION GENERIC ---------------- */
  section { padding: 72px 0; }
  .section-head { text-align: center; max-width: 560px; margin: 0 auto 44px; }
  .eyebrow {
    display: block; font-size: 13px; letter-spacing: 0.08em; color: var(--cyan);
    margin-bottom: 10px; font-weight: 600;
  }
  .section-head h2 { font-size: clamp(26px, 4vw, 36px); }
  .section-head p { color: var(--text-muted); margin-top: 12px; font-size: 15.5px; }

  /* ---------------- FEATURES ---------------- */
  .feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
  .feature-card {
    background: var(--bg-panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 26px; text-align: left;
  }
  .feature-card .icon { font-size: 28px; margin-bottom: 14px; display: block; }
  .feature-card h3 { font-size: 17px; margin-bottom: 8px; font-family: "Kanit", sans-serif; font-weight: 600; }
  .feature-card p { color: var(--text-muted); font-size: 14px; margin: 0; }

  /* ---------------- PROMO BAR (แจกฟรี 10 คนแรก) ---------------- */
  .promo-bar {
    background: linear-gradient(90deg, var(--red), var(--orange));
    color: #241608; text-align: center; font-family: "Kanit", sans-serif; font-weight: 600;
    font-size: 14px; padding: 10px 16px;
  }
  .promo-bar a { color: #241608; text-decoration: underline; font-weight: 700; }
  .promo-slots {
    display: inline-flex; align-items: center; gap: 6px; background: rgba(36,24,18,0.18);
    border-radius: 999px; padding: 2px 12px; margin-left: 8px; font-size: 13px;
  }

  /* ---------------- PRICING ---------------- */
  .price-single { display: flex; justify-content: center; }
  .price-card {
    background: var(--bg-panel); border: 1px solid var(--border); border-radius: 16px;
    padding: 36px 34px; text-align: center; position: relative;
    max-width: 380px; width: 100%;
  }
  .price-card.featured { border-color: var(--orange); background: var(--bg-panel-2); }
  .badge {
    position: absolute; top: -13px; left: 50%; transform: translateX(-50%);
    background: var(--orange); color: #241608; font-size: 12px; font-weight: 700;
    padding: 4px 14px; border-radius: 999px; white-space: nowrap;
  }
  .price-card h3 { font-size: 20px; font-family: "Kanit", sans-serif; font-weight: 600; margin-bottom: 6px; }
  .price-card .price-tag { font-size: 38px; font-weight: 700; color: var(--cyan); margin: 16px 0 2px; }
  .price-card .price-tag small { font-size: 14px; color: var(--text-muted); font-weight: 500; }
  .price-card .price-original {
    font-size: 16px; color: var(--text-muted); text-decoration: line-through; margin-top: 6px;
  }
  .price-card .price-note { font-size: 12.5px; color: var(--text-muted); margin-top: 10px; }
  .price-card ul { list-style: none; padding: 0; margin: 24px 0 26px; text-align: left; font-size: 14px; color: var(--text-muted); }
  .price-card li { padding: 6px 0; display: flex; gap: 8px; }
  .price-card li::before { content: "✓"; color: var(--cyan); font-weight: 700; }

  /* ---------------- HOW IT WORKS ---------------- */
  .steps { max-width: 640px; margin: 0 auto; }
  .step { display: flex; gap: 20px; padding: 20px 0; border-bottom: 1px solid var(--border); }
  .step:last-child { border-bottom: none; }
  .step-num {
    flex-shrink: 0; width: 36px; height: 36px; border-radius: 50%;
    background: var(--bg-panel-2); border: 1px solid var(--border);
    display: flex; align-items: center; justify-content: center;
    font-family: "Kanit", sans-serif; font-weight: 700; color: var(--orange); font-size: 15px;
  }
  .step h3 { font-size: 16px; font-family: "Kanit", sans-serif; font-weight: 600; margin-bottom: 4px; }
  .step p { margin: 0; color: var(--text-muted); font-size: 14px; }

  /* ---------------- FAQ ---------------- */
  .faq-item {
    background: var(--bg-panel); border: 1px solid var(--border); border-radius: 12px;
    margin-bottom: 12px; overflow: hidden;
  }
  .faq-item summary {
    cursor: pointer; padding: 18px 22px; font-weight: 600; font-size: 15px;
    font-family: "Kanit", sans-serif; list-style: none; display: flex; justify-content: space-between;
    align-items: center;
  }
  .faq-item summary::-webkit-details-marker { display: none; }
  .faq-item summary::after { content: "+"; font-size: 20px; color: var(--orange); }
  .faq-item[open] summary::after { content: "−"; }
  .faq-item .faq-body { padding: 0 22px 20px; color: var(--text-muted); font-size: 14.5px; }
  .faq-item .faq-body strong { color: var(--text); }

  .disclaimer-box {
    background: rgba(220, 60, 40, 0.08); border: 1px solid rgba(220, 60, 40, 0.35);
    border-radius: 12px; padding: 20px 22px; font-size: 14px; color: var(--text-muted);
    max-width: 720px; margin: 40px auto 0;
  }
  .disclaimer-box strong { color: var(--red); }

  /* ---------------- FOOTER ---------------- */
  footer { border-top: 1px solid var(--border); padding: 40px 0; text-align: center; }
  footer p { color: var(--text-muted); font-size: 13px; margin: 6px 0; }
  footer a { color: var(--cyan); text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  @media (max-width: 720px) {
    .feature-grid { grid-template-columns: 1fr; }
    nav .links { display: none; }
  }
</style>
</head>
<body>

<div class="promo-bar">
  🎉 เปิดตัว! แจกฟรีให้ 10 คนแรกเท่านั้น
  <span class="promo-slots">เหลือสิทธิ์จำนวนจำกัด</span>
  — <a href="#pricing">ดูรายละเอียด ↓</a>
</div>

<nav>
  <div class="wrap">
    <div class="brand"><img class="logo-mark" src="data:image/png;base64,__LOGO_BASE64__" alt="AutoGo"> AutoGo</div>
    <div class="links">
      <a href="#features">ฟีเจอร์</a>
      <a href="#pricing">ราคา</a>
      <a href="#how">วิธีใช้</a>
      <a href="/guide">คู่มือติดตั้ง</a>
      <a href="#faq">คำถามที่พบบ่อย</a>
    </div>
  </div>
</nav>

<header class="hero">
  <div class="wrap">
    <img class="hero-logo" src="data:image/png;base64,__LOGO_BASE64__" alt="CookieRunAutoGo">
    <div class="product-tag">CookieRunAutoGo <span>· โดย AutoGo</span></div>
    <div class="status-pill"><span class="status-dot"></span> ทำงานอัตโนมัติได้ตลอด 24 ชั่วโมง</div>
    <h1>ให้บอทฟาร์มไอเทมแทนคุณ<br><span>ไม่ต้องนั่งเฝ้าจอทั้งวัน</span></h1>
    <p class="sub">
      ตั้งค่า Boost, กดวิ่งต่อเนื่อง, เก็บ Gift Box, ส่งหัวใจให้เพื่อนอัตโนมัติ —
      เปิดทิ้งไว้แล้วไปทำอย่างอื่น ปล่อยให้คุกกี้วิ่งเก็บของให้เอง
    </p>
    <div class="cta-row">
      <a class="btn btn-primary" href="#" id="download-link">⬇️ ดาวน์โหลดโปรแกรม</a>
      <a class="btn btn-secondary" href="#" id="facebook-link" target="_blank" rel="noopener">💬 ทักเพจเพื่อซื้อ License</a>
    </div>
  </div>
</header>

<section id="features">
  <div class="wrap">
    <div class="section-head">
      <span class="eyebrow">ฟีเจอร์หลัก</span>
      <h2>ทำแทนคุณได้ทุกอย่างที่ต้องกดซ้ำๆ</h2>
      <p>ไม่ใช่แค่กด Play ซ้ำๆ แต่จัดการรายละเอียดทั้งหมดให้ครบ</p>
    </div>
    <div class="feature-grid">
      <div class="feature-card">
        <span class="icon">⚡</span>
        <h3>ตั้งค่า Boost อัตโนมัติ</h3>
        <p>เลือก Item Boost และ Random Boost ที่ต้องการ บอทจะซิงก์ให้ตรงทุกรอบโดยไม่ต้องกดเอง</p>
      </div>
      <div class="feature-card">
        <span class="icon">🏃</span>
        <h3>Fast Start และไม้ผลัดอัตโนมัติ</h3>
        <p>กดจับจังหวะปุ่มที่โผล่มาแวบเดียวให้แม่นยำ ไม่พลาดแม้แต่รอบเดียว</p>
      </div>
      <div class="feature-card">
        <span class="icon">🎁</span>
        <h3>เปิด Gift Box ให้ครบ</h3>
        <p>สุ่มกล่องของรางวัลต่อเนื่องจนกว่าจะหมดสิทธิ์ ไม่ต้องมานั่งกดเอง</p>
      </div>
      <div class="feature-card">
        <span class="icon">💌</span>
        <h3>ส่งหัวใจให้เพื่อนทั้งหมด</h3>
        <p>ไล่ส่งหัวใจให้เพื่อนทุกคนในลิสต์ในคลิกเดียว ประหยัดเวลาได้มาก</p>
      </div>
      <div class="feature-card">
        <span class="icon">🖥️</span>
        <h3>ใช้ได้ทุกความละเอียดจอ</h3>
        <p>ระบบปรับสเกลอัตโนมัติ ไม่ต้องตั้งค่า Emulator ให้ตรงเป๊ะกับใครก็ใช้ได้</p>
      </div>
      <div class="feature-card">
        <span class="icon">🔔</span>
        <h3>แจ้งเตือนอัปเดตอัตโนมัติ</h3>
        <p>เปิดโปรแกรมแล้วเช็คเวอร์ชันใหม่ให้เอง ไม่ต้องคอยเช็คเองว่ามีของใหม่ไหม</p>
      </div>
    </div>
  </div>
</section>

<section id="pricing">
  <div class="wrap">
    <div class="section-head">
      <span class="eyebrow">ราคา</span>
      <h2>License แบบถาวร จ่ายครั้งเดียวจบ</h2>
      <p>License ผูกกับ 1 เครื่องเท่านั้น ต้องการย้ายเครื่องติดต่อได้ทางเพจ</p>
    </div>
    <div class="price-single">
      <div class="price-card featured">
        <span class="badge">🎉 ฟรีสำหรับ 10 คนแรก</span>
        <h3>License แบบถาวร</h3>
        <div class="price-original">ราคาปกติ ฿199</div>
        <div class="price-tag">ฟรี <small>สำหรับ 10 คนแรก</small></div>
        <div class="price-note">หลังจากนั้นราคา ฿199 จ่ายครั้งเดียว ใช้ได้ตลอดชีพ</div>
        <ul>
          <li>ใช้งานได้ครบทุกฟีเจอร์</li>
          <li>ไม่มีวันหมดอายุ</li>
          <li>อัปเดตเวอร์ชันใหม่ฟรีตลอดชีพ</li>
        </ul>
        <a class="btn btn-primary" href="#" target="_blank" rel="noopener" style="width:100%; justify-content:center;">ทักเพจรับสิทธิ์ฟรี</a>
      </div>
    </div>
  </div>
</section>

<section id="how">
  <div class="wrap">
    <div class="section-head">
      <span class="eyebrow">เริ่มใช้งาน</span>
      <h2>4 ขั้นตอนง่ายๆ</h2>
    </div>
    <div class="steps">
      <div class="step">
        <div class="step-num">1</div>
        <div><h3>ดาวน์โหลดโปรแกรม</h3><p>กดปุ่มดาวน์โหลดด้านบน แล้วแตกไฟล์ไว้ในโฟลเดอร์เดียว (มีขั้นตอนละเอียดที่ <a href="/guide">คู่มือติดตั้ง</a>)</p></div>
      </div>
      <div class="step">
        <div class="step-num">2</div>
        <div><h3>ทักเพจแจ้งความจำนงรับสิทธิ์</h3><p>แจ้งชื่อ/ข้อมูลติดต่อทางเพจ รอทีมงานยืนยันสิทธิ์ (หรือโอนเงินตามที่แจ้ง หากเต็มโควตาฟรีแล้ว)</p></div>
      </div>
      <div class="step">
        <div class="step-num">3</div>
        <div><h3>รับ License Key ทางเพจ</h3><p>เราจะส่งคีย์ให้ทางข้อความส่วนตัวหลังยืนยันการชำระเงิน</p></div>
      </div>
      <div class="step">
        <div class="step-num">4</div>
        <div><h3>เปิดโปรแกรมและกรอกคีย์</h3><p>Activate ครั้งเดียว ผูกกับเครื่องนั้นอัตโนมัติ พร้อมใช้งานทันที</p></div>
      </div>
    </div>
  </div>
</section>

<section id="faq">
  <div class="wrap">
    <div class="section-head">
      <span class="eyebrow">คำถามที่พบบ่อย</span>
      <h2>ก่อนตัดสินใจ อ่านตรงนี้ก่อน</h2>
    </div>

    <details class="faq-item">
      <summary>ทำไม Windows Defender หรือแอนตี้ไวรัสเตือนตอนเปิดโปรแกรม?</summary>
      <div class="faq-body">
        โปรแกรมนี้ควบคุมการแตะหน้าจอ Emulator แบบอัตโนมัติ ซึ่งเป็นพฤติกรรมที่คล้ายกับเครื่องมือ
        ประเภทที่แอนตี้ไวรัสมักเฝ้าระวัง (ไม่ใช่เพราะมีไวรัสจริง) ถ้าเจอหน้าจอสีฟ้า
        "Windows protected your PC" ให้กดลิงก์ <strong>"More info"</strong> แล้วกดปุ่ม
        <strong>"Run anyway"</strong> ที่โผล่มา ทำครั้งเดียวก็พอ
      </div>
    </details>

    <details class="faq-item">
      <summary>โปรโมชันฟรี 10 คนแรก ต้องทำยังไง?</summary>
      <div class="faq-body">
        ทักเข้ามาทางเพจ Facebook แจ้งความประสงค์ขอรับสิทธิ์ ทีมงานจะยืนยันคิวให้ตามลำดับก่อนหลัง
        ถ้ายังไม่เต็ม 10 คนแรก จะได้รับ License แบบถาวรฟรีทันที ไม่มีค่าใช้จ่ายใดๆ
      </div>
    </details>

    <details class="faq-item">
      <summary>ย้ายไปใช้กับเครื่องอื่นได้ไหม?</summary>
      <div class="faq-body">
        License 1 ดอกผูกกับ 1 เครื่องเท่านั้น ถ้าต้องการย้ายเครื่อง ทักแจ้งทางเพจ เราจะปลดผูกให้
        แล้วนำคีย์เดิมไป Activate กับเครื่องใหม่ได้เลย
      </div>
    </details>

    <details class="faq-item">
      <summary>ใช้แล้วบัญชีเกมจะโดนแบนไหม?</summary>
      <div class="faq-body">
        การใช้โปรแกรมช่วยเล่นลักษณะนี้อาจขัดกับข้อตกลงการใช้งาน (Terms of Service) ของเกม
        ซึ่งมีความเสี่ยงที่บัญชีจะถูกจำกัดสิทธิ์หรือระงับการใช้งานได้ กรุณาพิจารณาความเสี่ยงนี้ก่อนตัดสินใจใช้
      </div>
    </details>

    <div class="disclaimer-box">
      <strong>ข้อควรทราบก่อนใช้งาน:</strong> โปรแกรมนี้เป็นเครื่องมือของบุคคลที่สาม ไม่มีความเกี่ยวข้อง
      หรือได้รับการรับรองจากผู้พัฒนาเกมแต่อย่างใด การใช้งานอยู่ในดุลยพินิจและความเสี่ยงของผู้ใช้เอง
      ผู้ให้บริการไม่รับผิดชอบต่อความเสียหายใดๆ ที่เกิดกับบัญชีเกมของผู้ใช้จากการใช้โปรแกรมนี้
    </div>
  </div>
</section>

<footer>
  <div class="wrap">
    <p>สอบถามหรือซื้อ License ทักได้ที่ <a href="#" id="facebook-link-footer" target="_blank" rel="noopener">เพจ Facebook ของเรา</a></p>
    <p>© 2026 AutoGo — เครื่องมือของบุคคลที่สาม ไม่ได้เป็นส่วนหนึ่งของผู้พัฒนาเกม</p>
  </div>
</footer>

<script>
  // =========================================================
  // ⚠️ แก้แค่ค่านี้ค่าเดียว (เพจ Facebook ไม่เปลี่ยนบ่อย จึง hardcode ได้)
  // ส่วนลิงก์ดาวน์โหลดดึงจาก /version API แบบไดนามิกแล้ว (ค่าเดียวกับที่ตั้งใน
  // Environment Variable DOWNLOAD_URL บน Render) แก้ที่จุดเดียวจบ ไม่ต้องมาแก้ไฟล์นี้
  // ซ้ำทุกครั้งที่ออกเวอร์ชันใหม่อีกต่อไป
  // =========================================================
  const FACEBOOK_PAGE_URL = "https://www.facebook.com/profile.php?id=61593159645007";

  document.querySelectorAll("#facebook-link, #facebook-link-footer").forEach(el => el.href = FACEBOOK_PAGE_URL);
  document.querySelectorAll('.price-card a.btn').forEach(el => el.href = FACEBOOK_PAGE_URL);

  // ดึงลิงก์ดาวน์โหลดล่าสุดจาก /version API (แหล่งข้อมูลเดียวกับที่ตัวโปรแกรมใช้เช็ค
  // อัปเดต) ถ้าดึงไม่สำเร็จ (เน็ตหลุด ฯลฯ) จะ fallback ไปหน้า Releases ทั่วไปแทน
  fetch("/version")
    .then(res => res.json())
    .then(data => {
      const url = data.download_url || "https://github.com/mirdkorakod-mkbnl/cookierun-autogo-releases/releases/latest";
      document.querySelectorAll("#download-link").forEach(el => el.href = url);
    })
    .catch(() => {
      document.querySelectorAll("#download-link").forEach(
        el => el.href = "https://github.com/mirdkorakod-mkbnl/cookierun-autogo-releases/releases/latest"
      );
    });
</script>

</body>
</html>
"""

SHOP_HTML = SHOP_HTML.replace("__LOGO_BASE64__", LOGO_BASE64)


GUIDE_HTML = r"""
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<title>คู่มือติดตั้ง — CookieRunAutoGo</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chonburi&family=Kanit:wght@500;600;700&family=Noto+Sans+Thai:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0B1326; --bg-panel: #141F35; --bg-panel-2: #1C2A45;
    --border: #2A3F5F; --text: #F0F4F8; --text-muted: #8FA3C4;
    --orange: #F0781A; --cyan: #3DE0E0; --red: #DC3C28;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: "Noto Sans Thai", sans-serif; line-height: 1.7; }
  h1, h2, h3 { font-family: "Chonburi", cursive; font-weight: 400; }
  a { color: var(--cyan); }
  .wrap { max-width: 860px; margin: 0 auto; padding: 0 24px; }

  nav {
    position: sticky; top: 0; z-index: 50; background: rgba(36,24,18,0.94);
    backdrop-filter: blur(8px); border-bottom: 1px solid var(--border);
  }
  nav .wrap { display: flex; align-items: center; justify-content: space-between; padding: 14px 24px; max-width: 1080px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 18px; font-family: "Kanit", sans-serif; text-decoration: none; color: var(--text); }
  .brand .logo-mark { width: 28px; height: 28px; border-radius: 50%; display: block; }
  nav .back { font-size: 14px; color: var(--text-muted); text-decoration: none; font-family: "Kanit", sans-serif; }
  nav .back:hover { color: var(--orange); }

  header.page-head { padding: 56px 0 28px; text-align: center; }
  header.page-head h1 { font-size: clamp(28px, 5vw, 42px); }
  header.page-head p { color: var(--text-muted); max-width: 520px; margin: 16px auto 0; }

  .callout {
    background: rgba(61,224,224,0.08); border: 1px solid rgba(61,224,224,0.35);
    border-radius: 12px; padding: 18px 22px; margin: 24px 0; font-size: 14.5px;
  }
  .callout strong { color: var(--cyan); }
  .callout.warn { background: rgba(240,120,26,0.08); border-color: rgba(240,120,26,0.4); }
  .callout.warn strong { color: var(--orange); }

  .toc {
    background: var(--bg-panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 22px 26px; margin: 32px 0;
  }
  .toc h3 { font-family: "Kanit", sans-serif; font-size: 15px; margin: 0 0 12px; color: var(--orange); }
  .toc ol { margin: 0; padding-left: 20px; font-size: 14px; }
  .toc li { padding: 4px 0; }
  .toc a { text-decoration: none; color: var(--text-muted); }
  .toc a:hover { color: var(--cyan); }

  section.step-block { padding: 40px 0; border-bottom: 1px solid var(--border); }
  section.step-block:last-of-type { border-bottom: none; }
  .step-tag {
    display: inline-block; font-family: "Kanit", sans-serif; font-size: 12.5px; font-weight: 600;
    color: var(--orange); background: rgba(240,120,26,0.1); border-radius: 999px;
    padding: 3px 12px; margin-bottom: 12px;
  }
  section.step-block h2 { font-size: 24px; margin: 0 0 14px; }
  section.step-block p { color: var(--text-muted); font-size: 15px; }

  table {
    width: 100%; border-collapse: collapse; margin: 18px 0; font-size: 14px;
    background: var(--bg-panel); border-radius: 10px; overflow: hidden;
  }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th { font-family: "Kanit", sans-serif; font-size: 13px; color: var(--orange); background: var(--bg-panel-2); }
  td { color: var(--text-muted); }
  tr:last-child td { border-bottom: none; }

  ul.checklist { list-style: none; padding: 0; margin: 20px 0; }
  ul.checklist li {
    display: flex; gap: 10px; align-items: flex-start; padding: 9px 0; font-size: 14.5px; color: var(--text-muted);
  }
  ul.checklist li::before { content: "☐"; color: var(--cyan); font-size: 17px; line-height: 1.3; }

  code {
    background: var(--bg-panel-2); border: 1px solid var(--border); border-radius: 5px;
    padding: 2px 7px; font-size: 13px; font-family: monospace; color: var(--cyan);
  }

  .btn-cta {
    display: inline-flex; align-items: center; gap: 8px; margin-top: 12px;
    background: var(--orange); color: #241608; padding: 12px 24px; border-radius: 10px;
    text-decoration: none; font-family: "Kanit", sans-serif; font-weight: 600; font-size: 14.5px;
  }
  .btn-cta:hover { filter: brightness(1.08); }

  footer { border-top: 1px solid var(--border); padding: 36px 0; text-align: center; }
  footer p { color: var(--text-muted); font-size: 13px; }

  @media (max-width: 640px) {
    table, thead, tbody, th, td, tr { display: block; }
    th { display: none; }
    td { border-bottom: none; padding: 4px 0; }
    tr { padding: 10px 0; border-bottom: 1px solid var(--border); }
    td::before { content: attr(data-label); display: block; font-family: "Kanit", sans-serif; font-size: 11px; color: var(--orange); margin-bottom: 2px; }
  }
</style>
</head>
<body>

<nav>
  <div class="wrap">
    <a class="brand" href="/shop"><img class="logo-mark" src="data:image/png;base64,__LOGO_BASE64__" alt="AutoGo"> AutoGo</a>
    <a class="back" href="/shop">← กลับหน้าหลัก</a>
  </div>
</nav>

<header class="page-head">
  <div class="wrap">
    <h1>คู่มือติดตั้งและตั้งค่าเริ่มต้น</h1>
    <p>ทำตามลำดับนี้ทีละขั้น จาก "ไม่มีอะไรเลย" จนถึง "บอทพร้อมกดเริ่มทำงาน"</p>
  </div>
</header>

<div class="wrap">

  <div class="callout warn">
    <strong>⚠️ อย่าข้ามขั้นตอนที่ 2 (ตั้งค่าความละเอียดจอ)</strong><br>
    เป็นขั้นตอนที่สำคัญที่สุด ถ้าตั้งผิดบอทจะจับตำแหน่งปุ่มในเกมพลาดตั้งแต่ต้น
  </div>

  <div class="toc">
    <h3>เนื้อหาในคู่มือนี้</h3>
    <ol>
      <li><a href="#why-resolution">ทำไมความละเอียดจอถึงสำคัญ</a></li>
      <li><a href="#step1">ขั้นตอนที่ 1: ติดตั้ง Emulator</a></li>
      <li><a href="#step2">ขั้นตอนที่ 2: ตั้งค่าความละเอียดจอเป็น 16:9</a></li>
      <li><a href="#step3">ขั้นตอนที่ 3: ติดตั้งเกมและเข้าสู่ระบบ</a></li>
      <li><a href="#step4">ขั้นตอนที่ 4: เปิด ADB Debugging</a></li>
      <li><a href="#step5">ขั้นตอนที่ 5: ติดตั้งโปรแกรม</a></li>
      <li><a href="#step6">ขั้นตอนที่ 6: เปิดโปรแกรมและ Activate License</a></li>
      <li><a href="#step7">ขั้นตอนที่ 7: ตั้งค่า ADB Path และ Device ID</a></li>
      <li><a href="#step8">ขั้นตอนที่ 8: เริ่มใช้งาน</a></li>
      <li><a href="#troubleshoot">แก้ปัญหาที่พบบ่อยเกี่ยวกับความละเอียด</a></li>
      <li><a href="#checklist">เช็คลิสต์ก่อนเริ่มใช้งานจริง</a></li>
    </ol>
  </div>

  <section class="step-block" id="why-resolution">
    <h2>ทำไมความละเอียดจอถึงสำคัญ</h2>
    <p>
      โปรแกรมนี้จดจำ "หน้าตา" ของปุ่มต่างๆ ในเกมมาจากภาพหน้าจอชุดหนึ่ง (เรียกว่า template)
      ถ้าความละเอียดจอ Emulator ของคุณมีอัตราส่วน (aspect ratio) ต่างไปจากที่ template ถูกสร้างมา
      (เช่น จอเป็น 4:3 แต่ template ทำมาจากจอ 16:9) ภาพจะถูกบีบ/ยืดผิดสัดส่วน ทำให้บอทจับคู่ปุ่มพลาด
    </p>
    <div class="callout">
      <strong>💡 ข่าวดี:</strong> โปรแกรมเวอร์ชันนี้มีระบบปรับขนาดอัตโนมัติ (auto-scale) อยู่แล้ว
      ไม่จำเป็นต้องตั้งความละเอียดให้ตรงเป๊ะกับตัวเลขที่ผู้สร้างใช้ แค่ตั้งเป็น<strong>อัตราส่วน 16:9</strong>
      เหมือนกันก็พอ ระบบจะปรับสเกลให้เองอัตโนมัติไม่ว่าคุณจะตั้งความละเอียดเป็นตัวเลขอะไรก็ตาม
    </div>
  </section>

  <section class="step-block" id="step1">
    <span class="step-tag">ขั้นตอนที่ 1</span>
    <h2>ติดตั้ง Emulator</h2>
    <p>
      เลือกยี่ห้อใดก็ได้ที่ถนัด (BlueStacks, LDPlayer, Nox, MEmu, MuMu) ดาวน์โหลดจากเว็บทางการ
      ของแต่ละยี่ห้อ ติดตั้งตามปกติ แล้วเปิดขึ้นมาให้เข้าสู่หน้าจอ Android เรียบร้อยก่อนไปขั้นตอนถัดไป
    </p>
  </section>

  <section class="step-block" id="step2">
    <span class="step-tag">ขั้นตอนที่ 2 — สำคัญที่สุด</span>
    <h2>ตั้งค่าความละเอียดจอเป็น 16:9</h2>
    <p>
      ต้องตั้งเป็นอัตราส่วน <strong style="color:var(--text)">16:9 เท่านั้น</strong> (ไม่ใช่ 4:3, 18:9)
      ตัวเลขที่แนะนำคือ <code>1280x720</code> หรือ <code>1920x1080</code>
    </p>
    <table>
      <thead><tr><th>Emulator</th><th>ขั้นตอนตั้งค่า</th></tr></thead>
      <tbody>
        <tr><td data-label="Emulator">BlueStacks 5 / nxt</td><td data-label="วิธีตั้งค่า">Settings (⚙️) → Display → Resolution → เลือก 1280x720 หรือ 1920x1080</td></tr>
        <tr><td data-label="Emulator">LDPlayer</td><td data-label="วิธีตั้งค่า">Settings (⚙️) → Display → Resolution → เลือก Preset หรือ Custom ใส่ 1280x720</td></tr>
        <tr><td data-label="Emulator">Nox Player</td><td data-label="วิธีตั้งค่า">Settings (⚙️) → ทั่วไป → ความละเอียดหน้าจอ → Tablet หรือ Custom ใส่ 1280x720</td></tr>
        <tr><td data-label="Emulator">MEmu</td><td data-label="วิธีตั้งค่า">Settings (⚙️) → อื่นๆ → Resolution → เลือก 1280x720</td></tr>
        <tr><td data-label="Emulator">MuMu Player</td><td data-label="วิธีตั้งค่า">Settings → ตัวเลือกพื้นฐาน → ความละเอียดหน้าจอ → เลือก 1280x720</td></tr>
      </tbody>
    </table>
    <p><strong style="color:var(--text)">หลังเปลี่ยนค่าแล้วต้อง Restart Emulator หนึ่งครั้ง</strong> ค่าความละเอียดถึงจะมีผลจริง</p>
    <div class="callout">
      🔍 <strong>เช็คว่าตั้งถูกไหม:</strong> หลัง Restart แล้ว ไปที่ Settings ของ Android ในตัว Emulator
      เอง → About Phone → Display จะเห็นค่าความละเอียดจริงที่ระบบ Android มองเห็น
    </div>
  </section>

  <section class="step-block" id="step3">
    <span class="step-tag">ขั้นตอนที่ 3</span>
    <h2>ติดตั้งเกมและเข้าสู่ระบบ</h2>
    <p>
      ติดตั้งเกมผ่าน Play Store ที่ติดมากับ Emulator ตามปกติ ล็อกอินให้เรียบร้อย แล้วเข้าไปถึง
      <strong style="color:var(--text)">หน้า Lobby หลัก</strong> ของเกมให้ได้ก่อน (บอทจะเริ่มทำงานจากหน้านี้)
    </p>
  </section>

  <section class="step-block" id="step4">
    <span class="step-tag">ขั้นตอนที่ 4</span>
    <h2>เปิด ADB Debugging</h2>
    <p>ไม่ว่ายี่ห้อไหน ต้องเปิดฟีเจอร์นี้ก่อนเสมอ ไม่งั้นบอทเชื่อมต่อไม่ได้</p>
    <table>
      <thead><tr><th>Emulator</th><th>วิธีเปิด</th></tr></thead>
      <tbody>
        <tr><td data-label="Emulator">BlueStacks 5 / nxt</td><td data-label="วิธีเปิด">Settings → Advanced → เปิด "Android Debug Bridge"</td></tr>
        <tr><td data-label="Emulator">LDPlayer</td><td data-label="วิธีเปิด">Settings → เพิ่มเติม (Others) → เปิด "ADB Debugging"</td></tr>
        <tr><td data-label="Emulator">Nox Player</td><td data-label="วิธีเปิด">Settings → ทั่วไป → เปิด "เปิดใช้งาน ADB Root Access"</td></tr>
        <tr><td data-label="Emulator">MEmu</td><td data-label="วิธีเปิด">Settings → อื่นๆ → เปิด "ADB Debugging"</td></tr>
        <tr><td data-label="Emulator">MuMu Player</td><td data-label="วิธีเปิด">Settings → ตัวเลือกเพิ่มเติม → เปิด "USB Debugging / ADB"</td></tr>
      </tbody>
    </table>
  </section>

  <section class="step-block" id="step5">
    <span class="step-tag">ขั้นตอนที่ 5</span>
    <h2>ติดตั้งโปรแกรม</h2>
    <p>
      ดับเบิลคลิกไฟล์ที่ดาวน์โหลดมา (<code>CookieRunAutoGo_Setup.exe</code>) แล้วกด
      "Next" ไปเรื่อยๆ จนติดตั้งเสร็จ — เลือกติ๊ก "สร้างไอคอนบน Desktop" ระหว่างทางได้ถ้าต้องการ
    </p>
    <div class="callout">
      💡 ไม่ต้องแตกไฟล์หรือย้ายไฟล์เองเหมือนก่อนหน้านี้อีกแล้ว ทั้งตัวโปรแกรมและไฟล์ template
      ทั้งหมดจะถูกติดตั้งไว้ด้วยกันโดยอัตโนมัติเสมอ ไม่มีทางแยกกันได้ ไม่ต้องกังวลเรื่องวางไฟล์
      ผิดที่อีกต่อไป
    </div>
    <div class="callout warn">
      ⚠️ <strong style="color:var(--text)">ถ้าเจอหน้าจอสีฟ้า "Windows protected your PC"</strong>
      เป็นเรื่องปกติสำหรับโปรแกรมใหม่ที่ยังไม่มี Digital Signature (ไม่ใช่ไวรัส) วิธีข้าม:
      <ol style="margin:10px 0 0; padding-left:20px;">
        <li>คลิกลิงก์ <strong style="color:var(--text)">"More info"</strong> (ตัวเล็กๆ ใต้ข้อความ)</li>
        <li>จะมีปุ่ม <strong style="color:var(--text)">"Run anyway"</strong> โผล่มา กดปุ่มนั้น</li>
      </ol>
      โปรแกรมจะเปิด/ติดตั้งต่อตามปกติทันที ทำครั้งเดียวก็พอ
    </div>
  </section>

  <section class="step-block" id="step6">
    <span class="step-tag">ขั้นตอนที่ 6</span>
    <h2>เปิดโปรแกรมและ Activate License</h2>
    <p>
      เปิดโปรแกรมจาก Shortcut บน Desktop (หรือค้นหาคำว่า "CookieRunAutoGo" ใน Start Menu)
      หน้าต่างแรกจะให้กรอก License Key — กรอกคีย์ที่ได้รับจากผู้ขาย แล้วกด Activate
      (คีย์ 1 ดอกใช้ได้ 1 เครื่องเท่านั้น)
    </p>
  </section>

  <section class="step-block" id="step7">
    <span class="step-tag">ขั้นตอนที่ 7</span>
    <h2>ตั้งค่า ADB Path และ ADB Device ID</h2>
    <p>ในหน้าโปรแกรมหลัก กดปุ่ม <strong style="color:var(--text)">"🔍 หาอัตโนมัติ"</strong> และ
    <strong style="color:var(--text)">"🔍 สแกนหาเครื่อง"</strong> โปรแกรมจะตั้งค่าให้เองอัตโนมัติ
    จากนั้นกด "ทดสอบ ADB" เพื่อยืนยันว่าเชื่อมต่อสำเร็จ</p>
  </section>

  <section class="step-block" id="step8">
    <span class="step-tag">ขั้นตอนที่ 8</span>
    <h2>เริ่มใช้งาน</h2>
    <p>
      ตรวจสอบว่าเกมอยู่ที่หน้า Lobby ตั้งค่า Boost ตามต้องการ แล้วกด "▶️ เริ่มบอท (START)"
    </p>
    <div class="callout">
      💡 ทุก Checkbox (HP Extension, Power Jelly, Fast Start ฯลฯ) เริ่มต้นเป็น "ไม่เลือก"
      ทั้งหมด ต้องกดเลือกเองทุกตัวที่ต้องการใช้ ไม่มีตัวไหนถูกเลือกไว้ล่วงหน้าให้
    </div>
  </section>

  <section class="step-block" id="troubleshoot">
    <h2>แก้ปัญหาที่พบบ่อยเกี่ยวกับความละเอียด</h2>
    <table>
      <thead><tr><th>อาการ</th><th>วิธีแก้</th></tr></thead>
      <tbody>
        <tr><td data-label="อาการ">บอทหาปุ่มไม่เจอเลยตั้งแต่เริ่ม</td><td data-label="วิธีแก้">กลับไปขั้นตอนที่ 2 ตั้งใหม่ให้เป็น 16:9 แล้ว Restart Emulator</td></tr>
        <tr><td data-label="อาการ">บอทกดตำแหน่งผิด ไม่ตรงปุ่ม</td><td data-label="วิธีแก้">เช็คว่าไฟล์ screen_reference.txt อยู่ในโฟลเดอร์ assets/ ของที่ติดตั้งไว้ (ปกติคือ AppData\Local\CookieRunAutoGo\assets\) ถ้าไม่มีให้ติดตั้งใหม่</td></tr>
        <tr><td data-label="อาการ">เปลี่ยนความละเอียด Emulator แล้วบอทพังกะทันหัน</td><td data-label="วิธีแก้">ตรวจสอบว่ายังเป็น 16:9 อยู่หรือไม่</td></tr>
      </tbody>
    </table>
  </section>

  <section class="step-block" id="checklist" style="border-bottom:none;">
    <h2>เช็คลิสต์ก่อนเริ่มใช้งานจริง</h2>
    <ul class="checklist">
      <li>ตั้งความละเอียด Emulator เป็น 16:9 แล้ว Restart Emulator แล้ว</li>
      <li>ล็อกอินเกมและเข้าถึงหน้า Lobby ได้แล้ว</li>
      <li>เปิด ADB Debugging ในตัว Emulator แล้ว</li>
      <li>ติดตั้งโปรแกรมผ่าน Setup.exe เรียบร้อยแล้ว</li>
      <li>Activate License สำเร็จแล้ว</li>
      <li>กด "ทดสอบ ADB" แล้วขึ้นว่าเชื่อมต่อสำเร็จ</li>
    </ul>
    <a class="btn-cta" href="/shop#pricing">← กลับไปรับ License</a>
  </section>

</div>

<footer>
  <div class="wrap">
    <p>ติดปัญหาที่คู่มือนี้ไม่ครอบคลุม? ทักถามได้ทางเพจ Facebook</p>
  </div>
</footer>

</body>
</html>
"""

GUIDE_HTML = GUIDE_HTML.replace("__LOGO_BASE64__", LOGO_BASE64)


@app.get("/guide", response_class=HTMLResponse)
def guide():
    """หน้าคู่มือติดตั้งแบบละเอียด (เนื้อหาเดียวกับ SETUP_GUIDE.md จัดหน้าเว็บให้อ่านง่าย)"""
    return GUIDE_HTML


@app.get("/shop", response_class=HTMLResponse)
def shop():
    """หน้าขาย/ดาวน์โหลดสำหรับลูกค้า — แก้ DOWNLOAD_URL และ FACEBOOK_PAGE_URL ใน SHOP_HTML ก่อนใช้งานจริง"""
    return SHOP_HTML


@app.get("/version")
def get_version():
    """
    เช็คเวอร์ชันล่าสุดของโปรแกรมบอท (ฝั่ง client เรียกตอนเปิดโปรแกรมเพื่อแจ้งเตือนอัปเดต)

    ค่าทั้งหมดตั้งผ่าน Environment Variable บน Render ได้เลย ไม่ต้องแก้โค้ด/redeploy:
        LATEST_VERSION        -> เวอร์ชันล่าสุดที่มี เช่น "1.1.0"
        DOWNLOAD_URL           -> ลิงก์ดาวน์โหลดเวอร์ชันล่าสุด
        CHANGELOG               -> ข้อความสรุปสิ่งที่เปลี่ยนแปลง (โชว์ให้ผู้ใช้เห็น)
        MIN_REQUIRED_VERSION     -> ถ้าตั้งไว้ และเวอร์ชันผู้ใช้ต่ำกว่านี้ จะบังคับให้อัปเดต
                                    ก่อนถึงจะใช้งานต่อได้ (เว้นว่างไว้ = ไม่บังคับ)
    """
    return {
        "latest_version": os.environ.get("LATEST_VERSION", "1.0.0"),
        "download_url": os.environ.get("DOWNLOAD_URL", ""),
        "changelog": os.environ.get("CHANGELOG", ""),
        "min_required_version": os.environ.get("MIN_REQUIRED_VERSION", ""),
    }


# ---------------------------------------------------------
# ADMIN DASHBOARD (หน้าเว็บจัดการ License ผ่านเบราว์เซอร์)
# ---------------------------------------------------------
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<title>License Dashboard - AutoGo</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #0f1117; --panel: #171a23; --panel2: #1e2230; --border: #2a2f3f;
    --text: #e6e8ef; --muted: #8b93a7; --accent: #4f8cff; --green: #34c77b;
    --red: #ef5a6f; --amber: #f2b84b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, "Segoe UI", "Sarabun", sans-serif;
    background: var(--bg); color: var(--text);
  }
  header {
    padding: 20px 28px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
  }
  header h1 { font-size: 18px; margin: 0; font-weight: 700; }
  header h1 span { color: var(--accent); }
  #loginBox, #app { padding: 28px; max-width: 1180px; margin: 0 auto; }
  #loginBox { max-width: 420px; margin-top: 80px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 18px 20px; margin-bottom: 18px;
  }
  label { font-size: 12px; color: var(--muted); display: block; margin-bottom: 5px; }
  input, select {
    width: 100%; padding: 9px 10px; border-radius: 7px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 14px; outline: none;
  }
  input:focus, select:focus { border-color: var(--accent); }
  button {
    cursor: pointer; border: none; border-radius: 7px; padding: 9px 16px;
    font-size: 13px; font-weight: 600; color: white; background: var(--accent);
  }
  button:hover { filter: brightness(1.1); }
  button.secondary { background: #333a4e; }
  button.danger { background: var(--red); }
  button.ghost { background: transparent; border: 1px solid var(--border); color: var(--text); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; }
  .row > div { flex: 1; min-width: 130px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 18px; }
  .stat { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .stat .num { font-size: 24px; font-weight: 700; }
  .stat .label { font-size: 12px; color: var(--muted); margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--muted); font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  td { padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .mono { font-family: "Consolas", monospace; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 20px; font-size: 11px; font-weight: 700; }
  .badge.rental { background: rgba(242,184,75,0.15); color: var(--amber); }
  .badge.permanent { background: rgba(79,140,255,0.15); color: var(--accent); }
  .badge.active { background: rgba(52,199,123,0.15); color: var(--green); }
  .badge.revoked { background: rgba(239,90,111,0.15); color: var(--red); }
  .badge.soon { background: rgba(239,90,111,0.15); color: var(--red); }
  .muted { color: var(--muted); }
  .actions button { margin-right: 6px; padding: 5px 10px; font-size: 12px; }
  #err { color: var(--red); font-size: 13px; margin-top: 8px; min-height: 18px; }
  #genResult { margin-top: 12px; }
  #genResult .keyline {
    font-family: monospace; background: var(--panel2); padding: 8px 10px; border-radius: 6px;
    margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center; gap: 8px;
  }
  .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px; }
  #search { max-width: 260px; }
  .section-title { font-size: 14px; font-weight: 700; margin-bottom: 12px; }
  .hint { font-size: 11px; color: var(--muted); margin-top: 4px; }
</style>
</head>
<body>

<div id="loginBox" class="card">
  <div class="section-title">🔐 เข้าสู่ระบบ Admin</div>
  <label>Admin Token</label>
  <input type="password" id="tokenInput" placeholder="วาง ADMIN_TOKEN ของเซิร์ฟเวอร์">
  <div style="margin-top:12px;">
    <button onclick="login()">เข้าสู่ระบบ</button>
  </div>
  <div id="loginErr" style="color:var(--red); font-size:13px; margin-top:10px;"></div>
</div>

<div id="app" style="display:none;">
  <header>
    <h1>🍪 AutoGo — <span>License Dashboard</span></h1>
    <button class="ghost" onclick="logout()">ออกจากระบบ</button>
  </header>

  <div style="padding: 24px 28px; max-width: 1180px; margin: 0 auto;">

    <div class="stats" id="stats"></div>

    <div class="card">
      <div class="section-title">➕ สร้าง License Key ใหม่</div>
      <div class="row">
        <div>
          <label>ประเภท</label>
          <select id="genType" onchange="toggleDaysField()">
            <option value="rental">เช่า (Rental)</option>
            <option value="permanent">ถาวร (Permanent)</option>
          </select>
        </div>
        <div id="daysField">
          <label>จำนวนวัน</label>
          <input type="number" id="genDays" value="30" min="1">
        </div>
        <div>
          <label>จำนวนคีย์</label>
          <input type="number" id="genCount" value="1" min="1" max="100">
        </div>
        <div>
          <label>หมายเหตุ (ไม่บังคับ)</label>
          <input type="text" id="genNote" placeholder="เช่น ชื่อลูกค้า">
        </div>
      </div>
      <div style="margin-top:14px;">
        <button onclick="generateKeys()">สร้าง License</button>
      </div>
      <div id="err"></div>
      <div id="genResult"></div>
    </div>

    <div class="card">
      <div class="toolbar">
        <div class="section-title" style="margin-bottom:0;">📋 รายการ License ทั้งหมด</div>
        <input id="search" placeholder="ค้นหาคีย์ / หมายเหตุ...">
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>License Key</th><th>ประเภท</th><th>สถานะ</th><th>หมดอายุ</th>
              <th>เครื่องที่ผูก</th><th>ใช้งานล่าสุด</th><th>หมายเหตุ</th><th>จัดการ</th>
            </tr>
          </thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<script>
let TOKEN = sessionStorage.getItem("admin_token") || "";
let ALL_LICENSES = [];

function toggleDaysField() {
  document.getElementById("daysField").style.display =
    document.getElementById("genType").value === "rental" ? "block" : "none";
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json", "X-Admin-Token": TOKEN },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) throw new Error("UNAUTHORIZED");
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

async function login() {
  TOKEN = document.getElementById("tokenInput").value.trim();
  document.getElementById("loginErr").textContent = "";
  try {
    await loadLicenses();
    sessionStorage.setItem("admin_token", TOKEN);
    document.getElementById("loginBox").style.display = "none";
    document.getElementById("app").style.display = "block";
  } catch (e) {
    document.getElementById("loginErr").textContent =
      e.message === "UNAUTHORIZED" ? "❌ Admin Token ไม่ถูกต้อง" : "❌ " + e.message;
  }
}

function logout() {
  sessionStorage.removeItem("admin_token");
  TOKEN = "";
  document.getElementById("app").style.display = "none";
  document.getElementById("loginBox").style.display = "block";
}

function toggleDaysFieldInit() { toggleDaysField(); }

async function loadLicenses() {
  ALL_LICENSES = await api("GET", "/admin/licenses");
  renderStats();
  renderTable();
}

function fmtDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleDateString("th-TH", { year: "numeric", month: "short", day: "numeric" }) +
    " " + d.toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" });
}

function isExpiringSoon(iso) {
  if (!iso) return false;
  const days = (new Date(iso) - new Date()) / (1000 * 60 * 60 * 24);
  return days > 0 && days <= 3;
}

function isExpired(iso) {
  if (!iso) return false;
  return new Date(iso) < new Date();
}

function renderStats() {
  const total = ALL_LICENSES.length;
  const active = ALL_LICENSES.filter(l => l.status === "active").length;
  const revoked = ALL_LICENSES.filter(l => l.status === "revoked").length;
  const rental = ALL_LICENSES.filter(l => l.license_type === "rental").length;
  const permanent = ALL_LICENSES.filter(l => l.license_type === "permanent").length;
  const expiringSoon = ALL_LICENSES.filter(
    l => l.status === "active" && l.expires_at && isExpiringSoon(l.expires_at)
  ).length;

  const stats = [
    ["ทั้งหมด", total, "var(--text)"],
    ["ใช้งานอยู่", active, "var(--green)"],
    ["ถูกเพิกถอน", revoked, "var(--red)"],
    ["แบบเช่า", rental, "var(--amber)"],
    ["แบบถาวร", permanent, "var(--accent)"],
    ["ใกล้หมดอายุ (≤3 วัน)", expiringSoon, "var(--red)"],
  ];

  document.getElementById("stats").innerHTML = stats.map(([label, num, color]) => `
    <div class="stat">
      <div class="num" style="color:${color}">${num}</div>
      <div class="label">${label}</div>
    </div>
  `).join("");
}

function renderTable() {
  const q = document.getElementById("search").value.trim().toLowerCase();
  const rows = ALL_LICENSES.filter(l =>
    !q || l.license_key.toLowerCase().includes(q) || (l.note || "").toLowerCase().includes(q)
  );

  document.getElementById("tbody").innerHTML = rows.map(l => {
    const expired = l.license_type === "rental" && isExpired(l.expires_at);
    const soon = l.license_type === "rental" && isExpiringSoon(l.expires_at);
    let statusBadge = l.status === "revoked"
      ? `<span class="badge revoked">เพิกถอนแล้ว</span>`
      : expired
        ? `<span class="badge revoked">หมดอายุแล้ว</span>`
        : `<span class="badge active">ใช้งานได้</span>`;

    const typeBadge = l.license_type === "permanent"
      ? `<span class="badge permanent">ถาวร</span>`
      : l.license_type === "admin"
        ? `<span class="badge permanent">แอดมิน</span>`
        : `<span class="badge rental">เช่า</span>`;

    const expiresText = l.expires_at
      ? `${fmtDate(l.expires_at)} ${soon && !expired ? '<span class="badge soon">ใกล้หมด</span>' : ""}`
      : `<span class="muted">ไม่มีวันหมดอายุ</span>`;

    const machineText = l.machine_id
      ? `<span class="mono" title="${l.machine_id}">${l.machine_id.slice(0,10)}…</span>`
      : `<span class="muted">ยังไม่ activate</span>`;

    return `
      <tr>
        <td>
          <span class="mono">${l.license_key}</span>
          <button class="ghost" style="padding:2px 8px; font-size:11px; margin-left:6px;"
            onclick="copyKey('${l.license_key}')">คัดลอก</button>
        </td>
        <td>${typeBadge}</td>
        <td>${statusBadge}</td>
        <td>${expiresText}</td>
        <td>${machineText}</td>
        <td class="muted">${fmtDate(l.last_seen_at)}</td>
        <td class="muted">${l.note || "-"}</td>
        <td class="actions">
          ${l.status === "active"
            ? `<button class="danger" onclick="revokeKey('${l.license_key}')">เพิกถอน</button>`
            : ""}
          ${l.machine_id
            ? `<button class="secondary" onclick="unbindKey('${l.license_key}')">ปลดผูกเครื่อง</button>`
            : ""}
        </td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="8" class="muted" style="text-align:center; padding:24px;">ไม่พบ License</td></tr>`;
}

function copyKey(key) {
  navigator.clipboard.writeText(key);
}

async function revokeKey(key) {
  if (!confirm(`ยืนยันเพิกถอน License:\n${key}\n\nผู้ใช้คีย์นี้จะใช้งานโปรแกรมต่อไม่ได้ทันที`)) return;
  try {
    await api("POST", "/admin/revoke", { license_key: key });
    await loadLicenses();
  } catch (e) { alert("❌ " + e.message); }
}

async function unbindKey(key) {
  if (!confirm(`ปลดผูกเครื่องของ License:\n${key}\n\nลูกค้าจะสามารถ activate คีย์นี้กับเครื่องใหม่ได้`)) return;
  try {
    await api("POST", "/admin/unbind", { license_key: key });
    await loadLicenses();
  } catch (e) { alert("❌ " + e.message); }
}

async function generateKeys() {
  const type = document.getElementById("genType").value;
  const days = parseInt(document.getElementById("genDays").value, 10);
  const count = parseInt(document.getElementById("genCount").value, 10);
  const note = document.getElementById("genNote").value.trim() || null;

  document.getElementById("err").textContent = "";

  try {
    const payload = { license_type: type, count, note };
    if (type === "rental") payload.days = days;

    const result = await api("POST", "/admin/generate", payload);

    document.getElementById("genResult").innerHTML =
      `<div class="hint" style="margin-bottom:8px;">✅ สร้างสำเร็จ ${result.created.length} คีย์ (คลิก "คัดลอก" เพื่อก็อปไปให้ลูกค้า):</div>` +
      result.created.map(c => `
        <div class="keyline">
          <span>${c.license_key} <span class="muted">[${c.license_type}${c.expires_at ? ", หมดอายุ " + fmtDate(c.expires_at) : ""}]</span></span>
          <button class="ghost" onclick="copyKey('${c.license_key}')">คัดลอก</button>
        </div>
      `).join("");

    await loadLicenses();
  } catch (e) {
    document.getElementById("err").textContent = "❌ " + e.message;
  }
}

document.getElementById("search").addEventListener("input", renderTable);
document.getElementById("tokenInput").addEventListener("keydown", e => { if (e.key === "Enter") login(); });

toggleDaysFieldInit();

// auto-login ถ้ามี token ที่เคยบันทึกไว้ใน session นี้แล้ว
if (TOKEN) {
  loadLicenses().then(() => {
    document.getElementById("loginBox").style.display = "none";
    document.getElementById("app").style.display = "block";
  }).catch(() => { sessionStorage.removeItem("admin_token"); TOKEN = ""; });
}
</script>
</body>
</html>
"""


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard():
    """หน้าเว็บจัดการ License ทั้งหมดผ่านเบราว์เซอร์ (ต้องกรอก Admin Token ตอนเข้าใช้งาน)"""
    return DASHBOARD_HTML
