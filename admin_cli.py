"""
เครื่องมือแอดมินสำหรับจัดการ License Key ผ่าน License Server

ตัวอย่างการใช้งาน:
    # สร้าง license แบบเช่า 30 วัน จำนวน 5 คีย์
    python admin_cli.py generate --type rental --days 30 --count 5

    # สร้าง license แบบถาวร 1 คีย์
    python admin_cli.py generate --type permanent --count 1

    # เพิกถอนคีย์
    python admin_cli.py revoke --key XXXXX-XXXXX-XXXXX-XXXXX

    # ปลดผูกเครื่อง (ให้ลูกค้าย้ายไปใช้เครื่องใหม่ได้)
    python admin_cli.py unbind --key XXXXX-XXXXX-XXXXX-XXXXX

    # ดูรายการ license ทั้งหมด
    python admin_cli.py list

ตั้งค่า URL เซิร์ฟเวอร์และ Admin Token ผ่าน Environment Variable ก่อนรัน:
    (Windows PowerShell)
        $env:LICENSE_SERVER_URL="https://your-server.example.com"
        $env:ADMIN_TOKEN="your-secret-admin-token"

    (Linux/Mac)
        export LICENSE_SERVER_URL="https://your-server.example.com"
        export ADMIN_TOKEN="your-secret-admin-token"
"""

import os
import json
import argparse
import urllib.request
import urllib.error

SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "http://127.0.0.1:8000")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


def call(method, path, payload=None):
    url = SERVER_URL.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None

    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Admin-Token", ADMIN_TOKEN)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"❌ HTTP {e.code}: {body}")
        raise SystemExit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        raise SystemExit(1)


def cmd_generate(args):
    payload = {
        "license_type": args.type,
        "days": args.days,
        "count": args.count,
        "note": args.note,
    }
    result = call("POST", "/admin/generate", payload)

    print(f"\n✅ สร้าง License สำเร็จ {len(result['created'])} คีย์:\n")
    for item in result["created"]:
        expiry = item["expires_at"] or "ไม่มีวันหมดอายุ (ถาวร)"
        print(f"  {item['license_key']}   [{item['license_type']}]   หมดอายุ: {expiry}")


def cmd_revoke(args):
    result = call("POST", "/admin/revoke", {"license_key": args.key})
    print(f"✅ เพิกถอนคีย์ {result['revoked']} เรียบร้อยแล้ว")


def cmd_unbind(args):
    result = call("POST", "/admin/unbind", {"license_key": args.key})
    print(f"✅ ปลดผูกเครื่องของคีย์ {result['unbound']} เรียบร้อยแล้ว (ใช้กับเครื่องใหม่ได้)")


def cmd_list(args):
    rows = call("GET", "/admin/licenses")
    print(f"\nรายการ License ทั้งหมด ({len(rows)} รายการ):\n")
    for r in rows:
        expiry = r["expires_at"] or "-"
        machine = r["machine_id"] or "(ยังไม่ activate)"
        print(f"  {r['license_key']}  [{r['license_type']}]  status={r['status']}  "
              f"หมดอายุ={expiry}  เครื่อง={machine}")


def main():
    parser = argparse.ArgumentParser(description="License Server Admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="สร้าง license key ใหม่")
    p_gen.add_argument("--type", choices=["rental", "permanent", "admin"], required=True)
    p_gen.add_argument("--days", type=int, default=None, help="จำนวนวัน (จำเป็นถ้า type=rental)")
    p_gen.add_argument("--count", type=int, default=1)
    p_gen.add_argument("--note", type=str, default=None)
    p_gen.set_defaults(func=cmd_generate)

    p_rev = sub.add_parser("revoke", help="เพิกถอน license key")
    p_rev.add_argument("--key", required=True)
    p_rev.set_defaults(func=cmd_revoke)

    p_unbind = sub.add_parser("unbind", help="ปลดผูกเครื่องของ license key")
    p_unbind.add_argument("--key", required=True)
    p_unbind.set_defaults(func=cmd_unbind)

    p_list = sub.add_parser("list", help="ดูรายการ license ทั้งหมด")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()

    if not ADMIN_TOKEN:
        print("⚠️ ยังไม่ได้ตั้งค่า ADMIN_TOKEN (environment variable) — คำสั่งนี้จะถูกปฏิเสธจากเซิร์ฟเวอร์")

    args.func(args)


if __name__ == "__main__":
    main()
