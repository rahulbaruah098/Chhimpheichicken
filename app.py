import os
import io
import math
from io import BytesIO
from datetime import datetime, timedelta
from random import randint
import csv, zipfile, json
from datetime import date
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from flask import make_response
from sqlite3 import IntegrityError
# ---- Env + Twilio
from dotenv import load_dotenv
load_dotenv()  # reads .env


app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "dev-only-change-this")  # set real secret in production

# WebView Session Configuration
from datetime import timedelta
app.config['SESSION_COOKIE_HTTPONLY'] = False  # Allow WebView to use cookies
app.config['SESSION_COOKIE_SECURE'] = False    # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = None   # Allow cross-origin cookies for mobile
app.config['SESSION_COOKIE_NAME'] = 'session'  # Consistent cookie name
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)


# Your existing CORS setup should cover this, but verify:
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

print("[RUNNING]", __file__)


# NOTE: db.py must define these
from db import (
    init_db, query, execute, add_order_event,
    create_password_reset_token, get_valid_reset_token, consume_reset_token,
    # Live GPS helpers
    save_delivery_location, get_latest_location_for_order,
    # Ratings + complaints helpers
    add_product_rating, add_store_rating,
    get_product_rating_summary, get_store_rating_summary,
    file_complaint, list_recent_complaints, update_complaint_status,
    # NEW admin helpers
    render_export_to_csv_zip_bytes, get_user_by_id, can_delete_user_hard, hard_delete_user,
    # NEW for atomic checkout + stock changes
    get_conn
)

def _parse_since_to_sqlite(since_raw: str):
    """
    Returns a string in 'YYYY-MM-DD HH:MM:SS' that SQLite datetime() can safely compare.
    Accepts ISO ('T' separator) and sqlite style (' ' separator).
    """
    if not since_raw:
        dt = datetime.utcnow() - timedelta(minutes=2)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    s = str(since_raw).strip()

    # Remove trailing 'Z'
    if s.endswith("Z"):
        s = s[:-1]

    dt = None

    # Try ISO first (supports microseconds)
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        dt = None

    # Try sqlite style
    if dt is None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except Exception:
                continue

    if dt is None:
        dt = datetime.utcnow() - timedelta(minutes=2)

    return dt.strftime("%Y-%m-%d %H:%M:%S")
# ---------------------------
# CONTEXT (globals to templates)
# ---------------------------
@app.context_processor
def inject_globals():
    return {
        "datetime": datetime,
        "service_area": session.get("service_area")  # {address,pincode,lat,lng} or None
    }


@app.context_processor
def inject_cart_count():
    try:
        u = current_user()
        if not u:
            return dict(cart_count=0)
        cid = get_or_create_cart(u['id'])
        row = query_one("SELECT COUNT(*) AS c FROM cart_items WHERE cart_id=?", (cid,))
        return dict(cart_count=int(row["c"]) if row else 0)
    except Exception:
        return dict(cart_count=0)



# ---- Footer links site-wide ----
FOOTER_LINKS = [
    {"label": "Privacy", "endpoint": "legal_privacy"},
    {"label": "Security", "endpoint": "legal_security"},
    {"label": "Terms of Service", "endpoint": "legal_terms"},
    {"label": "Help & Support", "endpoint": "legal_help"},
    {"label": "Report a Fraud", "endpoint": "legal_report_fraud"},
]
@app.context_processor
def inject_footer_links():
    return {"FOOTER_LINKS": FOOTER_LINKS}

# ----------------------
# DELIVERY CONFIG
# ----------------------
BASE_DELIVERY_FEE_INR = 40
DELIVERY_SURCHARGE_SLABS = [
    (0, 2, 0),
    (2, 5, 15),
    (5, 7, 25),
    (7, 10, 35),
]
MAX_DELIVERY_KM = 10.0


def _store_delivery_setting(store, key, default):
    """Read a delivery setting from a sqlite Row/dict with a safe default."""
    if store is None:
        return default
    try:
        value = store[key]
    except (KeyError, TypeError, IndexError):
        return default
    return default if value is None else value


def get_store_delivery_config(store):
    """Return normalized store-specific delivery settings."""
    try:
        enabled = int(_store_delivery_setting(store, "delivery_charge_enabled", 1)) == 1
    except (TypeError, ValueError):
        enabled = True

    defaults = {
        "fee_0_2_km": 40.0,
        "fee_2_5_km": 55.0,
        "fee_5_7_km": 65.0,
        "fee_7_10_km": 75.0,
    }
    columns = {
        "fee_0_2_km": "delivery_fee_0_2_km",
        "fee_2_5_km": "delivery_fee_2_5_km",
        "fee_5_7_km": "delivery_fee_5_7_km",
        "fee_7_10_km": "delivery_fee_7_10_km",
    }

    config = {"enabled": enabled}
    for config_key, column_name in columns.items():
        try:
            amount = float(_store_delivery_setting(store, column_name, defaults[config_key]))
        except (TypeError, ValueError):
            amount = defaults[config_key]
        config[config_key] = max(0.0, round(amount, 2)) if enabled else 0.0

    return config


def calculate_store_delivery_fee(store, distance_km):
    """Calculate the authoritative delivery fee for one store and distance."""
    km = None
    if distance_km is not None:
        try:
            km = float(distance_km)
        except (TypeError, ValueError):
            km = None
        if km is not None and (km < 0 or km > MAX_DELIVERY_KM):
            return None

    config = get_store_delivery_config(store)
    if not config["enabled"]:
        return 0.0
    if km is None:
        return config["fee_0_2_km"]
    if km < 2:
        return config["fee_0_2_km"]
    if km < 5:
        return config["fee_2_5_km"]
    if km < 7:
        return config["fee_5_7_km"]
    return config["fee_7_10_km"]


def delivery_preview_values(store):
    """Convert store totals to the base-plus-extra structure used by checkout.html."""
    config = get_store_delivery_config(store)
    base_fee = config["fee_0_2_km"]
    slabs = [
        (0, 2, 0.0),
        (2, 5, config["fee_2_5_km"] - base_fee),
        (5, 7, config["fee_5_7_km"] - base_fee),
        (7, 10, config["fee_7_10_km"] - base_fee),
    ]
    return config, base_fee, slabs

def haversine_km(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2):
        return None
    R = 6371.0
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlmb = math.radians(float(lon2) - float(lon1))
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def _ensure_contact_messages_status_column():
    try:
        cols = [r["name"] for r in query("PRAGMA table_info(contact_messages)")]
        if "status" not in cols:
            execute("ALTER TABLE contact_messages ADD COLUMN status TEXT DEFAULT 'NEW'")
    except Exception:
        pass

# ======================
# SERVICEABLE PINCODES
# ======================
def _ensure_serviceable_table():
    try:
        execute("""
            CREATE TABLE IF NOT EXISTS serviceable_pincodes (
              pincode TEXT PRIMARY KEY,
              label   TEXT
            )
        """)
    except Exception:
        pass

# Default seed (Aizawl)
SEED_PINS = [
    ("796001", "Aizawl"),
    ("796004", "Aizawl"),
    ("796005", "Aizawl"),
    ("796007", "Aizawl"),
    ("796008", "Aizawl"),
    ("796009", "Aizawl"),
    ("796012", "Aizawl"),
    ("796014", "Aizawl"),
    ("796015", "Aizawl"),
    ("796017", "Aizawl"),
]
def _seed_pincodes_if_empty():
    rows = query("SELECT COUNT(*) c FROM serviceable_pincodes")
    if rows and rows[0]["c"] == 0:
        for pc, label in SEED_PINS:
            try:
                execute("INSERT INTO serviceable_pincodes (pincode, label) VALUES (?,?)", (pc, label))
            except Exception:
                pass

with app.app_context():
    init_db()
    _ensure_serviceable_table()
    _seed_pincodes_if_empty()
    _ensure_contact_messages_status_column()


def normalize_phone(phone: str) -> str:
    """
    Normalize to E.164. If user typed a 10-digit Indian number, prefix +91.
    If already starts with '+', return as-is.
    """
    p = (phone or "").strip().replace(" ", "")
    if p.startswith("+"):
        return p
    digits = "".join(ch for ch in p if ch.isdigit())
    if len(digits) == 10:
        return "+91" + digits
    return "+" + digits if digits and not digits.startswith("+") else digits


def _clean_pin(pin) -> str:
    """Keep digits only and trim spaces (handles '796001 ', 796001, etc.)."""
    if pin is None:
        return ""
    s = str(pin).strip()
    return "".join(ch for ch in s if ch.isdigit())

def get_serviceable_pincodes():
    rows = query("SELECT pincode FROM serviceable_pincodes ORDER BY pincode")
    return [r["pincode"] for r in rows]

def is_serviceable_pincode(pin: str) -> bool:
    clean_pin = _clean_pin(pin)
    if not clean_pin:
        return False
    # normalize every row from DB too
    pins = [_clean_pin(r) for r in get_serviceable_pincodes()]
    return clean_pin in set(pins)

@app.route("/api/service/pincodes")
def api_service_pincodes():
    return jsonify({"ok": True, "pincodes": get_serviceable_pincodes()})

# Store location data in session; front-end JS should call this after getting geolocation & pincode
@app.route("/api/location/set", methods=["POST"])
def api_location_set():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    pincode_raw = data.get("pincode")
    lat = data.get("lat")
    lng = data.get("lng")

    pincode = _clean_pin(pincode_raw)
    if not pincode:
        return jsonify({"ok": False, "error": "no pincode"}), 400

    # normalize coords
    try:
        lat_f = float(lat) if lat is not None and str(lat).strip() != "" else None
    except Exception:
        lat_f = None
    try:
        lng_f = float(lng) if lng is not None and str(lng).strip() != "" else None
    except Exception:
        lng_f = None

    serviceable = is_serviceable_pincode(pincode)

    # âœ… keep existing structure
    session["service_area"] = {
        "address": address or f"Pincode {pincode}",
        "pincode": pincode,
        "lat": lat_f,
        "lng": lng_f,
    }

    # âœ… add keys that your checkout() already uses
    session["location_pincode"] = pincode
    session["location_lat"] = lat_f
    session["location_lng"] = lng_f

    session.modified = True
    return jsonify({"ok": True, "serviceable": serviceable, "service_area": session["service_area"]})

@app.route("/api/location/clear", methods=["POST"])
def api_location_clear():
    session.pop("service_area", None)

    # âœ… also clear these
    session.pop("location_pincode", None)
    session.pop("location_lat", None)
    session.pop("location_lng", None)

    session.modified = True
    return jsonify({"ok": True})

# Backend Update for app.py
# Add this endpoint after the /api/service/pincodes endpoint (around line 197)

@app.route("/api/store/<int:store_id>/location")
def api_store_location(store_id):
    """
    Fetch store location + current delivery charge settings for the app.
    """
    try:
        # Fetch only the fields required by the checkout app
        store = query("""
            SELECT
                store_name,
                latitude,
                longitude,
                delivery_charge_enabled,
                delivery_fee_0_2_km,
                delivery_fee_2_5_km,
                delivery_fee_5_7_km,
                delivery_fee_7_10_km
            FROM stores
            WHERE id=?
        """, (store_id,))

        if not store:
            return jsonify({
                "ok": False,
                "error": "Store not found"
            }), 404

        store_data = store[0]

        # Keep existing location validation unchanged
        if store_data["latitude"] is None or store_data["longitude"] is None:
            return jsonify({
                "ok": False,
                "error": "Store coordinates not available"
            }), 400

        # Use the SAME delivery configuration already used by website checkout
        delivery_config = get_store_delivery_config(store_data)

        return jsonify({
            "ok": True,
            "store_id": store_id,
            "store_name": store_data["store_name"],
            "latitude": float(store_data["latitude"]),
            "longitude": float(store_data["longitude"]),

            # Delivery settings for Flutter checkout
            "delivery_charge_enabled": bool(delivery_config["enabled"]),
            "delivery_fee_0_2_km": float(delivery_config["fee_0_2_km"]),
            "delivery_fee_2_5_km": float(delivery_config["fee_2_5_km"]),
            "delivery_fee_5_7_km": float(delivery_config["fee_5_7_km"]),
            "delivery_fee_7_10_km": float(delivery_config["fee_7_10_km"]),
            "max_delivery_km": float(MAX_DELIVERY_KM)
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500

# Convenience fallback: you can also GET/POST here if you don't want to use fetch().
# /detect-location?lat=..&lng=..&pincode=..&address=..
@app.route("/detect-location", methods=["GET", "POST"])
def detect_location():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        pincode = (data.get("pincode") or "").strip()
        address = (data.get("address") or "").strip()
        lat = data.get("lat")
        lng = data.get("lng")
    else:
        pincode = (request.args.get("pincode") or "").strip()
        address = (request.args.get("address") or "").strip()
        lat = request.args.get("lat")
        lng = request.args.get("lng")

    if not pincode:
        flash("Could not detect pincode.", "warning")
        return redirect(request.referrer or url_for("index"))

    session["service_area"] = {
        "address": address or f"Pincode {pincode}",
        "pincode": pincode,
        "lat": float(lat) if lat else None,
        "lng": float(lng) if lng else None,
    }
    session.modified = True
    if not is_serviceable_pincode(pincode):
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pincode} is not serviceable.", "warning")
    else:
        flash(f"Location set to {pincode}.", "success")
    return redirect(request.referrer or url_for("index"))

# ----------------------
# ADMIN: Manage serviceable pincodes
# ----------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    rows = query("SELECT * FROM users WHERE id=?", (uid,))
    return dict(rows[0]) if rows else None

def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            u = current_user()
            if not u:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if role and u["role"] != role:
                flash("Access denied.", "danger")
                return redirect(url_for("index"))
            return fn(*a, **kw)
        return wrap
    return deco

# Helper: JWT-like session token (simplified)
def generate_session_token(user_id):
    """Generate a simple session token"""
    import hashlib
    from datetime import datetime
    raw = f"{user_id}:{datetime.utcnow().isoformat()}:{app.secret_key}"
    return hashlib.sha256(raw.encode()).hexdigest()

def verify_api_token():
    """Verify API token from Authorization header"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.replace('Bearer ', '')
    # Check if token exists in sessions table
    rows = query("SELECT user_id FROM api_sessions WHERE token=? AND expires_at > ?", 
                 (token, datetime.utcnow().isoformat()))
    if rows:
        return rows[0]['user_id']
    return None

from functools import wraps
from flask import jsonify

def api_login_required(_func=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # 1) normal web session (cookie login)
            u = current_user()
            if u:
                return f(user_id=u["id"], *args, **kwargs)

            # 2) token auth (mobile app)
            user_id = verify_api_token()
            if not user_id:
                return jsonify({"ok": False, "msg": "Unauthorized"}), 401

            return f(user_id=user_id, *args, **kwargs)
        return wrapped

    # supports @api_login_required and @api_login_required()
    if _func is None:
        return decorator
    return decorator(_func)



# Create API sessions table
def _ensure_api_sessions_table():
    try:
        execute("""
            CREATE TABLE IF NOT EXISTS api_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
    except Exception:
        pass

with app.app_context():
    _ensure_api_sessions_table()


# =========================================================
# MOBILE APP ADMIN CONTROLS
# Minimal persistent backend support for:
# 1) global maintenance mode
# 2) admin broadcast notifications
# =========================================================

MOBILE_MAINTENANCE_MESSAGE = (
    "Chhimphei Chicken is currently undergoing a system update. "
    "Chhimphei Chicken will be up and running smoother than ever. "
    "Sorry for any inconvenience!"
)


def _ensure_mobile_app_controls():
    """Create only the two small tables required by the mobile admin controls."""
    try:
        execute("""
            CREATE TABLE IF NOT EXISTS mobile_app_control (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                maintenance_mode INTEGER NOT NULL DEFAULT 0
                    CHECK (maintenance_mode IN (0, 1)),
                maintenance_message TEXT NOT NULL,
                updated_by INTEGER,
                updated_at TEXT,
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
        """)

        rows = query("SELECT id FROM mobile_app_control WHERE id=1")
        if not rows:
            execute("""
                INSERT INTO mobile_app_control (
                    id, maintenance_mode, maintenance_message, updated_by, updated_at
                )
                VALUES (1, 0, ?, NULL, ?)
            """, (MOBILE_MAINTENANCE_MESSAGE, datetime.utcnow().isoformat()))

        execute("""
            CREATE TABLE IF NOT EXISTS mobile_broadcast_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS mobile_update_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                target_build INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
    except Exception as e:
        print(f"[WARN] Mobile admin controls setup skipped: {e}")


with app.app_context():
    _ensure_mobile_app_controls()


def api_admin_required(f):
    """Require an authenticated, active admin for mobile-admin API actions."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        web_user = current_user()
        user_id = web_user["id"] if web_user else verify_api_token()

        if not user_id:
            return jsonify({
                "success": False,
                "ok": False,
                "error": "Unauthorized"
            }), 401

        rows = query(
            "SELECT id, role, is_active FROM users WHERE id=?",
            (user_id,)
        )
        if not rows:
            return jsonify({
                "success": False,
                "ok": False,
                "error": "Unauthorized"
            }), 401

        user = rows[0]
        if user["role"] != "admin" or int(user["is_active"] or 0) != 1:
            return jsonify({
                "success": False,
                "ok": False,
                "error": "Admin access required"
            }), 403

        return f(user_id=user_id, *args, **kwargs)

    return wrapped


@app.route("/api/app/status", methods=["GET"])
def api_mobile_app_status():
    """
    Public read-only status used by the Flutter app.
    Returns maintenance state and the latest admin broadcast.
    """
    control_rows = query("""
        SELECT maintenance_mode, maintenance_message, updated_at
        FROM mobile_app_control
        WHERE id=1
    """)

    if control_rows:
        control = control_rows[0]
        maintenance_mode = bool(int(control["maintenance_mode"] or 0))
        maintenance_message = (
            control["maintenance_message"] or MOBILE_MAINTENANCE_MESSAGE
        )
        maintenance_updated_at = control["updated_at"]
    else:
        maintenance_mode = False
        maintenance_message = MOBILE_MAINTENANCE_MESSAGE
        maintenance_updated_at = None

    notification_rows = query("""
        SELECT id, title, message, created_at
        FROM mobile_broadcast_notifications
        ORDER BY id DESC
        LIMIT 1
    """)

    latest_notification = None
    if notification_rows:
        n = notification_rows[0]
        latest_notification = {
            "id": int(n["id"]),
            "title": n["title"],
            "message": n["message"],
            "created_at": n["created_at"],
        }

    # Optional installed build reported by newer Flutter clients.
    # If it is missing/invalid, do not return a targeted update reminder.
    client_build = None
    raw_build = request.args.get("build_number")
    if raw_build is not None:
        try:
            client_build = int(str(raw_build).strip())
        except (TypeError, ValueError):
            client_build = None

    update_rows = query("""
        SELECT id, title, message, target_build, created_at
        FROM mobile_update_notifications
        ORDER BY id DESC
        LIMIT 1
    """)

    latest_update_notification = None
    if client_build is not None and update_rows:
        u = update_rows[0]
        target_build = int(u["target_build"])
        if client_build < target_build:
            latest_update_notification = {
                "id": int(u["id"]),
                "title": u["title"],
                "message": u["message"],
                "target_build": target_build,
                "created_at": u["created_at"],
            }

    response = jsonify({
        "success": True,
        "ok": True,
        "maintenance_mode": maintenance_mode,
        "maintenance_message": maintenance_message,
        "maintenance_updated_at": maintenance_updated_at,
        "latest_notification": latest_notification,
        "latest_update_notification": latest_update_notification,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/admin/notification", methods=["POST"])
@api_admin_required
def api_admin_send_notification(user_id):
    """Create one new broadcast notification for customer app dashboards."""
    data = request.get_json(silent=True) or {}

    title = (data.get("title") or "Chhimphei Chicken").strip()
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Notification message is required"
        }), 400

    if len(title) > 120:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Notification title is too long"
        }), 400

    if len(message) > 1000:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Notification message is too long"
        }), 400

    notification_id = execute("""
        INSERT INTO mobile_broadcast_notifications (
            title, message, created_by, created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        title,
        message,
        user_id,
        datetime.utcnow().isoformat(),
    ))

    return jsonify({
        "success": True,
        "ok": True,
        "message": "Notification sent successfully",
        "notification": {
            "id": notification_id,
            "title": title,
            "message": message,
        }
    }), 201


@app.route("/api/admin/update-notification", methods=["POST"])
@api_admin_required
def api_admin_send_update_notification(user_id):
    """Create an update reminder shown only to app builds older than target_build."""
    data = request.get_json(silent=True) or {}

    title = (data.get("title") or "Update Your App").strip()
    message = (data.get("message") or "A new version of Chhimphei Chicken is available. Please update your app.").strip()

    try:
        target_build = int(data.get("target_build"))
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Valid target_build is required"
        }), 400

    if target_build <= 0:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "target_build must be greater than 0"
        }), 400

    if not message:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Notification message is required"
        }), 400

    if len(title) > 120:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Notification title is too long"
        }), 400

    if len(message) > 1000:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "Notification message is too long"
        }), 400

    notification_id = execute("""
        INSERT INTO mobile_update_notifications (
            title, message, target_build, created_by, created_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        title,
        message,
        target_build,
        user_id,
        datetime.utcnow().isoformat(),
    ))

    return jsonify({
        "success": True,
        "ok": True,
        "message": "Update reminder sent to outdated app versions",
        "notification": {
            "id": notification_id,
            "title": title,
            "message": message,
            "target_build": target_build,
        }
    }), 201


@app.route("/api/admin/maintenance", methods=["POST"])
@api_admin_required
def api_admin_set_maintenance(user_id):
    """Turn global mobile-app maintenance mode on or off."""
    data = request.get_json(silent=True) or {}
    raw_enabled = data.get("enabled")

    if isinstance(raw_enabled, bool):
        enabled = raw_enabled
    elif isinstance(raw_enabled, (int, float)) and raw_enabled in (0, 1):
        enabled = bool(raw_enabled)
    elif isinstance(raw_enabled, str) and raw_enabled.strip().lower() in {
        "true", "false", "1", "0", "on", "off"
    }:
        enabled = raw_enabled.strip().lower() in {"true", "1", "on"}
    else:
        return jsonify({
            "success": False,
            "ok": False,
            "error": "enabled must be true or false"
        }), 400

    now = datetime.utcnow().isoformat()
    execute("""
        UPDATE mobile_app_control
        SET maintenance_mode=?,
            maintenance_message=?,
            updated_by=?,
            updated_at=?
        WHERE id=1
    """, (
        1 if enabled else 0,
        MOBILE_MAINTENANCE_MESSAGE,
        user_id,
        now,
    ))

    return jsonify({
        "success": True,
        "ok": True,
        "maintenance_mode": enabled,
        "maintenance_message": MOBILE_MAINTENANCE_MESSAGE,
        "message": (
            "Maintenance mode enabled"
            if enabled
            else "Maintenance mode disabled"
        ),
    })


@app.route("/admin/pincodes", methods=["GET"], endpoint="admin_pincodes")
@login_required(role='admin')
def admin_pincodes():
    pins = query("SELECT pincode, COALESCE(label,'') AS label FROM serviceable_pincodes ORDER BY pincode")
    return render_template("admin_pincodes.html", user=current_user(), pincodes=pins)

@app.route("/admin/pincodes/add", methods=["POST"], endpoint="admin_pincodes_add")
@login_required(role='admin')
def admin_pincodes_add():
    pin = (request.form.get("pincode") or "").strip()
    label = (request.form.get("label") or "").strip() or None
    if not pin.isdigit():
        flash("Enter a numeric pincode.", "warning")
        return redirect(url_for("admin_pincodes"))
    try:
        execute("INSERT INTO serviceable_pincodes (pincode, label) VALUES (?,?)", (pin, label))
        flash(f"Pincode {pin} added.", "success")
    except Exception:
        flash("Pincode already exists or DB error.", "danger")
    return redirect(url_for("admin_pincodes"))

@app.route("/admin/pincodes/<pin>/delete", methods=["POST"], endpoint="admin_pincodes_delete")
@login_required(role='admin')
def admin_pincodes_delete(pin):
    execute("DELETE FROM serviceable_pincodes WHERE pincode=?", (pin,))
    flash(f"Pincode {pin} removed.", "info")
    return redirect(url_for("admin_pincodes"))

# ----------------------
# MISC UTILS
# ----------------------
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTS = {"jpg","jpeg","png","webp"}
def allowed_file(filename): 
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTS

def _row_get(row, key, default=0):
    try:
        v = row[key]
        return default if v is None else v
    except Exception:
        return default

def order_total_payable(order_row):
    return float(_row_get(order_row, 'total_amount', 0)) + \
           float(_row_get(order_row, 'delivery_fee', 0)) + \
           float(_row_get(order_row, 'tip_amount', 0))

def ensure_admin_seed_password():
    rows = query("SELECT id,password_hash FROM users WHERE email=?", ("admin@chhimphei.local",))
    if rows and rows[0]["password_hash"] == "!!set_in_app!!":
        execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash("admin123"), rows[0]["id"]))

def send_sms(phone: str, message: str) -> bool:
    print(f"[DEV SMS] to={phone} :: {message}")
    return True

with app.app_context():
    ensure_admin_seed_password()

# =========================================================
# CUSTOMER CANCEL ORDER
# =========================================================
CANCELLABLE_STATUSES = {"PLACED", "CONFIRMED","PREPARING"}
def is_cancellable(status: str) -> bool:
    return status and status.upper() in CANCELLABLE_STATUSES

@app.route('/orders/<int:oid>/cancel', methods=['POST'])
@login_required()
def order_cancel(oid):
    u = current_user()
    rows = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, u["id"]))
    if not rows:
        flash("Order not found.", "danger")
        return redirect(url_for("orders"))

    order_row = dict(rows[0])
    if order_row["status"] not in CANCELLABLE_STATUSES:
        flash("This order can no longer be cancelled.", "warning")
        return redirect(url_for("order_track", oid=oid))

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")

        cur.execute("SELECT status FROM orders WHERE id=? AND user_id=?", (oid, u["id"]))
        cur_status = cur.fetchone()
        if not cur_status or cur_status["status"] not in CANCELLABLE_STATUSES:
            conn.rollback()
            flash("This order can no longer be cancelled.", "warning")
            return redirect(url_for("order_track", oid=oid))

        cur.execute("SELECT product_id, weight_kg FROM order_items WHERE order_id=?", (oid,))
        for line in cur.fetchall():
            pid, w = int(line["product_id"]), float(line["weight_kg"] or 0)
            cur.execute("UPDATE products SET stock_kg = stock_kg + ? WHERE id=?", (w, pid))
            cur.execute("UPDATE products SET is_active=1 WHERE id=? AND stock_kg > 0", (pid,))

        now = datetime.utcnow().isoformat()
        cur.execute("""
            UPDATE orders
            SET status='CANCELLED',
                payment_status=CASE WHEN payment_status='PAID' THEN 'REFUNDED' ELSE payment_status END,
                delivery_partner_id=NULL
            WHERE id=?
        """, (oid,))
        cur.execute("""
            UPDATE transactions
            SET status=CASE
                WHEN status='PAID' THEN 'REFUNDED'
                ELSE 'VOID'
            END
            WHERE order_id=?
        """, (oid,))
        cur.execute("""
            INSERT INTO order_events (order_id, status, note, created_at)
            VALUES (?,?,?,?)
        """, (oid, "CANCELLED", "Cancelled by customer", now))

        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Could not cancel order: {e}", "danger")
        return redirect(url_for("order_track", oid=oid))
    finally:
        conn.close()

    flash("Order cancelled successfully.", "success")
    return redirect(url_for("orders"))

# ----------------------
# PUBLIC PAGES (with pincode gating)
# ----------------------
def _session_pin_is_serviceable():
    sa = session.get("service_area")
    pin = (sa.get("pincode").strip() if sa and sa.get("pincode") else "")
    return is_serviceable_pincode(pin), pin

@app.route('/')
def index():
    allow, pin = _session_pin_is_serviceable()
    if session.get("service_area") and not allow:
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pin or '(none)'} is not serviceable.", "warning")
        products = []
    else:
        products = query("""
            SELECT
              p.*,
              s.store_name,
              s.id AS store_id,
              (SELECT ROUND(AVG(r.rating), 1) FROM product_ratings r WHERE r.product_id = p.id) AS avg_rating,
              (SELECT COUNT(*) FROM product_ratings r2 WHERE r2.product_id = p.id) AS rating_count
            FROM products p
            JOIN stores s ON s.id = p.store_id
            WHERE p.is_active=1 AND p.stock_kg > 0
            ORDER BY p.created_at DESC
            LIMIT 12
        """)

    product_rating_map = {}
    store_rating_map = {}
    for p in products:
        product_rating_map[p["id"]] = {
            "avg": p["avg_rating"] if p["avg_rating"] is not None else 0,
            "count": p["rating_count"] if p["rating_count"] is not None else 0
        }
        sid = p["store_id"]
        if sid not in store_rating_map:
            store_rating_map[sid] = get_store_rating_summary(sid)

    return render_template(
        'index.html',
        user=current_user(),
        products=products,
        product_rating_map=product_rating_map,
        store_rating_map=store_rating_map
    )

# ----------------------
# LEGAL & HELP PAGES
# ----------------------
@app.route('/legal/privacy')
def legal_privacy():
    return render_template('legal/privacy.html', user=current_user())

@app.route('/legal/security')
def legal_security():
    return render_template('legal/security.html', user=current_user())

@app.route('/legal/terms')
def legal_terms():
    return render_template('legal/terms.html', user=current_user())

@app.route('/help')
def legal_help():
    return render_template('legal/help.html', user=current_user())

@app.route('/report-fraud')
def legal_report_fraud():
    return render_template('legal/report_fraud.html', user=current_user())

# ----------------------
# AUTH
# ----------------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').lower().strip()
        password = request.form.get('password','')
        rows = query('SELECT * FROM users WHERE email=?', (email,))
        if not rows:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        u = rows[0]



        if not u['is_active'] and u['role'] != 'customer':
            flash('Your account awaits admin approval.', 'warning')
            return redirect(url_for('login'))

        if check_password_hash(u['password_hash'], password):
            session['user_id'] = u['id']
            flash('Welcome back!', 'success')
            if u['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif u['role'] == 'store':
                return redirect(url_for('store_dashboard'))
            elif u['role'] == 'delivery':
                return redirect(url_for('delivery_dashboard'))
            else:
                return redirect(url_for('index'))

        flash('Invalid credentials.', 'danger')

    return render_template('login.html')

# ---------- Forgot Password ----------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier','').strip().lower()
        rows = query("SELECT * FROM users WHERE lower(email)=? OR phone=?", (identifier, identifier))
        if rows:
            u = dict(rows[0])
            token = create_password_reset_token(u['id'], minutes_valid=30)
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"[DEV RESET LINK] Send this to the user: {reset_link}")
            if u.get('phone'):
                try: send_sms(u['phone'], f"Reset your password: {reset_link}")
                except Exception: pass
        flash("If the account exists, a reset link has been sent.", "info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    row = get_valid_reset_token(token)
    if not row:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form.get('password','')
        confirm = request.form.get('confirm','')
        if not new_pw or len(new_pw) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return redirect(url_for('reset_password', token=token))
        if new_pw != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for('reset_password', token=token))
        pwd_hash = generate_password_hash(new_pw)
        execute("UPDATE users SET password_hash=? WHERE id=?", (pwd_hash, row['user_id']))
        consume_reset_token(token)
        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ---------- Register + OTP ----------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = (request.form.get('name','') or '').strip()
        email = (request.form.get('email','') or '').lower().strip()
        phone = (request.form.get('phone','') or '').strip()
        password = request.form.get('password','') or ''

        # Basic validation
        if not name or not email or not password:
            flash('Please fill all required fields.', 'warning')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'warning')
            return redirect(url_for('register'))

        # Optional: standardize phone but no OTP is used
        if phone:
            phone = normalize_phone(phone)

        try:
            # Create customer as verified & active immediately
            uid = execute("""
                INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
                VALUES (?,?,?,?, 'customer', 1, 1, ?)
            """, (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat()))
        except Exception:
            flash('Email or phone already registered.', 'danger')
            return redirect(url_for('register'))

        # Auto-login on successful signup
        session['user_id'] = uid
        flash('Account created! You are logged in.', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')







@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.','info')
    return redirect(url_for('index'))

# ----------------------
# CUSTOMER PROFILE + ADDRESSES
# ----------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required()
def profile():
    u = current_user()
    if request.method == "POST":
        name = request.form.get("name","").strip()
        phone = request.form.get("phone","").strip()
        if name: execute("UPDATE users SET name=? WHERE id=?", (name, u["id"]))
        if phone: execute("UPDATE users SET phone=? WHERE id=?", (phone, u["id"]))
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))

    addrs = query("SELECT * FROM addresses WHERE user_id=? ORDER BY is_default DESC, id DESC", (u["id"],))
    return render_template("profile.html", user=u, addresses=addrs)

@app.route("/profile/address/new", methods=["POST"])
@login_required()
def address_new():
    u = current_user()
    line1 = request.form.get("line1","").strip()
    line2 = request.form.get("line2","").strip()
    city = request.form.get("city","").strip()
    state = request.form.get("state","").strip()
    pincode = request.form.get("pincode","").strip()
    label = request.form.get("label","").strip() or "Home"
    is_def = 1 if request.form.get("is_default") == "1" else 0

    # âœ… Lat/Lng from hidden fields (synced from manual inputs)
    lat_raw = (request.form.get("latitude") or "").strip()
    lng_raw = (request.form.get("longitude") or "").strip()

    # âœ… Safe conversion + range validation
    latitude = None
    longitude = None
    if lat_raw:
        try:
            latitude = float(lat_raw)
            if latitude < -90 or latitude > 90:
                raise ValueError("Latitude out of range")
        except Exception:
            latitude = None

    if lng_raw:
        try:
            longitude = float(lng_raw)
            if longitude < -180 or longitude > 180:
                raise ValueError("Longitude out of range")
        except Exception:
            longitude = None

    if not line1:
        flash("Address line 1 is required.", "warning")
        return redirect(url_for("profile"))

    if is_def:
        execute("UPDATE addresses SET is_default=0 WHERE user_id=?", (u["id"],))

    execute("""
        INSERT INTO addresses (user_id,label,line1,line2,city,state,pincode,latitude,longitude,is_default,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        u["id"], label, line1, line2, city, state, pincode,
        latitude, longitude,
        is_def, datetime.utcnow().isoformat()
    ))

    flash("Address saved.", "success")
    return redirect(url_for("profile"))
  

@app.route("/profile/address/<int:aid>/delete", methods=["POST"])
@login_required()
def address_delete(aid):
    u = current_user()
    execute("DELETE FROM addresses WHERE id=? AND user_id=?", (aid, u["id"]))
    flash("Address deleted.", "info")
    return redirect(url_for("profile"))

@app.route("/profile/address/<int:aid>/default", methods=["POST"])
@login_required()
def address_set_default(aid):
    u = current_user()
    execute("UPDATE addresses SET is_default=0 WHERE user_id=?", (u["id"],))
    execute("UPDATE addresses SET is_default=1 WHERE id=? AND user_id=?", (aid, u["id"]))
    flash("Default address updated.", "success")
    return redirect(url_for("profile"))

@app.route("/api/profile/address/detect", methods=["POST"])
@login_required()
def api_address_detect():
    u = current_user()
    data = request.get_json(silent=True) or {}
    lat = data.get("latitude"); lng = data.get("longitude")
    if lat is None or lng is None:
        return jsonify({"ok": False, "msg": "No coordinates"}), 400
    aid = execute("""
        INSERT INTO addresses (user_id,label,line1,city,state,pincode,latitude,longitude,is_default,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (u["id"], "Detected", "(Detected location)", "", "", "",
          float(lat), float(lng), 0, datetime.utcnow().isoformat()))
    return jsonify({"ok": True, "address_id": aid})

# ----------------------
# CATALOG + CART
# ----------------------
@app.route('/products')
def products():
    allow, pin = _session_pin_is_serviceable()
    if session.get("service_area") and not allow:
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pin or '(none)'} is not serviceable.", "warning")
        products = []
    else:
        products = query("""
        SELECT p.*, s.store_name
        FROM products p JOIN stores s ON s.id = p.store_id
        WHERE p.is_active=1 AND p.stock_kg > 0
        ORDER BY p.created_at DESC
    """)
    return render_template('products.html', products=products, user=current_user())

def get_or_create_cart(uid):
    rows = query('SELECT * FROM carts WHERE user_id=? ORDER BY id DESC LIMIT 1', (uid,))
    if rows: return rows[0]['id']
    return execute('INSERT INTO carts (user_id, created_at) VALUES (?,?)', (uid, datetime.utcnow().isoformat()))


@app.route('/cart')
@login_required()
def cart_page():
    u = current_user()
    cid = get_or_create_cart(u['id'])

    # IMPORTANT: return product_id and store_name so the template can link & show
    items = query('''
        SELECT
          ci.id                 AS cart_item_id,
          ci.weight_kg          AS weight_kg,
          p.id                  AS product_id,
          p.name                AS name,
          p.price_per_kg        AS price_per_kg,
          p.image_path          AS image_path,
          p.stock_kg            AS stock_kg,
          p.is_active           AS is_active,
          p.store_id            AS store_id,        
          s.store_name          AS store_name
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        JOIN stores  s ON s.id = p.store_id
        WHERE ci.cart_id = ?
        ORDER BY ci.id DESC
    ''', (cid,))

    # âœ… Enforce single-store cart (optional)
    # If cart contains products from different stores, keep ONLY the most recent store's items
    # (you can change this behavior if you want)
    if items:
        current_store_id = items[0]["store_id"]  # most recent item store
        execute("""
            DELETE FROM cart_items
            WHERE cart_id=? AND product_id IN (
                SELECT p.id
                FROM products p
                WHERE p.id = cart_items.product_id AND p.store_id <> ?
            )
        """, (cid, current_store_id))

        # Re-fetch items after cleanup
        items = query('''
            SELECT
              ci.id                 AS cart_item_id,
              ci.weight_kg          AS weight_kg,
              p.id                  AS product_id,
              p.name                AS name,
              p.price_per_kg        AS price_per_kg,
              p.image_path          AS image_path,
              p.stock_kg            AS stock_kg,
              p.is_active           AS is_active,
              p.store_id            AS store_id,
              s.store_name          AS store_name
            FROM cart_items ci
            JOIN products p ON p.id = ci.product_id
            JOIN stores  s ON s.id = p.store_id
            WHERE ci.cart_id = ?
            ORDER BY ci.id DESC
        ''', (cid,))

    total = sum([(row['weight_kg'] or 0) * (row['price_per_kg'] or 0) for row in items])

    return render_template('cart.html', items=items, total=total, user=u)


# ==================== CART API (WEB + APP TOKEN) ====================

def _get_api_or_web_user():
    """
    If request has Authorization: Bearer <token>, use API session user_id.
    Else fall back to normal website session user (current_user()).
    """
    try:
        uid = verify_api_token()
        if uid:
            return {"id": int(uid)}
    except Exception:
        pass

    # fallback: website session
    try:
        u = current_user()
        if u and u.get("id"):
            return {"id": int(u["id"])}
    except Exception:
        pass

    return None



@app.route('/api/cart/add', methods=['POST'])
@api_login_required
def api_cart_add(user_id):
    try:
        product_id = int(request.form.get('product_id'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'msg': 'Invalid product'}), 400

    try:
        weight_kg = float(request.form.get('weight_kg', '1') or 1)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'msg': 'Invalid weight'}), 400

    if weight_kg < 0.25:
        return jsonify({'ok': False, 'msg': 'Minimum 0.25 kg'}), 400

    weight_kg = round(round(weight_kg * 4) / 4, 2)

    # âœ… Fetch product including store_id
    prow = query("SELECT stock_kg, is_active, store_id FROM products WHERE id=?", (product_id,))
    if not prow:
        return jsonify({'ok': False, 'msg': 'Product not found'}), 404

    stock = float(prow[0]['stock_kg'] or 0)
    active = int(prow[0]['is_active'] or 0)
    new_store_id = int(prow[0]['store_id'])

    if active != 1 or stock <= 0:
        return jsonify({'ok': False, 'msg': 'This item is sold out'}), 409

    if weight_kg > stock:
        return jsonify({'ok': False, 'msg': f'Max available is {stock:.2f} kg'}), 409

    cid = get_or_create_cart(user_id)

    # =========================================================
    # âœ… SINGLE-STORE ENFORCEMENT (BLOCK adding from other store)
    # =========================================================
    existing_store = query("""
        SELECT DISTINCT p.store_id AS store_id
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        WHERE ci.cart_id=?
    """, (cid,))

    if existing_store:
        cart_store_id = int(existing_store[0]["store_id"])
        if cart_store_id != new_store_id:
            return jsonify({
                "ok": False,
                "code": "DIFF_STORE",
                "msg": "Your cart already has items from another store. Please clear the cart first to add from this store."
            }), 409

    # âœ… Normal add/update
    rows = query(
        'SELECT id FROM cart_items WHERE cart_id=? AND product_id=?',
        (cid, product_id)
    )

    if rows:
        execute('UPDATE cart_items SET weight_kg=? WHERE id=?', (weight_kg, rows[0]['id']))
    else:
        execute('INSERT INTO cart_items (cart_id, product_id, weight_kg) VALUES (?,?,?)', (cid, product_id, weight_kg))

    debug_rows = query("SELECT id, cart_id, product_id, weight_kg FROM cart_items WHERE cart_id=? ORDER BY id DESC", (cid,))
    print("âœ… CART_ITEMS (for this cart_id):", debug_rows)

    c = query("SELECT COUNT(*) AS c FROM cart_items WHERE cart_id=?", (cid,))
    cart_count = int(c[0]["c"] or 0) if c else 0

    return jsonify({'ok': True, 'msg': 'Added to cart', 'cart_count': cart_count})

@app.route('/api/cart/remove', methods=['POST'])
@api_login_required
def api_cart_remove(user_id):
    data = request.get_json(silent=True) or {}
    item_id = data.get('item_id') or request.form.get('item_id')

    try:
        item_id = int(item_id)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'msg': 'Invalid item'}), 400

    cid = get_or_create_cart(user_id)
    execute('DELETE FROM cart_items WHERE id=? AND cart_id=?', (item_id, cid))

    row = query_one('SELECT COUNT(*) AS c FROM cart_items WHERE cart_id=?', (cid,))
    cart_count = int(row['c']) if row else 0   # âœ… FIX: sqlite3.Row has no .get()

    return jsonify({'ok': True, 'cart_count': cart_count})




# ----------------------
# CHECKOUT + ORDERS
# ----------------------
@app.route('/checkout', methods=['GET','POST'])
@login_required()
def checkout():
    u = current_user()
    cid = get_or_create_cart(u['id'])

    # Always defined (used by checkout.html data-store-lat/lng)
    store_lat = None
    store_lng = None
    checkout_store = None

    #Load cart items
    items = query('''
        SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id, p.stock_kg, p.is_active
        FROM cart_items ci 
        JOIN products p ON p.id = ci.product_id
        WHERE ci.cart_id=?
    ''', (cid,))

    # âœ… Multi-store cart protection (GET + POST entry gate)
    store_ids = sorted(set([int(it["store_id"]) for it in items])) if items else []
    cart_store_count = len(store_ids)

    # If multiple stores -> block checkout immediately
    if cart_store_count > 1:
        flash("Your cart contains items from multiple stores. Please clear the cart and order from one store at a time.", "danger")
        return redirect(url_for("cart_page"))
    
    # Addresses for selection
    addresses = query("SELECT * FROM addresses WHERE user_id=? ORDER BY is_default DESC, id DESC", (u["id"],))




    # Store coords for GET (fee preview JS needs it)
    if items:
        try:
            store_id_first = int(items[0]['store_id'])
            srow = query("SELECT * FROM stores WHERE id=?", (store_id_first,))
            if srow:
                checkout_store = srow[0]
                store_lat = checkout_store["latitude"]
                store_lng = checkout_store["longitude"]
        except Exception:
            checkout_store = None
            store_lat, store_lng = None, None

    # -------------------------
    # POST: place COD order
    # -------------------------
    if request.method == 'POST':
        if not items:
            flash('Your cart is empty.', 'warning')
            return redirect(url_for('cart_page'))
        
        # âœ… Multi-store POST guard again (in case of request manipulation)
        store_ids_post = sorted(set([int(it["store_id"]) for it in items]))
        if len(store_ids_post) > 1:
            flash("Your cart contains items from multiple stores. Please order from one store at a time.", "danger")
            return redirect(url_for("cart_page"))
                
        # Stock validation
        for it in items:
            if int(it['is_active'] or 0) != 1:
                flash('One or more items are sold out.', 'danger')
                return redirect(url_for('cart_page'))
            if float(it['stock_kg'] or 0) <= 0:
                flash('One or more items are sold out.', 'danger')
                return redirect(url_for('cart_page'))
            if float(it['weight_kg'] or 0) > float(it['stock_kg'] or 0):
                flash('One or more items have reduced stock. Please update your cart.', 'danger')
                return redirect(url_for('cart_page'))

        # Address selection
        addr_id = request.form.get("address_id")
        if not addr_id:
            flash("Please select a delivery address.", "warning")
            return redirect(url_for("checkout"))

        sel_rows = query("SELECT * FROM addresses WHERE id=? AND user_id=?", (addr_id, u["id"]))
        if not sel_rows:
            flash("Invalid address selected.", "danger")
            return redirect(url_for("checkout"))
        sel = sel_rows[0]

        # Pincode serviceability check (backend final authority)
        sel_pin = (sel["pincode"] if "pincode" in sel.keys() and sel["pincode"] else "").strip()
        if not is_serviceable_pincode(sel_pin):
            flash(
                f"Sorry, we currently deliver only to allowed pincodes. "
                f"Your address pincode {sel_pin or '(none)'} is not serviceable.",
                "danger"
            )
            return redirect(url_for("checkout"))

        #Totals
        items_total = sum([it['weight_kg']*it['price_per_kg'] for it in items])

        #Store fetch (for POST distance calc too)
        store_id = items[0]['store_id']
        store_row = query("SELECT * FROM stores WHERE id=?", (store_id,))
        store = store_row[0] if store_row else None

        store_lat = store['latitude'] if store and 'latitude' in store.keys() else None
        store_lng = store['longitude'] if store and 'longitude' in store.keys() else None

        # âœ… Use address coords if present, else fallback to session "current location"
        addr_lat = sel["latitude"] if sel["latitude"] else session.get("location_lat")
        addr_lng = sel["longitude"] if sel["longitude"] else session.get("location_lng")

        km = haversine_km(store_lat, store_lng, addr_lat, addr_lng)

        # Distance limit rule (only if km is known)
        if km is not None and km > MAX_DELIVERY_KM:
            flash(f"Delivery distance ({km:.1f} km) exceeds our limit of {MAX_DELIVERY_KM} km.", "danger")
            return redirect(url_for("checkout"))

        # Store-specific delivery fee (or free delivery when disabled)
        delivery_fee = calculate_store_delivery_fee(store, km)
        if delivery_fee is None:
            flash("Delivery not available for this distance.", "danger")
            return redirect(url_for("checkout"))

        # Tip amount clamp
        tip_amount = request.form.get("tip_amount", "0").strip()
        try:
            tip_amount = float(tip_amount or 0)
        except ValueError:
            tip_amount = 0.0
        if tip_amount < 0: 
            tip_amount = 0.0
        if tip_amount > 10000: 
            tip_amount = 10000.0
        tip_amount = round(tip_amount, 2)

        # -------------------------
        # Atomic checkout transaction
        # -------------------------
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")

            # Re-fetch inside transaction
            cur.execute('''
                SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id, p.stock_kg, p.is_active
                FROM cart_items ci JOIN products p ON p.id = ci.product_id
                WHERE ci.cart_id=?
            ''', (cid,))
            tx_items = cur.fetchall()

            if not tx_items:
                conn.rollback()
                flash('Your cart is empty.', 'warning')
                return redirect(url_for('cart_page'))

            # âœ… Multi-store FINAL safety (inside lock)
            tx_store_ids = sorted(set([int(it["store_id"]) for it in tx_items]))
            if len(tx_store_ids) > 1:
                conn.rollback()
                flash("Your cart contains items from multiple stores. Please order from one store at a time.", "danger")
                return redirect(url_for("cart_page"))

            # Re-read the store settings while holding the write lock so the
            # fee saved on the order is the current authoritative amount.
            store_id = tx_store_ids[0]
            cur.execute("SELECT * FROM stores WHERE id=?", (store_id,))
            tx_store = cur.fetchone()
            if tx_store is None:
                conn.rollback()
                flash("Store not found.", "danger")
                return redirect(url_for("cart_page"))

            delivery_fee = calculate_store_delivery_fee(tx_store, km)
            if delivery_fee is None:
                conn.rollback()
                flash("Delivery not available for this distance.", "danger")
                return redirect(url_for("checkout"))

            # Validate again inside lock
            for it in tx_items:
                stock = float(it["stock_kg"] or 0)
                need  = float(it["weight_kg"] or 0)
                if int(it["is_active"] or 0) != 1 or stock <= 0 or need > stock:
                    conn.rollback()
                    flash('One or more items are sold out or reduced in stock.', 'danger')
                    return redirect(url_for('cart_page'))

            now = datetime.utcnow().isoformat()
            tx_items_total = sum(
                float(it["weight_kg"]) * float(it["price_per_kg"]) 
                for it in tx_items
                )

            #create order
            cur.execute('''
                INSERT INTO orders (
                        user_id, store_id, total_amount, status, payment_status, created_at,
                         delivery_fee, distance_km, tip_amount
                        )
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (
                u['id'], store_id, tx_items_total, 
                  'PLACED', 'PENDING', now,
                  float(delivery_fee),
                  float(km) if km is not None else None, 
                  float(tip_amount)
            ))
            oid = cur.lastrowid
                        
            # Insert order items + decrement stock
            for it in tx_items:
                pid = int(it["product_id"])
                need = float(it["weight_kg"] or 0)
                price = float(it["price_per_kg"] or 0)
                line_total = need * price

                cur.execute('''
                    INSERT INTO order_items (order_id, product_id, weight_kg, unit_price_per_kg, line_total)
                    VALUES (?,?,?,?,?)
                ''', (oid, pid, need, price, line_total))
                cur.execute("UPDATE products SET stock_kg = stock_kg - ? WHERE id=?", (need, pid))

            total_payable = tx_items_total + float(delivery_fee) + float(tip_amount)


            # Transaction row
            cur.execute("""
                INSERT INTO transactions (order_id, amount, payment_method, status, created_at)
                VALUES (?,?, 'COD','PENDING',?)
            """, (oid, total_payable, now))

            # Store delivery address snapshot
            cur.execute("""
                INSERT INTO order_addresses (
                        order_id,line1,line2,city,state,pincode,latitude,longitude,created_at
                        )
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                oid, sel["line1"], sel["line2"], sel["city"], sel["state"], sel["pincode"],
                  sel["latitude"], sel["longitude"], 
                  now))

            # Event
            cur.execute(
                "INSERT INTO order_events (order_id, status, note, created_at) VALUES (?,?,?,?)",
                (oid, 'PLACED', '', now)
            )

            # Clear cart
            cur.execute("DELETE FROM cart_items WHERE cart_id=?", (cid,))
            conn.commit()
            


        except Exception as e:
            conn.rollback()
            flash(f'Checkout failed: {e}', 'danger')
            return redirect(url_for('cart_page'))
        finally:
            conn.close()

        flash('Order placed! (COD)', 'success')
        return redirect(url_for('orders'))

    # -------------------------
    # GET: totals for UI
    # -------------------------
    total = sum([float(it['weight_kg'] or 0) * float(it['price_per_kg'] or 0) for it in items])
    delivery_config, preview_base_fee, preview_slabs = delivery_preview_values(checkout_store)

    return render_template(
        "checkout.html",
        user=u,
        addresses=addresses,
        total=total,
        base_fee=preview_base_fee,
        slabs=preview_slabs,
        delivery_charge_enabled=delivery_config["enabled"],
        max_km=MAX_DELIVERY_KM,
        store_lat=store_lat,
        store_lng=store_lng,
        cart_store_count=cart_store_count,
    )

# Orders list
@app.route("/orders", endpoint="orders")
@login_required()
def my_orders():
    u = current_user()
    orders = query('''
        SELECT o.*, s.store_name
        FROM orders o JOIN stores s ON s.id = o.store_id
        WHERE o.user_id=? ORDER BY o.created_at DESC
    ''', (u['id'],))
    return render_template('orders.html', orders=orders, user=u)

# ---------- Order tracking ----------
def get_order_full(oid, for_user_id=None):
    where = "o.id=?"
    params = [oid]
    if for_user_id is not None:
        where += " AND o.user_id=?"
        params.append(for_user_id)

    order = query(f"""
        SELECT o.*, s.store_name, dp.name AS delivery_partner_name
        FROM orders o
        JOIN stores s ON s.id = o.store_id
        LEFT JOIN users dp ON dp.id = o.delivery_partner_id
        WHERE {where}
        LIMIT 1
    """, tuple(params))
    if not order:
        return None

    items = query("""
        SELECT oi.*, p.name, p.image_path, p.price_per_kg
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id=?
    """, (oid,))

    addr = query("SELECT * FROM order_addresses WHERE order_id=? ORDER BY id DESC LIMIT 1", (oid,))
    events = query("SELECT status, note, created_at FROM order_events WHERE order_id=? ORDER BY id ASC", (oid,))

    return {
        "order": dict(order[0]),
        "items": [dict(i) for i in items],
        "address": dict(addr[0]) if addr else None,
        "events": [dict(e) for e in events],
    }

@app.route('/about')
def about():
    """
    About Us page for Chhimphei Women Poultry Producer Company Limited
    """
    company_info = {
        "name": "Chhimphei Women Poultry Producer Company Limited",
        "year": 2018,
        "location": "Melriat, Aizawl, Mizoram",
        "fssai": "21825102002418",
        "phone": "8132831406",
        "website": "chhimphei.com",
        "supported_by": "Mizoram State Rural Livelihood Mission (MzSRLM)",
    }

    u = current_user()
    cart_count = 0

    if u:
        cid = get_or_create_cart(u["id"])

        # query_one returns sqlite3.Row, not dict -> no .get()
        row = query_one("SELECT COUNT(*) AS c FROM cart_items WHERE cart_id = ?", (cid,))
        if row is not None:
            cart_count = int(row["c"] or 0)   # âœ… safe

    return render_template(
        "about.html",
        info=company_info,
        user=u,
        cart_count=cart_count
    )


@app.route("/orders/<int:oid>")
@login_required()
def order_track(oid):
    u = current_user()
    data = get_order_full(oid, for_user_id=u["id"] if u["role"] == "customer" else None)
    if not data:
        flash("Order not found.", "danger")
        return redirect(url_for("orders"))
    return render_template("order_track.html", user=u, **data)

# ---------- Feedback ----------
def _clamp_rating(val):
    try:
        v = int(val)
    except (TypeError, ValueError):
        return None
    if v < 1 or v > 5:
        return None
    return v

@app.route("/orders/<int:oid>/feedback", methods=["POST"])
@login_required()
def order_feedback(oid):
    u = current_user()
    own = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, u["id"]))
    if not own:
        flash("Order not found.", "danger")
        return redirect(url_for('orders'))
    order_row = dict(own[0])

    if order_row["status"] != "DELIVERED":
        flash("You can submit feedback only after delivery.", "warning")
        return redirect(url_for("order_track", oid=oid))

    if request.form.get("received_confirm") != "1":
        flash("Please confirm that you received your items.", "warning")
        return redirect(url_for("order_track", oid=oid))

    order_items = query("""
        SELECT oi.product_id, p.name
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id=?
    """, (oid,))

    store_rating = _clamp_rating(request.form.get("store_rating"))
    if store_rating:
        add_store_rating(u['id'], order_row["store_id"], store_rating, request.form.get("store_comment","").strip() or None)

    if order_row.get("delivery_partner_id"):
        delivery_rating = _clamp_rating(request.form.get("delivery_rating"))
        if delivery_rating:
            execute("""
                CREATE TABLE IF NOT EXISTS delivery_ratings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    order_id INTEGER NOT NULL,
                    delivery_partner_id INTEGER NOT NULL,
                    rating INTEGER NOT NULL,
                    comment TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            execute("""
                INSERT INTO delivery_ratings (user_id, order_id, delivery_partner_id, rating, comment, created_at)
                VALUES (?,?,?,?,?,?)
            """, (u["id"], oid, order_row["delivery_partner_id"], delivery_rating,
                  (request.form.get("delivery_comment") or "").strip() or None, datetime.utcnow().isoformat()))

    for it in order_items:
        pid = it["product_id"]
        r = _clamp_rating(request.form.get(f"product_rating_{pid}"))
        c = (request.form.get(f"product_comment_{pid}") or "").strip() or None
        if r:
            add_product_rating(u['id'], pid, r, c)

    title = (request.form.get("complaint_title") or "").strip()
    desc  = (request.form.get("complaint_description") or "").strip()
    image = request.files.get("complaint_image")
    image_path = None
    if image and image.filename and allowed_file(image.filename):
        fn = secure_filename(image.filename)
        save_as = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + fn
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        image.save(os.path.join(app.config["UPLOAD_FOLDER"], save_as))
        image_path = f"uploads/{save_as}"

    if title or desc or image_path:
        msg = f"{title}\n{desc}".strip()
        try:
            file_complaint(u['id'], 'store', order_row["store_id"], msg, oid, image_path=image_path, title=title or None)
        except Exception:
            pass
        if order_row.get("delivery_partner_id"):
            try:
                file_complaint(u['id'], 'delivery', int(order_row["delivery_partner_id"]), msg, oid, image_path=image_path, title=title or None)
            except Exception:
                pass

    flash("Thanks for your feedback!", "success")
    return redirect(url_for("order_track", oid=oid))

# ----------------------
# DELIVERY
# ----------------------

@app.route('/delivery')
@login_required(role='delivery')
def delivery_dashboard():
    u = current_user()
    orders = query('''
    SELECT o.*, s.store_name,
           cu.name  AS customer_name,
           cu.phone AS customer_phone,
           oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
           oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
    FROM orders o
    JOIN stores s ON s.id = o.store_id
    JOIN users  cu ON cu.id = o.user_id
    LEFT JOIN order_addresses oa ON oa.order_id = o.id
    WHERE o.delivery_partner_id = ? OR o.delivery_partner_id IS NULL
    GROUP BY o.id
    ORDER BY o.created_at DESC
''', (u['id'],))
    return render_template('delivery_dashboard.html', user=u, orders=orders)

@app.route('/delivery/order/<int:oid>/assign', methods=['POST'])
@login_required(role='delivery')
def delivery_assign(oid):
    u = current_user()
    execute('UPDATE orders SET delivery_partner_id=? WHERE id=?', (u['id'], oid))
    add_order_event(oid, 'ASSIGNED_TO_DELIVERY')
    flash('Order assigned to you.','success')
    return redirect(url_for('delivery_dashboard'))

@app.route('/delivery/order/<int:oid>/status', methods=['POST'])
@login_required(role='delivery')
def delivery_status(oid):
    new_status = request.form.get('status', 'OUT_FOR_DELIVERY').upper()

    if new_status == 'DELIVERED':
        cod_received = request.form.get('cod_received')
        if cod_received != '1':
            flash('Please confirm that payment (COD) has been received before marking Delivered.', 'warning')
            return redirect(url_for('delivery_dashboard'))

        execute('UPDATE orders SET status=? WHERE id=?', (new_status, oid))
        add_order_event(oid, new_status, "COD received")
        execute("UPDATE transactions SET status='PAID' WHERE order_id=?", (oid,))
        execute("UPDATE orders SET payment_status='PAID' WHERE id=?", (oid,))
        flash('Delivery completed and payment confirmed.','success')
        return redirect(url_for('delivery_dashboard'))

    execute('UPDATE orders SET status=? WHERE id=?', (new_status, oid))
    add_order_event(oid, new_status)
    flash('Delivery status updated.','success')
    return redirect(url_for('delivery_dashboard'))

# ----------------------
# DELIVERY API â€” Customer polls rider location
# ----------------------
@app.route('/delivery/api/location', methods=['POST'])
@login_required(role='delivery')
def delivery_update_location():
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get('latitude')); lng = float(data.get('longitude'))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "latitude/longitude required"}), 400

    oid = data.get('order_id')
    heading = data.get('heading'); speed = data.get('speed')

    if oid:
        chk = query("SELECT id FROM orders WHERE id=?", (oid,))
        if not chk:
            return jsonify({"ok": False, "error": "order not found"}), 404

    save_delivery_location(current_user()["id"], lat, lng, oid, heading, speed)
    return jsonify({"ok": True})

# --- Product detail with ratings ---
@app.route('/product/<int:pid>')
def product_detail(pid):
    rows = query("""
        SELECT p.*, s.store_name, s.id AS store_id
        FROM products p
        JOIN stores s ON s.id = p.store_id
        WHERE p.id=? LIMIT 1
    """, (pid,))
    if not rows:
        flash("Product not found.","warning")
        return redirect(url_for('products'))

    p = dict(rows[0])
    u = current_user()
    is_staff = bool(u and (u.get("role") in ("admin","store")))
    if not is_staff and (int(p.get("is_active") or 0) != 1 or float(p.get("stock_kg") or 0) <= 0):
        abort(404)

    rating_summary = get_product_rating_summary(pid)
    reviews = query("""
        SELECT pr.rating, pr.comment, pr.created_at, u.name AS reviewer_name
        FROM product_ratings pr
        JOIN users u ON u.id = pr.user_id
        WHERE pr.product_id=?
        ORDER BY pr.created_at DESC
    """, (pid,))

    return render_template(
        'product.html',
        user=u,
        product=p,
        rating=rating_summary,
        reviews=reviews
    )

@app.route('/api/delivery/orders/<int:oid>/location', methods=['GET'])
@login_required()
def delivery_api_get_latest(oid):
    row = query(
        "SELECT latitude, longitude, recorded_at AS updated_at "
        "FROM delivery_locations WHERE order_id=? "
        "ORDER BY id DESC LIMIT 1",
        (oid,)
    )
    if not row:
        return jsonify({"ok": True, "has_location": False})
    r = row[0]
    return jsonify({"ok": True, "has_location": True, "data": {
        "latitude": r["latitude"],
        "longitude": r["longitude"],
        "updated_at": r["updated_at"]
    }})

# ----------- ALERTS -----------
@app.route('/api/alerts/store', methods=['GET'])
@login_required(role='store')
def api_alerts_store():
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        return jsonify({'ok': True, 'new': [], 'next_last_id': 0})

    sid = srow[0]['id']

    try:
        last_id = int(request.args.get('last_id', '0'))
    except Exception:
        last_id = 0


    rows = query("""
      SELECT o.id, o.total_amount, o.delivery_fee, o.tip_amount
      FROM orders o
      WHERE o.store_id=? AND o.id > ?
      ORDER BY o.id ASC
    """, (sid, last_id))

    new_items = []
    max_id = last_id

    for r in rows:
        oid = int(r['id'])
        if oid > max_id:
            max_id = oid

        new_items.append({
            "order_id": oid,
            "total_payable": order_total_payable(r),
        })

    return jsonify({
        "ok": True,
        "new": new_items,
        "next_last_id": max_id
    })


@app.route('/api/alerts/delivery', methods=['GET'])
@login_required(role='delivery')
def api_alerts_delivery():
    since = request.args.get('since') or (datetime.utcnow() - timedelta(minutes=2)).isoformat()
    rows = query("""
      SELECT o.id, o.created_at, o.total_amount, o.delivery_fee, o.tip_amount
      FROM orders o
      WHERE (o.delivery_partner_id IS NULL) AND o.created_at>?
      ORDER BY o.created_at DESC
    """, (since,))
    new_items = []
    for r in rows:
        total_payable = order_total_payable(r)
        new_items.append({'order_id': r['id'], 'created_at': r['created_at'], 'total_payable': total_payable})
    return jsonify({'ok': True, 'new': new_items})

@app.route('/api/store/orders/<int:oid>', methods=['GET'])
@login_required(role='store')
def api_store_order_detail(oid):
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        return jsonify({'ok': False, 'error': 'store not found'}), 404
    sid = srow[0]['id']

    rows = query('''
        SELECT o.*, 
               u.name  AS customer_name,
               u.phone AS customer_phone,
               oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
               oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
        FROM orders o
        JOIN users u ON u.id = o.user_id
        LEFT JOIN order_addresses oa ON oa.order_id = o.id
        WHERE o.id=? AND o.store_id=?
        GROUP BY o.id
        LIMIT 1
    ''', (oid, sid))
    if not rows:
        return jsonify({'ok': False, 'error': 'not found'}), 404

    o = dict(rows[0])
    return jsonify({
        'ok': True,
        'order': {
            'id': o['id'],
            'created_at': o['created_at'],
            'status': o['status'],
            'payment_status': o['payment_status'],
            'total_amount': float(o.get('total_amount') or 0.0),
            'delivery_fee': float(o.get('delivery_fee') or 0.0),
            'tip_amount': float(o.get('tip_amount') or 0.0),
            'customer_name': o.get('customer_name'),
            'customer_phone': o.get('customer_phone'),
            'addr_line1': o.get('addr_line1'),
            'addr_line2': o.get('addr_line2'),
            'addr_city': o.get('addr_city'),
            'addr_state': o.get('addr_state'),
            'addr_pincode': o.get('addr_pincode'),
            'addr_lat': o.get('addr_lat'),
            'addr_lng': o.get('addr_lng'),
        }
    })

# ======================
# UNIVERSAL SEARCH
# ======================
@app.route("/search")
def search():
    q = (request.args.get("q", "") or "").strip()
    user = current_user()

    products = []
    stores = []

    if q:
        like = f"%{q.lower()}%"
        products = query("""
            SELECT p.*, s.store_name, s.id AS store_id
            FROM products p
            JOIN stores s ON s.id = p.store_id
            WHERE p.is_active=1 AND p.stock_kg > 0
              AND (lower(p.name) LIKE ? OR lower(s.store_name) LIKE ?)
            ORDER BY p.created_at DESC
            LIMIT 50
        """, (like, like))

        stores = query("""
            SELECT s.id, s.store_name, s.address,
                   COUNT(p.id) AS product_count
            FROM stores s
            JOIN products p ON p.store_id = s.id
            WHERE p.is_active=1 AND p.stock_kg > 0
              AND (lower(s.store_name) LIKE ?)
            GROUP BY s.id
            ORDER BY product_count DESC
            LIMIT 30
        """, (like,))

    return render_template("search.html", user=user, q=q, products=products, stores=stores)

# ======================
# STORE CATALOG PAGE (also gated)
# ======================
@app.route("/stores/<int:sid>")
def store_catalog(sid):
    user = current_user()
    srows = query("SELECT id, store_name, address FROM stores WHERE id=?", (sid,))
    if not srows:
        flash("Store not found.", "warning")
        return redirect(url_for("products"))
    store = dict(srows[0])

    allow, pin = _session_pin_is_serviceable()
    if session.get("service_area") and not allow:
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pin or '(none)'} is not serviceable.", "warning")
        products = []
    else:
        products = query("""
        SELECT p.*, s.store_name
        FROM products p
        JOIN stores s ON s.id = p.store_id
        WHERE p.store_id=? AND p.is_active=1 AND p.stock_kg > 0
        ORDER BY p.created_at DESC
    """, (sid,))

    return render_template("store_catalog.html", user=user, store=store, products=products)

@app.route("/api/search/suggest")
def api_search_suggest():
    q = (request.args.get("q","") or "").strip().lower()
    if not q:
        return jsonify({"ok": True, "products": [], "stores": []})
    like = f"%{q}%"
    pro = query("""
      SELECT p.id, p.name, s.store_name
      FROM products p JOIN stores s ON s.id=p.store_id
      WHERE p.is_active=1 AND p.stock_kg>0 AND (lower(p.name) LIKE ?)
      ORDER BY p.created_at DESC LIMIT 8
    """, (like,))
    sto = query("""
      SELECT id, store_name FROM stores
      WHERE lower(store_name) LIKE ? LIMIT 6
    """, (like,))
    return jsonify({
        "ok": True,
        "products": [dict(r) for r in pro],
        "stores": [dict(r) for r in sto]
    })

# ----------------------
# Ratings routes â€” disabled (from feedback only)
# ----------------------
@app.route('/rate/product/<int:pid>', methods=['POST'])
@login_required()
def rate_product_disabled(pid):
    flash('Please rate from the order page after your delivery is completed.', 'info')
    return redirect(request.referrer or url_for('orders'))

@app.route('/rate/store/<int:sid>', methods=['POST'])
@login_required()
def rate_store_disabled(sid):
    flash('Please rate from the order page after your delivery is completed.', 'info')
    return redirect(request.referrer or url_for('orders'))

@app.route('/api/ratings/product/<int:pid>')
def api_ratings_product(pid):
    s = get_product_rating_summary(pid)
    return jsonify({"ok": True, "avg": s["avg"], "count": s["count"]})

@app.route('/api/ratings/store/<int:sid>')
def api_ratings_store(sid):
    s = get_store_rating_summary(sid)
    return jsonify({"ok": True, "avg": s["avg"], "count": s["count"]})

# ----------------------
# Complaints
# ----------------------
@app.route('/complaints', methods=['POST'])
@login_required()
def complaints_create():
    u = current_user()
    target_type = (request.form.get('target_type','') or '').lower()
    target_id = int(request.form.get('target_id','0') or 0)
    message = (request.form.get('message','') or '').strip()
    order_id = request.form.get('order_id')
    order_id = int(order_id) if order_id else None
    title = (request.form.get('title') or '').strip() or None

    if target_type not in ('store','delivery','product') or not target_id or not message:
        flash('Please provide valid complaint details.','warning')
        return redirect(request.referrer or url_for('index'))

    image_path = None
    f = request.files.get('image')
    if f and f.filename:
        fn = secure_filename(f.filename)
        save_as = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + fn
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        f.save(os.path.join(app.config["UPLOAD_FOLDER"], save_as))
        image_path = f"uploads/{save_as}"

    try:
        file_complaint(u['id'], target_type, target_id, message, order_id, image_path=image_path, title=title)
        flash('Complaint submitted. Weâ€™ll review it shortly.','success')
    except Exception as e:
        flash(f'Could not submit complaint: {e}','danger')
    return redirect(request.referrer or url_for('index'))

# ----------------------
# ADMIN
# ----------------------
def table_has_columns(table, columns):
    try:
        cols = [row['name'] for row in query(f"PRAGMA table_info({table})")]
        return all(col in cols for col in columns)
    except Exception:
        return False

def _csv_from_rows(rows):
    if not rows:
        return [], []
    dict_rows = [dict(r) if not isinstance(r, dict) else r for r in rows]
    keys = set()
    for r in dict_rows:
        keys.update(r.keys())
    fieldnames = sorted(keys)
    return fieldnames, dict_rows

def _zip_add_csv(zf, name, rows):
    fieldnames, dict_rows = _csv_from_rows(rows)
    buf = io.StringIO()
    if fieldnames:
        w = csv.DictWriter(buf, fieldnames=fieldnames)
        w.writeheader()
        for r in dict_rows:
            row = {k: r.get(k) for k in fieldnames}
            w.writerow(row)
    zf.writestr(name, buf.getvalue())

def _zip_add_json(zf, name, obj):
    zf.writestr(name, json.dumps(obj, indent=2, default=str))

@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    metrics = {
        'users': query('SELECT COUNT(*) c FROM users')[0]['c'],
        'stores': query('SELECT COUNT(*) c FROM stores')[0]['c'],
        'products': query('SELECT COUNT(*) c FROM products')[0]['c'],
        'orders': query('SELECT COUNT(*) c FROM orders')[0]['c'],
        'gmv': query("""
            SELECT COALESCE(
                SUM(
                    CASE
                        WHEN status='DELIVERED' THEN (
                            COALESCE(total_amount, 0)
                            + COALESCE(delivery_fee, 0)
                            + COALESCE(tip_amount, 0)
                        )
                        ELSE 0
                    END
                ),
                0
            ) AS amt
            FROM orders
        """)[0]['amt'],
    }

    by_store = query("""
        SELECT
            s.id AS store_id,
            s.store_name,
            COUNT(o.id) AS orders,
            COALESCE(
                SUM(
                    CASE
                        WHEN o.status='DELIVERED' THEN (
                            COALESCE(o.total_amount, 0)
                            + COALESCE(o.delivery_fee, 0)
                            + COALESCE(o.tip_amount, 0)
                        )
                        ELSE 0
                    END
                ),
                0
            ) AS revenue
        FROM stores s
        LEFT JOIN orders o ON o.store_id = s.id
        GROUP BY s.id
        ORDER BY revenue DESC
    """)



    top_store_complaints = []
    top_delivery_complaints = []

    legacy_complaints = table_has_columns('complaints', ['target_type', 'target_id', 'message'])
    new_store_col = table_has_columns('complaints', ['store_id'])
    new_delivery_col = table_has_columns('complaints', ['delivery_partner_id'])

    if new_store_col:
        top_store_complaints = query('''
            SELECT s.id AS store_id, s.store_name, COUNT(*) AS cnt
            FROM complaints c
            JOIN stores s ON s.id = c.store_id
            GROUP BY s.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')
    elif legacy_complaints:
        top_store_complaints = query('''
            SELECT s.id AS store_id, s.store_name, COUNT(*) AS cnt
            FROM complaints c
            JOIN stores s ON s.id = c.target_id
            WHERE c.target_type = 'store'
            GROUP BY s.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')

    if new_delivery_col:
        top_delivery_complaints = query('''
            SELECT u.id AS delivery_id, u.name, COUNT(*) AS cnt
            FROM complaints c
            JOIN users u ON u.id = c.delivery_partner_id
            WHERE u.role = 'delivery'
            GROUP BY u.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')
    elif legacy_complaints:
        top_delivery_complaints = query('''
            SELECT u.id AS delivery_id, u.name, COUNT(*) AS cnt
            FROM complaints c
            JOIN users u ON u.id = c.target_id
            WHERE c.target_type = 'delivery' AND u.role = 'delivery'
            GROUP BY u.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')

    # NOTE: Add in admin_dashboard.html: <a href="{{ url_for('admin_pincodes') }}">Manage Pincodes</a>
    return render_template(
        'admin_dashboard.html',
        user=current_user(),
        metrics=metrics,
        by_store=by_store,
        top_store_complaints=top_store_complaints,
        top_delivery_complaints=top_delivery_complaints
    )

@app.route('/admin/approvals')
@login_required(role='admin')
def admin_approvals():
    flash('Approval feature under development.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create-store', methods=['GET', 'POST'])
@login_required(role='admin')
def admin_create_store():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').lower().strip()
        phone = (request.form.get('phone') or '').strip()
        password = request.form.get('password') or ''
        store_name = (request.form.get('store_name') or '').strip()
        address = (request.form.get('address') or '').strip()


        print("âœ… FORM KEYS:", list(request.form.keys()), flush=True)
        print("âœ… LAT RAW:", repr(request.form.get("latitude")), flush=True)
        print("âœ… LNG RAW:", repr(request.form.get("longitude")), flush=True)

        # âœ… NEW: read lat/lng coming from admin_create_store.html
        lat_raw = (request.form.get('latitude') or '').strip()
        lng_raw = (request.form.get('longitude') or '').strip()


       

        # âœ… Safe convert
        latitude = None
        longitude = None
        try:
            latitude = float(lat_raw) if lat_raw else None
        except Exception:
            latitude = None
        try:
            longitude = float(lng_raw) if lng_raw else None
        except Exception:
            longitude = None

        # âœ… Minimal validation (optional but recommended)
        if not name or not email or not phone or not password or not store_name:
            flash("Please fill all required fields.", "warning")
            return redirect(url_for('admin_create_store'))

        # If you want to force location:
        # if latitude is None or longitude is None:
        #     flash("Please click 'Use Current Location' to capture store coordinates.", "warning")
        #     return redirect(url_for('admin_create_store'))

        try:
            uid = execute("""
                INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
                VALUES (?,?,?,?, 'store', 1, 1, ?)
            """, (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat()))

            execute("""
                INSERT INTO stores (user_id, store_name, address, created_at, latitude, longitude)
                VALUES (?,?,?,?,?,?)
            """, (uid, store_name, address, datetime.utcnow().isoformat(), latitude, longitude))

        except Exception as e:
            flash(f"Store creation failed: {e}", "danger")
            return redirect(url_for('admin_create_store'))

        flash('Store created.', 'success')
        return redirect(url_for('admin_create_store'))

    # GET
    return render_template('admin_create_store.html', user=current_user())

@app.route('/admin/create-delivery', methods=['GET','POST'])
@login_required(role='admin')
def admin_create_delivery():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').lower().strip()
        phone = request.form.get('phone','').strip()
        password = request.form.get('password','')

        if not name or not email or not phone or not password:
            flash('Please fill all required fields.', 'error')
            return redirect(url_for('admin_create_delivery'))

        # âœ… query() returns sqlite3.Row -> use ['col'] not .get()
        rows = query("SELECT id, role, name FROM users WHERE email = ? LIMIT 1", (email,))
        if rows:
            existing = rows[0]
            ex_name = existing['name'] if 'name' in existing.keys() else ''
            ex_role = existing['role'] if 'role' in existing.keys() else ''
            flash(f"Email already exists (User: {ex_name} | Role: {ex_role}). Use a different email.", "error")
            return redirect(url_for('admin_create_delivery'))

        try:
            execute(
                """INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
                   VALUES (?,?,?,?, 'delivery', 1, 1, ?)""",
                (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat())
            )
        except IntegrityError:
            # âœ… If race-condition / same email inserted by another request
            flash("This email is already registered. Please use a different email.", "error")
            return redirect(url_for('admin_create_delivery'))
        except Exception as e:
            flash(f"Failed to create delivery partner: {str(e)}", "error")
            return redirect(url_for('admin_create_delivery'))

        flash('Delivery partner created.', 'success')
        return redirect(url_for('admin_create_delivery'))

    return render_template('admin_create_delivery.html', user=current_user())

# ---- Enable/Disable/Delete/Export per-user ----
@app.route('/admin/users/<int:uid>/enable', methods=['POST'])
@login_required(role='admin')
def admin_user_enable(uid):
    execute("UPDATE users SET is_active=1 WHERE id=?", (uid,))
    flash('User activated.', 'success')
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/transactions.csv')
@login_required(role='admin')
def admin_transactions_csv():
    rows = query('''
        SELECT t.id as txn_id, t.created_at, o.id as order_id, o.total_amount, t.amount, t.status
        FROM transactions t JOIN orders o ON o.id = t.order_id
        ORDER BY t.created_at DESC
    ''')
    csv_lines = ['txn_id,created_at,order_id,total_amount,amount,status']
    for r in rows:
        csv_lines.append(f"{r['txn_id']},{r['created_at']},{r['order_id']},{r['total_amount']},{r['amount']},{r['status']}")
    data = "\n".join(csv_lines).encode('utf-8')
    return send_file(io.BytesIO(data), mimetype='text/csv', as_attachment=True, download_name='transactions.csv')

@app.route('/admin/users/<int:uid>/transactions.csv')
@login_required(role='admin')
def admin_user_transactions_csv(uid):
    user_orders = query("SELECT id FROM orders WHERE user_id=? OR delivery_partner_id=?", (uid, uid))
    srows = query("SELECT id FROM stores WHERE user_id=?", (uid,))
    if srows:
        sids = [r['id'] for r in srows]
        ph = ','.join('?' * len(sids))
        more = query(f"SELECT id FROM orders WHERE store_id IN ({ph})", tuple(sids))
        user_orders += more
    if not user_orders:
        return send_file(io.BytesIO(b"txn_id,created_at,order_id,amount,status\n"), mimetype='text/csv', as_attachment=True, download_name=f'user_{uid}_transactions.csv')

    oids = [r['id'] for r in user_orders]
    ph = ','.join('?' * len(oids))
    rows = query(f"""
        SELECT t.id as txn_id, t.created_at, t.order_id, t.amount, t.status
        FROM transactions t
        WHERE t.order_id IN ({ph})
        ORDER BY t.created_at DESC
    """, tuple(oids))

    csv_lines = ['txn_id,created_at,order_id,amount,status']
    for r in rows:
        csv_lines.append(f"{r['txn_id']},{r['created_at']},{r['order_id']},{r['amount']},{r['status']}")
    data = "\n".join(csv_lines).encode('utf-8')
    return send_file(io.BytesIO(data), mimetype='text/csv', as_attachment=True, download_name=f'user_{uid}_transactions.csv')

@app.route('/admin/users/<int:uid>/export', methods=['GET'])
@login_required(role='admin')
def admin_user_export(uid):
    u = get_user_by_id(uid)
    if not u:
        flash('User not found.','warning')
        return redirect(url_for('admin_users'))
    try:
        data = render_export_to_csv_zip_bytes(uid)
    except Exception as e:
        flash(f'Failed to prepare export: {e}', 'danger')
        return redirect(url_for('admin_users'))
    fn = f"user_{uid}_export_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip"
    return send_file(BytesIO(data), mimetype='application/zip', as_attachment=True, download_name=fn)

@app.route('/admin/users/<int:uid>/export.zip', methods=['GET'])
@login_required(role='admin')
def admin_user_export_zip(uid):
    return admin_user_export(uid)

@app.route('/admin/users/<int:uid>/delete-hard', methods=['POST'])
@login_required(role='admin')
def admin_user_delete_hard(uid):
    ok, reason = can_delete_user_hard(uid)
    if not ok:
        flash(f'Cannot hard-delete: {reason}. The account should remain or be disabled.', 'warning')
        return redirect(request.referrer or url_for('admin_users'))
    try:
        if hard_delete_user(uid):
            flash('User hard-deleted.','success')
        else:
            flash('Hard delete failed.','danger')
    except Exception as e:
        flash(f'Hard delete failed: {e}','danger')
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/complaints')
@login_required(role='admin')
def admin_complaints():
    complaints = list_recent_complaints(limit=200)
    return render_template('admin_complaints.html', user=current_user(), complaints=complaints)

@app.route('/admin/complaints/<int:cid>/status', methods=['POST'])
@login_required(role='admin')
def admin_complaint_set_status(cid):
    status = request.form.get('status','OPEN')
    try:
        update_complaint_status(cid, status)
        flash('Complaint status updated.','success')
    except Exception as e:
        flash(f'Failed to update: {e}','danger')
    return redirect(url_for('admin_complaints'))

@app.route('/admin/users')
@login_required(role='admin')
def admin_users():
    users = query("SELECT id,name,email,phone,role,is_active,created_at FROM users ORDER BY created_at DESC")
    return render_template('admin_users.html', user=current_user(), users=users)

@app.route('/admin/users/<int:uid>/disable', methods=['POST'])
@login_required(role='admin')
def admin_user_disable(uid):
    execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    flash('User disabled.','info')
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required(role='admin')
def admin_user_delete(uid):
    urows = query("SELECT id, role FROM users WHERE id=?", (uid,))
    if not urows:
        flash('User not found.','warning'); return redirect(request.referrer or url_for('admin_users'))
    role = urows[0]['role']

    if role == 'store':
        srow = query("SELECT id FROM stores WHERE user_id=?", (uid,))
        sid = srow[0]['id'] if srow else None
        order_cnt = query("SELECT COUNT(*) c FROM orders WHERE store_id=?", (sid,))[0]['c'] if sid else 0
        if order_cnt and order_cnt > 0:
            execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
            flash("Store has orders; user disabled instead of hard delete.","warning")
            return redirect(request.referrer or url_for('admin_users'))
        if sid:
            execute("DELETE FROM products WHERE store_id=?", (sid,))
            execute("DELETE FROM stores WHERE id=?", (sid,))
        execute("DELETE FROM users WHERE id=?", (uid,))
        flash("Store user removed (no orders).","success")
        return redirect(request.referrer or url_for('admin_users'))

    if role == 'customer':
        oc = query("SELECT COUNT(*) c FROM orders WHERE user_id=?", (uid,))[0]['c']
        if oc and oc > 0:
            execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
            flash("Customer has orders; user disabled instead of hard delete.","warning")
            return redirect(request.referrer or url_for('admin_users'))
        execute("DELETE FROM addresses WHERE user_id=?", (uid,))
        execute("DELETE FROM users WHERE id=?", (uid,))
        flash("Customer removed.","success")
        return redirect(request.referrer or url_for('admin_users'))

    if role == 'delivery':
        oc = query("SELECT COUNT(*) c FROM orders WHERE delivery_partner_id=?", (uid,))[0]['c']
        if oc and oc > 0:
            execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
            flash("Delivery partner has order history; user disabled.","warning")
            return redirect(request.referrer or url_for('admin_users'))
        execute("DELETE FROM users WHERE id=?", (uid,))
        flash("Delivery partner removed.","success")
        return redirect(request.referrer or url_for('admin_users'))

    flash("Refused to delete admin via UI.","danger")
    return redirect(request.referrer or url_for('admin_users'))

# ----------------------
# STORE
# ----------------------
@app.route('/store')
@login_required(role='store')
def store_dashboard():
    u = current_user()
    store = query('SELECT * FROM stores WHERE user_id=?', (u['id'],))
    sid = store[0]['id'] if store else None

    # ===== Store KPIs =====
    # Total orders + GMV (Delivered only; includes product + delivery + tip)
    if sid:
        k_orders = query("""
            SELECT
                COUNT(*) AS total_orders,
                COALESCE(
                    SUM(
                        CASE
                            WHEN status='DELIVERED' THEN (
                                COALESCE(total_amount, 0)
                                + COALESCE(delivery_fee, 0)
                                + COALESCE(tip_amount, 0)
                            )
                            ELSE 0
                        END
                    ),
                    0
                ) AS gmv_total
            FROM orders
            WHERE store_id=?
        """, (sid,))[0]
    else:
        k_orders = {"total_orders": 0, "gmv_total": 0}

    # Paid transactions total (Delivered only; product price only)
    # (So it will not change before delivery, and won't include delivery/tip)
    if sid:
        k_txn = query("""
            SELECT
                COALESCE(
                    SUM(
                        CASE
                            WHEN o.status='DELIVERED' AND t.status='PAID' THEN COALESCE(o.total_amount, 0)
                            ELSE 0
                        END
                    ),
                    0
                ) AS paid_total,
                COALESCE(
                    SUM(
                        CASE
                            WHEN o.status='DELIVERED' AND t.status='PAID' THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS txn_count
            FROM transactions t
            JOIN orders o ON o.id = t.order_id
            WHERE o.store_id=?
        """, (sid,))[0]
    else:
        k_txn = {"paid_total": 0, "txn_count": 0}

    # Unique customers who ordered from this store
    if sid:
        k_cust = query("""
            SELECT COUNT(DISTINCT user_id) AS unique_customers
            FROM orders
            WHERE store_id=?
        """, (sid,))[0]
    else:
        k_cust = {"unique_customers": 0}

    metrics = {
        "total_orders":        k_orders["total_orders"] or 0,
        "gmv_total":           float(k_orders["gmv_total"] or 0.0),
        "paid_total":          float(k_txn["paid_total"] or 0.0),
        "txn_count":           k_txn["txn_count"] or 0,
        "unique_customers":    k_cust["unique_customers"] or 0,
    }

    products = query(
        'SELECT * FROM products WHERE store_id=? ORDER BY created_at DESC',
        (sid,)
    ) if sid else []

    # Only show active (not delivered or cancelled) orders on dashboard
    orders = query('''
    SELECT o.*, 
           u.name  AS customer_name,
           u.phone AS customer_phone,
           oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
           oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
    FROM orders o
    JOIN users u ON u.id = o.user_id
    LEFT JOIN order_addresses oa ON oa.order_id = o.id
    WHERE o.store_id=? 
      AND o.status NOT IN ('DELIVERED','CANCELLED')
    GROUP BY o.id
    ORDER BY o.created_at DESC
''', (sid,)) if sid else []

# template switching
    view = (request.args.get("view") or "auto").lower()

    def is_phone_ua():
        ua = (request.user_agent.string or "").lower()
        return any(k in ua for k in ("android", "iphone", "ipad", "mobile"))

    if view == "mobile":
        template = "store_dashboard_mobile.html"
    elif view == "desktop":
        template = "store_dashboard.html"
    else:
        template = "store_dashboard_mobile.html" if is_phone_ua() else "store_dashboard.html"

    return render_template(
        template,
        user=u,
        store=store[0] if store else None,
        products=products,
        orders=orders,
        metrics=metrics   # <-- add this
    )


@app.route('/store/delivery-settings', methods=['POST'])
@login_required(role='store')
def store_delivery_settings_update():
    """Update delivery prices only for the currently signed-in store."""
    u = current_user()
    store_rows = query('SELECT * FROM stores WHERE user_id=?', (u['id'],))

    return_view = (request.form.get('return_view') or '').strip().lower()
    redirect_args = {"view": return_view} if return_view in ("desktop", "mobile") else {}

    if not store_rows:
        flash('Store not found.', 'danger')
        return redirect(url_for('store_dashboard', **redirect_args))

    store = store_rows[0]
    enabled = "1" in request.form.getlist('delivery_charge_enabled')

    fee_fields = {
        "delivery_fee_0_2_km": "0â€“2 km",
        "delivery_fee_2_5_km": "2â€“5 km",
        "delivery_fee_5_7_km": "5â€“7 km",
        "delivery_fee_7_10_km": "7â€“10 km",
    }
    fee_values = {}

    for field_name, distance_label in fee_fields.items():
        raw_value = request.form.get(field_name)
        if raw_value is None or str(raw_value).strip() == "":
            flash(f'Enter a delivery charge for {distance_label}.', 'warning')
            return redirect(url_for('store_dashboard', **redirect_args))
        try:
            amount = round(float(raw_value), 2)
        except (TypeError, ValueError):
            flash(f'Enter a valid delivery charge for {distance_label}.', 'warning')
            return redirect(url_for('store_dashboard', **redirect_args))
        if not math.isfinite(amount) or amount < 0 or amount > 10000:
            flash(f'Delivery charge for {distance_label} must be between â‚¹0 and â‚¹10,000.', 'warning')
            return redirect(url_for('store_dashboard', **redirect_args))
        fee_values[field_name] = amount

    execute('''
        UPDATE stores
        SET delivery_charge_enabled=?,
            delivery_fee_0_2_km=?,
            delivery_fee_2_5_km=?,
            delivery_fee_5_7_km=?,
            delivery_fee_7_10_km=?
        WHERE id=? AND user_id=?
    ''', (
        1 if enabled else 0,
        fee_values["delivery_fee_0_2_km"],
        fee_values["delivery_fee_2_5_km"],
        fee_values["delivery_fee_5_7_km"],
        fee_values["delivery_fee_7_10_km"],
        store["id"],
        u["id"],
    ))

    if enabled:
        flash('Delivery charges updated successfully.', 'success')
    else:
        flash('Free delivery is now enabled for your store.', 'success')
    return redirect(url_for('store_dashboard', **redirect_args))



@app.route('/store/delivered-orders')
@login_required(role='store')
def store_delivered_orders():
    """Show all delivered orders for this store."""
    u = current_user()
    srow = query('SELECT id, store_name FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        flash('Store not found.', 'danger')
        return redirect(url_for('store_dashboard'))
    sid = srow[0]['id']

    delivered = query('''
    SELECT o.*, 
           u.name  AS customer_name,
           u.phone AS customer_phone,
           oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
           oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
    FROM orders o
    JOIN users u ON u.id = o.user_id
    LEFT JOIN order_addresses oa ON oa.order_id = o.id
    WHERE o.store_id=? AND o.status='DELIVERED'
    GROUP BY o.id
    ORDER BY o.created_at DESC
    ''', (sid,))
    return render_template('store_delivered_orders.html', user=u, store=srow[0], orders=delivered)



@app.route('/store/product/new', methods=['POST']) 
@login_required(role='store')
def store_product_new():
    u = current_user()
    sid = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))[0]['id']

    name = request.form.get('name','').strip()
    price_per_kg = float(request.form.get('price_per_kg','0') or 0)
    stock_kg = float(request.form.get('stock_kg','0') or 0)

    # NEW: category fields
    category = (request.form.get('category') or '').strip()
    sub_category = (request.form.get('sub_category') or '').strip()

    # ---- VALIDATION ----
    allowed_categories = ['Fresh cuts', 'Ready to cook', 'Spices']
    fresh_cut_subs = ['Curry cuts', 'Boneless & Mince', 'Offals']

    if category not in allowed_categories:
        flash('Invalid category selected.', 'warning')
        return redirect(url_for('store_dashboard'))

    if category == 'Fresh cuts':
        if sub_category not in fresh_cut_subs:
            flash('Please select a valid sub-category for Fresh cuts.', 'warning')
            return redirect(url_for('store_dashboard'))
    else:
        sub_category = None  # enforce rule

    image = request.files.get('image')
    image_path = None
    if image and '.' in image.filename and allowed_file(image.filename):
        fn = secure_filename(image.filename)
        save_as = datetime.utcnow().strftime('%Y%m%d%H%M%S_') + fn
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], save_as))
        image_path = f'uploads/{save_as}'

    execute('''
        INSERT INTO products
            (store_id, name, price_per_kg, stock_kg, image_path,
             category, sub_category, is_active, created_at)
        VALUES (?,?,?,?,?,?,?,1,?)
    ''', (
        sid, name, price_per_kg, stock_kg, image_path,
        category, sub_category, datetime.utcnow().isoformat()
    ))

    flash('Product added.', 'success')
    return redirect(url_for('store_dashboard'))

@app.route('/store/product/<int:pid>/toggle', methods=['POST'])
@login_required(role='store')
def store_product_toggle(pid):
    u = current_user()
    sid = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))[0]['id']
    execute('UPDATE products SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=? AND store_id=?',
            (pid, sid))
    return redirect(url_for('store_dashboard'))


@app.route('/store/product/<int:pid>/stock/add', methods=['POST'], endpoint='store_product_add_stock')
@login_required(role='store')
def store_product_add_stock(pid):
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        flash('Store not found.', 'danger')
        return redirect(url_for('store_dashboard'))
    sid = srow[0]['id']

    try:
        add_kg = float(request.form.get('add_kg', '0') or 0)
    except ValueError:
        add_kg = 0.0

    if add_kg <= 0:
        flash('Enter a positive stock amount.', 'warning')
        return redirect(url_for('store_dashboard'))

    execute('UPDATE products SET stock_kg = stock_kg + ? WHERE id=? AND store_id=?', (add_kg, pid, sid))
    flash(f'Added {add_kg:.2f} kg to stock.', 'success')
    return redirect(url_for('store_dashboard'))


@app.route('/store/product/<int:pid>/edit', methods=['GET'], endpoint='store_product_edit')
@login_required(role='store')
def store_product_edit(pid):
    """Render edit form for a product that belongs to the current store."""
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        flash('Store not found.', 'danger')
        return redirect(url_for('store_dashboard'))
    sid = srow[0]['id']

    rows = query('SELECT * FROM products WHERE id=? AND store_id=?', (pid, sid))
    if not rows:
        flash('Product not found for your store.', 'warning')
        return redirect(url_for('store_dashboard'))

    p = dict(rows[0])  # includes category/sub_category now (DB columns)
    return render_template('store_product_edit.html', user=u, product=p)

@app.route('/store/product/<int:pid>/edit', methods=['POST'], endpoint='store_product_update')
@login_required(role='store')
def store_product_update(pid):
    """Handle updates for product fields (name, price, stock, image, category)."""
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        flash('Store not found.', 'danger')
        return redirect(url_for('store_dashboard'))
    sid = srow[0]['id']

    # Ensure product belongs to this store
    rows = query('SELECT * FROM products WHERE id=? AND store_id=?', (pid, sid))
    if not rows:
        flash('Product not found for your store.', 'warning')
        return redirect(url_for('store_dashboard'))
    prod = dict(rows[0])

    # Read form fields
    name = (request.form.get('name') or '').strip()
    price_per_kg = request.form.get('price_per_kg', '')
    stock_kg     = request.form.get('stock_kg', '')
    image        = request.files.get('image')

    # âœ… NEW: category fields
    category = (request.form.get('category') or '').strip()
    sub_category = (request.form.get('sub_category') or '').strip()

    # Validate numeric inputs safely
    try:
        price = float(price_per_kg)
        if price < 0:
            raise ValueError()
    except Exception:
        flash('Enter a valid non-negative price.', 'warning')
        return redirect(url_for('store_product_edit', pid=pid))

    try:
        stock = float(stock_kg)
        if stock < 0:
            raise ValueError()
    except Exception:
        flash('Enter a valid non-negative stock (kg).', 'warning')
        return redirect(url_for('store_product_edit', pid=pid))

    # ---- VALIDATION (category/sub_category) ----
    allowed_categories = ['Fresh cuts', 'Ready to cook', 'Spices']
    fresh_cut_subs = ['Curry cuts', 'Boneless & Mince', 'Offals']

    if category not in allowed_categories:
        flash('Invalid category selected.', 'warning')
        return redirect(url_for('store_product_edit', pid=pid))

    if category == 'Fresh cuts':
        if sub_category not in fresh_cut_subs:
            flash('Please select a valid sub-category for Fresh cuts.', 'warning')
            return redirect(url_for('store_product_edit', pid=pid))
    else:
        sub_category = None  # enforce rule

    image_path = prod.get('image_path')
    if image and image.filename and '.' in image.filename and allowed_file(image.filename):
        fn = secure_filename(image.filename)
        save_as = datetime.utcnow().strftime('%Y%m%d%H%M%S_') + fn
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], save_as))
        image_path = f'uploads/{save_as}'

    # Update the row (now includes category/sub_category)
    execute('''
        UPDATE products
        SET name=?, price_per_kg=?, stock_kg=?, image_path=?,
            category=?, sub_category=?
        WHERE id=? AND store_id=?
    ''', (
        name, price, stock, image_path,
        category, sub_category, pid, sid
    ))

    flash('Product updated.', 'success')
    return redirect(url_for('store_dashboard'))



@app.route('/store/transactions.csv')
@login_required(role='store')
def store_txn_csv():
    """
    Download transactions for this store as CSV.
    Supported presets via ?range=day|week|month (UTC dates).
    You can also pass explicit ?start=YYYY-MM-DD&end=YYYY-MM-DD (end exclusive).
    Only PAID transactions are included.
    """
    u = current_user()
    srow = query('SELECT id, store_name FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        flash('Store not found.', 'danger')
        return redirect(url_for('store_dashboard'))
    sid = srow[0]['id']

    # --- Parse preset or explicit dates
    preset = (request.args.get('range') or '').lower()  # 'day' | 'week' | 'month' | ''
    start_str = request.args.get('start')
    end_str   = request.args.get('end')    # exclusive end

    def iso(d): return d.isoformat()

    # Compute start/end (UTC date bounds)
    if start_str and end_str:
        # explicit range
        try:
            start_date = date.fromisoformat(start_str)
            end_date   = date.fromisoformat(end_str)
        except Exception:
            flash('Invalid start/end date. Use YYYY-MM-DD.', 'warning')
            return redirect(url_for('store_dashboard'))
    else:
        today = datetime.utcnow().date()
        if preset == 'day':
            start_date = today
            end_date   = today + timedelta(days=1)
        elif preset == 'week':
            # Monday..Sunday window
            start_date = today - timedelta(days=today.weekday())
            end_date   = start_date + timedelta(days=7)
        elif preset == 'month':
            start_date = date(today.year, today.month, 1)
            if today.month == 12:
                end_date = date(today.year + 1, 1, 1)
            else:
                end_date = date(today.year, today.month + 1, 1)
        else:
            # default: today
            start_date = today
            end_date   = today + timedelta(days=1)

    # Convert date-only bounds to ISO datetimes (inclusive start, exclusive end)
    start_iso = f"{iso(start_date)}T00:00:00"
    end_iso   = f"{iso(end_date)}T00:00:00"

    # Fetch PAID transactions for this store in window
    rows = query("""
        SELECT
          t.id                AS txn_id,
          t.created_at        AS txn_created_at,
          o.id                AS order_id,
          o.total_amount      AS items_total,
          COALESCE(o.delivery_fee,0) AS delivery_fee,
          COALESCE(o.tip_amount,0)   AS tip_amount,
          t.amount            AS paid_amount,
          t.status            AS txn_status
        FROM transactions t
        JOIN orders o ON o.id = t.order_id
        WHERE o.store_id = ?
          AND t.status = 'PAID'
          AND t.created_at >= ?
          AND t.created_at < ?
        ORDER BY t.created_at DESC
    """, (sid, start_iso, end_iso))

    # Build CSV
    csv_lines = [
        "txn_id,txn_created_at,order_id,items_total,delivery_fee,tip_amount,paid_amount,txn_status"
    ]
    for r in rows:
        csv_lines.append(",".join([
            str(r["txn_id"]),
            str(r["txn_created_at"]),
            str(r["order_id"]),
            f'{float(r["items_total"] or 0):.2f}',
            f'{float(r["delivery_fee"] or 0):.2f}',
            f'{float(r["tip_amount"] or 0):.2f}',
            f'{float(r["paid_amount"] or 0):.2f}',
            str(r["txn_status"]),
        ]))

    data = "\n".join(csv_lines).encode("utf-8")
    # Nice filename: store_<id>_<range>_YYYYMMDD.csv
    stamp = datetime.utcnow().strftime("%Y%m%d")
    label = preset or "day"
    fn = f"store_{sid}_txns_{label}_{stamp}.csv"

    return send_file(
        io.BytesIO(data),
        mimetype="text/csv",
        as_attachment=True,
        download_name=fn
    )



@app.route('/store/order/<int:oid>/status', methods=['POST'])
@login_required(role='store')
def store_order_status(oid):
    new_status = request.form.get('status','PLACED').upper()
    execute('UPDATE orders SET status=? WHERE id=?', (new_status, oid))
    add_order_event(oid, new_status)

    if new_status == 'DELIVERED':
        execute("UPDATE transactions SET status='PAID' WHERE order_id=?", (oid,))
        execute("UPDATE orders SET payment_status='PAID' WHERE id=?", (oid,))

    flash('Order status updated.','success')
    return redirect(url_for('store_dashboard'))

# --- API alias for order status so templates can call `api_order_status` ---
# --- Read-only JSON: current order status for live tracking ---
# --- Read-only JSON: current order status for live tracking ---
@app.route("/api/orders/<int:oid>/status", methods=["GET"], endpoint="api_order_status")
@login_required()
def api_order_status(oid):
    u = current_user()
    data = get_order_full(oid, for_user_id=u["id"] if u["role"] == "customer" else None)
    if not data:
        return jsonify({"ok": False, "error": "not found"}), 404

    o = data["order"]
    return jsonify({
        "ok": True,
        "id": o["id"],
        "status": o["status"],
        "payment_status": o["payment_status"],
        "delivery_partner_name": o.get("delivery_partner_name"),
        "events": data["events"],   # [{status,note,created_at}...]
    })



# -----------------------------------------------------------------------------
# Mobile (token) orders API
# -----------------------------------------------------------------------------

@app.route('/api/orders', methods=['GET'])
@api_login_required
def api_orders_list(user_id):
    orders = query('''
        SELECT o.*, s.store_name
        FROM orders o
        JOIN stores s ON s.id = o.store_id
        WHERE o.user_id = ?
        ORDER BY o.created_at DESC
    ''', (user_id,))

    return jsonify({
        'success': True,
        'orders': [{
            'id': o['id'],
            'store_name': o['store_name'],
            'total_amount': float(o['total_amount'] or 0),
            'delivery_fee': float(o['delivery_fee'] or 0),
            'tip_amount': float(o['tip_amount'] or 0),
            'status': o['status'],
            'payment_status': o['payment_status'],
            'created_at': o['created_at']
        } for o in orders]
    })


@app.route('/api/orders/<int:oid>', methods=['GET'])
@api_login_required
def api_order_detail(user_id, oid):
    data = get_order_full(oid, for_user_id=user_id)
    if not data:
        return jsonify({'success': False, 'error': 'Order not found'}), 404

    o = data['order']
    return jsonify({
        'success': True,
        'order': {
            'id': o['id'],
            'store_name': o.get('store_name'),
            'total_amount': float(o['total_amount'] or 0),
            'delivery_fee': float(o['delivery_fee'] or 0),
            'tip_amount': float(o['tip_amount'] or 0),
            'status': o.get('status'),
            'payment_status': o.get('payment_status'),
            'created_at': o.get('created_at'),
            # optional
            'delivery_partner_name': o.get('delivery_partner_name'),
            'items': [{
                'product_id': item.get('product_id'),
                'name': item.get('name'),
                'weight_kg': float(item.get('weight_kg') or 0),
                'unit_price_per_kg': float(item.get('unit_price_per_kg') or 0),
                'line_total': float(item.get('line_total') or 0),
                'image_path': item.get('image_path')
            } for item in data.get('items', [])],
            'address': data.get('address'),
            'events': data.get('events')
        }
    })


@app.route('/api/orders/<int:oid>/rider_location', methods=['GET'])
@api_login_required
def api_order_rider_location(user_id, oid):
    # Ensure the order belongs to this user
    ok = query('SELECT id FROM orders WHERE id=? AND user_id=? LIMIT 1', (oid, user_id))
    if not ok:
        return jsonify({'success': False, 'error': 'Order not found'}), 404

    row = query(
        "SELECT latitude, longitude, recorded_at AS updated_at "
        "FROM delivery_locations WHERE order_id=? "
        "ORDER BY id DESC LIMIT 1",
        (oid,)
    )
    if not row:
        return jsonify({'success': True, 'has_location': False})

    r = row[0]
    return jsonify({
        'success': True,
        'has_location': True,
        'data': {
            'latitude': r['latitude'],
            'longitude': r['longitude'],
            'updated_at': r['updated_at'],
        }
    })



# ----------------------
# NEWSLETTER & UPLOADS
# ----------------------
@app.route('/newsletter/subscribe', methods=['POST'])
def newsletter_subscribe():
    email = request.form.get('email','').strip().lower()
    if not email or '@' not in email:
        flash('Please enter a valid email.','danger'); return redirect(request.referrer or url_for('index'))
    try:
        execute('INSERT INTO newsletter_subscribers (email, created_at) VALUES (?,?)', (email, datetime.utcnow().isoformat()))
        flash('Subscribed to newsletter!','success')
    except Exception:
        flash('You are already subscribed.','info')
    return redirect(request.referrer or url_for('index'))

@app.route('/uploads/<path:fn>')
def uploaded_file(fn):
    if '..' in fn or fn.startswith('/'):
        return abort(404)
    full = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    if not os.path.isfile(full):
        return abort(404)
    return send_file(full)

@app.after_request
def add_no_cache_headers(resp):
    # help fetch() always get fresh data
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route('/__routes')
def __routes():
    return "<pre>" + "\n".join(
        f"{r.endpoint:30} {r.methods} {r}"
        for r in app.url_map.iter_rules()
    ) + "</pre>"








@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip() or None
        subject = (request.form.get("subject") or "").strip()
        message = (request.form.get("message") or "").strip()

        if not name or not email or not subject or not message:
            flash("Please fill all required fields.", "warning")
            return redirect(url_for("contact"))

        execute("""
            INSERT INTO contact_messages (name, email, phone, subject, message, status, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (name, email, phone, subject, message, "NEW", datetime.utcnow().isoformat()))

        flash("Message sent! We will contact you soon.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", user=current_user())




@app.route("/admin/contact-messages")
@login_required(role="admin")
def admin_contact_messages():
    messages = query("""
        SELECT *
        FROM contact_messages
        ORDER BY created_at DESC
    """)
    return render_template(
        "admin_contact_messages.html",
        user=current_user(),
        messages=messages
    )
@app.route(
    "/admin/contact-messages/<int:mid>/status",
    methods=["POST"],
    endpoint="admin_contact_message_status"
)
@login_required(role="admin")
def admin_contact_message_status(mid):
    status = (request.form.get("status") or "NEW").upper()
    if status not in ("NEW", "READ", "RESOLVED"):
        status = "NEW"

    execute(
        "UPDATE contact_messages SET status=? WHERE id=?",
        (status, mid)
    )

    return redirect(url_for("admin_contact_messages"))


# ==================== AUTH API ====================

@app.route("/api/auth/web-session", methods=["POST"])
@api_login_required
def api_create_web_session():
    """
    Create a web session for mobile app users.
    
    This endpoint allows mobile app users (who authenticate with JWT tokens)
    to access the web dashboard by generating a session cookie.
    
    Flow:
    1. Mobile app authenticates via /api/auth/login (gets JWT token)
    2. Mobile app calls this endpoint with JWT token in Authorization header
    3. Backend validates JWT, creates Flask session, returns session identifier
    4. Mobile app injects session cookie into WebView
    5. WebView can now access protected web routes as authenticated user
    
    Returns:
        JSON with session cookie that mobile app should inject into WebView
    """
    try:
        # Get user_id from session (set by @login_required_api decorator)
        user_id = session.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User not found in session'
            }), 401
        
        # Fetch user details from database
        rows = query("SELECT * FROM users WHERE id=?", (user_id,))
        if not rows:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        user = dict(rows[0])
        
        # Verify user is a store owner
        if user.get('role') != 'store':
            return jsonify({
                'success': False,
                'error': 'Only store owners can access the web dashboard'
            }), 403
        
        # Create Flask session (same as regular web login)
        session['user_id'] = user['id']
        session['user_role'] = user['role']
        session.permanent = True  # Make session permanent (respects PERMANENT_SESSION_LIFETIME)
        session.modified = True
        
        # Generate unique session identifier for tracking
        import secrets
        session_identifier = secrets.token_urlsafe(32)
        session['mobile_session_id'] = session_identifier
        
        # Log session creation
        print(f"âœ… Web session created for user {user['id']} ({user['email']})")
        
        # Return session information to mobile app
        return jsonify({
            'success': True,
            'message': 'Web session created successfully',
            'cookie_name': app.config.get('SESSION_COOKIE_NAME', 'session'),
            'session_cookie': session_identifier,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
        
    except Exception as e:
        print(f"âŒ Error creating web session: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500
    
# # ---------------------------------
# # STEP 3: (OPTIONAL) ADD SESSION CLEANUP
# # ---------------------------------
# # Paste this if you want to clean up expired sessions

# @app.route("/api/auth/cleanup-sessions", methods=["POST"])
# @admin_approvals
# def api_cleanup_sessions():
#     """
#     Clean up expired mobile sessions (admin only).
    
#     This is optional but recommended for production.
#     You can run this periodically via a cron job or task scheduler.
#     """
#     try:
#         # If using custom web_sessions table (see alternative approach):
#         # execute('''
#         #     DELETE FROM web_sessions 
#         #     WHERE expires_at < ?
#         # ''', (datetime.utcnow().isoformat(),))
        
#         return jsonify({
#             'success': True,
#             'message': 'Session cleanup completed'
#         }), 200
        
#     except Exception as e:
#         print(f"âŒ Error cleaning up sessions: {e}")
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 500


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    
    rows = query('SELECT * FROM users WHERE email=?', (email,))
    if not rows:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    u = dict(rows[0])
    
    if not check_password_hash(u['password_hash'], password):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    if not u['is_active']:
        return jsonify({'success': False, 'error': 'Account is inactive'}), 403
    
    # Generate token
    token = generate_session_token(u['id'])
    expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
    
    execute("""
        INSERT INTO api_sessions (user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (u['id'], token, datetime.utcnow().isoformat(), expires_at))
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': u['id'],
            'name': u['name'],
            'email': u['email'],
            'phone': u['phone'],
            'role': u['role']
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def api_auth_register():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').lower().strip()
    phone = data.get('phone', '').strip()
    password = data.get('password', '')
    
    if not name or not email or not password:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    if phone:
        phone = normalize_phone(phone)
    
    try:
        uid = execute("""
            INSERT INTO users (name, email, phone, password_hash, role, phone_verified, is_active, created_at)
            VALUES (?, ?, ?, ?, 'customer', 1, 1, ?)
        """, (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat()))
    except Exception:
        return jsonify({'success': False, 'error': 'Email or phone already registered'}), 409
    
    # Auto-login: generate token
    token = generate_session_token(uid)
    expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
    
    execute("""
        INSERT INTO api_sessions (user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (uid, token, datetime.utcnow().isoformat(), expires_at))
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': uid,
            'name': name,
            'email': email,
            'phone': phone,
            'role': 'customer'
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
@api_login_required
def api_auth_logout(user_id):
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    execute("DELETE FROM api_sessions WHERE token=?", (token,))
    return jsonify({'success': True})

# ==================== PRODUCTS API ====================

@app.route('/api/products', methods=['GET'])
def api_products_list():
    category = (request.args.get('category') or '').strip()
    sub_category = (request.args.get('sub_category') or '').strip()
    search = (request.args.get('search') or '').strip()

    allowed_categories = ['Fresh cuts', 'Ready to cook', 'Spices']
    fresh_cut_subs = ['Curry cuts', 'Boneless & Mince', 'Offals']

    query_sql = """
        SELECT p.*, s.store_name, s.id AS store_id,
               (SELECT ROUND(AVG(r.rating), 1) FROM product_ratings r WHERE r.product_id = p.id) AS avg_rating,
               (SELECT COUNT(*) FROM product_ratings r2 WHERE r2.product_id = p.id) AS rating_count
        FROM products p
        JOIN stores s ON s.id = p.store_id
        WHERE p.is_active = 1 AND p.stock_kg > 0
    """
    params = []

    # âœ… Category filter
    if category:
        if category not in allowed_categories:
            return jsonify({'success': False, 'error': 'Invalid category'}), 400
        query_sql += " AND p.category = ?"
        params.append(category)

        # âœ… Sub-category filter (only valid for Fresh cuts)
        if sub_category:
            if category != 'Fresh cuts':
                return jsonify({'success': False, 'error': 'sub_category only valid for Fresh cuts'}), 400
            if sub_category not in fresh_cut_subs:
                return jsonify({'success': False, 'error': 'Invalid sub_category'}), 400
            query_sql += " AND p.sub_category = ?"
            params.append(sub_category)

    # âœ… Search filter
    if search:
        query_sql += " AND (LOWER(p.name) LIKE ? OR LOWER(s.store_name) LIKE ?)"
        search_term = f"%{search.lower()}%"
        params.extend([search_term, search_term])

    query_sql += " ORDER BY p.created_at DESC LIMIT 100"

    products = query(query_sql, tuple(params))

    return jsonify({
        'success': True,
        'products': [{
            'id': p['id'],
            'name': p['name'],
            'price_per_kg': float(p['price_per_kg'] or 0),
            'stock_kg': float(p['stock_kg'] or 0),
            'image_path': p['image_path'],
            'store_name': p['store_name'],
            'store_id': p['store_id'],
            'avg_rating': float(p['avg_rating'] or 0),
            'rating_count': int(p['rating_count'] or 0),

            # âœ… NEW (for app-side filtering/debug)
            'category': p['category'],
            'sub_category': p['sub_category'],

        } for p in products]
    })


@app.route('/api/products/<int:pid>', methods=['GET'])
def api_product_detail(pid):
    rows = query("""
        SELECT p.*, s.store_name, s.id AS store_id,
               (SELECT ROUND(AVG(r.rating), 1) FROM product_ratings r WHERE r.product_id = p.id) AS avg_rating,
               (SELECT COUNT(*) FROM product_ratings r2 WHERE r2.product_id = p.id) AS rating_count
        FROM products p
        JOIN stores s ON s.id = p.store_id
        WHERE p.id = ? AND p.is_active = 1 AND p.stock_kg > 0
    """, (pid,))

    if not rows:
        return jsonify({'success': False, 'error': 'Product not found'}), 404

    p = dict(rows[0])

    return jsonify({
        'success': True,
        'product': {
            'id': p['id'],
            'name': p['name'],
            'price_per_kg': float(p['price_per_kg'] or 0),
            'stock_kg': float(p['stock_kg'] or 0),
            'image_path': p['image_path'],
            'store_name': p['store_name'],
            'store_id': p['store_id'],
            'avg_rating': float(p['avg_rating'] or 0),
            'rating_count': int(p['rating_count'] or 0),

            # âœ… NEW
            'category': p['category'],
            'sub_category': p['sub_category'],

        }
    })

# ==================== CATEGORIES API ====================

@app.route('/api/categories', methods=['GET'])
def api_categories_list():
    # Since you don't have categories in your schema, return product types or empty
    return jsonify({
        'success': True,
        'categories': [
            {'id': 1, 'name': 'Fresh Chicken', 'slug': 'fresh-chicken'},
            {'id': 2, 'name': 'Processed', 'slug': 'processed'},
        ]
    })

# ==================== USER PROFILE API ====================

@app.route('/api/user/profile', methods=['GET'])
@api_login_required
def api_user_profile(user_id):
    rows = query("SELECT * FROM users WHERE id=?", (user_id,))
    if not rows:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    u = dict(rows[0])
    
    return jsonify({
        'success': True,
        'user': {
            'id': u['id'],
            'name': u['name'],
            'email': u['email'],
            'phone': u['phone'],
            'role': u['role']
        }
    })

@app.route('/api/user/profile', methods=['PUT'])
@api_login_required
def api_user_profile_update(user_id):
    data = request.get_json(silent=True) or {}
    
    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    
    if name:
        execute("UPDATE users SET name=? WHERE id=?", (name, user_id))
    if phone:
        execute("UPDATE users SET phone=? WHERE id=?", (phone, user_id))
    
    return jsonify({'success': True})

# ==================== CART API ====================

@app.route('/api/cart', methods=['GET'])
@api_login_required
def api_cart_get(user_id):
    cid = get_or_create_cart(user_id)
    
    items = query('''
                  SELECT ci.id AS cart_item_id, ci.weight_kg, ci.product_id,
                    p.name, p.price_per_kg, p.image_path, p.stock_kg,
                    p.store_id AS store_id
                        FROM cart_items ci
                        JOIN products p ON p.id = ci.product_id
                        WHERE ci.cart_id = ?
                    ''', (cid,))
    
    total = sum([(row['weight_kg'] or 0) * (row['price_per_kg'] or 0) for row in items])
    
    return jsonify({
        'success': True,
        'items': [{
            'id': item['cart_item_id'],
            'product_id': item['product_id'],
            'name': item['name'],
            'price_per_kg': float(item['price_per_kg'] or 0),
            'weight_kg': float(item['weight_kg'] or 0),
            'image_path': item['image_path'],
            'stock_kg': float(item['stock_kg'] or 0),
            'store_id': int(item['store_id']) if item['store_id'] is not None else None,
        } for item in items],
        'total': float(total)
    }), 200

@app.route('/api/cart/clear', methods=['POST'])
@api_login_required
def api_cart_clear(user_id):
    cid = get_or_create_cart(user_id)
    execute("DELETE FROM cart_items WHERE cart_id=?", (cid,))
    return jsonify({'ok': True})


# @app.route('/api/cart', methods=['POST'])
# @api_login_required
# def api_cart_add(user_id):
#     data = request.get_json(silent=True) or {}
#     product_id = data.get('product_id')
#     quantity = float(data.get('quantity', 1))
    
#     if not product_id or quantity < 0.25:
#         return jsonify({'success': False, 'error': 'Invalid product or quantity'}), 400
    
#     prow = query("SELECT stock_kg, is_active FROM products WHERE id=?", (product_id,))
#     if not prow or prow[0]['is_active'] != 1 or prow[0]['stock_kg'] <= 0:
#         return jsonify({'success': False, 'error': 'Product not available'}), 404
    
#     if quantity > prow[0]['stock_kg']:
#         return jsonify({'success': False, 'error': 'Insufficient stock'}), 409
    
#     cid = get_or_create_cart(user_id)
    
#     rows = query('SELECT id FROM cart_items WHERE cart_id=? AND product_id=?', (cid, product_id))
#     if rows:
#         execute('UPDATE cart_items SET weight_kg=? WHERE id=?', (quantity, rows[0]['id']))
#     else:
#         execute('INSERT INTO cart_items (cart_id, product_id, weight_kg) VALUES (?,?,?)', 
#                 (cid, product_id, quantity))
    
#     return jsonify({'success': True})

# @app.route('/api/cart/<int:cart_item_id>', methods=['DELETE'])
# @api_login_required
# def api_cart_remove(user_id, cart_item_id):
#     execute('DELETE FROM cart_items WHERE id=?', (cart_item_id,))
#     return jsonify({'success': True})

# ==================== ORDERS API ====================

# @app.route('/api/orders', methods=['GET'])
# @api_login_required
# def api_orders_list(user_id):
#     orders = query('''
#         SELECT o.*, s.store_name
#         FROM orders o
#         JOIN stores s ON s.id = o.store_id
#         WHERE o.user_id = ?
#         ORDER BY o.created_at DESC
#     ''', (user_id,))
    
#     return jsonify({
#         'success': True,
#         'orders': [{
#             'id': o['id'],
#             'store_name': o['store_name'],
#             'total_amount': float(o['total_amount'] or 0),
#             'delivery_fee': float(o['delivery_fee'] or 0),
#             'tip_amount': float(o['tip_amount'] or 0),
#             'status': o['status'],
#             'payment_status': o['payment_status'],
#             'created_at': o['created_at']
#         } for o in orders]
#     })

# @app.route('/api/orders/<int:oid>', methods=['GET'])
# @api_login_required
# def api_order_detail(user_id, oid):
#     data = get_order_full(oid, for_user_id=user_id)
#     if not data:
#         return jsonify({'success': False, 'error': 'Order not found'}), 404
    
#     o = data['order']
    
#     return jsonify({
#         'success': True,
#         'order': {
#             'id': o['id'],
#             'store_name': o['store_name'],
#             'total_amount': float(o['total_amount'] or 0),
#             'delivery_fee': float(o['delivery_fee'] or 0),
#             'tip_amount': float(o['tip_amount'] or 0),
#             'status': o['status'],
#             'payment_status': o['payment_status'],
#             'created_at': o['created_at'],
#             'items': [{
#                 'product_id': item['product_id'],
#                 'name': item['name'],
#                 'weight_kg': float(item['weight_kg'] or 0),
#                 'unit_price_per_kg': float(item['unit_price_per_kg'] or 0),
#                 'line_total': float(item['line_total'] or 0),
#                 'image_path': item['image_path']
#             } for item in data['items']],
#             'address': data['address'],
#             'events': data['events']
#         }
#     })

# @app.route('/api/orders', methods=['POST'])
# @api_login_required
# def api_order_create(user_id):
#     data = request.get_json(silent=True) or {}
#     items = data.get('items', [])  # [{'product_id': X, 'weight_kg': Y}, ...]
#     delivery_address = data.get('delivery_address', '')
#     payment_method = data.get('payment_method', 'COD')
    
#     if not items or not delivery_address:
#         return jsonify({'success': False, 'error': 'Missing items or address'}), 400
    
#     # This is a simplified version - you should use your existing checkout logic
#     # For now, just return success with a dummy order ID
#     return jsonify({
#         'success': True,
#         'order_id': 1,
#         'message': 'Please use the website checkout for now'
#     })


# this is for the mobile app's address reused the website's logic with minimul updates

# Add this to your app.py file
# Place it near the other API order endpoints (around line 2450)

@app.route('/api/orders/<int:oid>/cancel', methods=['POST'])
@api_login_required
def api_order_cancel(user_id, oid):
    """
    Cancel an order (API endpoint for mobile app)
    """
    # Check if order exists and belongs to user
    rows = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, user_id))
    if not rows:
        return jsonify({
            'success': False,
            'error': 'Order not found'
        }), 404

    order_row = dict(rows[0])
    
    # Check if order can be cancelled
    CANCELLABLE_STATUSES = ['PLACED', 'CONFIRMED', 'PREPARING']
    if order_row["status"] not in CANCELLABLE_STATUSES:
        return jsonify({
            'success': False,
            'error': 'This order can no longer be cancelled'
        }), 400

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")

        # Double-check status hasn't changed
        cur.execute("SELECT status FROM orders WHERE id=? AND user_id=?", (oid, user_id))
        cur_status = cur.fetchone()
        if not cur_status or cur_status["status"] not in CANCELLABLE_STATUSES:
            conn.rollback()
            return jsonify({
                'success': False,
                'error': 'This order can no longer be cancelled'
            }), 400

        # Restore stock for all items
        cur.execute("SELECT product_id, weight_kg FROM order_items WHERE order_id=?", (oid,))
        for line in cur.fetchall():
            pid, w = int(line["product_id"]), float(line["weight_kg"] or 0)
            cur.execute("UPDATE products SET stock_kg = stock_kg + ? WHERE id=?", (w, pid))
            cur.execute("UPDATE products SET is_active=1 WHERE id=? AND stock_kg > 0", (pid,))

        # Update order status
        now = datetime.utcnow().isoformat()
        cur.execute("""
            UPDATE orders
            SET status='CANCELLED',
                payment_status=CASE WHEN payment_status='PAID' THEN 'REFUNDED' ELSE payment_status END,
                delivery_partner_id=NULL
            WHERE id=?
        """, (oid,))
        
        # Update transaction status
        cur.execute("""
            UPDATE transactions
            SET status=CASE
                WHEN status='PAID' THEN 'REFUNDED'
                ELSE 'VOID'
            END
            WHERE order_id=?
        """, (oid,))
        
        # Add cancellation event
        cur.execute("""
            INSERT INTO order_events (order_id, status, note, created_at)
            VALUES (?,?,?,?)
        """, (oid, "CANCELLED", "Cancelled by customer via mobile app", now))

        conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Order cancelled successfully'
        })
        
    except Exception as e:
        conn.rollback()
        print(f"âŒ Error cancelling order {oid}: {e}")
        return jsonify({
            'success': False,
            'error': f'Could not cancel order: {str(e)}'
        }), 500
    finally:
        conn.close()


@app.route('/api/cart', methods=['POST'])
@api_login_required
def api_cart_add_json(user_id):
    data = request.get_json(silent=True) or {}

    product_id = data.get('product_id')
    weight_kg = data.get('weight_kg', 1)

    try:
        product_id = int(product_id)
        weight_kg = float(weight_kg)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid product or weight'}), 400

    if weight_kg < 0.25:
        return jsonify({'success': False, 'error': 'Minimum 0.25 kg'}), 400

    # round to 0.25 steps
    weight_kg = round(round(weight_kg * 4) / 4, 2)

    # Fetch product with store_id
    prow = query("SELECT stock_kg, is_active, store_id FROM products WHERE id=?", (product_id,))
    if not prow:
        return jsonify({'success': False, 'error': 'Product not found'}), 404

    stock = float(prow[0]['stock_kg'] or 0)
    active = int(prow[0]['is_active'] or 0)
    new_store_id = int(prow[0]['store_id']) if prow[0]['store_id'] is not None else None

    if active != 1 or stock <= 0:
        return jsonify({'success': False, 'error': 'This item is sold out'}), 409

    if weight_kg > stock:
        return jsonify({'success': False, 'error': f'Max available is {stock:.2f} kg'}), 409

    cid = get_or_create_cart(user_id)

    # Single-store enforcement
    existing_store = query("""
        SELECT DISTINCT p.store_id AS store_id
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        WHERE ci.cart_id=?
    """, (cid,))

    if existing_store and new_store_id is not None:
        cart_store_id = int(existing_store[0]["store_id"])
        if cart_store_id != new_store_id:
            return jsonify({
                "success": False,
                "code": "DIFF_STORE",
                "error": "Your cart already has items from another store. Please clear the cart first."
            }), 409

    # Add/update
    rows = query('SELECT id FROM cart_items WHERE cart_id=? AND product_id=?', (cid, product_id))
    if rows:
        execute('UPDATE cart_items SET weight_kg=? WHERE id=?', (weight_kg, rows[0]['id']))
        cart_item_id = rows[0]['id']
    else:
        execute('INSERT INTO cart_items (cart_id, product_id, weight_kg) VALUES (?,?,?)', (cid, product_id, weight_kg))
        # if you have lastrowid helper, use it; else ignore
        cart_item_id = None

    c = query("SELECT COUNT(*) AS c FROM cart_items WHERE cart_id=?", (cid,))
    cart_count = int(c[0]["c"] or 0) if c else 0

    return jsonify({
        'success': True,
        'cart_count': cart_count,
        'store_id': new_store_id,
        'cart_item_id': cart_item_id
    }), 200


@app.route("/api/addresses", methods=["POST"])
@api_login_required
def api_address_create(user_id):
    data = request.get_json(silent=True) or {}

    line1 = (data.get("line1") or "").strip()
    line2 = (data.get("line2") or "").strip()
    city  = (data.get("city") or "").strip()
    state = (data.get("state") or "").strip()
    pincode = (data.get("pincode") or "").strip()
    lat = data.get("latitude")
    lng = data.get("longitude")
    label = (data.get("label") or "").strip() or "Home"
    is_def = 1 if bool(data.get("is_default", True)) else 0  # default True for app

    if not line1:
        return jsonify({"success": False, "error": "Address line1 is required"}), 400

    if not pincode or len(pincode) != 6 or not pincode.isdigit():
        return jsonify({"success": False, "error": "Valid 6-digit pincode required"}), 400

    if not is_serviceable_pincode(pincode):
        return jsonify({"success": False, "error": "Pincode not serviceable"}), 400

    if is_def:
        execute("UPDATE addresses SET is_default=0 WHERE user_id=?", (user_id,))

    aid = execute("""
        INSERT INTO addresses (user_id,label,line1,line2,city,state,pincode,latitude,longitude,is_default,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user_id, label, line1, line2, city, state, pincode,
        float(lat) if lat is not None and str(lat).strip() != "" else None,
        float(lng) if lng is not None and str(lng).strip() != "" else None,
        is_def, datetime.utcnow().isoformat()
    ))

    return jsonify({"success": True, "address_id": aid}), 201


@app.route("/api/addresses", methods=["GET"])
@api_login_required
def api_addresses_list(user_id):
    rows = query(
        "SELECT id,label,line1,line2,city,state,pincode,latitude,longitude,is_default,created_at "
        "FROM addresses WHERE user_id=? ORDER BY is_default DESC, id DESC",
        (user_id,),
    )

    return jsonify({
        "success": True,
        "addresses": [{
            "id": r["id"],
            "label": r["label"],
            # Keep app-friendly keys expected by Flutter UI
            "address_line_1": r["line1"],
            "address_line_2": r["line2"],
            "city": r["city"],
            "state": r["state"],
            "pincode": r["pincode"],
            "latitude": float(r["latitude"]) if r["latitude"] is not None else None,
            "longitude": float(r["longitude"]) if r["longitude"] is not None else None,
            "is_default": bool(r["is_default"]),
            "created_at": r["created_at"],
        } for r in rows]
    }), 200


def query_one(sql, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


@app.route("/api/addresses/<int:address_id>", methods=["DELETE"])
@api_login_required
def api_delete_address(user_id, address_id):
    # Ensure the address exists and belongs to this user
    row = query_one(
        "SELECT id FROM addresses WHERE id=? AND user_id=?",
        (address_id, user_id),
    )
    if not row:
        return jsonify({"success": False, "error": "Address not found"}), 404

    # Delete
    execute(
        "DELETE FROM addresses WHERE id=? AND user_id=?",
        (address_id, user_id),
    )

    return jsonify({"success": True}), 200


# Optional POST fallback delete (if your app uses POST instead of DELETE)
@app.route("/api/addresses/<int:address_id>/delete", methods=["POST"])
@api_login_required
def api_addresses_delete_post(user_id, address_id):
    return api_delete_address(user_id, address_id)


# ====================
# API CHECKOUT (FINAL FIXED)
# - Uses address_id from app (recommended)
# - Falls back to default address if address_id not sent
# - Creates order + items + transactions + order_addresses + order_events
# - Clears cart
# ====================

# @app.route('/api/checkout', methods=['POST'])
# @api_login_required
# def api_checkout(user_id):


#     data = request.get_json(silent=True) or {}

#     payment_method = (data.get('payment_method') or 'COD').strip() or 'COD'
#     tip_amount = data.get('tip_amount', 0)

#     # âœ… Preferred: address_id sent by app
#     address_id = data.get('address_id')

#     # --- Load cart items for this user ---
#     cid = get_or_create_cart(user_id)
#     items = query('''
#         SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id,
#                p.stock_kg, p.is_active
#         FROM cart_items ci
#         JOIN products p ON p.id = ci.product_id
#         WHERE ci.cart_id = ?
#     ''', (cid,))

#     if not items:
#         return jsonify({'success': False, 'error': 'Cart is empty'}), 400

#     # --- Fetch address (address_id OR default) ---
#     addr = None
#     if address_id is not None:
#         try:
#             aid = int(address_id)
#         except Exception:
#             return jsonify({'success': False, 'error': 'Invalid address_id'}), 400

#         rows = query("SELECT * FROM addresses WHERE id=? AND user_id=?", (aid, user_id))
#         if not rows:
#             return jsonify({'success': False, 'error': 'Address not found'}), 404
#         addr = rows[0]
#     else:
#         rows = query(
#             "SELECT * FROM addresses WHERE user_id=? ORDER BY is_default DESC, id DESC LIMIT 1",
#             (user_id,)
#         )
#         if not rows:
#             return jsonify({'success': False, 'error': 'No delivery address found'}), 400
#         addr = rows[0]

#     # --- Validate address fields ---
#     line1 = (addr.get('line1') or '').strip()
#     pincode = (addr.get('pincode') or '').strip()

#     if not line1 or not pincode:
#         return jsonify({'success': False, 'error': 'Address line1 and pincode are required'}), 400

#     if len(pincode) != 6 or not pincode.isdigit():
#         return jsonify({'success': False, 'error': 'Invalid pincode'}), 400

#     if not is_serviceable_pincode(pincode):
#         return jsonify({'success': False, 'error': 'Pincode not serviceable'}), 400

#     # --- Validate items & stock ---
#     for it in items:
#         if int(it['is_active'] or 0) != 1:
#             return jsonify({'success': False, 'error': 'Product inactive'}), 400
#         if float(it['stock_kg'] or 0) <= 0:
#             return jsonify({'success': False, 'error': 'Item sold out'}), 409
#         if float(it['weight_kg'] or 0) > float(it['stock_kg'] or 0):
#             return jsonify({'success': False, 'error': 'Insufficient stock'}), 409

#     # âœ… Single-store checkout assumption (same as your website checkout)
#     store_id = int(items[0]['store_id'])

#     # --- Tip normalize ---
#     try:
#         tip_amount = float(tip_amount or 0)
#     except Exception:
#         tip_amount = 0.0
#     if tip_amount < 0:
#         tip_amount = 0.0
#     if tip_amount > 10000:
#         tip_amount = 10000.0
#     tip_amount = round(tip_amount, 2)

#     # --- Calculate distance & delivery fee (same pattern as website) ---
#     now = datetime.utcnow().isoformat()
#     store_row = query("SELECT * FROM stores WHERE id=?", (store_id,))
#     store = store_row[0] if store_row else None

#     km = None
#     try:
#         store_lat = store['latitude'] if store and 'latitude' in store.keys() else None
#         store_lng = store['longitude'] if store and 'longitude' in store.keys() else None
#         addr_lat = addr.get('latitude')
#         addr_lng = addr.get('longitude')

#         if store_lat is not None and store_lng is not None and addr_lat is not None and addr_lng is not None:
#             km = haversine_km(float(store_lat), float(store_lng), float(addr_lat), float(addr_lng))
#     except Exception:
#         km = None

#     if km is not None and km > MAX_DELIVERY_KM:
#         return jsonify({'success': False, 'error': f'Delivery distance ({km:.1f} km) exceeds limit'}), 400

#     if km is None:
#         delivery_fee = BASE_DELIVERY_FEE_INR
#     else:
#         extra = None
#         for low, high, fee in DELIVERY_SURCHARGE_SLABS:
#             last_high = DELIVERY_SURCHARGE_SLABS[-1][1]
#             if (km >= low) and (km < high or high == last_high):
#                 extra = fee
#                 break
#         if extra is None:
#             return jsonify({'success': False, 'error': 'Delivery not available for this distance'}), 400
#         delivery_fee = BASE_DELIVERY_FEE_INR + extra

#     items_total = sum(float(it['weight_kg']) * float(it['price_per_kg']) for it in items)
#     total_payable = float(items_total) + float(delivery_fee) + float(tip_amount)

#     # --- Transaction + Order creation (atomic) ---
#     conn = get_conn()
#     try:
#         cur = conn.cursor()
#         cur.execute("BEGIN IMMEDIATE")

#         # Re-check stock inside transaction
#         cur.execute('''
#             SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id,
#                    p.stock_kg, p.is_active
#             FROM cart_items ci
#             JOIN products p ON p.id = ci.product_id
#             WHERE ci.cart_id = ?
#         ''', (cid,))
#         tx_items = cur.fetchall()

#         if not tx_items:
#             conn.rollback()
#             return jsonify({'success': False, 'error': 'Cart is empty'}), 400

#         for it in tx_items:
#             stock = float(it["stock_kg"] or 0)
#             need  = float(it["weight_kg"] or 0)
#             if int(it["is_active"] or 0) != 1 or stock <= 0:
#                 conn.rollback()
#                 return jsonify({'success': False, 'error': 'One or more items are sold out'}), 409
#             if need > stock:
#                 conn.rollback()
#                 return jsonify({'success': False, 'error': 'Insufficient stock'}), 409

#         tx_items_total = sum(float(it["weight_kg"]) * float(it["price_per_kg"]) for it in tx_items)

#         # 1) Create order
#         cur.execute('''
#             INSERT INTO orders (user_id, store_id, total_amount, status, payment_status, created_at, delivery_fee, distance_km, tip_amount)
#             VALUES (?,?,?,?,?,?,?,?,?)
#         ''', (
#             user_id, store_id, tx_items_total,
#             'PLACED', 'PENDING', now,
#             float(delivery_fee),
#             float(km) if km is not None else None,
#             float(tip_amount)
#         ))
#         order_id = cur.lastrowid

#         # 2) order_items + stock updates
#         for it in tx_items:
#             pid = int(it["product_id"])
#             need = float(it["weight_kg"])
#             price = float(it["price_per_kg"])
#             line_total = need * price

#             cur.execute('''
#                 INSERT INTO order_items (order_id, product_id, weight_kg, unit_price_per_kg, line_total)
#                 VALUES (?,?,?,?,?)
#             ''', (order_id, pid, need, price, line_total))

#             cur.execute("UPDATE products SET stock_kg = stock_kg - ? WHERE id=?", (need, pid))

#         # 3) transactions
#         cur.execute('''
#             INSERT INTO transactions (order_id, amount, payment_method, status, created_at)
#             VALUES (?,?,?,?,?)
#         ''', (order_id, float(total_payable), payment_method, 'PENDING', now))

#         # 4) order_addresses snapshot
#         cur.execute('''
#             INSERT INTO order_addresses (order_id, line1, line2, city, state, pincode, latitude, longitude, created_at)
#             VALUES (?,?,?,?,?,?,?,?,?)
#         ''', (
#             order_id,
#             (addr.get('line1') or ''),
#             (addr.get('line2') or ''),
#             (addr.get('city') or ''),
#             (addr.get('state') or ''),
#             (addr.get('pincode') or ''),
#             addr.get('latitude'),
#             addr.get('longitude'),
#             now
#         ))

#         # 5) order_events
#         cur.execute(
#             "INSERT INTO order_events (order_id, status, note, created_at) VALUES (?,?,?,?)",
#             (order_id, 'PLACED', '', now)
#         )

#         # 6) clear cart
#         cur.execute("DELETE FROM cart_items WHERE cart_id=?", (cid,))

#         conn.commit()

#     except Exception as e:
#         conn.rollback()
#         return jsonify({'success': False, 'error': str(e)}), 500
#     finally:
#         conn.close()

#     return jsonify({
#         'success': True,
#         'order_id': order_id,
#         'total_payable': round(float(total_payable), 2),
#         'delivery_fee': float(delivery_fee),
#         'distance_km': float(km) if km is not None else None,
#         'message': 'Order placed successfully'
#     }), 201


#     # ======================



# API CHECKOUT (APP)
# ======================
@app.route('/api/checkout', methods=['POST'])
@api_login_required
def api_checkout(user_id):
    data = request.get_json(silent=True) or {}

    payment_method = (data.get('payment_method') or 'COD').strip() or 'COD'
    tip_amount = data.get('tip_amount', 0)

    # --- Address from app (Option A) ---
    # Expected:
    # address: {
    #   line1, line2, city, state, pincode, latitude, longitude, is_default(optional)
    # }
    addr_in = data.get('address') or {}
    if not isinstance(addr_in, dict):
        addr_in = {}

    line1 = (addr_in.get('line1') or '').strip()
    line2 = (addr_in.get('line2') or '').strip()
    city  = (addr_in.get('city') or '').strip()
    state = (addr_in.get('state') or '').strip()
    pincode = (addr_in.get('pincode') or '').strip()

    # lat/lng may be None
    latitude = addr_in.get('latitude')
    longitude = addr_in.get('longitude')

    if not line1 or not pincode:
        return jsonify({'success': False, 'error': 'Address line1 and pincode are required'}), 400

    if len(pincode) != 6 or not pincode.isdigit():
        return jsonify({'success': False, 'error': 'Invalid pincode'}), 400

    # serviceability check
    if not is_serviceable_pincode(pincode):
        return jsonify({'success': False, 'error': 'Pincode not serviceable'}), 400

    # --- Load cart items for this user ---
    # --- Load cart items (APP can send items directly; else fallback to DB cart_items) ---
    cid = get_or_create_cart(user_id)

    items_in = data.get('items')
    items = []

    def _as_float(x, default=0.0):
        try:
            return float(x)
        except Exception:
            return default

    if isinstance(items_in, list) and len(items_in) > 0:
        # âœ… Build items from payload
        agg = {}  # product_id -> weight_kg
        for row in items_in:
            if not isinstance(row, dict):
                continue
            pid = row.get("product_id")
            wkg = row.get("weight_kg")
            try:
                pid = int(pid)
            except Exception:
                pid = 0
            wkg = _as_float(wkg, 0.0)
            if pid <= 0 or wkg <= 0:
                continue
            agg[pid] = agg.get(pid, 0.0) + wkg

        if not agg:
            return jsonify({'success': False, 'error': 'Cart is empty'}), 400

        # fetch product data
        qmarks = ",".join(["?"] * len(agg))
        prows = query(f'''
            SELECT id, price_per_kg, store_id, stock_kg, is_active
            FROM products
            WHERE id IN ({qmarks})
        ''', tuple(agg.keys()))

        pmap = {int(r["id"]): r for r in prows}

        for pid, wkg in agg.items():
            p = pmap.get(pid)
            if not p:
                return jsonify({'success': False, 'error': f'Invalid product_id: {pid}'}), 400
            items.append({
                "product_id": pid,
                "weight_kg": wkg,
                "price_per_kg": p["price_per_kg"],
                "store_id": p["store_id"],
                "stock_kg": p["stock_kg"],
                "is_active": p["is_active"],
            })

    else:
        # âœ… Fallback to website cart_items table
        items = query('''
            SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id,
                p.stock_kg, p.is_active
            FROM cart_items ci
            JOIN products p ON p.id = ci.product_id
            WHERE ci.cart_id = ?
        ''', (cid,))

        if not items:
            return jsonify({'success': False, 'error': 'Cart is empty'}), 400


    # Validate items & stock
    for it in items:
        if int(it['is_active'] or 0) != 1:
            return jsonify({'success': False, 'error': 'Product inactive'}), 400
        if float(it['stock_kg'] or 0) <= 0:
            return jsonify({'success': False, 'error': 'Item sold out'}), 409
        if float(it['weight_kg'] or 0) > float(it['stock_kg'] or 0):
            return jsonify({'success': False, 'error': 'Insufficient stock'}), 409

    # IMPORTANT: single-store checkout (same assumption as website)
    store_id = int(items[0]['store_id'])

    # --- Save/Upsert address into addresses table (Option A) ---
    # We try to insert a new address row and mark default.
    now = datetime.utcnow().isoformat()

    # Tip
    try:
        tip_amount = float(tip_amount or 0)
    except Exception:
        tip_amount = 0.0
    if tip_amount < 0:
        tip_amount = 0.0
    if tip_amount > 10000:
        tip_amount = 10000.0
    tip_amount = round(tip_amount, 2)

    # --- Calculate distance & delivery fee ---
    store_row = query("SELECT * FROM stores WHERE id=?", (store_id,))
    store = store_row[0] if store_row else None

    km = None
    if store and latitude is not None and longitude is not None:
        try:
            store_lat = store['latitude'] if 'latitude' in store.keys() else None
            store_lng = store['longitude'] if 'longitude' in store.keys() else None
            if store_lat is not None and store_lng is not None:
                km = haversine_km(store_lat, store_lng, float(latitude), float(longitude))
        except Exception:
            km = None

    if km is not None and km > MAX_DELIVERY_KM:
        return jsonify({'success': False, 'error': f'Delivery distance ({km:.1f} km) exceeds limit'}), 400

    # Store-specific delivery fee (or free delivery when disabled)
    delivery_fee = calculate_store_delivery_fee(store, km)
    if delivery_fee is None:
        return jsonify({'success': False, 'error': 'Delivery not available for this distance'}), 400

    items_total = sum(float(it['weight_kg']) * float(it['price_per_kg']) for it in items)
    total_payable = items_total + float(delivery_fee) + float(tip_amount)

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")

        # Re-read delivery settings inside the transaction so the order uses
        # the current store-owned configuration.
        cur.execute("SELECT * FROM stores WHERE id=?", (store_id,))
        tx_store = cur.fetchone()
        if tx_store is None:
            conn.rollback()
            return jsonify({'success': False, 'error': 'Store not found'}), 404

        delivery_fee = calculate_store_delivery_fee(tx_store, km)
        if delivery_fee is None:
            conn.rollback()
            return jsonify({'success': False, 'error': 'Delivery not available for this distance'}), 400
        total_payable = items_total + float(delivery_fee) + float(tip_amount)

        # 1) Insert address into addresses table
        # Make this the default address (simple approach)
        try:
            cur.execute("UPDATE addresses SET is_default=0 WHERE user_id=?", (user_id,))
        except Exception:
            # if column doesn't exist, ignore
            pass

        # Insert (try with common columns)
        # Your website uses: line1,line2,city,state,pincode,latitude,longitude,is_default,created_at
        addr_id = None
        try:
            cur.execute('''
                INSERT INTO addresses (user_id, line1, line2, city, state, pincode, latitude, longitude, is_default, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            ''', (user_id, line1, line2, city, state, pincode, latitude, longitude, 1, now))
            addr_id = cur.lastrowid
        except Exception:
            # fallback if created_at not present
            cur.execute('''
                INSERT INTO addresses (user_id, line1, line2, city, state, pincode, latitude, longitude, is_default)
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (user_id, line1, line2, city, state, pincode, latitude, longitude, 1))
            addr_id = cur.lastrowid

        # 2) Create order
        cur.execute('''
            INSERT INTO orders (
                user_id, store_id, total_amount,
                status, payment_status, created_at,
                delivery_fee, distance_km, tip_amount
            )
            VALUES (?,?,?,?,?,?,?,?,?)
        ''', (
            user_id, store_id, items_total,
            'PLACED', 'PENDING', now,
            float(delivery_fee), float(km) if km is not None else None, tip_amount
        ))
        order_id = cur.lastrowid

        # 3) Order items + stock update
        for it in items:
            pid = int(it['product_id'])
            need = float(it['weight_kg'])
            price = float(it['price_per_kg'])
            line_total = need * price

            cur.execute('''
                INSERT INTO order_items (
                    order_id, product_id, weight_kg,
                    unit_price_per_kg, line_total
                )
                VALUES (?,?,?,?,?)
            ''', (order_id, pid, need, price, line_total))

            cur.execute("UPDATE products SET stock_kg = stock_kg - ? WHERE id=?", (need, pid))

        # 4) Transaction
        cur.execute('''
            INSERT INTO transactions (order_id, amount, payment_method, status, created_at)
            VALUES (?,?,?,?,?)
        ''', (order_id, float(total_payable), payment_method, 'PENDING', now))

        # 5) Order address snapshot
        cur.execute('''
            INSERT INTO order_addresses (
                order_id, line1, line2, city, state,
                pincode, latitude, longitude, created_at
            )
            VALUES (?,?,?,?,?,?,?,?,?)
        ''', (
            order_id,
            line1, line2, city, state, pincode,
            latitude, longitude, now
        ))

        # 6) Event
        cur.execute(
            "INSERT INTO order_events (order_id, status, note, created_at) VALUES (?,?,?,?)",
            (order_id, 'PLACED', '', now)
        )

        # 7) Clear cart
        cur.execute("DELETE FROM cart_items WHERE cart_id=?", (cid,))

        conn.commit()

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'order_id': order_id,
        'total_payable': round(float(total_payable), 2),
        'delivery_fee': float(delivery_fee),
        'distance_km': float(km) if km is not None else None,
        'message': 'Order placed successfully'
    }), 201








print("\n=== ROUTES LOADED ===")
print(app.url_map)
print("=====================\n")



if __name__ == '__main__':
    app.run(host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False)