import os
import json
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS

from scanner.engine import scan_url
from scanner.report import build_pdf


app = Flask(__name__)

# --------------------------------------------------
# Application and session configuration
# --------------------------------------------------

app.secret_key = os.getenv("SECRET_KEY", "change-this-secret")

frontend_url = os.getenv(
    "FRONTEND_URL",
    "http://localhost:5173"
).rstrip("/")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.getenv(
        "COOKIE_SAMESITE",
        "Lax"
    ),
    SESSION_COOKIE_SECURE=os.getenv(
        "COOKIE_SECURE",
        "false"
    ).lower() == "true",
)

# --------------------------------------------------
# CORS configuration
# --------------------------------------------------

allowed_origins = [
    frontend_url,
    "https://vulnscan-lite-upgraded-1.onrender.com",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Remove duplicate origins
allowed_origins = list(dict.fromkeys(allowed_origins))

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": allowed_origins
        }
    },
    supports_credentials=True,
)

# --------------------------------------------------
# Database
# --------------------------------------------------

DB = os.path.join(
    os.path.dirname(__file__),
    "vulnscan.db"
)


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                risk_level TEXT,
                risk_score INTEGER,
                result_json TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )


# --------------------------------------------------
# Authentication
# --------------------------------------------------

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return jsonify({
                "error": "Authentication required"
            }), 401

        return fn(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# Error handling
# --------------------------------------------------

@app.errorhandler(Exception)
def handle_error(exc):
    app.logger.exception(exc)

    return jsonify({
        "error": "Unexpected server error",
        "detail": str(exc)
    }), 500


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "VulnScan-Lite"
    })


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    expected_user = os.getenv(
        "ADMIN_USERNAME",
        "admin"
    )

    expected_pass = os.getenv(
        "ADMIN_PASSWORD",
        "admin123"
    )

    if username == expected_user and password == expected_pass:
        session.clear()
        session["user"] = username

        return jsonify({
            "authenticated": True,
            "username": username
        })

    return jsonify({
        "error": "Invalid credentials"
    }), 401


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.post("/api/logout")
def logout():
    session.clear()

    return jsonify({
        "authenticated": False
    })


# --------------------------------------------------
# Current user
# --------------------------------------------------

@app.get("/api/me")
def me():
    username = session.get("user")

    return jsonify({
        "authenticated": bool(username),
        "username": username
    })


# --------------------------------------------------
# Run scan
# --------------------------------------------------

@app.post("/api/scan")
@auth_required
def scan():
    data = request.get_json(silent=True) or {}

    target = (data.get("url") or "").strip()

    if not target:
        return jsonify({
            "error": "URL is required"
        }), 400

    result = scan_url(target)

    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                target,
                risk_level,
                risk_score,
                result_json,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                result["target"],
                result["risk_level"],
                result["risk_score"],
                json.dumps(result),
                result["scanned_at"]
            )
        )

        result["id"] = cur.lastrowid

    return jsonify(result)


# --------------------------------------------------
# Scan history
# --------------------------------------------------

@app.get("/api/history")
@auth_required
def history():
    with db() as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                target,
                risk_level,
                risk_score,
                scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

    return jsonify([
        dict(row)
        for row in rows
    ])


# --------------------------------------------------
# Get individual scan
# --------------------------------------------------

@app.get("/api/scans/<int:scan_id>")
@auth_required
def get_scan(scan_id):
    with db() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        ).fetchone()

    if not row:
        return jsonify({
            "error": "Scan not found"
        }), 404

    result = json.loads(row["result_json"])
    result["id"] = row["id"]

    return jsonify(result)


# --------------------------------------------------
# Download PDF report
# --------------------------------------------------

@app.get("/api/scans/<int:scan_id>/report")
@auth_required
def report(scan_id):
    with db() as conn:
        row = conn.execute(
            """
            SELECT result_json
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        ).fetchone()

    if not row:
        return jsonify({
            "error": "Scan not found"
        }), 404

    result = json.loads(row["result_json"])
    pdf = build_pdf(result)

    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vulnscan-report-{scan_id}.pdf"
    )


# --------------------------------------------------
# Start application
# --------------------------------------------------

init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=False
    )