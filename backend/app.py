"""
Main Flask Application - Cybersecurity Log Analyzer

This is the REST API backend that handles:
- User authentication (JWT-based)
- Log file upload and storage
- Log parsing and analysis
- Anomaly detection (hybrid: statistical rules + Claude AI)

AI DOCUMENTATION:
-----------------
This application uses TWO layers of AI/analysis:

1. RULE-BASED STATISTICAL ANALYSIS (analyzer.py):
   - Detects anomalies using predefined rules and statistical thresholds
   - Examples: high request rates, unusual hours, large data transfers
   - Fast, deterministic, no external API needed
   - Provides confidence scores based on how far values deviate from normal

2. CLAUDE AI ANALYSIS (ai_analyzer.py):
   - Uses Anthropic's Claude API to perform deeper contextual analysis
   - Summarizes the overall threat landscape from the logs
   - Generates a SOC analyst-friendly timeline of events
   - Identifies patterns that rule-based systems might miss
   - Provides natural-language explanations of findings
"""

import os
import uuid
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import psycopg
from psycopg.rows import dict_row
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt

from config import ActiveConfig
from parser import parse_log_file
from analyzer import analyze_logs
from ai_analyzer import ai_analyze_logs

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(ActiveConfig)

CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

ALLOWED_EXTENSIONS = app.config["ALLOWED_EXTENSIONS"]

# ---------------------------------------------------------------------------
# Basic Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Return a small status payload for the API root."""
    return jsonify(
        {
            "name": "CyberScope Log Analyzer API",
            "status": "ok",
            "health": "/api/health",
            "routes": {
                "register": "/api/auth/register",
                "login": "/api/auth/login",
                "upload": "/api/upload",
                "uploads": "/api/uploads",
            },
        }
    ), 200


# ---------------------------------------------------------------------------
# Database Helpers
# ---------------------------------------------------------------------------

def get_db():
    """Get a database connection for the current request."""
    if "db" not in g:
        g.db = psycopg.connect(app.config["DATABASE_URL"], row_factory=dict_row)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with the schema."""
    with psycopg.connect(app.config["DATABASE_URL"]) as db:
        with db.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS uploads (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id),
                    filename TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    upload_time TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    total_entries INTEGER DEFAULT 0,
                    anomaly_count INTEGER DEFAULT 0,
                    results TEXT,
                    ai_summary TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_uploads_user_time
                ON uploads (user_id, upload_time DESC)
                """
            )

            # Create a default demo user for easy testing.
            demo_hash = generate_password_hash("demo1234", method="pbkdf2:sha256")
            cur.execute(
                """
                INSERT INTO users (id, username, password_hash, created_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING
                """,
                (str(uuid.uuid4()), "demo", demo_hash, datetime.utcnow().isoformat()),
            )
            if cur.rowcount == 1:
                print("✅ Created demo user — username: demo / password: demo1234")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def token_required(f):
    """Decorator that checks for a valid JWT token in the Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Authentication token is missing"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            db = get_db()
            current_user = db.execute(
                "SELECT * FROM users WHERE id = %s", (data["user_id"],)
            ).fetchone()
            if current_user is None:
                return jsonify({"error": "User not found"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        g.current_user = current_user
        return f(*args, **kwargs)

    return decorated


@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user account."""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = %s", (username,)).fetchone()
    if existing:
        return jsonify({"error": "Username already exists"}), 409

    user_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (%s, %s, %s, %s)",
        (user_id, username, generate_password_hash(password, method="pbkdf2:sha256"), datetime.utcnow().isoformat()),
    )
    db.commit()

    token = jwt.encode(
        {"user_id": user_id, "exp": datetime.utcnow() + timedelta(hours=24)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify({"token": token, "username": username}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate a user and return a JWT token."""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = jwt.encode(
        {"user_id": user["id"], "exp": datetime.utcnow() + timedelta(hours=24)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify({"token": token, "username": username}), 200


# ---------------------------------------------------------------------------
# File Upload & Analysis
# ---------------------------------------------------------------------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/api/upload", methods=["POST"])
@token_required
def upload_file():
    """
    Upload a log file for analysis.

    Workflow:
    1. Validate and save the uploaded file
    2. Parse the raw log lines into structured entries
    3. Run rule-based anomaly detection
    4. (Optionally) run Claude AI analysis for deeper insights
    5. Store results in the database and return them
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": f"File type not allowed. Use: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

    # Save the file
    upload_id = str(uuid.uuid4())
    safe_name = secure_filename(file.filename)
    stored_name = f"{upload_id}_{safe_name}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    file.save(filepath)

    # Parse the log file
    try:
        entries = parse_log_file(filepath)
    except Exception as e:
        return jsonify({"error": f"Failed to parse log file: {str(e)}"}), 400

    if not entries:
        return jsonify({"error": "No valid log entries found in file"}), 400

    # ---- RULE-BASED ANOMALY DETECTION ----
    analysis_results = analyze_logs(entries)

    # ---- AI-POWERED ANALYSIS (Claude API) ----
    use_ai = request.form.get("use_ai", "true").lower() == "true"
    ai_summary = None
    if use_ai:
        try:
            ai_summary = ai_analyze_logs(entries, analysis_results)
        except Exception as e:
            ai_summary = {
                "error": f"AI analysis unavailable: {str(e)}",
                "suggestion": "Set ANTHROPIC_API_KEY environment variable to enable AI analysis.",
            }

    # Store in database
    anomaly_count = len(analysis_results.get("anomalies", []))
    db = get_db()
    db.execute(
        """INSERT INTO uploads
           (id, user_id, filename, original_filename, upload_time, status,
            total_entries, anomaly_count, results, ai_summary)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            upload_id,
            g.current_user["id"],
            stored_name,
            safe_name,
            datetime.utcnow().isoformat(),
            "completed",
            len(entries),
            anomaly_count,
            json.dumps(analysis_results),
            json.dumps(ai_summary) if ai_summary else None,
        ),
    )
    db.commit()

    return jsonify(
        {
            "upload_id": upload_id,
            "filename": safe_name,
            "total_entries": len(entries),
            "anomaly_count": anomaly_count,
            "analysis": analysis_results,
            "ai_summary": ai_summary,
        }
    ), 200


@app.route("/api/uploads", methods=["GET"])
@token_required
def list_uploads():
    """List all uploads for the authenticated user."""
    db = get_db()
    rows = db.execute(
        """SELECT id, original_filename, upload_time, status, total_entries, anomaly_count
           FROM uploads WHERE user_id = %s ORDER BY upload_time DESC""",
        (g.current_user["id"],),
    ).fetchall()

    return jsonify(
        [
            {
                "id": r["id"],
                "filename": r["original_filename"],
                "upload_time": r["upload_time"],
                "status": r["status"],
                "total_entries": r["total_entries"],
                "anomaly_count": r["anomaly_count"],
            }
            for r in rows
        ]
    ), 200


@app.route("/api/uploads/<upload_id>", methods=["GET"])
@token_required
def get_upload(upload_id):
    """Get full analysis results for a specific upload."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM uploads WHERE id = %s AND user_id = %s",
        (upload_id, g.current_user["id"]),
    ).fetchone()

    if not row:
        return jsonify({"error": "Upload not found"}), 404

    return jsonify(
        {
            "id": row["id"],
            "filename": row["original_filename"],
            "upload_time": row["upload_time"],
            "status": row["status"],
            "total_entries": row["total_entries"],
            "anomaly_count": row["anomaly_count"],
            "analysis": json.loads(row["results"]) if row["results"] else None,
            "ai_summary": json.loads(row["ai_summary"]) if row["ai_summary"] else None,
        }
    ), 200


# Health check
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
init_db()
