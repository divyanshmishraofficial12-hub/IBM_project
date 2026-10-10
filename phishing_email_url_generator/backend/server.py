"""
server.py — Flask application entry point.

Features:
  • CORS with configurable origins
  • Per-IP rate limiting on scan & auth endpoints
  • Input sanitization on all POST bodies
  • SQLite via SQLAlchemy
  • JWT-protected scan history
  • Clean JSON error responses
"""

import os
import logging
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()                       # must run before any os.getenv() calls

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt

from database import db, ScanHistory, init_db
from auth import auth_bp, bcrypt, token_required, optional_token
from scanner import load_model, scan_url, scan_email, scan_message, scan_upi_qr
from utils import sanitize_input, validate_url, validate_email_text, safe_unshorten_url

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)

    # ── Core config ──────────────────────────────────────────────────────────
    app.config["SECRET_KEY"]              = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["JWT_SECRET_KEY"]          = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
    raw_db_uri = os.getenv("DATABASE_URL", "sqlite:///phishing_detector.db")
    if raw_db_uri.startswith("postgres://"):
        raw_db_uri = raw_db_uri.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = raw_db_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Extensions ───────────────────────────────────────────────────────────
    bcrypt.init_app(app)

    cors_origins_env = os.getenv("CORS_ORIGINS", "*").strip()
    if cors_origins_env == "*":
        CORS(app, resources={r"/*": {"origins": "*"}}, allow_headers=["Content-Type", "Authorization"])
    else:
        allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
        CORS(app, resources={r"/*": {"origins": allowed_origins}}, allow_headers=["Content-Type", "Authorization"], supports_credentials=True)

    # Use Redis for shared rate limiting across workers (falls back to in-memory)
    _limiter_storage = os.getenv("REDIS_URL", "memory://")
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],          # no global limit; apply per-route
        storage_uri=_limiter_storage,
    )

    # ── Database ─────────────────────────────────────────────────────────────
    init_db(app)

    # ── Blueprints ───────────────────────────────────────────────────────────
    app.register_blueprint(auth_bp)

    # ── ML Model ─────────────────────────────────────────────────────────────
    with app.app_context():
        load_model()

    # ────────────────────────────────────────────────────────────────────────
    # Scan Routes
    # ────────────────────────────────────────────────────────────────────────

    SCAN_LIMIT = os.getenv("RATE_LIMIT_SCAN", "10 per minute")

    @app.route("/api/scan/url", methods=["POST"])
    @limiter.limit(SCAN_LIMIT)
    @optional_token
    def api_scan_url():
        """
        POST /api/scan/url
        Body: { "url": "https://example.com" }
        Auth: optional Bearer JWT
        """
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "")

        # Sanitize
        try:
            url = sanitize_input(str(raw_url), max_length=2048)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Validate
        valid, reason = validate_url(url)
        if not valid:
            return jsonify({"error": reason}), 422

        # Scan
        result = scan_url(url)

        # Persist
        _save_scan(
            user_id    = g.user_id,
            target     = url,
            scan_type  = "url",
            result     = result,
        )

        return jsonify({
            "target":    url,
            "scan_type": "url",
            **result,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }), 200


    @app.route("/api/scan/email", methods=["POST"])
    @limiter.limit(SCAN_LIMIT)
    @optional_token
    def api_scan_email():
        """
        POST /api/scan/email
        Body: { "email_text": "Dear customer, click here..." }
        Auth: optional Bearer JWT
        """
        data = request.get_json(silent=True) or {}
        raw_text = data.get("email_text", "")

        # Sanitize
        try:
            email_text = sanitize_input(str(raw_text), max_length=50_000)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Validate
        valid, reason = validate_email_text(email_text)
        if not valid:
            return jsonify({"error": reason}), 422

        # Scan
        result = scan_email(email_text)

        # Persist
        snippet = email_text[:200] + ("…" if len(email_text) > 200 else "")
        _save_scan(
            user_id   = g.user_id,
            target    = snippet,
            scan_type = "email",
            result    = result,
        )

        return jsonify({
            "scan_type": "email",
            **result,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }), 200

    @app.route("/api/scan/message", methods=["POST"])
    @limiter.limit(SCAN_LIMIT)
    @optional_token
    def api_scan_message():
        """
        POST /api/scan/message
        Body: { "message_text": "Electricity will be cut tonight..." }
        Auth: optional Bearer JWT
        """
        data = request.get_json(silent=True) or {}
        raw_text = data.get("message_text", "")
        try:
            msg_text = sanitize_input(str(raw_text), max_length=50_000)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        valid, reason = validate_email_text(msg_text)
        if not valid:
            return jsonify({"error": reason}), 422

        result = scan_message(msg_text)
        snippet = msg_text[:200] + ("…" if len(msg_text) > 200 else "")
        _save_scan(
            user_id   = g.user_id,
            target    = snippet,
            scan_type = "message",
            result    = result,
        )
        return jsonify({
            "scan_type": "message",
            **result,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }), 200

    @app.route("/api/scan/qr", methods=["POST"])
    @limiter.limit(SCAN_LIMIT)
    @optional_token
    def api_scan_qr():
        """
        POST /api/scan/qr
        Body: { "payload": "upi://pay?pa=..." or "https://..." }
        Auth: optional Bearer JWT
        """
        data = request.get_json(silent=True) or {}
        raw_payload = data.get("payload", "")
        if not raw_payload or not str(raw_payload).strip():
            return jsonify({"error": "QR payload cannot be empty."}), 422

        try:
            payload = sanitize_input(str(raw_payload), max_length=4096)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        result = scan_upi_qr(payload)
        snippet = payload[:200] + ("…" if len(payload) > 200 else "")
        _save_scan(
            user_id   = g.user_id,
            target    = snippet,
            scan_type = "qr",
            result    = result,
        )
        return jsonify({
            "scan_type": "qr",
            **result,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }), 200

    @app.route("/api/scan/unshorten", methods=["POST"])
    @limiter.limit(SCAN_LIMIT)
    def api_scan_unshorten():
        """
        POST /api/scan/unshorten
        Body: { "url": "https://bit.ly/..." }
        """
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "")
        try:
            url = sanitize_input(str(raw_url), max_length=2048)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        valid, reason = validate_url(url)
        if not valid:
            return jsonify({"error": reason}), 422

        res = safe_unshorten_url(url)
        return jsonify(res), 200



    # ────────────────────────────────────────────────────────────────────────
    # Scan History Routes
    # ────────────────────────────────────────────────────────────────────────

    @app.route("/api/history", methods=["GET"])
    @token_required
    def api_history():
        """
        GET /api/history?page=1&per_page=20
        Returns the authenticated user's paginated scan history.
        """
        page     = request.args.get("page",     1,  type=int)
        per_page = request.args.get("per_page", 20, type=int)
        per_page = min(per_page, 100)           # hard cap

        pagination = (
            ScanHistory.query
            .filter_by(user_id=g.user_id)
            .order_by(ScanHistory.timestamp.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )

        return jsonify({
            "items":       [s.to_dict() for s in pagination.items],
            "total":       pagination.total,
            "page":        pagination.page,
            "per_page":    pagination.per_page,
            "total_pages": pagination.pages,
        }), 200


    @app.route("/api/history/<int:scan_id>", methods=["DELETE"])
    @token_required
    def api_delete_history(scan_id: int):
        """DELETE /api/history/<id> — Delete a single history record."""
        record = ScanHistory.query.filter_by(id=scan_id, user_id=g.user_id).first()
        if not record:
            return jsonify({"error": "Record not found."}), 404
        db.session.delete(record)
        db.session.commit()
        return jsonify({"message": "Record deleted."}), 200


    @app.route("/api/history", methods=["DELETE"])
    @token_required
    def api_delete_all_history():
        """DELETE /api/history — Bulk delete all scan records for the authenticated user."""
        count = ScanHistory.query.filter_by(user_id=g.user_id).delete()
        db.session.commit()
        return jsonify({"message": f"Deleted {count} records.", "deleted": count}), 200


    @app.route("/api/history/stats", methods=["GET"])
    @token_required
    def api_history_stats():
        """GET /api/history/stats — Aggregate counts per verdict for the user."""
        from sqlalchemy import func
        rows = (
            db.session.query(ScanHistory.verdict, func.count(ScanHistory.id))
            .filter_by(user_id=g.user_id)
            .group_by(ScanHistory.verdict)
            .all()
        )
        stats = {verdict: count for verdict, count in rows}
        total = sum(stats.values())
        return jsonify({"stats": stats, "total": total}), 200


    # ────────────────────────────────────────────────────────────────────────
    # Health check
    # ────────────────────────────────────────────────────────────────────────

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "version": "1.0.0"}), 200

    @app.route("/", methods=["GET"])
    def root_service_info():
        return jsonify({
            "status": "healthy",
            "service": "PhishGuard AI Phishing Detection API",
            "version": "1.0.0",
            "docs": "/api/health"
        }), 200


    # ────────────────────────────────────────────────────────────────────────
    # Global error handlers
    # ────────────────────────────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(429)
    def rate_limited(_e):
        return jsonify({"error": "Too many requests. Please slow down."}), 429

    @app.errorhandler(500)
    def internal_error(exc):
        logger.exception("Unhandled exception: %s", exc)
        return jsonify({"error": "Internal server error."}), 500

    return app


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _save_scan(user_id, target, scan_type, result):
    """Persist a scan result to the database (fire-and-forget style)."""
    try:
        record = ScanHistory(
            user_id    = user_id,
            target     = target,
            scan_type  = scan_type,
            risk_score = result["risk_score"],
            verdict    = result["verdict"],
            ml_score   = result.get("ml_score"),
            gsb_flagged    = result.get("gsb_flagged", False),
            vt_positives   = result.get("vt_positives", 0),
        )
        db.session.add(record)
        db.session.commit()
    except Exception as exc:
        logger.error("Failed to save scan record: %s", exc)
        db.session.rollback()


# ---------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"  # default OFF for safety
    logger.info("Starting Phishing Detector API on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
