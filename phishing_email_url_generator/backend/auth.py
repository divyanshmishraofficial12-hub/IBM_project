"""
auth.py — Registration, login, and JWT token helpers.
Passwords are hashed with bcrypt via Flask-Bcrypt.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Blueprint, request, jsonify, current_app, g
from flask_bcrypt import Bcrypt

from database import db, User

logger  = logging.getLogger(__name__)
bcrypt  = Bcrypt()
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _jwt_secret() -> str:
    return current_app.config["JWT_SECRET_KEY"]


def generate_token(user_id: int, username: str) -> str:
    """Create a signed JWT valid for JWT_ACCESS_TOKEN_EXPIRES_HOURS."""
    hours   = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_HOURS", 24))
    payload = {
        "sub":      user_id,
        "username": username,
        "iat":      datetime.now(timezone.utc),
        "exp":      datetime.now(timezone.utc) + timedelta(hours=hours),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT. Returns payload dict or None on failure."""
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.debug("JWT expired.")
    except jwt.InvalidTokenError as exc:
        logger.debug("JWT invalid: %s", exc)
    return None


def token_required(f):
    """Decorator: extract & validate Bearer JWT; set g.user_id / g.username."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header."}), 401

        token   = auth_header.split(" ", 1)[1]
        payload = decode_token(token)
        if payload is None:
            return jsonify({"error": "Invalid or expired token."}), 401

        g.user_id  = payload["sub"]
        g.username = payload["username"]
        return f(*args, **kwargs)
    return decorated


def optional_token(f):
    """Decorator: silently set g.user_id if a valid JWT is present, else None."""
    @wraps(f)
    def decorated(*args, **kwargs):
        g.user_id  = None
        g.username = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token   = auth_header.split(" ", 1)[1]
            payload = decode_token(token)
            if payload:
                g.user_id  = payload["sub"]
                g.username = payload["username"]
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    POST /api/auth/register
    Body: { "username": "...", "email": "...", "password": "..." }
    """
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "").strip()

    # --- Validation ---
    errors = []
    if not username or len(username) < 3:
        errors.append("Username must be at least 3 characters.")
    if len(username) > 80:
        errors.append("Username must be 80 characters or fewer.")
    if not email or "@" not in email:
        errors.append("A valid email address is required.")
    if not password or len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if errors:
        return jsonify({"error": errors}), 400

    # --- Uniqueness check ---
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered."}), 409

    # --- Persist ---
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user    = User(username=username, email=email, password_hash=pw_hash)
    db.session.add(user)
    db.session.commit()

    token = generate_token(user.id, user.username)
    logger.info("New user registered: %s (id=%d)", username, user.id)

    return jsonify({
        "message": "Account created successfully.",
        "token":   token,
        "user":    user.to_dict(),
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    POST /api/auth/login
    Body: { "username": "...", "password": "..." }
    """
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials."}), 401

    token = generate_token(user.id, user.username)
    logger.info("User logged in: %s (id=%d)", username, user.id)

    return jsonify({
        "message": "Login successful.",
        "token":   token,
        "user":    user.to_dict(),
    }), 200


@auth_bp.route("/me", methods=["GET"])
@token_required
def me():
    """GET /api/auth/me — Return current user info from JWT."""
    user = db.session.get(User, g.user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"user": user.to_dict()}), 200
