"""
database.py — SQLAlchemy ORM models and database initialization.
Handles User authentication data and Scan History persistence.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    """Registered user account."""

    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans = db.relationship("ScanHistory", backref="user", lazy=True,
                            cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id":         self.id,
            "username":   self.username,
            "email":      self.email,
            "created_at": self.created_at.isoformat(),
        }


class ScanHistory(db.Model):
    """Record of a single phishing scan performed by a user."""

    __tablename__ = "scan_history"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target     = db.Column(db.Text,    nullable=False)          # URL or email snippet
    scan_type  = db.Column(db.String(10), nullable=False)       # "url" | "email"
    risk_score = db.Column(db.Float,   nullable=False, default=0.0)  # 0.0 – 1.0
    verdict    = db.Column(db.String(20), nullable=False)       # safe | suspicious | phishing
    ml_score   = db.Column(db.Float,   nullable=True)
    gsb_flagged    = db.Column(db.Boolean, default=False)       # Google Safe Browsing
    vt_positives   = db.Column(db.Integer, default=0)           # VirusTotal positives
    timestamp  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "user_id":      self.user_id,
            "target":       self.target,
            "scan_type":    self.scan_type,
            "risk_score":   round(self.risk_score, 4),
            "verdict":      self.verdict,
            "ml_score":     round(self.ml_score, 4) if self.ml_score is not None else None,
            "gsb_flagged":  self.gsb_flagged,
            "vt_positives": self.vt_positives,
            "timestamp":    self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def init_db(app):
    """Bind the db to the Flask app and create all tables."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
