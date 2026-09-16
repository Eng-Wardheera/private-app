from datetime import datetime
import enum
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from app import db



# ============================================================
# USER MODEL
# PostgreSQL / Neon
# ============================================================

class User(UserMixin, db.Model):

    __tablename__ = "users"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # ========================================================
    # BASIC USER INFORMATION
    # ========================================================

    username = db.Column(
        db.String(150),
        unique=True,
        nullable=True,
        index=True
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=True,
        index=True
    )

    fullname = db.Column(
        db.String(150),
        unique=True,
        nullable=True
    )

    password = db.Column(
        db.String(255),
        nullable=True
    )

    phone = db.Column(
        db.String(20),
        nullable=True,
        index=True
    )

    # ========================================================
    # LOCATION
    # ========================================================

    country = db.Column(
        db.String(255),
        nullable=True
    )

    city = db.Column(
        db.String(255),
        nullable=True
    )

    state = db.Column(
        db.String(255),
        nullable=True
    )

    address = db.Column(
        db.String(255),
        nullable=True
    )

    # ========================================================
    # BIO
    # ========================================================

    bio = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # ROLE & STATUS
    # ========================================================

    role = db.Column(
        db.String(50),
        nullable=True,
        index=True
    )

    status = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        server_default="true"
    )

    is_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default="false"
    )

    # ========================================================
    # PROFILE PHOTO
    # ========================================================

    photo = db.Column(
        db.String(255),
        nullable=True
    )

    photo_visibility = db.Column(
        db.String(20),
        nullable=False,
        default="everyone",
        server_default="everyone"
    )

    # ========================================================
    # AUTHENTICATION STATUS
    # ========================================================

    auth_status = db.Column(
        db.String(10),
        nullable=False,
        default="logout",
        server_default="logout"
    )

    session_token = db.Column(
        db.String(64),
        nullable=True,
        unique=True,
        index=True
    )

    login_time = db.Column(
        db.DateTime,
        nullable=True,
        default=None
    )

    last_active = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow
    )

    # ========================================================
    # SOCIAL MEDIA
    # ========================================================

    facebook = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    twitter = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    google = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    linkedin = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    skype = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    whatsapp = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    instagram = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    github = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    # ========================================================
    # PERSONAL INFORMATION
    # ========================================================

    dob = db.Column(
        db.Date,
        nullable=True
    )

    pob = db.Column(
        db.String(255),
        nullable=True,
        default=None
    )

    gender = db.Column(
        db.String(20),
        nullable=True,
        default=None
    )

    # ========================================================
    # TIMESTAMPS
    # ========================================================

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    properties = db.relationship(
        "Property",
        backref="agent",
        lazy=True,
        cascade="all, delete-orphan"
    )

    # ========================================================
    # PASSWORD METHODS
    # ========================================================

    def set_password(self, raw_password):

        self.password = generate_password_hash(
            raw_password,
            method="pbkdf2:sha256"
        )

    # --------------------------------------------------------

    def check_password(self, raw_password):

        if not self.password:
            return False

        return check_password_hash(
            self.password,
            raw_password
        )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return f"<User {self.username}>"

