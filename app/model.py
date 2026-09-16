from datetime import datetime
import enum
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from app import db


# ============================================================
# USER ROLE
# ============================================================

class UserRole(enum.Enum):

    superadmin = "superadmin"

    school_admin = "school_admin"

    branch_admin = "branch_admin"

    teacher = "teacher"

    student = "student"

    parent = "parent"


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
    # ROLE
    # ========================================================

    role = db.Column(
        db.String(50),
        nullable=False,
        default=UserRole.student.value,
        server_default=UserRole.student.value,
        index=True
    )

    # ========================================================
    # ACCOUNT STATUS
    # ========================================================

    status = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        server_default="true",
        index=True
    )

    is_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True
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
        server_default="logout",
        index=True
    )

    session_token = db.Column(
        db.String(64),
        unique=True,
        nullable=True,
        index=True
    )

    login_time = db.Column(
        db.DateTime,
        nullable=True
    )

    last_active = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow,
        server_default=db.func.now(),
        index=True
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow,
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # SOCIAL MEDIA
    # ========================================================

    facebook = db.Column(
        db.String(255),
        nullable=True
    )

    twitter = db.Column(
        db.String(255),
        nullable=True
    )

    google = db.Column(
        db.String(255),
        nullable=True
    )

    linkedin = db.Column(
        db.String(255),
        nullable=True
    )

    skype = db.Column(
        db.String(255),
        nullable=True
    )

    whatsapp = db.Column(
        db.String(255),
        nullable=True
    )

    instagram = db.Column(
        db.String(255),
        nullable=True
    )

    github = db.Column(
        db.String(255),
        nullable=True
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
        nullable=True
    )

    gender = db.Column(
        db.String(20),
        nullable=True
    )

    # ========================================================
    # TIMESTAMPS
    # ========================================================

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=db.func.now(),
        index=True
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=db.func.now()
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
    # USER ROLE HELPERS
    # ========================================================

    def is_superadmin(self):

        return self.role == UserRole.superadmin.value

    # --------------------------------------------------------

    def is_school_admin(self):

        return self.role == UserRole.school_admin.value

    # --------------------------------------------------------

    def is_branch_admin(self):

        return self.role == UserRole.branch_admin.value

    # --------------------------------------------------------

    def is_teacher(self):

        return self.role == UserRole.teacher.value

    # --------------------------------------------------------

    def is_student(self):

        return self.role == UserRole.student.value

    # --------------------------------------------------------

    def is_parent(self):

        return self.role == UserRole.parent.value

    # ========================================================
    # ACCOUNT HELPERS
    # ========================================================

    def is_active(self):

        return bool(self.status)

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<User "
            f"id={self.id} "
            f"username={self.username!r} "
            f"role={self.role!r}>"
        )



   