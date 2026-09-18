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
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # BRANCH RELATIONSHIP
    # ========================================================

    branch_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "branches.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
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
        nullable=True,
        index=True
    )

    password = db.Column(
        db.String(255),
        nullable=True
    )

    phone = db.Column(
        db.String(30),
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
        server_default=db.text("TRUE"),
        index=True
    )

    is_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("FALSE"),
        index=True
    )

    # ========================================================
    # PROFILE PHOTO
    # ========================================================

    photo = db.Column(
        db.String(500),
        nullable=True
    )

    photo_visibility = db.Column(
        db.String(20),
        nullable=False,
        default="everyone",
        server_default="everyone",
        index=True
    )

    # ========================================================
    # AUTHENTICATION STATUS
    # ========================================================

    auth_status = db.Column(
        db.String(20),
        nullable=False,
        default="logout",
        server_default="logout",
        index=True
    )

    session_token = db.Column(
        db.String(128),
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="users",
        foreign_keys=[institution_id]
    )

    branch = db.relationship(
        "Branch",
        back_populates="users",
        foreign_keys=[branch_id]
    )

    # ========================================================
    # PASSWORD METHODS
    # ========================================================

    def set_password(self, raw_password):

        if not raw_password:
            self.password = None
            return

        self.password = generate_password_hash(
            raw_password,
            method="pbkdf2:sha256"
        )

    # --------------------------------------------------------

    def check_password(self, raw_password):

        if not self.password or not raw_password:
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

    # --------------------------------------------------------

    def is_verified_account(self):
        return bool(self.is_verified)

    # --------------------------------------------------------

    def is_logged_in(self):
        return self.auth_status == "login"

    # ========================================================
    # USER DISPLAY NAME
    # ========================================================

    @property
    def display_name(self):

        return (
            self.fullname
            or self.username
            or self.email
            or f"User {self.id}"
        )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<User "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"username={self.username!r} "
            f"role={self.role!r}>"
        )




# ============================================================
# INSTITUTION MODEL
# PostgreSQL / Neon
# ============================================================

class Institution(db.Model):

    __tablename__ = "institutions"

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    name = db.Column(
        db.String(200),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        unique=True,
        index=True
    )

    short_name = db.Column(
        db.String(100),
        nullable=True
    )

    tagline = db.Column(
        db.String(255),
        nullable=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    phone = db.Column(
        db.String(30),
        nullable=True,
        index=True
    )

    email = db.Column(
        db.String(150),
        nullable=True,
        index=True
    )

    website = db.Column(
        db.String(255),
        nullable=True
    )

    country = db.Column(
        db.String(100),
        nullable=True,
        index=True
    )

    state = db.Column(
        db.String(100),
        nullable=True,
        index=True
    )

    city = db.Column(
        db.String(100),
        nullable=True,
        index=True
    )

    address = db.Column(
        db.String(255),
        nullable=True
    )

    main_logo = db.Column(
        db.String(500),
        nullable=True
    )

    sub_logo = db.Column(
        db.String(500),
        nullable=True
    )

    signature_photo = db.Column(
        db.String(500),
        nullable=True
    )

    favicon = db.Column(
        db.String(500),
        nullable=True
    )

    primary_color = db.Column(
        db.String(20),
        nullable=True,
        default="#06245f",
        server_default="#06245f"
    )

    secondary_color = db.Column(
        db.String(20),
        nullable=True,
        default="#32b73a",
        server_default="#32b73a"
    )

    accent_color = db.Column(
        db.String(20),
        nullable=True,
        default="#33206f",
        server_default="#33206f"
    )

    academic_year = db.Column(
        db.String(50),
        nullable=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
    )

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
    # USER RELATIONSHIP
    #
    # One Institution → Many Users
    # ========================================================

    users = db.relationship(
        "User",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    branches = db.relationship(
        "Branch",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    academic_years = db.relationship(
        "AcademicYear",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    terms = db.relationship(
        "Term",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    programs = db.relationship(
        "Program",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    assessment_plans = db.relationship(
        "AssessmentPlan",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    classes = db.relationship(
        "Class",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    sections = db.relationship(
        "Section",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    def __repr__(self):

        return (
            f"<Institution "
            f"id={self.id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"status={self.status!r}>"
        )



# ============================================================
# BRANCH MODEL
# PostgreSQL / Neon
# ============================================================

class Branch(db.Model):

    __tablename__ = "branches"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # BASIC BRANCH INFORMATION
    # ========================================================

    name = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        unique=True,
        index=True
    )

    # ========================================================
    # CONTACT INFORMATION
    # ========================================================

    phone = db.Column(
        db.String(30),
        nullable=True
    )

    email = db.Column(
        db.String(150),
        nullable=True
    )

    # ========================================================
    # LOCATION
    # ========================================================

    address = db.Column(
        db.String(255),
        nullable=True
    )

    city = db.Column(
        db.String(100),
        nullable=True,
        index=True
    )

    # ========================================================
    # BRANCH BRANDING / MEDIA
    # ========================================================

    # Main Branch Logo
    main_logo = db.Column(
        db.String(500),
        nullable=True
    )

    # Secondary / Sub Logo
    sub_logo = db.Column(
        db.String(500),
        nullable=True
    )

    # Authorized Signature Photo
    signature_photo = db.Column(
        db.String(500),
        nullable=True
    )

    # ========================================================
    # STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
    )

    # ========================================================
    # DESCRIPTION
    # ========================================================

    description = db.Column(
        db.Text,
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
    # RELATIONSHIP
    # ========================================================
    users = db.relationship(
        "User",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    institution = db.relationship(
        "Institution",
        back_populates="branches"
    )
    programs = db.relationship(
        "Program",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    classes = db.relationship(
        "Class",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    sections = db.relationship(
        "Section",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Branch "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# ACADEMIC YEAR MODEL
# PostgreSQL / Neon
# ============================================================

class AcademicYear(db.Model):

    __tablename__ = "academic_years"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR INFORMATION
    # ========================================================

    name = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # DATE RANGE
    # ========================================================

    start_date = db.Column(
        db.Date,
        nullable=False,
        index=True
    )

    end_date = db.Column(
        db.Date,
        nullable=False,
        index=True
    )

    # ========================================================
    # CURRENT ACADEMIC YEAR
    # ========================================================

    is_current = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("FALSE"),
        index=True
    )

    # ========================================================
    # STATUS
    # active
    # inactive
    # closed
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
    )

    # ========================================================
    # DESCRIPTION
    # ========================================================

    description = db.Column(
        db.Text,
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIP
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="academic_years"
    )

    terms = db.relationship(
        "Term",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    assessment_plans = db.relationship(
        "AssessmentPlan",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    classes = db.relationship(
        "Class",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    sections = db.relationship(
        "Section",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<AcademicYear "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"is_current={self.is_current} "
            f"status={self.status!r}>"
        )


# ============================================================
# TERM MODEL
# PostgreSQL / Neon
# ============================================================

class Term(db.Model):

    __tablename__ = "terms"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR RELATIONSHIP
    # ========================================================

    academic_year_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "academic_years.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # TERM INFORMATION
    # ========================================================

    name = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # ORDER / SEQUENCE
    # Example:
    # Term 1 = 1
    # Term 2 = 2
    # Term 3 = 3
    # ========================================================

    sequence = db.Column(
        db.Integer,
        nullable=False,
        default=1,
        index=True
    )

    # ========================================================
    # DATE RANGE
    # ========================================================

    start_date = db.Column(
        db.Date,
        nullable=False,
        index=True
    )

    end_date = db.Column(
        db.Date,
        nullable=False,
        index=True
    )

    # ========================================================
    # CURRENT TERM
    # ========================================================

    is_current = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("FALSE"),
        index=True
    )

    # ========================================================
    # STATUS
    # active
    # inactive
    # closed
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
    )

    # ========================================================
    # DESCRIPTION
    # ========================================================

    description = db.Column(
        db.Text,
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="terms"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="terms"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # Same code cannot repeat inside the same academic year
        db.UniqueConstraint(
            "academic_year_id",
            "code",
            name="uq_term_academic_year_code"
        ),

        # Same name cannot repeat inside the same academic year
        db.UniqueConstraint(
            "academic_year_id",
            "name",
            name="uq_term_academic_year_name"
        ),

        # Same sequence cannot repeat inside the same academic year
        db.UniqueConstraint(
            "academic_year_id",
            "sequence",
            name="uq_term_academic_year_sequence"
        ),
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Term "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"academic_year_id={self.academic_year_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"sequence={self.sequence} "
            f"is_current={self.is_current} "
            f"status={self.status!r}>"
        )



# ============================================================
# PROGRAM MODEL
# PostgreSQL / Neon
# ============================================================

class Program(db.Model):

    __tablename__ = "programs"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # BRANCH RELATIONSHIP
    #
    # Nullable = True
    # because one program can be available in
    # multiple branches.
    # ========================================================

    branch_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "branches.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # PROGRAM INFORMATION
    # ========================================================

    name = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    short_name = db.Column(
        db.String(100),
        nullable=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # PROGRAM TYPE
    #
    # Examples:
    # language
    # science
    # computer
    # vocational
    # academic
    # professional
    # ========================================================

    program_type = db.Column(
        db.String(50),
        nullable=True,
        index=True
    )

    # ========================================================
    # DURATION
    # ========================================================

    duration_months = db.Column(
        db.Integer,
        nullable=True
    )

    # ========================================================
    # STATUS
    # active / inactive
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="programs"
    )

    branch = db.relationship(
        "Branch",
        back_populates="programs"
    )
    assessment_plans = db.relationship(
        "AssessmentPlan",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    classes = db.relationship(
        "Class",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # Program code unique within institution
        db.UniqueConstraint(
            "institution_id",
            "code",
            name="uq_program_institution_code"
        ),

    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Program "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# ASSESSMENT PLAN MODEL
# PostgreSQL / Neon
# ============================================================

class AssessmentPlan(db.Model):

    __tablename__ = "assessment_plans"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # PROGRAM RELATIONSHIP
    # ========================================================

    program_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "programs.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR RELATIONSHIP
    # ========================================================

    academic_year_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "academic_years.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # BASIC INFORMATION
    # ========================================================

    name = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # ASSESSMENT FREQUENCY
    #
    # monthly
    # bi_monthly
    # quarterly
    # semester
    # custom
    # ========================================================

    frequency = db.Column(
        db.String(30),
        nullable=False,
        default="monthly",
        server_default="monthly",
        index=True
    )

    # ========================================================
    # INTERVAL IN MONTHS
    #
    # Monthly      = 1
    # Bi-monthly   = 2
    # Quarterly    = 3
    # Semester     = 6
    # ========================================================

    interval_months = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    # ========================================================
    # PLAN START / END
    # ========================================================

    start_date = db.Column(
        db.Date,
        nullable=False,
        index=True
    )

    end_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    # ========================================================
    # EXAM GENERATION
    #
    # Determines whether the system can automatically
    # generate exam cycles from this plan.
    # ========================================================

    auto_generate = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        server_default=db.text("TRUE"),
        index=True
    )

    # ========================================================
    # STATUS
    #
    # active
    # inactive
    # completed
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="assessment_plans"
    )

    program = db.relationship(
        "Program",
        back_populates="assessment_plans"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="assessment_plans"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # Code unique within institution
        db.UniqueConstraint(
            "institution_id",
            "code",
            name="uq_assessment_plan_institution_code"
        ),

        # One program can have one plan/code per academic year
        db.UniqueConstraint(
            "program_id",
            "academic_year_id",
            "code",
            name="uq_assessment_plan_program_year_code"
        ),

        # Prevent invalid intervals
        db.CheckConstraint(
            "interval_months > 0",
            name="ck_assessment_plan_interval_months"
        ),

    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<AssessmentPlan "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"program_id={self.program_id} "
            f"academic_year_id={self.academic_year_id} "
            f"name={self.name!r} "
            f"frequency={self.frequency!r} "
            f"interval_months={self.interval_months} "
            f"status={self.status!r}>"
        )


# ============================================================
# CLASS MODEL
# PostgreSQL / Neon
# ============================================================

class Class(db.Model):

    __tablename__ = "classes"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # BRANCH RELATIONSHIP
    # ========================================================

    branch_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "branches.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # PROGRAM RELATIONSHIP
    # ========================================================

    program_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "programs.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR RELATIONSHIP
    # ========================================================

    academic_year_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "academic_years.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )
    sections = db.relationship(
        "Section",
        back_populates="class_",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # CLASS INFORMATION
    # ========================================================

    name = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # OPTIONAL CLASS LEVEL / GRADE
    #
    # Examples:
    # Level 1
    # Level 2
    # Form 1
    # Grade 8
    # Beginner
    # Intermediate
    # ========================================================

    level = db.Column(
        db.String(100),
        nullable=True,
        index=True
    )

    # ========================================================
    # CAPACITY
    # ========================================================

    capacity = db.Column(
        db.Integer,
        nullable=True
    )

    # ========================================================
    # DESCRIPTION
    # ========================================================

    description = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # STATUS
    #
    # active
    # inactive
    # completed
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="classes"
    )

    branch = db.relationship(
        "Branch",
        back_populates="classes"
    )

    program = db.relationship(
        "Program",
        back_populates="classes"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="classes"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # Same class code cannot repeat within
        # the same branch + academic year.
        db.UniqueConstraint(
            "branch_id",
            "academic_year_id",
            "code",
            name="uq_class_branch_year_code"
        ),

        # Same class name cannot repeat within
        # the same branch + academic year.
        db.UniqueConstraint(
            "branch_id",
            "academic_year_id",
            "name",
            name="uq_class_branch_year_name"
        ),

        # Capacity cannot be negative
        db.CheckConstraint(
            "capacity IS NULL OR capacity >= 0",
            name="ck_class_capacity"
        ),

    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Class "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"program_id={self.program_id} "
            f"academic_year_id={self.academic_year_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# SECTION MODEL
# PostgreSQL / Neon
# ============================================================

class Section(db.Model):

    __tablename__ = "sections"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION RELATIONSHIP
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # BRANCH RELATIONSHIP
    # ========================================================

    branch_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "branches.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # CLASS RELATIONSHIP
    # ========================================================

    class_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "classes.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR RELATIONSHIP
    # ========================================================

    academic_year_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "academic_years.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # BASIC INFORMATION
    # ========================================================

    name = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    # Example:
    # A
    # B
    # C
    # Morning A
    # Evening B

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # OPTIONAL INFORMATION
    # ========================================================

    capacity = db.Column(
        db.Integer,
        nullable=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        server_default="active",
        index=True
    )

    # active
    # inactive
    # suspended

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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="sections"
    )

    branch = db.relationship(
        "Branch",
        back_populates="sections"
    )

    class_ = db.relationship(
        "Class",
        back_populates="sections"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="sections"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # Same section code cannot repeat
        # inside the same class and academic year.
        db.UniqueConstraint(
            "class_id",
            "academic_year_id",
            "code",
            name="uq_section_class_year_code"
        ),

        # Same section name cannot repeat
        # inside the same class and academic year.
        db.UniqueConstraint(
            "class_id",
            "academic_year_id",
            "name",
            name="uq_section_class_year_name"
        ),

        # Capacity cannot be negative.
        db.CheckConstraint(
            "capacity IS NULL OR capacity >= 0",
            name="ck_section_capacity"
        ),
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Section "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"class_id={self.class_id} "
            f"academic_year_id={self.academic_year_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"status={self.status!r}>"
        )





















   