from datetime import date, datetime, timezone
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
    subjects = db.relationship(
        "Subject",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    teachers = db.relationship(
        "Teacher",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # STUDENTS
    # ========================================================

    students = db.relationship(
        "Student",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # STUDENT ENROLLMENTS
    # ========================================================

    student_enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # STUDENT CHARGES
    # ========================================================

    student_charges = db.relationship(
        "StudentCharge",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # `EXAMS
    # ========================================================

    exams = db.relationship(
        "Exam",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    student_results = db.relationship(
        "StudentResult",
        back_populates="institution",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="institution",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    # ========================================================
    # SITE SETTINGS
    #
    # One Institution → One SiteSettings
    # ========================================================

    site_settings = db.relationship(
        "SiteSettings",
        back_populates="institution",
        uselist=False,
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
    subjects = db.relationship(
        "Subject",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    teachers = db.relationship(
        "Teacher",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # STUDENTS
    # ========================================================

    students = db.relationship(
        "Student",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # STUDENT ENROLLMENTS
    # ========================================================

    student_enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # STUDENT CHARGES
    # ========================================================

    student_charges = db.relationship(
        "StudentCharge",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # EXAMS
    # ========================================================

    exams = db.relationship(
        "Exam",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="branch",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="branch",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    # ========================================================
    # SITE SETTINGS
    #
    # Branch → Optional SiteSettings
    # ========================================================

    site_settings = db.relationship(
        "SiteSettings",
        back_populates="branch",
        uselist=False,
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
    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # STUDENT ENROLLMENTS
    # ========================================================

    student_enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # STUDENT CHARGES
    # ========================================================

    student_charges = db.relationship(
        "StudentCharge",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # EXAMS
    # ========================================================

    exams = db.relationship(
        "Exam",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    student_results = db.relationship(
        "StudentResult",
        back_populates="academic_year",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="academic_year",
        lazy="dynamic",
        cascade="all, delete-orphan"
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
    # EXAMS
    # ========================================================

    exams = db.relationship(
        "Exam",
        back_populates="term",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="term",
        cascade="all, delete-orphan",
        passive_deletes=True
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
    # PROGRAM PRICE
    #
    # Example:
    # 100.00
    # 250.00
    # 500.00
    #
    # Numeric is recommended for money values.
    # ========================================================

    price = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
        server_default="0",
        index=True
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

    subjects = db.relationship(
        "Subject",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    student_enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # EXAMS
    # ========================================================

    exams = db.relationship(
        "Exam",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
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

        # Price cannot be negative
        db.CheckConstraint(
            "price >= 0",
            name="ck_program_price"
        ),

        # Duration cannot be negative
        db.CheckConstraint(
            "duration_months IS NULL OR duration_months >= 0",
            name="ck_program_duration_months"
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
            f"price={self.price} "
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
    # EXAMS
    # ========================================================

    exams = db.relationship(
        "Exam",
        back_populates="assessment_plan",
        cascade="all, delete-orphan",
        passive_deletes=True
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
    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="class_",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="class_",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    # ========================================================
    # EXAM SUBJECTS
    # ========================================================

    exam_subjects = db.relationship(
        "ExamSubject",
        back_populates="class_",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="class_",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="class_",
        lazy="dynamic",
        cascade="all, delete-orphan"
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
    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="section",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="section",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="section",
        lazy="dynamic"
    )

    # ========================================================
    # EXAM SUBJECTS
    # ========================================================

    exam_subjects = db.relationship(
        "ExamSubject",
        back_populates="section",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="section",
        cascade="all, delete-orphan",
        passive_deletes=True
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


# ============================================================
# SUBJECT MODEL
# PostgreSQL / Neon
# ============================================================

class Subject(db.Model):

    __tablename__ = "subjects"

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
    #
    # Subject is currently created for a specific branch.
    #
    # NULL is still allowed at database level so that
    # institution-wide/shared subjects can be supported later.
    #
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
    # PROGRAM RELATIONSHIP
    # ========================================================

    program_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "programs.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # BASIC SUBJECT INFORMATION
    # ========================================================

    name = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    # ========================================================
    # SUBJECT CODE
    # ========================================================
    #
    # Example:
    #
    # SUB001
    # SUB002
    # SUB003
    #
    # Code counter is scoped by:
    #
    # institution + branch
    #
    # Program does NOT affect the code sequence.
    #
    # ========================================================

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # SHORT NAME
    # ========================================================
    #
    # Generated server-side from subject name.
    #
    # Examples:
    #
    # Basic English Grammar -> BEG
    # Advanced Computer Science -> ACS
    # English Language -> EL
    #
    # ========================================================

    short_name = db.Column(
        db.String(100),
        nullable=True,
        index=True
    )

    # ========================================================
    # SUBJECT TYPE
    # ========================================================

    subject_type = db.Column(
        db.String(50),
        nullable=False,
        default="academic",
        server_default="academic",
        index=True
    )

    # Possible values:
    #
    # academic
    # practical
    # language
    # religious
    # vocational
    # elective
    # compulsory

    # ========================================================
    # CREDIT / HOURS
    # ========================================================

    weekly_hours = db.Column(
        db.Numeric(5, 2),
        nullable=True
    )

    credit_hours = db.Column(
        db.Numeric(5, 2),
        nullable=True
    )

    # ========================================================
    # MARK / EXAM CONFIGURATION
    # ========================================================

    # --------------------------------------------------------
    # MAXIMUM MARKS
    # --------------------------------------------------------

    max_marks = db.Column(
        db.Numeric(6, 2),
        nullable=False,
        default=100,
        server_default="100"
    )

    # --------------------------------------------------------
    # PASS MARKS
    # --------------------------------------------------------
    #
    # OPTIONAL.
    #
    # Blank form value becomes NULL.
    #
    # Example:
    #
    # pass_marks = NULL
    #
    # OR:
    #
    # pass_marks = 50
    #
    # ========================================================

    pass_marks = db.Column(
        db.Numeric(6, 2),
        nullable=True,
        default=None,
        server_default=None
    )

    # ========================================================
    # OPTIONAL DESCRIPTION
    # ========================================================

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
        back_populates="subjects"
    )

    branch = db.relationship(
        "Branch",
        back_populates="subjects"
    )

    program = db.relationship(
        "Program",
        back_populates="subjects"
    )

    # ========================================================
    # TEACHER SUBJECTS
    # ========================================================

    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="subject",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # EXAM SUBJECTS
    # ========================================================

    exam_subjects = db.relationship(
        "ExamSubject",
        back_populates="subject",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # ATTENDANCE SESSIONS
    # ========================================================

    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="subject",
        lazy="dynamic"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # ====================================================
        # SUBJECT CODE UNIQUE
        # ====================================================
        #
        # Code is unique by:
        #
        # institution + branch
        #
        # Program is intentionally NOT included.
        #
        # Example:
        #
        # Nursing:
        #   SUB001
        #   SUB002
        #
        # IT:
        #   SUB003
        #   SUB004
        #
        # Business:
        #   SUB005
        #
        # ====================================================

        db.UniqueConstraint(
            "institution_id",
            "branch_id",
            "code",
            name="uq_subject_institution_branch_code"
        ),

        # ====================================================
        # SUBJECT NAME UNIQUE
        # ====================================================
        #
        # Same subject name is allowed in different programs.
        #
        # Example:
        #
        # Nursing:
        #   English
        #
        # IT:
        #   English
        #
        # Business:
        #   English
        #
        # But this is NOT allowed:
        #
        # Nursing:
        #   English
        # Nursing:
        #   English
        #
        # Therefore:
        #
        # institution + branch + program + name
        #
        # ====================================================

        db.UniqueConstraint(
            "institution_id",
            "branch_id",
            "program_id",
            "name",
            name="uq_subject_institution_branch_program_name"
        ),

        # ====================================================
        # MAX MARKS
        # ====================================================

        db.CheckConstraint(
            "max_marks > 0",
            name="ck_subject_max_marks"
        ),

        # ====================================================
        # PASS MARKS
        # ====================================================
        #
        # NULL is allowed.
        #
        # If a value exists, it cannot be negative.
        #
        # ====================================================

        db.CheckConstraint(
            "pass_marks IS NULL OR pass_marks >= 0",
            name="ck_subject_pass_marks"
        ),

        # ====================================================
        # PASS MARKS <= MAX MARKS
        # ====================================================
        #
        # NULL is allowed.
        #
        # ====================================================

        db.CheckConstraint(
            "pass_marks IS NULL OR pass_marks <= max_marks",
            name="ck_subject_pass_marks_max"
        ),

        # ====================================================
        # WEEKLY HOURS
        # ====================================================

        db.CheckConstraint(
            "weekly_hours IS NULL OR weekly_hours >= 0",
            name="ck_subject_weekly_hours"
        ),

        # ====================================================
        # CREDIT HOURS
        # ====================================================

        db.CheckConstraint(
            "credit_hours IS NULL OR credit_hours >= 0",
            name="ck_subject_credit_hours"
        ),
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Subject "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"program_id={self.program_id} "
            f"name={self.name!r} "
            f"code={self.code!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# TEACHER MODEL
# PostgreSQL / Neon
# ============================================================

class Teacher(db.Model):

    __tablename__ = "teachers"

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
    # LOGIN / ACCOUNT INFORMATION
    # ========================================================

    username = db.Column(
        db.String(150),
        nullable=False,
        unique=True,
        index=True
    )

    email = db.Column(
        db.String(150),
        nullable=True,
        unique=True,
        index=True
    )

    # Password is stored as a HASH.
    # Never store plain-text passwords.

    password = db.Column(
        db.String(255),
        nullable=False
    )

    # ========================================================
    # ROLE
    # ========================================================

    role = db.Column(
        db.String(50),
        nullable=False,
        default="teacher",
        server_default="teacher",
        index=True
    )

    # ========================================================
    # TEACHER ROLL NUMBER
    # ========================================================

    # Example:
    # T001
    # T002
    # T003

    roll_no = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # TEACHER NAME
    # ========================================================

    full_name = db.Column(
        db.String(200),
        nullable=False,
        index=True
    )

    # ========================================================
    # PERSONAL INFORMATION
    # ========================================================

    gender = db.Column(
        db.String(20),
        nullable=True,
        index=True
    )

    date_of_birth = db.Column(
        db.Date,
        nullable=True
    )

    phone = db.Column(
        db.String(30),
        nullable=True,
        index=True
    )

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
    # PROFESSIONAL INFORMATION
    # ========================================================

    qualification = db.Column(
        db.String(255),
        nullable=True
    )

    specialization = db.Column(
        db.String(255),
        nullable=True
    )

    experience_years = db.Column(
        db.Integer,
        nullable=True
    )

    hire_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    # ========================================================
    # PHOTO
    # ========================================================

    photo = db.Column(
        db.String(500),
        nullable=True
    )

    # ========================================================
    # ACCOUNT STATUS
    # ========================================================

    is_active = db.Column(
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
    # LOGIN TRACKING
    # ========================================================

    login_time = db.Column(
        db.DateTime,
        nullable=True
    )

    last_login = db.Column(
        db.DateTime,
        nullable=True,
        index=True
    )

    last_active = db.Column(
        db.DateTime,
        nullable=True,
        index=True
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
    # resigned

    # ========================================================
    # NOTES
    # ========================================================

    notes = db.Column(
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
        back_populates="teachers"
    )

    branch = db.relationship(
        "Branch",
        back_populates="teachers"
    )
    teacher_subjects = db.relationship(
        "TeacherSubject",
        back_populates="teacher",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # MARKS ENTERED
    # ========================================================

    entered_marks = db.relationship(
        "Mark",
        foreign_keys="Mark.entered_by",
        back_populates="entered_by_teacher",
        passive_deletes=True
    )

    # ========================================================
    # EXAM SUBJECTS
    # ========================================================

    exam_subjects = db.relationship(
        "ExamSubject",
        back_populates="teacher",
        passive_deletes=True
    )
    attendance_sessions = db.relationship(
    "AttendanceSession",
        back_populates="teacher",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    marked_attendance = db.relationship(
        "AttendanceRecord",
        foreign_keys="AttendanceRecord.marked_by_teacher_id",
        back_populates="marked_by_teacher",
        passive_deletes=True
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # Roll number unique within institution
        db.UniqueConstraint(
            "institution_id",
            "roll_no",
            name="uq_teacher_institution_roll_no"
        ),

        # Experience cannot be negative
        db.CheckConstraint(
            "experience_years IS NULL OR experience_years >= 0",
            name="ck_teacher_experience_years"
        ),
    )

    # ========================================================
    # PASSWORD METHODS
    # ========================================================

    def set_password(self, raw_password):

        if not raw_password:
            raise ValueError(
                "Teacher password cannot be empty."
            )

        self.password = generate_password_hash(
            raw_password,
            method="pbkdf2:sha256"
        )

    def check_password(self, raw_password):

        if not self.password or not raw_password:
            return False

        return check_password_hash(
            self.password,
            raw_password
        )

    # ========================================================
    # ACCOUNT CHECK
    # ========================================================

    def is_account_active(self):

        return (
            self.is_active
            and self.status == "active"
        )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Teacher "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"roll_no={self.roll_no!r} "
            f"username={self.username!r} "
            f"full_name={self.full_name!r} "
            f"role={self.role!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# TEACHER SUBJECT MODEL
# PostgreSQL / Neon
# ============================================================

class TeacherSubject(db.Model):

    __tablename__ = "teacher_subjects"

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    branch_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "branches.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    teacher_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "teachers.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # PROGRAM
    # ========================================================

    program_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "programs.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # SUBJECT
    # ========================================================

    subject_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "subjects.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # CLASS
    # ========================================================

    class_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "classes.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # SECTION
    # ========================================================

    section_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "sections.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR
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
    # ASSIGNMENT TYPE
    # ========================================================

    assignment_type = db.Column(
        db.String(30),
        nullable=False,
        default="subject",
        server_default="subject",
        index=True
    )

    # program
    # class
    # section
    # subject

    # ========================================================
    # SCOPE
    # ========================================================

    scope = db.Column(
        db.String(30),
        nullable=False,
        default="specific",
        server_default="specific",
        index=True
    )

    # all
    # selected
    # specific

    # ========================================================
    # TEACHING TYPE
    # ========================================================

    teaching_type = db.Column(
        db.String(50),
        nullable=False,
        default="teacher",
        server_default="teacher",
        index=True
    )

    # teacher
    # assistant
    # coordinator
    # substitute

    # ========================================================
    # PRIMARY TEACHER
    # ========================================================

    is_primary = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        server_default=db.text("TRUE"),
        index=True
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
    # DATES
    # ========================================================

    start_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    end_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    notes = db.Column(
        db.Text,
        nullable=True
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
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="teacher_subjects"
    )

    branch = db.relationship(
        "Branch",
        back_populates="teacher_subjects"
    )

    teacher = db.relationship(
        "Teacher",
        back_populates="teacher_subjects"
    )

    program = db.relationship(
        "Program",
        back_populates="teacher_subjects"
    )

    subject = db.relationship(
        "Subject",
        back_populates="teacher_subjects"
    )

    class_ = db.relationship(
        "Class",
        back_populates="teacher_subjects"
    )

    section = db.relationship(
        "Section",
        back_populates="teacher_subjects"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="teacher_subjects"
    )
    attendance_sessions = db.relationship(
        "AttendanceSession",
        back_populates="teacher_subject",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    __table_args__ = (

        db.CheckConstraint(
            "end_date IS NULL OR "
            "start_date IS NULL OR "
            "end_date >= start_date",
            name="ck_teacher_subject_date_range"
        ),

    )

    def __repr__(self):

        return (
            f"<TeacherSubject "
            f"id={self.id} "
            f"teacher_id={self.teacher_id} "
            f"program_id={self.program_id} "
            f"class_id={self.class_id} "
            f"section_id={self.section_id} "
            f"subject_id={self.subject_id} "
            f"assignment_type={self.assignment_type!r} "
            f"scope={self.scope!r}>"
        )



# ============================================================
# STUDENT MODEL
# PostgreSQL / Neon
# ============================================================

class Student(UserMixin, db.Model):

    __tablename__ = "students"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION
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
    # BRANCH
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
    # LOGIN INFORMATION
    # ========================================================

    username = db.Column(
        db.String(150),
        nullable=False,
        unique=True,
        index=True
    )

    email = db.Column(
        db.String(150),
        nullable=True,
        unique=True,
        index=True
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(50),
        nullable=False,
        default="student",
        server_default="student",
        index=True
    )

    # ========================================================
    # ACCOUNT STATUS
    # ========================================================

    is_active = db.Column(
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
    # SESSION / LOGIN TRACKING
    # ========================================================

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

    last_login = db.Column(
        db.DateTime,
        nullable=True,
        index=True
    )

    last_active = db.Column(
        db.DateTime,
        nullable=True,
        index=True
    )

    # ========================================================
    # STUDENT IDENTIFICATION
    # ========================================================

    admission_no = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    roll_no = db.Column(
        db.String(50),
        nullable=True,
        index=True
    )

    # ========================================================
    # PERSONAL INFORMATION
    # ========================================================

    full_name = db.Column(
        db.String(200),
        nullable=False,
        index=True
    )

    gender = db.Column(
        db.String(20),
        nullable=True,
        index=True
    )

    date_of_birth = db.Column(
        db.Date,
        nullable=True
    )

    place_of_birth = db.Column(
        db.String(150),
        nullable=True
    )

    nationality = db.Column(
        db.String(100),
        nullable=True
    )

    # ========================================================
    # CONTACT
    # ========================================================

    phone = db.Column(
        db.String(30),
        nullable=True,
        index=True
    )

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
    # PARENT / GUARDIAN
    # ========================================================

    parent_name = db.Column(
        db.String(200),
        nullable=True,
        index=True
    )

    parent_phone = db.Column(
        db.String(30),
        nullable=True,
        index=True
    )

    parent_email = db.Column(
        db.String(150),
        nullable=True
    )

    parent_address = db.Column(
        db.String(255),
        nullable=True
    )

    relationship_to_student = db.Column(
        db.String(50),
        nullable=True
    )

    # ========================================================
    # PHOTO
    # ========================================================

    photo = db.Column(
        db.String(500),
        nullable=True
    )

    # ========================================================
    # STUDENT STATUS
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
    # graduated
    # transferred
    # suspended
    # withdrawn

    # ========================================================
    # NOTES
    # ========================================================

    notes = db.Column(
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
        back_populates="students"
    )

    branch = db.relationship(
        "Branch",
        back_populates="students"
    )

    enrollments = db.relationship(
        "StudentEnrollment",
        back_populates="student",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    charges = db.relationship(
        "StudentCharge",
        back_populates="student",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="student",
        cascade="all, delete-orphan",
        passive_deletes=True
    )


    # ========================================================
    # MARKS
    # ========================================================

    marks = db.relationship(
        "Mark",
        back_populates="student",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    attendance_records = db.relationship(
        "AttendanceRecord",
        back_populates="student",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # CONSTRAINTS
    # ========================================================

    __table_args__ = (

        db.UniqueConstraint(
            "institution_id",
            "admission_no",
            name="uq_student_institution_admission_no"
        ),

        db.CheckConstraint(
            "status IN ("
            "'active', "
            "'inactive', "
            "'graduated', "
            "'transferred', "
            "'suspended', "
            "'withdrawn'"
            ")",
            name="ck_student_status"
        ),

    )

    # ========================================================
    # PASSWORD MANAGEMENT
    # ========================================================

    def set_password(self, raw_password):

        if not raw_password:
            raise ValueError(
                "Student password cannot be empty."
            )

        self.password = generate_password_hash(
            raw_password,
            method="pbkdf2:sha256"
        )

    # ========================================================
    # CHECK PASSWORD
    # ========================================================

    def check_password(self, raw_password):

        if not self.password or not raw_password:
            return False

        return check_password_hash(
            self.password,
            raw_password
        )

    # ========================================================
    # ACCOUNT STATUS
    # ========================================================

    def is_account_active(self):

        return (
            self.is_active
            and self.status == "active"
        )

    # ========================================================
    # FLASK-LOGIN ID
    # ========================================================

    def get_id(self):

        return str(self.id)

    # ========================================================
    # DISPLAY NAME
    # ========================================================

    @property
    def display_name(self):

        return (
            self.full_name
            or self.username
            or self.email
            or f"Student {self.id}"
        )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Student "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"admission_no={self.admission_no!r} "
            f"username={self.username!r} "
            f"full_name={self.full_name!r} "
            f"role={self.role!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# STUDENT ENROLLMENT MODEL
# PostgreSQL / Neon
# ============================================================

class StudentEnrollment(db.Model):

    __tablename__ = "student_enrollments"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION
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
    # BRANCH
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
    # STUDENT
    # ========================================================

    student_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "students.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR
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
    # PROGRAM
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
    # CLASS
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
    # SECTION
    # ========================================================

    section_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "sections.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # ENROLLMENT NUMBER
    # ========================================================

    enrollment_no = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # ENROLLMENT DATE
    # ========================================================

    enrollment_date = db.Column(
        db.Date,
        nullable=False,
        default=date.today,
        server_default=db.func.current_date(),
        index=True
    )

    # ========================================================
    # STATUS
    # ========================================================

    status = db.Column(
        db.String(30),
        nullable=False,
        default="active",
        server_default="active",
        index=True
    )

    # active
    # completed
    # transferred
    # withdrawn
    # suspended
    # promoted

    # ========================================================
    # PREVIOUS CLASS / NOTES
    # ========================================================

    notes = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # CREATED / UPDATED
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
        back_populates="student_enrollments"
    )

    branch = db.relationship(
        "Branch",
        back_populates="student_enrollments"
    )

    student = db.relationship(
        "Student",
        back_populates="enrollments"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="student_enrollments"
    )

    program = db.relationship(
        "Program",
        back_populates="student_enrollments"
    )

    class_ = db.relationship(
        "Class",
        back_populates="student_enrollments"
    )

    section = db.relationship(
        "Section",
        back_populates="student_enrollments"
    )

    charges = db.relationship(
        "StudentCharge",
        back_populates="enrollment",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="student_enrollment",
        passive_deletes=True
    )
    attendance_records = db.relationship(
        "AttendanceRecord",
        back_populates="enrollment",
        passive_deletes=True
    )

    # ========================================================
    # CONSTRAINTS
    # ========================================================

    __table_args__ = (

        db.UniqueConstraint(
            "institution_id",
            "enrollment_no",
            name="uq_enrollment_institution_no"
        ),

        db.UniqueConstraint(
            "student_id",
            "academic_year_id",
            name="uq_student_academic_year_enrollment"
        ),

        db.CheckConstraint(
            "status IN ("
            "'active', "
            "'completed', "
            "'transferred', "
            "'withdrawn', "
            "'suspended', "
            "'promoted'"
            ")",
            name="ck_student_enrollment_status"
        ),
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<StudentEnrollment "
            f"id={self.id} "
            f"student_id={self.student_id} "
            f"academic_year_id={self.academic_year_id} "
            f"program_id={self.program_id} "
            f"class_id={self.class_id} "
            f"section_id={self.section_id} "
            f"enrollment_no={self.enrollment_no!r} "
            f"status={self.status!r}>"
        )


# ============================================================
# STUDENT CHARGE MODEL
# PostgreSQL / Neon
# ============================================================
class StudentCharge(db.Model):

    __tablename__ = "student_charges"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION
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
    # BRANCH
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
    # STUDENT
    # ========================================================

    student_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "students.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ENROLLMENT
    # ========================================================

    enrollment_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "student_enrollments.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR
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
    # CHARGE TYPE
    #
    # Registration:
    #     registration
    #
    # Program:
    #     program_fee
    #
    # Future:
    #     tuition
    #     exam
    #     books
    #     uniform
    #     transport
    #     laboratory
    #     library
    #     certificate
    #     other
    # ========================================================

    charge_type = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # CHARGE NAME
    # ========================================================

    charge_name = db.Column(
        db.String(150),
        nullable=False,
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
    # AMOUNT
    # ========================================================

    amount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # DISCOUNT
    # ========================================================

    discount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # NET AMOUNT
    # ========================================================

    net_amount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # PAID AMOUNT
    # ========================================================

    paid_amount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # BALANCE
    # ========================================================

    balance = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # DUE DATE
    # ========================================================

    due_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    # ========================================================
    # PAYMENT STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="unpaid",
        server_default="unpaid",
        index=True
    )

    # ========================================================
    # CREATED BY
    # ========================================================

    created_by = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="SET NULL"
        ),
        nullable=True,
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
        back_populates="student_charges"
    )

    branch = db.relationship(
        "Branch",
        back_populates="student_charges"
    )

    student = db.relationship(
        "Student",
        back_populates="charges"
    )

    enrollment = db.relationship(
        "StudentEnrollment",
        back_populates="charges"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="student_charges"
    )

    created_by_user = db.relationship(
        "User",
        foreign_keys=[created_by]
    )

    # ========================================================
    # CONSTRAINTS
    # ========================================================

    __table_args__ = (

        db.CheckConstraint(
            "amount >= 0",
            name="ck_student_charge_amount"
        ),

        db.CheckConstraint(
            "discount >= 0",
            name="ck_student_charge_discount"
        ),

        db.CheckConstraint(
            "discount <= amount",
            name="ck_student_charge_discount_amount"
        ),

        db.CheckConstraint(
            "net_amount >= 0",
            name="ck_student_charge_net_amount"
        ),

        db.CheckConstraint(
            "paid_amount >= 0",
            name="ck_student_charge_paid_amount"
        ),

        db.CheckConstraint(
            "paid_amount <= net_amount",
            name="ck_student_charge_paid_net_amount"
        ),

        db.CheckConstraint(
            "balance >= 0",
            name="ck_student_charge_balance"
        ),

        db.CheckConstraint(
            "status IN ("
            "'unpaid', "
            "'partial', "
            "'paid', "
            "'cancelled', "
            "'overdue'"
            ")",
            name="ck_student_charge_status"
        ),

        db.CheckConstraint(
            "charge_type IN ("
            "'registration', "
            "'program_fee', "
            "'tuition', "
            "'exam', "
            "'admission', "
            "'id_card', "
            "'uniform', "
            "'books', "
            "'transport', "
            "'laboratory', "
            "'library', "
            "'certificate', "
            "'other'"
            ")",
            name="ck_student_charge_type"
        ),
    )

    # ========================================================
    # CALCULATE BALANCE
    # ========================================================

    def calculate_balance(self):

        self.net_amount = (
            self.amount - self.discount
        )

        self.balance = (
            self.net_amount - self.paid_amount
        )

        if self.balance <= 0:

            self.balance = 0
            self.status = "paid"

        elif self.paid_amount > 0:

            self.status = "partial"

        else:

            self.status = "unpaid"

        return self.balance

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<StudentCharge "
            f"id={self.id} "
            f"student_id={self.student_id} "
            f"charge_type={self.charge_type!r} "
            f"charge_name={self.charge_name!r} "
            f"amount={self.amount} "
            f"net_amount={self.net_amount} "
            f"paid_amount={self.paid_amount} "
            f"balance={self.balance} "
            f"status={self.status!r}>"
        )


# ============================================================
# EXAM MODEL
# PostgreSQL / Neon
# ============================================================

class Exam(db.Model):

    __tablename__ = "exams"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION
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
    # BRANCH
    # ========================================================

    # Exam-ku wuxuu ka dhacayaa branch gaar ah.
    # Sidaas darteed branch_id waa REQUIRED.

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
    # PROGRAM
    # ========================================================

    # Exam-ku wuxuu leeyahay Program uu u yahay.
    #
    # Tusaale:
    # English Program
    # Computer Science Program
    # Nursing Program

    program_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "programs.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ASSESSMENT PLAN
    # ========================================================

    # AssessmentPlan wuxuu qeexayaa:
    #
    # Monthly
    # Bi-Monthly
    # Quarterly
    # Semester
    # Custom
    #
    # NULL waa loo oggol yahay haddii uu yahay:
    #
    # Mock Exam
    # Entrance Exam
    # Resit Exam
    # Supplementary Exam
    # Special Exam

    assessment_plan_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "assessment_plans.id",
            ondelete="RESTRICT"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR
    # ========================================================

    academic_year_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "academic_years.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # TERM
    # ========================================================

    term_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "terms.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # EXAM NAME
    # ========================================================

    name = db.Column(
        db.String(150),
        nullable=False,
        index=True
    )

    # ========================================================
    # EXAM CODE
    # ========================================================

    code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    # ========================================================
    # EXAM TYPE
    # ========================================================

    exam_type = db.Column(
        db.String(50),
        nullable=False,
        default="term",
        server_default="term",
        index=True
    )

    # Possible values:
    #
    # monthly
    # bi_monthly
    # quarterly
    # semester
    # midterm
    # final
    # annual
    # mock
    # entrance
    # supplementary
    # resit
    # special

    # ========================================================
    # DESCRIPTION
    # ========================================================

    description = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # START DATE
    # ========================================================

    start_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    # ========================================================
    # END DATE
    # ========================================================

    end_date = db.Column(
        db.Date,
        nullable=True,
        index=True
    )

    # ========================================================
    # STATUS
    # ========================================================

    status = db.Column(
        db.String(30),
        nullable=False,
        default="draft",
        server_default="draft",
        index=True
    )

    # Possible values:
    #
    # draft
    # scheduled
    # ongoing
    # completed
    # cancelled
    # published

    # ========================================================
    # CREATED AT
    # ========================================================

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # UPDATED AT
    # ========================================================

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="exams"
    )

    branch = db.relationship(
        "Branch",
        back_populates="exams"
    )

    program = db.relationship(
        "Program",
        back_populates="exams"
    )

    assessment_plan = db.relationship(
        "AssessmentPlan",
        back_populates="exams"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="exams"
    )

    term = db.relationship(
        "Term",
        back_populates="exams"
    )
    exam_subjects = db.relationship(
        "ExamSubject",
        back_populates="exam",
        cascade="all, delete-orphan",
        lazy=True
    )
    student_results = db.relationship(
        "StudentResult",
        back_populates="exam",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    
    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # ----------------------------------------------------
        # UNIQUE EXAM CODE PER BRANCH + ACADEMIC YEAR
        # ----------------------------------------------------

        db.UniqueConstraint(
            "institution_id",
            "branch_id",
            "academic_year_id",
            "code",
            name="uq_exam_branch_year_code"
        ),

        # ----------------------------------------------------
        # INSTITUTION + BRANCH
        # ----------------------------------------------------

        db.Index(
            "ix_exams_institution_branch",
            "institution_id",
            "branch_id"
        ),

        # ----------------------------------------------------
        # PROGRAM + ACADEMIC YEAR
        # ----------------------------------------------------

        db.Index(
            "ix_exams_program_year",
            "program_id",
            "academic_year_id"
        ),

        # ----------------------------------------------------
        # ASSESSMENT PLAN
        # ----------------------------------------------------

        db.Index(
            "ix_exams_assessment_plan",
            "assessment_plan_id"
        ),

        # ----------------------------------------------------
        # ACADEMIC YEAR + TERM
        # ----------------------------------------------------

        db.Index(
            "ix_exams_academic_year_term",
            "academic_year_id",
            "term_id"
        ),

        # ----------------------------------------------------
        # EXAM DATE RANGE
        # ----------------------------------------------------

        db.Index(
            "ix_exams_dates",
            "start_date",
            "end_date"
        ),

    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Exam "
            f"id={self.id} "
            f"code='{self.code}' "
            f"name='{self.name}' "
            f"program_id={self.program_id} "
            f"assessment_plan_id={self.assessment_plan_id} "
            f"status='{self.status}'>"
        )


# ============================================================
# EXAM SUBJECT MODEL
# PostgreSQL / Neon
# ============================================================

class ExamSubject(db.Model):

    __tablename__ = "exam_subjects"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # EXAM
    # ========================================================

    exam_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "exams.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # SUBJECT
    # ========================================================

    subject_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "subjects.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # CLASS
    # ========================================================

    # Optional.
    # Program-yada qaar Class ma laha.

    class_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "classes.id",
            ondelete="RESTRICT"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # SECTION
    # ========================================================

    # Optional.
    # Class-yada qaar Section ma laha.

    section_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "sections.id",
            ondelete="RESTRICT"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # TEACHER
    # ========================================================

    # Optional.
    # Teacher ayaa dambe loo assign-gareyn karaa.

    teacher_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "teachers.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # MARK SETTINGS
    # ========================================================

    max_marks = db.Column(
        db.Numeric(6, 2),
        nullable=False,
        default=100,
        server_default="100"
    )

    pass_marks = db.Column(
        db.Numeric(6, 2),
        nullable=False,
        default=50,
        server_default="50"
    )

    weight = db.Column(
        db.Numeric(6, 2),
        nullable=False,
        default=100,
        server_default="100"
    )

    # ========================================================
    # DISPLAY ORDER
    # ========================================================

    display_order = db.Column(
        db.Integer,
        nullable=False,
        default=1,
        server_default="1"
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
    # CREATED / UPDATED
    # ========================================================

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=db.func.now()
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=db.func.now()
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    exam = db.relationship(
        "Exam",
        back_populates="exam_subjects"
    )

    subject = db.relationship(
        "Subject",
        back_populates="exam_subjects"
    )

    class_ = db.relationship(
        "Class",
        back_populates="exam_subjects"
    )

    section = db.relationship(
        "Section",
        back_populates="exam_subjects"
    )

    teacher = db.relationship(
        "Teacher",
        back_populates="exam_subjects"
    )
    # ========================================================
    # MARKS
    # ========================================================

    marks = db.relationship(
        "Mark",
        back_populates="exam_subject",
        cascade="all, delete-orphan",
        passive_deletes=True
    )


    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        db.CheckConstraint(
            "max_marks > 0",
            name="ck_exam_subject_max_marks"
        ),

        db.CheckConstraint(
            "pass_marks >= 0",
            name="ck_exam_subject_pass_marks"
        ),

        db.CheckConstraint(
            "pass_marks <= max_marks",
            name="ck_exam_subject_pass_marks_limit"
        ),

        db.CheckConstraint(
            "weight > 0",
            name="ck_exam_subject_weight"
        ),

        db.CheckConstraint(
            "display_order > 0",
            name="ck_exam_subject_display_order"
        ),

        db.Index(
            "ix_exam_subjects_exam_subject",
            "exam_id",
            "subject_id"
        ),

        db.Index(
            "ix_exam_subjects_class_section",
            "class_id",
            "section_id"
        ),
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<ExamSubject "
            f"id={self.id} "
            f"exam_id={self.exam_id} "
            f"subject_id={self.subject_id} "
            f"class_id={self.class_id} "
            f"section_id={self.section_id}>"
        )


# ============================================================
# MARK MODEL
# PostgreSQL / Neon
# ============================================================

class Mark(db.Model):

    __tablename__ = "marks"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # EXAM SUBJECT
    # ========================================================

    exam_subject_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "exam_subjects.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # STUDENT
    # ========================================================

    student_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "students.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # MARKS OBTAINED
    # ========================================================

    marks_obtained = db.Column(
        db.Numeric(6, 2),
        nullable=True
    )

    # ========================================================
    # ABSENT
    # ========================================================

    is_absent = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("FALSE"),
        index=True
    )

    # ========================================================
    # EXEMPTED
    # ========================================================

    is_exempted = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("FALSE"),
        index=True
    )

    # ========================================================
    # REMARKS
    # ========================================================

    remarks = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="draft",
        server_default="draft",
        index=True
    )

    # ========================================================
    # ENTERED BY TEACHER
    # ========================================================

    entered_by = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "teachers.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # SUBMITTED AT
    # ========================================================

    submitted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # ========================================================
    # APPROVED AT
    # ========================================================

    approved_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # ========================================================
    # CREATED AT
    # ========================================================

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # UPDATED AT
    # ========================================================

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    exam_subject = db.relationship(
        "ExamSubject",
        back_populates="marks"
    )

    student = db.relationship(
        "Student",
        back_populates="marks"
    )

    entered_by_teacher = db.relationship(
        "Teacher",
        foreign_keys=[entered_by],
        back_populates="entered_marks"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # ----------------------------------------------------
        # ONE MARK PER STUDENT PER EXAM SUBJECT
        # ----------------------------------------------------

        db.UniqueConstraint(
            "exam_subject_id",
            "student_id",
            name="uq_mark_exam_subject_student"
        ),

        # ----------------------------------------------------
        # MARK CANNOT BE NEGATIVE
        # ----------------------------------------------------

        db.CheckConstraint(
            "marks_obtained IS NULL OR marks_obtained >= 0",
            name="ck_mark_non_negative"
        ),

        # ----------------------------------------------------
        # INDEX
        # ----------------------------------------------------

        db.Index(
            "ix_marks_exam_subject_student",
            "exam_subject_id",
            "student_id"
        ),

    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<Mark "
            f"id={self.id} "
            f"exam_subject_id={self.exam_subject_id} "
            f"student_id={self.student_id} "
            f"marks_obtained={self.marks_obtained} "
            f"status='{self.status}'>"
        )


# ============================================================
# STUDENT RESULT MODEL
# PostgreSQL / Neon
# ============================================================

class StudentResult(db.Model):

    __tablename__ = "student_results"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # EXAM
    # ========================================================

    exam_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "exams.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # STUDENT
    # ========================================================

    student_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "students.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # STUDENT ENROLLMENT
    # ========================================================

    student_enrollment_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "student_enrollments.id",
            ondelete="RESTRICT"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # INSTITUTION
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
    # BRANCH
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
    # PROGRAM
    # ========================================================

    program_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "programs.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR
    # ========================================================

    academic_year_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "academic_years.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # TERM
    # ========================================================

    term_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "terms.id",
            ondelete="RESTRICT"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # CLASS
    # ========================================================

    class_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "classes.id",
            ondelete="RESTRICT"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # SECTION
    # ========================================================

    section_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "sections.id",
            ondelete="RESTRICT"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # TOTAL MARKS
    # ========================================================

    total_marks = db.Column(
        db.Numeric(10, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # TOTAL POSSIBLE MARKS
    # ========================================================

    total_possible_marks = db.Column(
        db.Numeric(10, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # PERCENTAGE
    # ========================================================

    percentage = db.Column(
        db.Numeric(6, 2),
        nullable=False,
        default=0,
        server_default="0",
        index=True
    )

    # ========================================================
    # AVERAGE
    # ========================================================

    average = db.Column(
        db.Numeric(6, 2),
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # SUBJECTS TOTAL
    # ========================================================

    subjects_total = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # SUBJECTS COMPLETED
    # ========================================================

    subjects_completed = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # SUBJECTS FAILED
    # ========================================================

    subjects_failed = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        server_default="0"
    )

    # ========================================================
    # GRADE
    # ========================================================

    grade = db.Column(
        db.String(10),
        nullable=True,
        index=True
    )

    # ========================================================
    # GPA
    # ========================================================

    gpa = db.Column(
        db.Numeric(4, 2),
        nullable=True,
        index=True
    )

    # ========================================================
    # RESULT STATUS
    # ========================================================

    result_status = db.Column(
        db.String(20),
        nullable=False,
        default="incomplete",
        server_default="incomplete",
        index=True
    )

    # Possible:
    #
    # PASS
    # FAIL
    # INCOMPLETE
    #

    # ========================================================
    # REMARKS
    # ========================================================

    remarks = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # INSTITUTION POSITION
    # ========================================================

    institution_position = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    # ========================================================
    # BRANCH POSITION
    # ========================================================

    branch_position = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    # ========================================================
    # PROGRAM POSITION
    # ========================================================

    program_position = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    # ========================================================
    # CLASS POSITION
    # ========================================================

    class_position = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    # ========================================================
    # SECTION POSITION
    # ========================================================

    section_position = db.Column(
        db.Integer,
        nullable=True,
        index=True
    )

    # ========================================================
    # RESULT STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="draft",
        server_default="draft",
        index=True
    )

    # Possible:
    #
    # draft
    # submitted
    # approved
    # published
    #

    # ========================================================
    # CALCULATED AT
    # ========================================================

    calculated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # ========================================================
    # APPROVED AT
    # ========================================================

    approved_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # ========================================================
    # PUBLISHED AT
    # ========================================================

    published_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # ========================================================
    # CREATED AT
    # ========================================================

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # UPDATED AT
    # ========================================================

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=db.func.now(),
        index=True
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    exam = db.relationship(
        "Exam",
        back_populates="student_results"
    )

    student = db.relationship(
        "Student",
        back_populates="student_results"
    )

    student_enrollment = db.relationship(
        "StudentEnrollment",
        back_populates="student_results"
    )

    institution = db.relationship(
        "Institution",
        back_populates="student_results"
    )

    branch = db.relationship(
        "Branch",
        back_populates="student_results"
    )

    program = db.relationship(
        "Program",
        back_populates="student_results"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="student_results"
    )

    term = db.relationship(
        "Term",
        back_populates="student_results"
    )

    class_ = db.relationship(
        "Class",
        back_populates="student_results"
    )

    section = db.relationship(
        "Section",
        back_populates="student_results"
    )

    # ========================================================
    # TABLE CONSTRAINTS
    # ========================================================

    __table_args__ = (

        # ----------------------------------------------------
        # ONE RESULT PER STUDENT PER EXAM
        # ----------------------------------------------------

        db.UniqueConstraint(
            "exam_id",
            "student_id",
            name="uq_student_result_exam_student"
        ),

        # ----------------------------------------------------
        # TOTAL MARKS CANNOT BE NEGATIVE
        # ----------------------------------------------------

        db.CheckConstraint(
            "total_marks >= 0",
            name="ck_student_result_total_marks"
        ),

        # ----------------------------------------------------
        # TOTAL POSSIBLE MARKS CANNOT BE NEGATIVE
        # ----------------------------------------------------

        db.CheckConstraint(
            "total_possible_marks >= 0",
            name="ck_student_result_total_possible_marks"
        ),

        # ----------------------------------------------------
        # TOTAL MARKS CANNOT EXCEED POSSIBLE MARKS
        # ----------------------------------------------------

        db.CheckConstraint(
            "total_marks <= total_possible_marks",
            name="ck_student_result_total_marks_limit"
        ),

        # ----------------------------------------------------
        # PERCENTAGE
        # ----------------------------------------------------

        db.CheckConstraint(
            "percentage >= 0 AND percentage <= 100",
            name="ck_student_result_percentage"
        ),

        # ----------------------------------------------------
        # AVERAGE
        # ----------------------------------------------------

        db.CheckConstraint(
            "average >= 0 AND average <= 100",
            name="ck_student_result_average"
        ),

        # ----------------------------------------------------
        # SUBJECT COUNTS
        # ----------------------------------------------------

        db.CheckConstraint(
            "subjects_total >= 0",
            name="ck_student_result_subjects_total"
        ),

        db.CheckConstraint(
            "subjects_completed >= 0",
            name="ck_student_result_subjects_completed"
        ),

        db.CheckConstraint(
            "subjects_failed >= 0",
            name="ck_student_result_subjects_failed"
        ),

        # ----------------------------------------------------
        # GPA
        # ----------------------------------------------------

        db.CheckConstraint(
            "gpa IS NULL OR gpa >= 0",
            name="ck_student_result_gpa"
        ),

        # ----------------------------------------------------
        # POSITIONS
        # ----------------------------------------------------

        db.CheckConstraint(
            "institution_position IS NULL OR institution_position > 0",
            name="ck_student_result_institution_position"
        ),

        db.CheckConstraint(
            "branch_position IS NULL OR branch_position > 0",
            name="ck_student_result_branch_position"
        ),

        db.CheckConstraint(
            "program_position IS NULL OR program_position > 0",
            name="ck_student_result_program_position"
        ),

        db.CheckConstraint(
            "class_position IS NULL OR class_position > 0",
            name="ck_student_result_class_position"
        ),

        db.CheckConstraint(
            "section_position IS NULL OR section_position > 0",
            name="ck_student_result_section_position"
        ),

        # ----------------------------------------------------
        # PERFORMANCE INDEXES
        # ----------------------------------------------------

        db.Index(
            "ix_student_results_exam_student",
            "exam_id",
            "student_id"
        ),

        db.Index(
            "ix_student_results_exam_branch",
            "exam_id",
            "branch_id"
        ),

        db.Index(
            "ix_student_results_exam_program",
            "exam_id",
            "program_id"
        ),

        db.Index(
            "ix_student_results_exam_class",
            "exam_id",
            "class_id"
        ),

        db.Index(
            "ix_student_results_exam_section",
            "exam_id",
            "section_id"
        ),

        db.Index(
            "ix_student_results_exam_percentage",
            "exam_id",
            "percentage"
        ),

        db.Index(
            "ix_student_results_exam_positions",
            "exam_id",
            "institution_position",
            "branch_position",
            "program_position",
            "class_position",
            "section_position"
        ),

        db.Index(
            "ix_student_results_academic_term",
            "academic_year_id",
            "term_id"
        ),
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<StudentResult "
            f"id={self.id} "
            f"exam_id={self.exam_id} "
            f"student_id={self.student_id} "
            f"total_marks={self.total_marks} "
            f"percentage={self.percentage} "
            f"grade='{self.grade}' "
            f"result_status='{self.result_status}' "
            f"status='{self.status}'>"
        )



# ============================================================
# ATTENDANCE SESSION MODEL
# PostgreSQL / Neon
# ============================================================

class AttendanceSession(db.Model):

    __tablename__ = "attendance_sessions"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION
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
    # BRANCH
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
    # TEACHER
    # ========================================================

    teacher_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "teachers.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # TEACHER ASSIGNMENT
    # ========================================================

    teacher_subject_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "teacher_subjects.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ACADEMIC YEAR
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
    # CLASS
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
    # SECTION
    # ========================================================

    section_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "sections.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # SUBJECT
    # ========================================================

    subject_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "subjects.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # ATTENDANCE DATE
    # ========================================================

    attendance_date = db.Column(
        db.Date,
        nullable=False,
        index=True
    )

    # ========================================================
    # SESSION TYPE
    # ========================================================

    session_type = db.Column(
        db.String(30),
        nullable=False,
        default="class",
        server_default="class",
        index=True
    )

    # class
    # subject
    # morning
    # afternoon
    # exam
    # other

    # ========================================================
    # PERIOD / LESSON
    # ========================================================

    period = db.Column(
        db.String(50),
        nullable=True
    )

    # Example:
    # Period 1
    # Period 2
    # Morning
    # Afternoon

    # ========================================================
    # STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="open",
        server_default="open",
        index=True
    )

    # open
    # completed
    # locked
    # cancelled

    # ========================================================
    # NOTES
    # ========================================================

    notes = db.Column(
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
        back_populates="attendance_sessions"
    )

    branch = db.relationship(
        "Branch",
        back_populates="attendance_sessions"
    )

    teacher = db.relationship(
        "Teacher",
        back_populates="attendance_sessions"
    )

    teacher_subject = db.relationship(
        "TeacherSubject",
        back_populates="attendance_sessions"
    )

    academic_year = db.relationship(
        "AcademicYear",
        back_populates="attendance_sessions"
    )

    class_ = db.relationship(
        "Class",
        back_populates="attendance_sessions"
    )

    section = db.relationship(
        "Section",
        back_populates="attendance_sessions"
    )

    subject = db.relationship(
        "Subject",
        back_populates="attendance_sessions"
    )

    records = db.relationship(
        "AttendanceRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ========================================================
    # CONSTRAINTS
    # ========================================================

    __table_args__ = (

        db.CheckConstraint(
            "status IN ("
            "'open', "
            "'completed', "
            "'locked', "
            "'cancelled'"
            ")",
            name="ck_attendance_session_status"
        ),

        db.CheckConstraint(
            "session_type IN ("
            "'class', "
            "'subject', "
            "'morning', "
            "'afternoon', "
            "'exam', "
            "'other'"
            ")",
            name="ck_attendance_session_type"
        ),

    )

    def __repr__(self):

        return (
            f"<AttendanceSession "
            f"id={self.id} "
            f"teacher_id={self.teacher_id} "
            f"class_id={self.class_id} "
            f"section_id={self.section_id} "
            f"subject_id={self.subject_id} "
            f"date={self.attendance_date}>"
        )


# ============================================================
# ATTENDANCE RECORD MODEL
# PostgreSQL / Neon
# ============================================================

class AttendanceRecord(db.Model):

    __tablename__ = "attendance_records"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # SESSION
    # ========================================================

    attendance_session_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "attendance_sessions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # STUDENT
    # ========================================================

    student_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "students.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    # ========================================================
    # ENROLLMENT
    # ========================================================

    enrollment_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "student_enrollments.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    # ========================================================
    # ATTENDANCE STATUS
    # ========================================================

    status = db.Column(
        db.String(20),
        nullable=False,
        default="present",
        server_default="present",
        index=True
    )

    # present
    # absent
    # late
    # excused
    # sick
    # leave

    # ========================================================
    # CHECK IN
    # ========================================================

    check_in = db.Column(
        db.DateTime,
        nullable=True
    )

    # ========================================================
    # CHECK OUT
    # ========================================================

    check_out = db.Column(
        db.DateTime,
        nullable=True
    )

    # ========================================================
    # MINUTES LATE
    # ========================================================

    minutes_late = db.Column(
        db.Integer,
        nullable=True
    )

    # ========================================================
    # NOTES
    # ========================================================

    notes = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # MARKED BY
    # ========================================================

    marked_by_teacher_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "teachers.id",
            ondelete="SET NULL"
        ),
        nullable=True,
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

    session = db.relationship(
        "AttendanceSession",
        back_populates="records"
    )

    student = db.relationship(
        "Student",
        back_populates="attendance_records"
    )

    enrollment = db.relationship(
        "StudentEnrollment",
        back_populates="attendance_records"
    )

    marked_by_teacher = db.relationship(
        "Teacher",
        foreign_keys=[marked_by_teacher_id],
        back_populates="marked_attendance"
    )

    # ========================================================
    # CONSTRAINTS
    # ========================================================

    __table_args__ = (

        db.UniqueConstraint(
            "attendance_session_id",
            "student_id",
            name="uq_attendance_session_student"
        ),

        db.CheckConstraint(
            "status IN ("
            "'present', "
            "'absent', "
            "'late', "
            "'excused', "
            "'sick', "
            "'leave'"
            ")",
            name="ck_attendance_record_status"
        ),

        db.CheckConstraint(
            "minutes_late IS NULL OR minutes_late >= 0",
            name="ck_attendance_minutes_late"
        ),

    )

    def __repr__(self):

        return (
            f"<AttendanceRecord "
            f"id={self.id} "
            f"session_id={self.attendance_session_id} "
            f"student_id={self.student_id} "
            f"status={self.status!r}>"
        )








# ============================================================
# SITE SETTINGS MODEL
# PostgreSQL / Neon
# ============================================================

class SiteSettings(db.Model):

    __tablename__ = "site_settings"

    # ========================================================
    # PRIMARY KEY
    # ========================================================

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    # ========================================================
    # INSTITUTION
    #
    # One Institution → One SiteSettings
    # ========================================================

    institution_id = db.Column(
        db.BigInteger,
        db.ForeignKey(
            "institutions.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        unique=True,
        index=True
    )

    # ========================================================
    # OPTIONAL DEFAULT BRANCH
    #
    # Can be used when the site is operating under
    # a specific/default branch.
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
    # GENERAL SITE INFORMATION
    # ========================================================

    site_title = db.Column(
        db.String(200),
        nullable=True
    )

    site_name = db.Column(
        db.String(200),
        nullable=True
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

    website = db.Column(
        db.String(255),
        nullable=True
    )

    country = db.Column(
        db.String(100),
        nullable=True
    )

    state = db.Column(
        db.String(100),
        nullable=True
    )

    city = db.Column(
        db.String(100),
        nullable=True
    )

    address = db.Column(
        db.String(255),
        nullable=True
    )

    # ========================================================
    # BRANDING / LOGOS
    # ========================================================

    main_logo = db.Column(
        db.String(500),
        nullable=True
    )

    sub_logo = db.Column(
        db.String(500),
        nullable=True
    )

    sign_logo = db.Column(
        db.String(500),
        nullable=True
    )

    favicon = db.Column(
        db.String(500),
        nullable=True
    )

    # ========================================================
    # COLORS
    # ========================================================

    primary_color = db.Column(
        db.String(20),
        nullable=False,
        default="#06245f",
        server_default="#06245f"
    )

    secondary_color = db.Column(
        db.String(20),
        nullable=False,
        default="#32b73a",
        server_default="#32b73a"
    )

    accent_color = db.Column(
        db.String(20),
        nullable=False,
        default="#33206f",
        server_default="#33206f"
    )

    # ========================================================
    # ACADEMIC INFORMATION
    # ========================================================

    academic_year = db.Column(
        db.String(50),
        nullable=True
    )

    # ========================================================
    # EXAM CARD / EXAMINATION SETTINGS
    # ========================================================

    exam_title = db.Column(
        db.String(200),
        nullable=True,
        default="STUDENT EXAM CARD"
    )

    exam_subtitle = db.Column(
        db.String(255),
        nullable=True,
        default="EXAMINATION ADMISSION CARD"
    )

    exam_footer = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # CERTIFICATE SETTINGS
    # ========================================================

    certificate_footer = db.Column(
        db.Text,
        nullable=True
    )

    # ========================================================
    # PRINCIPAL / AUTHORIZED PERSON
    # ========================================================

    principal_name = db.Column(
        db.String(150),
        nullable=True
    )

    principal_title = db.Column(
        db.String(100),
        nullable=True,
        default="Principal"
    )

    principal_phone = db.Column(
        db.String(30),
        nullable=True
    )

    principal_email = db.Column(
        db.String(150),
        nullable=True
    )

    principal_signature = db.Column(
        db.String(500),
        nullable=True
    )

    # ========================================================
    # SYSTEM / DISPLAY SETTINGS
    # ========================================================

    timezone = db.Column(
        db.String(100),
        nullable=False,
        default="Africa/Mogadishu",
        server_default="Africa/Mogadishu"
    )

    currency = db.Column(
        db.String(10),
        nullable=False,
        default="USD",
        server_default="USD"
    )

    date_format = db.Column(
        db.String(50),
        nullable=False,
        default="DD/MM/YYYY",
        server_default="DD/MM/YYYY"
    )

    language = db.Column(
        db.String(20),
        nullable=False,
        default="en",
        server_default="en"
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
    # RELATIONSHIPS
    # ========================================================

    institution = db.relationship(
        "Institution",
        back_populates="site_settings"
    )

    branch = db.relationship(
        "Branch",
        back_populates="site_settings"
    )

    # ========================================================
    # REPRESENTATION
    # ========================================================

    def __repr__(self):

        return (
            f"<SiteSettings "
            f"id={self.id} "
            f"institution_id={self.institution_id} "
            f"branch_id={self.branch_id} "
            f"site_name={self.site_name!r} "
            f"status={self.status!r}>"
        )











   