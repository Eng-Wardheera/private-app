import csv
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import StringIO
import os
import re
import secrets
import unicodedata
from uuid import uuid4
import uuid
import bcrypt
import cloudinary
from cloudinary import uploader
from flask import Blueprint, abort, current_app, flash, json, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Message
from openpyxl import load_workbook
import pytz
from slugify import slugify
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app import ALLOWED_EXTENSIONS
from app.model import AcademicYear, AssessmentPlan, Branch, Class, Institution, Program, Section, Student, Subject, Teacher, TeacherSubject, Term, User, UserRole, db

bp = Blueprint('main', __name__)


#------------------------------------------
#---- Function: 1 | Func Allowed Files  ---
#------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ============================================================
# PROFILE PHOTO SETTINGS
# ============================================================

ALLOWED_PROFILE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp"
}

MAX_PROFILE_PHOTO_SIZE = 5 * 1024 * 1024



#-----------------------------------------------
#---- Route: 1 | Home - Frontend Template ------
#-----------------------------------------------
@bp.route("/")
def index():

   

    # =====================================================
    # RENDER TEMPLATE
    # =====================================================
    return render_template(
        "frontend/index.html",
     
    )



# ================= LOGIN =================
@bp.route("/login", methods=["GET", "POST"])
def login():

    # ========================================================
    # ALREADY LOGGED IN
    # ========================================================

    if current_user.is_authenticated:

        flash(
            "You are already logged in.",
            "info"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # ========================================================
    # GET
    # ========================================================

    if request.method == "GET":

        return render_template(
            "backend/auth/login.html"
        )

    # ========================================================
    # FORM DATA
    # ========================================================

    username_or_email = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    # ========================================================
    # VALIDATION
    # ========================================================

    if not username_or_email:

        flash(
            "Username or email is required.",
            "danger"
        )

        return render_template(
            "backend/auth/login.html"
        )

    if not password:

        flash(
            "Password is required.",
            "danger"
        )

        return render_template(
            "backend/auth/login.html"
        )

    # ========================================================
    # FIND USER
    # ========================================================

    user = User.query.filter(
        db.or_(
            User.username == username_or_email,
            User.email == username_or_email.lower()
        )
    ).first()

    # ========================================================
    # CHECK USER
    # ========================================================

    if not user:

        flash(
            "Invalid username/email or password.",
            "danger"
        )

        return render_template(
            "backend/auth/login.html"
        )

    # ========================================================
    # CHECK PASSWORD
    # ========================================================

    if not user.check_password(password):

        flash(
            "Invalid username/email or password.",
            "danger"
        )

        return render_template(
            "backend/auth/login.html"
        )

    # ========================================================
    # CHECK ACCOUNT STATUS
    # ========================================================

    if not user.status:

        flash(
            "Your account is inactive. "
            "Please contact the administrator.",
            "danger"
        )

        return render_template(
            "backend/auth/login.html"
        )

    # ========================================================
    # CHECK DATABASE AUTH STATUS
    # ========================================================

    if user.auth_status == "login":

        flash(
            "This account is already logged in.",
            "warning"
        )

        return redirect(
            url_for("main.login")
        )

    # ========================================================
    # LOGIN USER
    # ========================================================

    login_user(
        user,
        remember=True
    )

    # ========================================================
    # UPDATE AUTH STATUS
    # ========================================================

    now = datetime.utcnow()

    user.auth_status = "login"

    user.login_time = now

    user.last_active = now

    user.last_seen = now

    # ========================================================
    # GENERATE SESSION TOKEN
    # ========================================================

    user.session_token = secrets.token_hex(32)

    # ========================================================
    # SAVE
    # ========================================================

    try:

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Login update error"
        )

        logout_user()

        flash(
            "Unable to complete login. Please try again.",
            "danger"
        )

        return render_template(
            "backend/auth/login.html"
        )

    # ========================================================
    # SUCCESS MESSAGE
    # ========================================================

    flash(
        f"Welcome back, "
        f"{user.fullname or user.username}!",
        "success"
    )

    # ========================================================
    # REDIRECT DASHBOARD
    # ========================================================

    return redirect(
        url_for("main.dashboard")
    )


# ================= REGISTER =================
@bp.route("/register", methods=["GET", "POST"])
def register():

    # ========================================================
    # ALREADY LOGGED IN
    # ========================================================

    if current_user.is_authenticated:

        flash(
            "You are already logged in.",
            "info"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # ========================================================
    # CHECK IF USERS ALREADY EXIST
    # ========================================================
    #
    # First registration only:
    # First user = Superadmin
    #
    # After the first user exists, public registration
    # is disabled.
    # ========================================================

    if User.query.first():

        flash(
            "Registration is currently closed.",
            "warning"
        )

        return redirect(
            url_for("main.login")
        )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM DATA
        # ====================================================

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        fullname = request.form.get(
            "fullname",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ====================================================
        # VALIDATION
        # ====================================================

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        if not email:

            flash(
                "Email is required.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        if not password:

            flash(
                "Password is required.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        # ====================================================
        # CHECK USERNAME
        # ====================================================

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:

            flash(
                "Username already exists.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        # ====================================================
        # CHECK EMAIL
        # ====================================================

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            flash(
                "Email already exists.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        # ====================================================
        # CREATE FIRST USER
        # ====================================================

        user = User(
            username=username,
            email=email,
            fullname=fullname,

            # First and only public registration
            role=UserRole.superadmin.value,

            status=True,
            is_verified=True,
            auth_status="logout"
        )

        # ====================================================
        # PASSWORD
        # ====================================================

        user.set_password(
            password
        )

        # ====================================================
        # SAVE
        # ====================================================

        try:

            db.session.add(
                user
            )

            db.session.commit()

        except Exception as e:

            db.session.rollback()

            current_app.logger.exception(
                "Registration error"
            )

            flash(
                "An error occurred while creating "
                "your account.",
                "danger"
            )

            return render_template(
                "backend/auth/register.html"
            )

        # ====================================================
        # SUCCESS
        # ====================================================

        flash(
            "Registration successful. "
            "Your Superadmin account has been created. "
            "Please login.",
            "success"
        )

        return redirect(
            url_for("main.login")
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/auth/register.html"
    )


@bp.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "backend/home/dashboard.html",
        user=current_user
    )



# ============================================================
# PROFILE PHOTO VALIDATION
# ============================================================

def allowed_profile_photo(filename):

    if not filename:
        return False

    filename = secure_filename(filename)

    if "." not in filename:
        return False

    extension = (
        filename
        .rsplit(".", 1)[1]
        .lower()
    )

    return extension in ALLOWED_PROFILE_EXTENSIONS





# ============================================================
# PROFILE
# ============================================================

@bp.route(
    "/profile",
    methods=["GET", "POST"]
)
@login_required
def profile():

    # ========================================================
    # GET CURRENT USER
    # ========================================================

    user = User.query.get(current_user.id)

    if not user:

        logout_user()

        flash(
            "Your account could not be found.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # BASIC INFORMATION
        # ====================================================

        username = (
            request.form.get(
                "username",
                ""
            )
            .strip()
        )

        email = (
            request.form.get(
                "email",
                ""
            )
            .strip()
            .lower()
        )

        fullname = (
            request.form.get(
                "fullname",
                ""
            )
            .strip()
        )

        phone = (
            request.form.get(
                "phone",
                ""
            )
            .strip()
        )

        # ====================================================
        # LOCATION
        # ====================================================

        country = (
            request.form.get(
                "country",
                ""
            )
            .strip()
        )

        city = (
            request.form.get(
                "city",
                ""
            )
            .strip()
        )

        state = (
            request.form.get(
                "state",
                ""
            )
            .strip()
        )

        address = (
            request.form.get(
                "address",
                ""
            )
            .strip()
        )

        # ====================================================
        # BIO
        # ====================================================

        bio = (
            request.form.get(
                "bio",
                ""
            )
            .strip()
        )

        # ====================================================
        # PERSONAL INFORMATION
        # ====================================================

        gender = (
            request.form.get(
                "gender",
                ""
            )
            .strip()
        )

        pob = (
            request.form.get(
                "pob",
                ""
            )
            .strip()
        )

        dob = (
            request.form.get(
                "dob",
                ""
            )
            .strip()
        )

        # ====================================================
        # SOCIAL MEDIA
        # ====================================================

        facebook = (
            request.form.get(
                "facebook",
                ""
            )
            .strip()
            or None
        )

        twitter = (
            request.form.get(
                "twitter",
                ""
            )
            .strip()
            or None
        )

        google = (
            request.form.get(
                "google",
                ""
            )
            .strip()
            or None
        )

        linkedin = (
            request.form.get(
                "linkedin",
                ""
            )
            .strip()
            or None
        )

        skype = (
            request.form.get(
                "skype",
                ""
            )
            .strip()
            or None
        )

        whatsapp = (
            request.form.get(
                "whatsapp",
                ""
            )
            .strip()
            or None
        )

        instagram = (
            request.form.get(
                "instagram",
                ""
            )
            .strip()
            or None
        )

        github = (
            request.form.get(
                "github",
                ""
            )
            .strip()
            or None
        )

        # ====================================================
        # PHOTO VISIBILITY
        # ====================================================

        photo_visibility = (
            request.form.get(
                "photo_visibility",
                "everyone"
            )
            .strip()
            .lower()
        )

        allowed_visibility = {
            "everyone",
            "registered",
            "private"
        }

        if photo_visibility not in allowed_visibility:

            photo_visibility = "everyone"

        # ====================================================
        # PROFILE PHOTO
        # ====================================================

        profile_photo = request.files.get(
            "profile_photo"
        )

        # ====================================================
        # VALIDATION
        # ====================================================

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/profile_view.html",
                user=user
            )

        if not email:

            flash(
                "Email is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/profile_view.html",
                user=user
            )

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/profile_view.html",
                user=user
            )

        # ====================================================
        # USERNAME DUPLICATE
        # ====================================================

        existing_username = (
            User.query
            .filter(
                User.username == username,
                User.id != user.id
            )
            .first()
        )

        if existing_username:

            flash(
                "This username is already in use.",
                "danger"
            )

            return render_template(
                "backend/pages/users/profile_view.html",
                user=user
            )

        # ====================================================
        # EMAIL DUPLICATE
        # ====================================================

        existing_email = (
            User.query
            .filter(
                User.email == email,
                User.id != user.id
            )
            .first()
        )

        if existing_email:

            flash(
                "This email address is already in use.",
                "danger"
            )

            return render_template(
                "backend/pages/users/profile_view.html",
                user=user
            )

        # ====================================================
        # DATE OF BIRTH
        # ====================================================

        parsed_dob = None

        if dob:

            try:

                parsed_dob = datetime.strptime(
                    dob,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                flash(
                    "Invalid date of birth.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/profile_view.html",
                    user=user
                )

        # ====================================================
        # CLOUDINARY PHOTO
        # ====================================================

        new_photo_url = None

        if (
            profile_photo
            and profile_photo.filename
        ):

            # ------------------------------------------------
            # ALLOWED EXTENSIONS
            # ------------------------------------------------

            allowed_extensions = {
                "jpg",
                "jpeg",
                "png",
                "webp"
            }

            original_filename = (
                profile_photo.filename
                .strip()
            )

            extension = ""

            if "." in original_filename:

                extension = (
                    original_filename
                    .rsplit(".", 1)[1]
                    .lower()
                )

            if extension not in allowed_extensions:

                flash(
                    "Only JPG, JPEG, PNG and WEBP images are allowed.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/profile_view.html",
                    user=user
                )

            # ------------------------------------------------
            # FILE SIZE
            # ------------------------------------------------

            try:

                profile_photo.seek(
                    0,
                    os.SEEK_END
                )

                file_size = profile_photo.tell()

                profile_photo.seek(0)

            except Exception:

                flash(
                    "Unable to read the uploaded image.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/profile_view.html",
                    user=user
                )

            # ------------------------------------------------
            # MAX 5 MB
            # ------------------------------------------------

            if file_size > (
                5 * 1024 * 1024
            ):

                flash(
                    "Profile photo must not exceed 5 MB.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/profile_view.html",
                    user=user
                )

            # ------------------------------------------------
            # CLOUDINARY PUBLIC ID
            # ------------------------------------------------

            public_id = (
                "school_management/"
                "profile_photos/"
                f"user_{user.id}"
            )

            # ------------------------------------------------
            # CLOUDINARY UPLOAD
            # ------------------------------------------------

            try:

                upload_result = uploader.upload(
                    profile_photo,
                    public_id=public_id,
                    resource_type="image",
                    overwrite=True,
                    invalidate=True,
                    use_filename=False,
                    unique_filename=False,
                    transformation=[
                        {
                            "width": 600,
                            "height": 600,
                            "crop": "fill",
                            "gravity": "face"
                        }
                    ]
                )

                # --------------------------------------------
                # GET SECURE URL
                # --------------------------------------------

                new_photo_url = (
                    upload_result.get(
                        "secure_url"
                    )
                )

                if not new_photo_url:

                    current_app.logger.error(
                        "Cloudinary upload returned no secure_url: %s",
                        upload_result
                    )

                    flash(
                        "Cloudinary uploaded the image but did not return a valid URL.",
                        "danger"
                    )

                    return render_template(
                        "backend/pages/users/profile_view.html",
                        user=user
                    )

            except Exception as cloudinary_error:

                current_app.logger.exception(
                    "CLOUDINARY PROFILE PHOTO ERROR: %s",
                    cloudinary_error
                )

                flash(
                    "Unable to upload your profile photo. "
                    "Please check your Cloudinary configuration.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/profile_view.html",
                    user=user
                )

        # ====================================================
        # UPDATE BASIC INFORMATION
        # ====================================================

        user.username = username
        user.email = email
        user.fullname = fullname
        user.phone = phone or None

        # ====================================================
        # UPDATE LOCATION
        # ====================================================

        user.country = country or None
        user.city = city or None
        user.state = state or None
        user.address = address or None

        # ====================================================
        # UPDATE BIO
        # ====================================================

        user.bio = bio or None

        # ====================================================
        # UPDATE PERSONAL INFORMATION
        # ====================================================

        user.gender = gender or None
        user.pob = pob or None
        user.dob = parsed_dob

        # ====================================================
        # UPDATE SOCIAL MEDIA
        # ====================================================

        user.facebook = facebook
        user.twitter = twitter
        user.google = google
        user.linkedin = linkedin
        user.skype = skype
        user.whatsapp = whatsapp
        user.instagram = instagram
        user.github = github

        # ====================================================
        # UPDATE PHOTO VISIBILITY
        # ====================================================

        user.photo_visibility = photo_visibility

        # ====================================================
        # UPDATE PHOTO URL
        # ====================================================

        if new_photo_url:

            user.photo = new_photo_url

        # ====================================================
        # UPDATED TIMESTAMP
        # ====================================================

        user.updated_at = datetime.utcnow()

        # ====================================================
        # DATABASE COMMIT
        # ====================================================

        try:

            db.session.commit()

            flash(
                "Your profile has been updated successfully.",
                "success"
            )

            return redirect(
                url_for("main.profile")
            )

        except Exception as database_error:

            db.session.rollback()

            current_app.logger.exception(
                "PROFILE DATABASE UPDATE ERROR: %s",
                database_error
            )

            flash(
                "Unable to update your profile. Please try again.",
                "danger"
            )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/users/profile_view.html",
        user=user
    )


# ============================================================
# ACCOUNT SETTINGS
# ============================================================

@bp.route("/account-settings", methods=["GET", "POST"])
@login_required
def account_settings():

    # --------------------------------------------------------
    # GET CURRENT USER
    # --------------------------------------------------------

    user = User.query.get(int(current_user.get_id()))

    if not user:
        flash("User account could not be found.", "danger")
        return redirect(url_for("main.logout"))

    # --------------------------------------------------------
    # CHANGE PASSWORD
    # --------------------------------------------------------

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        ).strip()

        new_password = request.form.get(
            "new_password",
            ""
        ).strip()

        confirm_password = request.form.get(
            "confirm_password",
            ""
        ).strip()

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not current_password:
            flash(
                "Please enter your current password.",
                "danger"
            )

            return redirect(
                url_for("main.account_settings")
            )

        if not new_password:
            flash(
                "Please enter your new password.",
                "danger"
            )

            return redirect(
                url_for("main.account_settings")
            )

        if not confirm_password:
            flash(
                "Please confirm your new password.",
                "danger"
            )

            return redirect(
                url_for("main.account_settings")
            )

        # ----------------------------------------------------
        # VERIFY CURRENT PASSWORD
        # ----------------------------------------------------

        if not user.check_password(current_password):

            flash(
                "Your current password is incorrect.",
                "danger"
            )

            return redirect(
                url_for("main.account_settings")
            )

        # ----------------------------------------------------
        # NEW PASSWORD MATCH
        # ----------------------------------------------------

        if new_password != confirm_password:

            flash(
                "The new passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("main.account_settings")
            )

        # ----------------------------------------------------
        # PASSWORD LENGTH
        # ----------------------------------------------------

        if len(new_password) < 8:

            flash(
                "Your new password must contain at least 8 characters.",
                "danger"
            )

            return redirect(
                url_for("main.account_settings")
            )

        # ----------------------------------------------------
        # PREVENT SAME PASSWORD
        # ----------------------------------------------------

        if user.check_password(new_password):

            flash(
                "Your new password must be different from your current password.",
                "warning"
            )

            return redirect(
                url_for("main.account_settings")
            )

        # ----------------------------------------------------
        # SET NEW PASSWORD
        # ----------------------------------------------------

        user.set_password(new_password)

        # ----------------------------------------------------
        # UPDATE TIMESTAMP
        # ----------------------------------------------------

        user.updated_at = datetime.utcnow()

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        try:

            db.session.commit()

            flash(
                "Your password has been changed successfully.",
                "success"
            )

        except Exception as e:

            db.session.rollback()

            current_app.logger.exception(
                "Password change failed for user ID %s: %s",
                user.id,
                e
            )

            flash(
                "Unable to change your password. Please try again.",
                "danger"
            )

        return redirect(
            url_for("main.account_settings")
        )

    # --------------------------------------------------------
    # GET REQUEST
    # --------------------------------------------------------

    return render_template(
        "backend/pages/users/account_settings.html",
        user=user
    )



# ============================================================
# ALL USERS
# ============================================================

@bp.route("/all-users")
@login_required
def all_users():

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:
        flash(
            "Authentication required.",
            "danger"
        )
        return redirect(
            url_for("main.login")
        )

    if not current_user.is_superadmin():
        flash(
            "You do not have permission to access all users.",
            "danger"
        )
        return redirect(
            url_for("main.dashboard")
        )


    # ========================================================
    # ALLOWED ROLES
    # ========================================================

    allowed_roles = [
        UserRole.superadmin.value,
        UserRole.school_admin.value,
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value
    ]


    # ========================================================
    # FILTERS
    # ========================================================

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    role = request.args.get(
        "role",
        "",
        type=str
    ).strip().lower()

    status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    verification = request.args.get(
        "verification",
        "",
        type=str
    ).strip().lower()


    # --------------------------------------------------------
    # INSTITUTION FILTER
    # --------------------------------------------------------

    institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()


    # --------------------------------------------------------
    # BRANCH FILTER
    # --------------------------------------------------------

    branch_id = request.args.get(
        "branch_id",
        "",
        type=str
    ).strip()


    # ========================================================
    # SAFE INTEGER CONVERSION
    # ========================================================

    selected_institution_id = None
    selected_branch_id = None


    if institution_id:

        try:
            selected_institution_id = int(
                institution_id
            )

        except (TypeError, ValueError):

            selected_institution_id = None


    if branch_id:

        try:
            selected_branch_id = int(
                branch_id
            )

        except (TypeError, ValueError):

            selected_branch_id = None


    # ========================================================
    # LOAD INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # ========================================================
    # LOAD BRANCHES
    #
    # If institution is selected, only branches belonging
    # to that institution are loaded.
    # ========================================================

    branches_query = Branch.query


    if selected_institution_id:

        branches_query = branches_query.filter(
            Branch.institution_id ==
            selected_institution_id
        )


    branches = (
        branches_query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )


    # ========================================================
    # VALIDATE SELECTED INSTITUTION
    # ========================================================

    selected_institution = None

    if selected_institution_id:

        selected_institution = (
            Institution.query
            .filter(
                Institution.id ==
                selected_institution_id
            )
            .first()
        )

        if not selected_institution:

            selected_institution_id = None
            institution_id = ""

            # Reload all branches because the selected
            # institution was invalid.
            branches = (
                Branch.query
                .order_by(
                    Branch.name.asc()
                )
                .all()
            )


    # ========================================================
    # VALIDATE SELECTED BRANCH
    #
    # Branch must belong to the selected institution.
    # ========================================================

    selected_branch = None

    if selected_branch_id:

        branch_query = Branch.query.filter(
            Branch.id ==
            selected_branch_id
        )

        if selected_institution_id:

            branch_query = branch_query.filter(
                Branch.institution_id ==
                selected_institution_id
            )

        selected_branch = (
            branch_query
            .first()
        )

        if not selected_branch:

            selected_branch_id = None
            branch_id = ""


    # ========================================================
    # PAGINATION
    # ========================================================

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        20,
        type=int
    )


    if page < 1:
        page = 1


    allowed_per_page = [
        10,
        20,
        50,
        100
    ]


    if per_page not in allowed_per_page:
        per_page = 20


    # ========================================================
    # BASE QUERY
    # ========================================================

    query = User.query


    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        search_pattern = f"%{search}%"


        query = query.filter(
            db.or_(

                User.username.ilike(
                    search_pattern
                ),

                User.email.ilike(
                    search_pattern
                ),

                User.fullname.ilike(
                    search_pattern
                ),

                User.phone.ilike(
                    search_pattern
                ),

                User.country.ilike(
                    search_pattern
                ),

                User.city.ilike(
                    search_pattern
                ),

                User.state.ilike(
                    search_pattern
                ),

                User.address.ilike(
                    search_pattern
                )
            )
        )


    # ========================================================
    # ROLE FILTER
    # ========================================================

    if role and role in allowed_roles:

        query = query.filter(
            User.role == role
        )


    # ========================================================
    # STATUS FILTER
    # ========================================================

    if status == "active":

        query = query.filter(
            User.status.is_(True)
        )

    elif status == "inactive":

        query = query.filter(
            User.status.is_(False)
        )


    # ========================================================
    # VERIFICATION FILTER
    # ========================================================

    if verification == "verified":

        query = query.filter(
            User.is_verified.is_(True)
        )

    elif verification == "unverified":

        query = query.filter(
            User.is_verified.is_(False)
        )


    # ========================================================
    # INSTITUTION FILTER
    # ========================================================

    if selected_institution_id:

        query = query.filter(
            User.institution_id ==
            selected_institution_id
        )


    # ========================================================
    # BRANCH FILTER
    # ========================================================

    if selected_branch_id:

        query = query.filter(
            User.branch_id ==
            selected_branch_id
        )


    # ========================================================
    # ORDER
    # ========================================================

    query = query.order_by(
        User.created_at.desc(),
        User.id.desc()
    )


    # ========================================================
    # PAGINATION
    # ========================================================

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )


    users = pagination.items


    # ========================================================
    # GLOBAL USER STATISTICS
    #
    # These are global because superadmin is viewing the
    # complete user management system.
    # ========================================================

    total_users = (
        User.query.count()
    )


    active_users = (
        User.query
        .filter(
            User.status.is_(True)
        )
        .count()
    )


    inactive_users = (
        User.query
        .filter(
            User.status.is_(False)
        )
        .count()
    )


    verified_users = (
        User.query
        .filter(
            User.is_verified.is_(True)
        )
        .count()
    )


    unverified_users = (
        User.query
        .filter(
            User.is_verified.is_(False)
        )
        .count()
    )


    # ========================================================
    # ROLE STATISTICS
    # ========================================================

    superadmin_count = (
        User.query
        .filter(
            User.role ==
            UserRole.superadmin.value
        )
        .count()
    )


    school_admin_count = (
        User.query
        .filter(
            User.role ==
            UserRole.school_admin.value
        )
        .count()
    )


    branch_admin_count = (
        User.query
        .filter(
            User.role ==
            UserRole.branch_admin.value
        )
        .count()
    )


    teacher_count = (
        User.query
        .filter(
            User.role ==
            UserRole.teacher.value
        )
        .count()
    )


    student_count = (
        User.query
        .filter(
            User.role ==
            UserRole.student.value
        )
        .count()
    )


    parent_count = (
        User.query
        .filter(
            User.role ==
            UserRole.parent.value
        )
        .count()
    )


    # ========================================================
    # ONLINE USER COUNT
    #
    # User is considered online when last_active is within
    # the previous 30 seconds.
    # ========================================================

    online_threshold = (
        datetime.utcnow()
        - timedelta(seconds=30)
    )


    online_users = (
        User.query
        .filter(
            User.status.is_(True),
            User.last_active.isnot(None),
            User.last_active >= online_threshold
        )
        .count()
    )


    offline_users = max(
        0,
        total_users - online_users
    )


    # ========================================================
    # FILTERED STATISTICS
    #
    # These statistics change according to the selected
    # institution and branch.
    # ========================================================

    filtered_stats_query = User.query


    if selected_institution_id:

        filtered_stats_query = (
            filtered_stats_query
            .filter(
                User.institution_id ==
                selected_institution_id
            )
        )


    if selected_branch_id:

        filtered_stats_query = (
            filtered_stats_query
            .filter(
                User.branch_id ==
                selected_branch_id
            )
        )


    # --------------------------------------------------------
    # FILTERED TOTAL
    # --------------------------------------------------------

    filtered_total_users = (
        filtered_stats_query.count()
    )


    # --------------------------------------------------------
    # FILTERED ACTIVE
    # --------------------------------------------------------

    filtered_active_users = (
        filtered_stats_query
        .filter(
            User.status.is_(True)
        )
        .count()
    )


    # --------------------------------------------------------
    # FILTERED INACTIVE
    # --------------------------------------------------------

    filtered_inactive_users = (
        filtered_stats_query
        .filter(
            User.status.is_(False)
        )
        .count()
    )


    # --------------------------------------------------------
    # FILTERED VERIFIED
    # --------------------------------------------------------

    filtered_verified_users = (
        filtered_stats_query
        .filter(
            User.is_verified.is_(True)
        )
        .count()
    )


    # --------------------------------------------------------
    # FILTERED UNVERIFIED
    # --------------------------------------------------------

    filtered_unverified_users = (
        filtered_stats_query
        .filter(
            User.is_verified.is_(False)
        )
        .count()
    )


    # ========================================================
    # FILTERED ONLINE USERS
    # ========================================================

    filtered_online_users = (
        filtered_stats_query
        .filter(
            User.status.is_(True),
            User.last_active.isnot(None),
            User.last_active >= online_threshold
        )
        .count()
    )


    filtered_offline_users = max(
        0,
        filtered_total_users -
        filtered_online_users
    )


    # ========================================================
    # FILTERED ROLE STATISTICS
    # ========================================================

    filtered_superadmin_count = (
        filtered_stats_query
        .filter(
            User.role ==
            UserRole.superadmin.value
        )
        .count()
    )


    filtered_school_admin_count = (
        filtered_stats_query
        .filter(
            User.role ==
            UserRole.school_admin.value
        )
        .count()
    )


    filtered_branch_admin_count = (
        filtered_stats_query
        .filter(
            User.role ==
            UserRole.branch_admin.value
        )
        .count()
    )


    filtered_teacher_count = (
        filtered_stats_query
        .filter(
            User.role ==
            UserRole.teacher.value
        )
        .count()
    )


    filtered_student_count = (
        filtered_stats_query
        .filter(
            User.role ==
            UserRole.student.value
        )
        .count()
    )


    filtered_parent_count = (
        filtered_stats_query
        .filter(
            User.role ==
            UserRole.parent.value
        )
        .count()
    )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/users/all_users.html",

        # ----------------------------------------------------
        # CURRENT LOGGED-IN USER
        # ----------------------------------------------------

        user=current_user,


        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        users=users,


        # ----------------------------------------------------
        # PAGINATION
        # ----------------------------------------------------

        pagination=pagination,

        page=page,

        per_page=per_page,


        # ----------------------------------------------------
        # CURRENT FILTERS
        # ----------------------------------------------------

        search=search,

        selected_role=role,

        selected_status=status,

        selected_verification=verification,

        selected_institution_id=(
            selected_institution_id
        ),

        selected_branch_id=(
            selected_branch_id
        ),


        # ----------------------------------------------------
        # INSTITUTIONS / BRANCHES
        # ----------------------------------------------------

        institutions=institutions,

        branches=branches,

        selected_institution=(
            selected_institution
        ),

        selected_branch=(
            selected_branch
        ),


        # ----------------------------------------------------
        # ROLE LIST
        # ----------------------------------------------------

        roles=allowed_roles,


        # ====================================================
        # GLOBAL STATISTICS
        # ====================================================

        total_users=total_users,

        active_users=active_users,

        inactive_users=inactive_users,

        verified_users=verified_users,

        unverified_users=unverified_users,


        # ----------------------------------------------------
        # GLOBAL ONLINE STATISTICS
        # ----------------------------------------------------

        online_users=online_users,

        offline_users=offline_users,


        # ====================================================
        # GLOBAL ROLE STATISTICS
        # ====================================================

        superadmin_count=superadmin_count,

        school_admin_count=school_admin_count,

        branch_admin_count=branch_admin_count,

        teacher_count=teacher_count,

        student_count=student_count,

        parent_count=parent_count,


        # ====================================================
        # FILTERED STATISTICS
        # ====================================================

        filtered_total_users=(
            filtered_total_users
        ),

        filtered_active_users=(
            filtered_active_users
        ),

        filtered_inactive_users=(
            filtered_inactive_users
        ),

        filtered_verified_users=(
            filtered_verified_users
        ),

        filtered_unverified_users=(
            filtered_unverified_users
        ),


        # ----------------------------------------------------
        # FILTERED ONLINE STATISTICS
        # ----------------------------------------------------

        filtered_online_users=(
            filtered_online_users
        ),

        filtered_offline_users=(
            filtered_offline_users
        ),


        # ----------------------------------------------------
        # FILTERED ROLE STATISTICS
        # ----------------------------------------------------

        filtered_superadmin_count=(
            filtered_superadmin_count
        ),

        filtered_school_admin_count=(
            filtered_school_admin_count
        ),

        filtered_branch_admin_count=(
            filtered_branch_admin_count
        ),

        filtered_teacher_count=(
            filtered_teacher_count
        ),

        filtered_student_count=(
            filtered_student_count
        ),

        filtered_parent_count=(
            filtered_parent_count
        )
    )


# ========================================================
# ADD USER
# ========================================================
@bp.route("/add-user", methods=["GET", "POST"])
@login_required
def add_user():

    # ========================================================
    # PERMISSION
    # ========================================================

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to add users.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # ========================================================
    # ALLOWED ROLES
    # ========================================================

    allowed_roles = [
        UserRole.superadmin.value,
        UserRole.school_admin.value,
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value,
    ]

    # ========================================================
    # COUNTRY CALLING CODES
    # ========================================================

    COUNTRY_CALLING_CODES = {

        "AF": "93",
        "AL": "355",
        "DZ": "213",
        "AS": "1684",
        "AD": "376",
        "AO": "244",
        "AI": "1264",
        "AQ": "672",
        "AG": "1268",
        "AR": "54",
        "AM": "374",
        "AW": "297",
        "AU": "61",
        "AT": "43",
        "AZ": "994",

        "BS": "1242",
        "BH": "973",
        "BD": "880",
        "BB": "1246",
        "BY": "375",
        "BE": "32",
        "BZ": "501",
        "BJ": "229",
        "BM": "1441",
        "BT": "975",
        "BO": "591",
        "BQ": "599",
        "BA": "387",
        "BW": "267",
        "BR": "55",
        "IO": "246",
        "VG": "1284",
        "BN": "673",
        "BG": "359",
        "BF": "226",
        "BI": "257",

        "CV": "238",
        "KH": "855",
        "CM": "237",
        "CA": "1",
        "KY": "1345",
        "CF": "236",
        "TD": "235",
        "CL": "56",
        "CN": "86",
        "CX": "61",
        "CC": "61",
        "CO": "57",
        "KM": "269",
        "CG": "242",
        "CD": "243",
        "CK": "682",
        "CR": "506",
        "CI": "225",
        "HR": "385",
        "CU": "53",
        "CW": "599",
        "CY": "357",
        "CZ": "420",

        "DK": "45",
        "DJ": "253",
        "DM": "1767",
        "DO": "1809",

        "EC": "593",
        "EG": "20",
        "SV": "503",
        "GQ": "240",
        "ER": "291",
        "EE": "372",
        "SZ": "268",
        "ET": "251",

        "FK": "500",
        "FO": "298",
        "FJ": "679",
        "FI": "358",
        "FR": "33",
        "GF": "594",
        "PF": "689",

        "GA": "241",
        "GM": "220",
        "GE": "995",
        "DE": "49",
        "GH": "233",
        "GI": "350",
        "GR": "30",
        "GL": "299",
        "GD": "1473",
        "GP": "590",
        "GU": "1671",
        "GT": "502",
        "GG": "44",
        "GN": "224",
        "GW": "245",
        "GY": "592",

        "HT": "509",
        "HN": "504",
        "HK": "852",
        "HU": "36",

        "IS": "354",
        "IN": "91",
        "ID": "62",
        "IR": "98",
        "IQ": "964",
        "IE": "353",
        "IM": "44",
        "IL": "972",
        "IT": "39",

        "JM": "1876",
        "JP": "81",
        "JE": "44",
        "JO": "962",

        "KZ": "7",
        "KE": "254",
        "KI": "686",
        "KP": "850",
        "KR": "82",
        "KW": "965",
        "KG": "996",

        "LA": "856",
        "LV": "371",
        "LB": "961",
        "LS": "266",
        "LR": "231",
        "LY": "218",
        "LI": "423",
        "LT": "370",
        "LU": "352",

        "MO": "853",
        "MG": "261",
        "MW": "265",
        "MY": "60",
        "MV": "960",
        "ML": "223",
        "MT": "356",
        "MH": "692",
        "MQ": "596",
        "MR": "222",
        "MU": "230",
        "YT": "262",
        "MX": "52",
        "FM": "691",
        "MD": "373",
        "MC": "377",
        "MN": "976",
        "ME": "382",
        "MS": "1664",
        "MA": "212",
        "MZ": "258",
        "MM": "95",

        "NA": "264",
        "NR": "674",
        "NP": "977",
        "NL": "31",
        "NC": "687",
        "NZ": "64",
        "NI": "505",
        "NE": "227",
        "NG": "234",
        "NU": "683",
        "NF": "672",
        "MK": "389",
        "MP": "1670",
        "NO": "47",

        "OM": "968",

        "PK": "92",
        "PW": "680",
        "PS": "970",
        "PA": "507",
        "PG": "675",
        "PY": "595",
        "PE": "51",
        "PH": "63",
        "PL": "48",
        "PT": "351",
        "PR": "1787",
        "QA": "974",

        "RE": "262",
        "RO": "40",
        "RU": "7",
        "RW": "250",

        "BL": "590",
        "SH": "290",
        "KN": "1869",
        "LC": "1758",
        "MF": "590",
        "PM": "508",
        "VC": "1784",
        "WS": "685",
        "SM": "378",
        "ST": "239",
        "SA": "966",
        "SN": "221",
        "RS": "381",
        "SC": "248",
        "SL": "232",
        "SG": "65",
        "SX": "1721",
        "SK": "421",
        "SI": "386",
        "SB": "677",
        "SO": "252",
        "ZA": "27",
        "SS": "211",
        "ES": "34",
        "LK": "94",
        "SD": "249",
        "SR": "597",
        "SJ": "47",
        "SE": "46",
        "CH": "41",
        "SY": "963",

        "TW": "886",
        "TJ": "992",
        "TZ": "255",
        "TH": "66",
        "TL": "670",
        "TG": "228",
        "TK": "690",
        "TO": "676",
        "TT": "1868",
        "TN": "216",
        "TR": "90",
        "TM": "993",
        "TC": "1649",
        "TV": "688",

        "UG": "256",
        "UA": "380",
        "AE": "971",
        "GB": "44",
        "US": "1",
        "UY": "598",
        "UZ": "998",

        "VU": "678",
        "VA": "39",
        "VE": "58",
        "VN": "84",
        "VI": "1340",

        "WF": "681",
        "YE": "967",

        "ZM": "260",
        "ZW": "263",
    }

    # ========================================================
    # LOCAL PHONE DIGIT LIMITS
    # ========================================================

    PHONE_DIGIT_LIMITS = {

        "AF": 9,
        "AL": 9,
        "DZ": 9,
        "AD": 6,
        "AO": 9,
        "AR": 10,
        "AM": 8,
        "AU": 9,
        "AT": 10,
        "AZ": 9,

        "BH": 8,
        "BD": 10,
        "BB": 10,
        "BY": 9,
        "BE": 9,
        "BZ": 7,
        "BJ": 8,
        "BM": 10,
        "BT": 8,
        "BO": 8,
        "BA": 8,
        "BW": 8,
        "BR": 11,
        "BN": 7,
        "BG": 9,
        "BF": 8,
        "BI": 8,

        "KH": 9,
        "CM": 9,
        "CA": 10,
        "CV": 7,
        "CF": 8,
        "TD": 8,
        "CL": 9,
        "CN": 11,
        "CO": 10,
        "KM": 7,
        "CG": 9,
        "CD": 9,
        "CR": 8,
        "HR": 9,
        "CU": 8,
        "CY": 8,
        "CZ": 9,

        "DK": 8,
        "DJ": 8,
        "DM": 10,
        "DO": 10,

        "EC": 9,
        "EG": 10,
        "SV": 8,
        "GQ": 9,
        "ER": 7,
        "EE": 7,
        "SZ": 8,
        "ET": 9,

        "FJ": 7,
        "FI": 10,
        "FR": 9,

        "GA": 8,
        "GM": 7,
        "GE": 9,
        "DE": 11,
        "GH": 9,
        "GR": 10,
        "GD": 10,
        "GT": 8,
        "GN": 9,
        "GW": 7,
        "GY": 7,

        "HT": 8,
        "HN": 8,
        "HK": 8,
        "HU": 9,

        "IS": 7,
        "IN": 10,
        "ID": 11,
        "IR": 10,
        "IQ": 10,
        "IE": 9,
        "IL": 9,
        "IT": 10,

        "JM": 10,
        "JP": 10,
        "JO": 9,

        "KZ": 10,
        "KE": 9,
        "KI": 5,
        "KW": 8,
        "KG": 9,

        "LA": 10,
        "LV": 8,
        "LB": 8,
        "LS": 8,
        "LR": 8,
        "LI": 7,
        "LT": 8,
        "LU": 9,

        "MG": 9,
        "MW": 9,
        "MY": 10,
        "MV": 7,
        "ML": 8,
        "MT": 8,
        "MR": 8,
        "MU": 8,
        "MX": 10,
        "MD": 8,
        "MC": 8,
        "MN": 8,
        "ME": 8,
        "MA": 9,
        "MZ": 9,
        "MM": 9,

        "NA": 9,
        "NR": 7,
        "NP": 10,
        "NL": 9,
        "NZ": 9,
        "NI": 8,
        "NE": 8,
        "NG": 10,
        "MK": 8,
        "NO": 8,

        "OM": 8,

        "PK": 10,
        "PW": 7,
        "PA": 8,
        "PG": 8,
        "PY": 9,
        "PE": 9,
        "PH": 10,
        "PL": 9,
        "PT": 9,
        "PR": 10,
        "QA": 8,

        "RO": 9,
        "RU": 10,
        "RW": 9,

        "KN": 10,
        "LC": 10,
        "VC": 10,
        "WS": 7,
        "SM": 10,
        "ST": 7,
        "SA": 9,
        "SN": 9,
        "RS": 9,
        "SC": 7,
        "SL": 8,
        "SG": 8,
        "SK": 9,
        "SI": 8,
        "SB": 7,
        "SO": 9,
        "ZA": 9,
        "SS": 9,
        "ES": 9,
        "LK": 9,
        "SD": 9,
        "SR": 7,
        "SE": 9,
        "CH": 9,
        "SY": 9,

        "TW": 9,
        "TJ": 9,
        "TZ": 9,
        "TH": 9,
        "TL": 8,
        "TG": 8,
        "TO": 7,
        "TT": 10,
        "TN": 8,
        "TR": 10,
        "TM": 8,
        "TC": 10,

        "UG": 9,
        "UA": 9,
        "AE": 9,
        "GB": 10,
        "US": 10,
        "UY": 8,
        "UZ": 9,

        "VU": 7,
        "VA": 10,
        "VE": 10,
        "VN": 10,

        "YE": 9,

        "ZM": 9,
        "ZW": 9,
    }

    DEFAULT_PHONE_DIGIT_LIMIT = 15

    # ========================================================
    # LOAD INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc(),
            Institution.id.asc()
        )
        .all()
    )

    # ========================================================
    # LOAD BRANCHES
    # ========================================================

    def load_branches(institution_id=None):

        if not institution_id:
            return []

        return (
            Branch.query
            .filter(
                Branch.institution_id == institution_id
            )
            .order_by(
                Branch.name.asc(),
                Branch.id.asc()
            )
            .all()
        )

    # ========================================================
    # RENDER FORM
    # ========================================================

    def render_form(branches=None):

        return render_template(
            "backend/pages/users/add_user.html",

            roles=allowed_roles,

            institutions=institutions,

            branches=branches or [],

            user=current_user,

            somalia_regions=somalia_regions
        )

    # ========================================================
    # SOMALIA REGIONS
    # ========================================================

    somalia_regions = {

        "Awdal": [
            "Borama",
            "Baki",
            "Lughaya",
            "Zeila"
        ],

        "Woqooyi Galbeed": [
            "Hargeisa",
            "Berbera",
            "Gabiley",
            "Odweyne"
        ],

        "Togdheer": [
            "Burao",
            "Sheikh",
            "Oodweyne"
        ],

        "Sool": [
            "Las Anod",
            "Taleex",
            "Xudun"
        ],

        "Sanaag": [
            "Erigavo",
            "Badhan",
            "Lasqoray"
        ],

        "Bari": [
            "Bosaso",
            "Qardho",
            "Iskushuban",
            "Caluula"
        ],

        "Nugaal": [
            "Garowe",
            "Eyl",
            "Burtinle"
        ],

        "Mudug": [
            "Galkayo",
            "Hobyo",
            "Jariiban"
        ],

        "Galguduud": [
            "Dhuusamareeb",
            "Abudwaaq",
            "Guriel"
        ],

        "Hiraan": [
            "Beledweyne",
            "Bulo Burte",
            "Jalalaqsi"
        ],

        "Middle Shabelle": [
            "Jowhar",
            "Balcad",
            "Adale"
        ],

        "Banadir": [
            "Mogadishu"
        ],

        "Lower Shabelle": [
            "Marka",
            "Afgooye",
            "Wanlaweyn",
            "Qoryoley"
        ],

        "Bay": [
            "Baidoa",
            "Burhakaba",
            "Diinsoor"
        ],

        "Bakool": [
            "Hudur",
            "Wajid",
            "Rab Dhuure"
        ],

        "Gedo": [
            "Garbaharey",
            "Luuq",
            "Doolow",
            "Bardhere"
        ],

        "Middle Juba": [
            "Bu'aale",
            "Jilib",
            "Sakow"
        ],

        "Lower Juba": [
            "Kismayo",
            "Afmadow",
            "Jamame"
        ]
    }

    # ========================================================
    # GET
    # ========================================================

    if request.method == "GET":

        return render_form([])

    # ========================================================
    # BASIC INFORMATION
    # ========================================================

    fullname = request.form.get(
        "fullname",
        ""
    ).strip()

    username = request.form.get(
        "username",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    # ========================================================
    # ROLE
    # ========================================================

    role = request.form.get(
        "role",
        UserRole.student.value
    ).strip().lower()

    if role not in allowed_roles:

        flash(
            "Invalid user role selected.",
            "danger"
        )

        return render_form([])

    # ========================================================
    # INSTITUTION
    # ========================================================

    institution_id_raw = request.form.get(
        "institution_id",
        ""
    ).strip()

    institution = None
    institution_id = None
    branches = []

    if institution_id_raw:

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            TypeError,
            ValueError
        ):

            flash(
                "Invalid institution selected.",
                "danger"
            )

            return render_form([])

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )

        if institution is None:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_form([])

        branches = load_branches(
            institution.id
        )

    # ========================================================
    # BRANCH
    # ========================================================

    branch_id_raw = request.form.get(
        "branch_id",
        ""
    ).strip()

    branch = None
    branch_id = None

    if branch_id_raw:

        try:

            branch_id = int(
                branch_id_raw
            )

        except (
            TypeError,
            ValueError
        ):

            flash(
                "Invalid branch selected.",
                "danger"
            )

            return render_form(branches)

        branch = (
            Branch.query
            .filter(
                Branch.id == branch_id
            )
            .first()
        )

        if branch is None:

            flash(
                "Selected branch was not found.",
                "danger"
            )

            return render_form(branches)

        if institution is None:

            flash(
                "A branch cannot be selected without "
                "an institution.",
                "danger"
            )

            return render_form(branches)

        if branch.institution_id != institution.id:

            flash(
                "The selected branch does not belong "
                "to the selected institution.",
                "danger"
            )

            return render_form(branches)

    # ========================================================
    # ROLE / HIERARCHY VALIDATION
    # ========================================================

    branch_required_roles = {
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value,
    }

    if role != UserRole.superadmin.value:

        if institution is None:

            flash(
                "Institution is required for this user role.",
                "danger"
            )

            return render_form(branches)

    if role in branch_required_roles:

        if branch is None:

            flash(
                "Branch is required for this user role.",
                "danger"
            )

            return render_form(branches)

    # ========================================================
    # REQUIRED VALIDATION
    # ========================================================

    if not fullname:

        flash(
            "Full name is required.",
            "danger"
        )

        return render_form(branches)

    if not username:

        flash(
            "Username is required.",
            "danger"
        )

        return render_form(branches)

    if len(username) < 3:

        flash(
            "Username must contain at least 3 characters.",
            "danger"
        )

        return render_form(branches)

    if not email:

        flash(
            "Email address is required.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # EMAIL VALIDATION
    # ========================================================

    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):

        flash(
            "Please enter a valid email address.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # PASSWORD
    # ========================================================

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    if not password:

        flash(
            "Password is required.",
            "danger"
        )

        return render_form(branches)

    if len(password) < 6:

        flash(
            "Password must contain at least 6 characters.",
            "danger"
        )

        return render_form(branches)

    if password != confirm_password:

        flash(
            "Password and confirm password do not match.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # PHONE COUNTRY
    # ========================================================

    phone_country_raw = request.form.get(
        "phone_country",
        ""
    ).strip()

    phone_country = ""
    phone_calling_code = ""

    if phone_country_raw:

        normalized_phone_country = (
            phone_country_raw
            .replace(" ", "")
            .replace("-", "")
            .strip()
        )

        iso_candidate = (
            normalized_phone_country.upper()
        )

        # ----------------------------------------------------
        # ISO
        # ----------------------------------------------------

        if iso_candidate in COUNTRY_CALLING_CODES:

            phone_country = iso_candidate

            phone_calling_code = (
                "+"
                + COUNTRY_CALLING_CODES[
                    phone_country
                ]
            )

        else:

            # ------------------------------------------------
            # Legacy calling code
            # ------------------------------------------------

            numeric_candidate = (
                normalized_phone_country
                .lstrip("+")
            )

            if numeric_candidate.isdigit():

                matched_iso = None

                for iso, code in (
                    COUNTRY_CALLING_CODES.items()
                ):

                    if code == numeric_candidate:

                        matched_iso = iso
                        break

                if matched_iso:

                    phone_country = matched_iso

                    phone_calling_code = (
                        "+"
                        + COUNTRY_CALLING_CODES[
                            matched_iso
                        ]
                    )

                else:

                    flash(
                        "Invalid phone country code.",
                        "danger"
                    )

                    return render_form(branches)

            else:

                flash(
                    "Invalid phone country code.",
                    "danger"
                )

                return render_form(branches)

    # ========================================================
    # PHONE
    # ========================================================

    phone_raw = request.form.get(
        "phone",
        ""
    ).strip()

    phone = None

    if phone_raw:

        if not phone_country:

            flash(
                "Please select a phone country.",
                "danger"
            )

            return render_form(branches)

        phone_number = re.sub(
            r"[\s\-\(\)]",
            "",
            phone_raw
        )

        if not phone_number.isdigit():

            flash(
                "Phone number must contain digits only.",
                "danger"
            )

            return render_form(branches)

        max_phone_digits = PHONE_DIGIT_LIMITS.get(
            phone_country,
            DEFAULT_PHONE_DIGIT_LIMIT
        )

        # ----------------------------------------------------
        # Optional local trunk zero
        #
        # 0612345678 -> 612345678
        # ----------------------------------------------------

        if (
            phone_number.startswith("0")
            and len(phone_number) == max_phone_digits + 1
        ):

            phone_number = phone_number[1:]

        # ----------------------------------------------------
        # Maximum length
        # ----------------------------------------------------

        if len(phone_number) > max_phone_digits:

            flash(
                f"Phone number for "
                f"{phone_country} cannot contain "
                f"more than {max_phone_digits} "
                f"local digits.",
                "danger"
            )

            return render_form(branches)

        # ----------------------------------------------------
        # Country code must not be entered twice
        # ----------------------------------------------------

        country_digits = (
            phone_calling_code[1:]
        )

        if phone_number.startswith(
            country_digits
        ):

            flash(
                f"Do not enter {phone_calling_code} "
                "inside the phone number field. "
                "Enter local digits only.",
                "danger"
            )

            return render_form(branches)

        # ----------------------------------------------------
        # SAVE INTERNATIONAL FORMAT
        # ----------------------------------------------------

        phone = (
            phone_calling_code
            + phone_number
        )

    # ========================================================
    # LOCATION
    # ========================================================

    country = request.form.get(
        "country",
        ""
    ).strip()

    state = request.form.get(
        "state",
        ""
    ).strip()

    city = request.form.get(
        "city",
        ""
    ).strip()

    address = request.form.get(
        "address",
        ""
    ).strip()

    if country == "__other__":
        country = ""

    if state == "__other__":
        state = ""

    if city == "__other__":
        city = ""

    # ========================================================
    # OTHER INFORMATION
    # ========================================================

    bio = request.form.get(
        "bio",
        ""
    ).strip()

    gender = request.form.get(
        "gender",
        ""
    ).strip()

    pob = request.form.get(
        "pob",
        ""
    ).strip()

    # ========================================================
    # DATE OF BIRTH
    # ========================================================

    dob = None

    dob_value = request.form.get(
        "dob",
        ""
    ).strip()

    if dob_value:

        try:

            dob = datetime.strptime(
                dob_value,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            flash(
                "Invalid date of birth.",
                "danger"
            )

            return render_form(branches)

    # ========================================================
    # STATUS
    # ========================================================

    raw_status = request.form.get(
        "status",
        "true"
    ).strip().lower()

    if raw_status in {
        "true",
        "1",
        "active",
        "enabled",
        "on",
    }:

        status = True

    elif raw_status in {
        "false",
        "0",
        "inactive",
        "disabled",
        "off",
    }:

        status = False

    else:

        flash(
            "Invalid account status.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # EMAIL VERIFICATION
    # ========================================================

    raw_verified = request.form.get(
        "is_verified",
        "false"
    ).strip().lower()

    if raw_verified in {
        "true",
        "1",
        "verified",
        "yes",
        "on",
    }:

        is_verified = True

    elif raw_verified in {
        "false",
        "0",
        "unverified",
        "no",
        "off",
    }:

        is_verified = False

    else:

        flash(
            "Invalid verification value.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # PHOTO VISIBILITY
    # ========================================================

    photo_visibility = request.form.get(
        "photo_visibility",
        "everyone"
    ).strip().lower()

    if photo_visibility not in {
        "everyone",
        "private",
    }:

        photo_visibility = "everyone"

    # ========================================================
    # DUPLICATE USERNAME
    # ========================================================

    existing_username = (
        User.query
        .filter(
            db.func.lower(
                User.username
            ) == username.lower()
        )
        .first()
    )

    if existing_username:

        flash(
            "This username is already registered.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # DUPLICATE EMAIL
    # ========================================================

    existing_email = (
        User.query
        .filter(
            db.func.lower(
                User.email
            ) == email.lower()
        )
        .first()
    )

    if existing_email:

        flash(
            "This email address is already registered.",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # DUPLICATE PHONE
    # ========================================================

    if phone:

        existing_phone = (
            User.query
            .filter(
                User.phone == phone
            )
            .first()
        )

        if existing_phone:

            flash(
                "This phone number is already registered.",
                "danger"
            )

            return render_form(branches)

    # ========================================================
    # PHOTO FILE
    # ========================================================

    photo_file = request.files.get(
        "photo"
    )

    photo = None
    photo_public_id = None

    # ========================================================
    # CLOUDINARY PHOTO UPLOAD
    # ========================================================

    if photo_file and photo_file.filename:

        allowed_extensions = {
            "jpg",
            "jpeg",
            "png",
            "webp"
        }

        filename = (
            photo_file.filename
            .strip()
            .lower()
        )

        if "." not in filename:

            flash(
                "Invalid photo file.",
                "danger"
            )

            return render_form(branches)

        extension = (
            filename.rsplit(".", 1)[1]
        )

        if extension not in allowed_extensions:

            flash(
                "Invalid photo format. "
                "Use JPG, JPEG, PNG or WEBP.",
                "danger"
            )

            return render_form(branches)

        try:

            # ----------------------------------------------
            # Reset file pointer
            # ----------------------------------------------

            photo_file.stream.seek(0)

            # ----------------------------------------------
            # Cloudinary
            # ----------------------------------------------

            upload_result = (
                cloudinary.uploader.upload(

                    photo_file,

                    folder="users",

                    resource_type="image",

                    unique_filename=True,

                    overwrite=False,

                    use_filename=False,

                    secure=True,

                    quality="auto",

                    fetch_format="auto",

                    transformation=[
                        {
                            "width": 600,
                            "height": 600,
                            "crop": "limit"
                        }
                    ]
                )
            )

            # ----------------------------------------------
            # Secure URL
            # ----------------------------------------------

            photo = (
                upload_result.get(
                    "secure_url"
                )
                or
                upload_result.get(
                    "url"
                )
            )

            # ----------------------------------------------
            # Public ID
            # ----------------------------------------------

            photo_public_id = (
                upload_result.get(
                    "public_id"
                )
            )

            if not photo:

                raise RuntimeError(
                    "Cloudinary did not return "
                    "a valid image URL."
                )

        except Exception as e:

            current_app.logger.exception(
                "Cloudinary upload failed "
                "while creating user."
            )

            flash(
                "Unable to upload the profile photo. "
                "Please try again.",
                "danger"
            )

            return render_form(branches)

    # ========================================================
    # CREATE USER
    # ========================================================

    now = datetime.utcnow()

    try:

        new_user = User(

            # ------------------------------------------------
            # ORGANIZATION
            # ------------------------------------------------

            institution_id=(
                institution.id
                if institution
                else None
            ),

            branch_id=(
                branch.id
                if branch
                else None
            ),

            # ------------------------------------------------
            # BASIC
            # ------------------------------------------------

            fullname=fullname,

            username=username,

            email=email,

            phone=phone,

            # ------------------------------------------------
            # LOCATION
            # ------------------------------------------------

            country=country or None,

            state=state or None,

            city=city or None,

            address=address or None,

            # ------------------------------------------------
            # OTHER
            # ------------------------------------------------

            bio=bio or None,

            gender=gender or None,

            dob=dob,

            pob=pob or None,

            # ------------------------------------------------
            # ROLE
            # ------------------------------------------------

            role=role,

            # ------------------------------------------------
            # STATUS
            # ------------------------------------------------

            status=status,

            is_verified=is_verified,

            # ------------------------------------------------
            # PHOTO
            # ------------------------------------------------

            photo=photo,

            photo_visibility=photo_visibility,

            # ------------------------------------------------
            # AUTH
            # ------------------------------------------------

            auth_status="logout",

            session_token=None,

            login_time=None,

            # ------------------------------------------------
            # ACTIVITY
            # ------------------------------------------------

            last_active=now,

            last_seen=now,

            # ------------------------------------------------
            # TIMESTAMPS
            # ------------------------------------------------

            created_at=now,

            updated_at=now,
        )

        # ====================================================
        # PHONE COUNTRY
        # ====================================================

        if hasattr(
            new_user,
            "phone_country"
        ):

            new_user.phone_country = (
                phone_country or None
            )

        # ====================================================
        # CLOUDINARY PUBLIC ID
        # ====================================================

        if hasattr(
            new_user,
            "photo_public_id"
        ):

            new_user.photo_public_id = (
                photo_public_id
            )

        # ====================================================
        # PASSWORD
        # ====================================================

        new_user.set_password(
            password
        )

        # ====================================================
        # ADD USER
        # ========================================================

        db.session.add(
            new_user
        )

        db.session.commit()

    # ========================================================
    # DATABASE ERROR
    # ========================================================

    except Exception as e:

        db.session.rollback()

        # ----------------------------------------------------
        # If database fails after Cloudinary upload,
        # remove uploaded image so it does not become orphaned.
        # ----------------------------------------------------

        if photo_public_id:

            try:

                cloudinary.uploader.destroy(
                    photo_public_id,
                    resource_type="image"
                )

            except Exception:

                current_app.logger.exception(
                    "Failed to cleanup Cloudinary "
                    "image after database rollback."
                )

        # ----------------------------------------------------
        # Log error
        # ----------------------------------------------------

        current_app.logger.exception(
            "==================================================\n"
            "ERROR CREATING USER\n"
            "=================================================="
        )

        current_app.logger.error(
            "Username: %s",
            username
        )

        current_app.logger.error(
            "Email: %s",
            email
        )

        current_app.logger.error(
            "Role: %s",
            role
        )

        current_app.logger.error(
            "Institution ID: %s",
            institution_id
        )

        current_app.logger.error(
            "Branch ID: %s",
            branch_id
        )

        current_app.logger.error(
            "Phone Country ISO: %s",
            phone_country
        )

        current_app.logger.error(
            "Phone Calling Code: %s",
            phone_calling_code
        )

        current_app.logger.error(
            "Phone: %s",
            phone
        )

        current_app.logger.error(
            "Cloudinary Public ID: %s",
            photo_public_id
        )

        current_app.logger.error(
            "Database exception: %s",
            str(e)
        )

        flash(
            f"Unable to create user: {str(e)}",
            "danger"
        )

        return render_form(branches)

    # ========================================================
    # SUCCESS LOG
    # ========================================================

    current_app.logger.info(
        "=================================================="
    )

    current_app.logger.info(
        "NEW USER CREATED SUCCESSFULLY"
    )

    current_app.logger.info(
        "User ID: %s",
        new_user.id
    )

    current_app.logger.info(
        "Username: %s",
        new_user.username
    )

    current_app.logger.info(
        "Role: %s",
        new_user.role
    )

    current_app.logger.info(
        "Institution ID: %s",
        new_user.institution_id
    )

    current_app.logger.info(
        "Branch ID: %s",
        new_user.branch_id
    )

    current_app.logger.info(
        "Phone Country ISO: %s",
        phone_country
    )

    current_app.logger.info(
        "Phone Calling Code: %s",
        phone_calling_code
    )

    current_app.logger.info(
        "Phone: %s",
        new_user.phone
    )

    current_app.logger.info(
        "Cloudinary Photo: %s",
        new_user.photo
    )

    current_app.logger.info(
        "Cloudinary Public ID: %s",
        photo_public_id
    )

    current_app.logger.info(
        "Created by Superadmin ID: %s",
        current_user.id
    )

    current_app.logger.info(
        "=================================================="
    )

    # ========================================================
    # SUCCESS
    # ========================================================

    flash(
        f"User '{new_user.fullname}' "
        f"was created successfully.",
        "success"
    )

    return redirect(
        url_for(
            "main.all_users"
        )
    )

# ============================================================
# GET BRANCHES BY INSTITUTION
# ============================================================

@bp.route(
    "/get-branches/<int:institution_id>",
    methods=["GET"]
)
@login_required
def get_branches(institution_id):

    # ========================================================
    # PERMISSION
    # ========================================================

    if not current_user.is_superadmin():

        return jsonify({
            "success": False,
            "message": "You do not have permission to view branches.",
            "branches": []
        }), 403


    # ========================================================
    # CHECK INSTITUTION
    # ========================================================

    institution = (
        Institution.query
        .filter(
            Institution.id == institution_id
        )
        .first()
    )

    if not institution:

        return jsonify({
            "success": False,
            "message": "Institution not found.",
            "branches": []
        }), 404


    # ========================================================
    # GET BRANCHES
    # ========================================================

    branches = (
        Branch.query
        .filter(
            Branch.institution_id == institution.id
        )
        .order_by(
            Branch.name.asc(),
            Branch.id.asc()
        )
        .all()
    )


    # ========================================================
    # RESPONSE
    # ========================================================

    return jsonify({
        "success": True,
        "branches": [
            {
                "id": branch.id,
                "name": branch.name
            }
            for branch in branches
        ]
    }), 200




# ============================================================
# FORCE LOGOUT USER
# ============================================================
@bp.route("/force-logout-user/<int:user_id>", methods=["POST"])
@login_required
def force_logout_user(user_id):

    # ========================================================
    # AUTHENTICATION CHECK
    # ========================================================

    if not current_user.is_authenticated:
        return jsonify({
            "success": False,
            "status": "error",
            "message": "Authentication required."
        }), 401

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_superadmin():
        return jsonify({
            "success": False,
            "status": "error",
            "message": (
                "You do not have permission "
                "to force logout users."
            )
        }), 403

    # ========================================================
    # FIND USER
    # ========================================================

    user = User.query.get(user_id)

    if user is None:
        return jsonify({
            "success": False,
            "status": "error",
            "message": "User not found."
        }), 404

    # ========================================================
    # PREVENT SELF FORCE LOGOUT
    # ========================================================

    if user.id == current_user.id:
        return jsonify({
            "success": False,
            "status": "error",
            "message": (
                "You cannot force logout "
                "your own account."
            )
        }), 400

    # ========================================================
    # USER NAME
    # ========================================================

    user_name = (
        user.fullname
        or user.username
        or user.email
        or f"User #{user.id}"
    )

    # ========================================================
    # CHECK CURRENT AUTH STATUS
    # ========================================================

    old_auth_status = (
        user.auth_status
        or "logout"
    )

    already_logged_out = (
        old_auth_status != "login"
        and not user.session_token
        and user.login_time is None
    )

    # ========================================================
    # FORCE LOGOUT
    # ========================================================

    try:

        now = datetime.utcnow()

        user.auth_status = "logout"

        # Invalidate the user's current token
        user.session_token = None

        # Remove login time
        user.login_time = None

        # Update last seen
        user.last_seen = now

        # Update record timestamp
        user.updated_at = now

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error forcing logout. "
            "Target User ID: %s, "
            "Admin ID: %s, "
            "Error: %s",
            user_id,
            current_user.id,
            e
        )

        return jsonify({
            "success": False,
            "status": "error",
            "message": (
                "Unable to force logout this user."
            )
        }), 500

    # ========================================================
    # LOG
    # ========================================================

    current_app.logger.info(
        "User force logout completed. "
        "Target User ID: %s, "
        "Username: %s, "
        "Old Auth Status: %s, "
        "Performed By Superadmin ID: %s",
        user.id,
        user.username,
        old_auth_status,
        current_user.id
    )

    # ========================================================
    # RESPONSE MESSAGE
    # ========================================================

    if already_logged_out:

        message = (
            f"{user_name} is already logged out."
        )

    else:

        message = (
            f"{user_name} has been "
            f"logged out successfully."
        )

    # ========================================================
    # JSON RESPONSE
    # ========================================================

    return jsonify({

        "success": True,

        "status": "success",

        "message": message,

        "user_id": user.id,

        "username": user.username or "",

        "fullname": user.fullname or "",

        "auth_status": "logout",

        "is_online": False,

        "session_token": None,

        "login_time": None,

        "last_seen": (
            user.last_seen.strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if user.last_seen
            else None
        )

    }), 200





# ============================================================
# DELETE USER
# ============================================================
@bp.route("/delete-user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):

    # --------------------------------------------------------
    # PERMISSION
    # --------------------------------------------------------
    if not current_user.is_superadmin():

        return jsonify({
            "status": "error",
            "success": False,
            "message": "You do not have permission to delete users."
        }), 403

    # --------------------------------------------------------
    # FIND USER
    # --------------------------------------------------------
    user = User.query.get(user_id)

    if user is None:

        return jsonify({
            "status": "error",
            "success": False,
            "message": "User not found."
        }), 404

    # --------------------------------------------------------
    # PREVENT SELF DELETE
    # --------------------------------------------------------
    if user.id == current_user.id:

        return jsonify({
            "status": "error",
            "success": False,
            "message": "You cannot delete your own account."
        }), 400

    # --------------------------------------------------------
    # SAVE USER NAME FOR RESPONSE
    # --------------------------------------------------------
    user_name = (
        user.fullname
        or user.username
        or user.email
        or f"User #{user.id}"
    )

    # --------------------------------------------------------
    # DELETE USER
    # --------------------------------------------------------
    try:

        db.session.delete(user)

        db.session.commit()

        current_app.logger.info(
            "User deleted successfully. "
            "Deleted user ID: %s by superadmin ID: %s",
            user_id,
            current_user.id
        )

        return jsonify({
            "status": "success",
            "success": True,
            "message": f"{user_name} has been deleted successfully.",
            "user_id": user_id
        }), 200

    # --------------------------------------------------------
    # DATABASE ERROR
    # --------------------------------------------------------
    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error deleting user ID %s: %s",
            user_id,
            e
        )

        return jsonify({
            "status": "error",
            "success": False,
            "message": (
                "Unable to delete this user. "
                "The user may be connected to other records."
            )
        }), 500



# ============================================================
# EDIT USER
# ============================================================

@bp.route("/edit-user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):

    # ========================================================
    # PERMISSION
    # ========================================================

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to edit users.",
            "danger"
        )

        return redirect(
            url_for("main.all_users")
        )

    # ========================================================
    # GET USER
    # ========================================================

    user = User.query.get_or_404(user_id)

    # ========================================================
    # COUNTRY CALLING CODES
    # ISO -> CALLING CODE
    # ========================================================

    COUNTRY_CALLING_CODES = {

        "AF": "93",
        "AL": "355",
        "DZ": "213",
        "AS": "1684",
        "AD": "376",
        "AO": "244",
        "AI": "1264",
        "AQ": "672",
        "AG": "1268",
        "AR": "54",
        "AM": "374",
        "AW": "297",
        "AU": "61",
        "AT": "43",
        "AZ": "994",
        "BS": "1242",
        "BH": "973",
        "BD": "880",
        "BB": "1246",
        "BY": "375",
        "BE": "32",
        "BZ": "501",
        "BJ": "229",
        "BM": "1441",
        "BT": "975",
        "BO": "591",
        "BA": "387",
        "BW": "267",
        "BR": "55",
        "IO": "246",
        "VG": "1284",
        "BN": "673",
        "BG": "359",
        "BF": "226",
        "BI": "257",
        "KH": "855",
        "CM": "237",
        "CA": "1",
        "CV": "238",
        "KY": "1345",
        "CF": "236",
        "TD": "235",
        "CL": "56",
        "CN": "86",
        "CO": "57",
        "KM": "269",
        "CG": "242",
        "CD": "243",
        "CK": "682",
        "CR": "506",
        "CI": "225",
        "HR": "385",
        "CU": "53",
        "CY": "357",
        "CZ": "420",
        "DK": "45",
        "DJ": "253",
        "DM": "1767",
        "DO": "1809",
        "EC": "593",
        "EG": "20",
        "SV": "503",
        "GQ": "240",
        "ER": "291",
        "EE": "372",
        "SZ": "268",
        "ET": "251",
        "FK": "500",
        "FO": "298",
        "FJ": "679",
        "FI": "358",
        "FR": "33",
        "GF": "594",
        "PF": "689",
        "GA": "241",
        "GM": "220",
        "GE": "995",
        "DE": "49",
        "GH": "233",
        "GI": "350",
        "GR": "30",
        "GL": "299",
        "GD": "1473",
        "GP": "590",
        "GU": "1671",
        "GT": "502",
        "GG": "44",
        "GN": "224",
        "GW": "245",
        "GY": "592",
        "HT": "509",
        "HN": "504",
        "HK": "852",
        "HU": "36",
        "IS": "354",
        "IN": "91",
        "ID": "62",
        "IR": "98",
        "IQ": "964",
        "IE": "353",
        "IM": "44",
        "IL": "972",
        "IT": "39",
        "JM": "1876",
        "JP": "81",
        "JE": "44",
        "JO": "962",
        "KZ": "7",
        "KE": "254",
        "KI": "686",
        "KP": "850",
        "KR": "82",
        "KW": "965",
        "KG": "996",
        "LA": "856",
        "LV": "371",
        "LB": "961",
        "LS": "266",
        "LR": "231",
        "LY": "218",
        "LI": "423",
        "LT": "370",
        "LU": "352",
        "MO": "853",
        "MG": "261",
        "MW": "265",
        "MY": "60",
        "MV": "960",
        "ML": "223",
        "MT": "356",
        "MH": "692",
        "MQ": "596",
        "MR": "222",
        "MU": "230",
        "YT": "262",
        "MX": "52",
        "FM": "691",
        "MD": "373",
        "MC": "377",
        "MN": "976",
        "ME": "382",
        "MS": "1664",
        "MA": "212",
        "MZ": "258",
        "MM": "95",
        "NA": "264",
        "NR": "674",
        "NP": "977",
        "NL": "31",
        "NC": "687",
        "NZ": "64",
        "NI": "505",
        "NE": "227",
        "NG": "234",
        "NU": "683",
        "NF": "672",
        "MK": "389",
        "MP": "1670",
        "NO": "47",
        "OM": "968",
        "PK": "92",
        "PW": "680",
        "PS": "970",
        "PA": "507",
        "PG": "675",
        "PY": "595",
        "PE": "51",
        "PH": "63",
        "PL": "48",
        "PT": "351",
        "PR": "1787",
        "QA": "974",
        "RE": "262",
        "RO": "40",
        "RU": "7",
        "RW": "250",
        "BL": "590",
        "SH": "290",
        "KN": "1869",
        "LC": "1758",
        "MF": "590",
        "PM": "508",
        "VC": "1784",
        "WS": "685",
        "SM": "378",
        "ST": "239",
        "SA": "966",
        "SN": "221",
        "RS": "381",
        "SC": "248",
        "SL": "232",
        "SG": "65",
        "SX": "1721",
        "SK": "421",
        "SI": "386",
        "SB": "677",
        "SO": "252",
        "ZA": "27",
        "SS": "211",
        "ES": "34",
        "LK": "94",
        "SD": "249",
        "SR": "597",
        "SJ": "47",
        "SE": "46",
        "CH": "41",
        "SY": "963",
        "TW": "886",
        "TJ": "992",
        "TZ": "255",
        "TH": "66",
        "TL": "670",
        "TG": "228",
        "TK": "690",
        "TO": "676",
        "TT": "1868",
        "TN": "216",
        "TR": "90",
        "TM": "993",
        "TC": "1649",
        "TV": "688",
        "UG": "256",
        "UA": "380",
        "AE": "971",
        "GB": "44",
        "US": "1",
        "UY": "598",
        "UZ": "998",
        "VU": "678",
        "VA": "39",
        "VE": "58",
        "VN": "84",
        "VI": "1340",
        "WF": "681",
        "YE": "967",
        "ZM": "260",
        "ZW": "263"
    }

    # ========================================================
    # LOCAL PHONE DIGIT LIMITS
    # ========================================================

    PHONE_DIGIT_LIMITS = {

        "SO": 9,
        "KE": 9,
        "ET": 9,
        "UG": 9,
        "TZ": 9,
        "DJ": 8,
        "ER": 7,
        "SD": 9,
        "SS": 9,
        "AE": 9,
        "GB": 10,
        "US": 10,
        "CA": 10,
        "IN": 10,
        "PK": 10,
        "BD": 10,
        "SA": 9,
        "QA": 8,
        "OM": 8,
        "BH": 8,
        "KW": 8,
        "EG": 10,
        "ZA": 9,
        "NG": 10,
        "GH": 9,
        "RW": 9,
        "BI": 8,
        "CM": 9,
        "SN": 9,
        "MA": 9,
        "DZ": 9,
        "TN": 8,
        "TR": 10,
        "DE": 11,
        "FR": 9,
        "IT": 10,
        "ES": 9,
        "NL": 9,
        "BE": 9,
        "SE": 9,
        "NO": 8,
        "DK": 8,
        "FI": 9,
        "AU": 9,
        "NZ": 9,
        "MY": 9,
        "ID": 12,
        "PH": 10,
        "TH": 9,
        "JP": 10,
        "KR": 10,
        "CN": 11,
        "BR": 11,
        "MX": 10
    }

    DEFAULT_PHONE_DIGIT_LIMIT = 15

    # ========================================================
    # ALLOWED ROLES
    # ========================================================

    allowed_roles = [
        UserRole.school_admin.value,
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value,
    ]

    # ========================================================
    # BRANCH LOADER
    # ========================================================

    def load_branches(institution_id):

        if not institution_id:
            return []

        try:
            institution_id = int(institution_id)

        except (TypeError, ValueError):

            return []

        return (
            Branch.query
            .filter(
                Branch.institution_id == institution_id
            )
            .order_by(
                Branch.name.asc(),
                Branch.id.asc()
            )
            .all()
        )

    # ========================================================
    # SOMALIA REGIONS
    # ========================================================

    somalia_regions = {

        "Awdal": [
            "Borama",
            "Baki",
            "Lughaya",
            "Zeila"
        ],

        "Woqooyi Galbeed": [
            "Hargeisa",
            "Berbera",
            "Gabiley",
            "Odweyne"
        ],

        "Togdheer": [
            "Burao",
            "Sheikh",
            "Oodweyne"
        ],

        "Sool": [
            "Las Anod",
            "Taleex",
            "Xudun"
        ],

        "Sanaag": [
            "Erigavo",
            "Badhan",
            "Lasqoray"
        ],

        "Bari": [
            "Bosaso",
            "Qardho",
            "Iskushuban",
            "Caluula"
        ],

        "Nugaal": [
            "Garowe",
            "Eyl",
            "Burtinle"
        ],

        "Mudug": [
            "Galkayo",
            "Hobyo",
            "Jariiban"
        ],

        "Galguduud": [
            "Dhuusamareeb",
            "Abudwaaq",
            "Guriel"
        ],

        "Hiraan": [
            "Beledweyne",
            "Bulo Burte",
            "Jalalaqsi"
        ],

        "Middle Shabelle": [
            "Jowhar",
            "Balcad",
            "Adale"
        ],

        "Banadir": [
            "Mogadishu"
        ],

        "Lower Shabelle": [
            "Marka",
            "Afgooye",
            "Wanlaweyn",
            "Qoryoley"
        ],

        "Bay": [
            "Baidoa",
            "Burhakaba",
            "Diinsoor"
        ],

        "Bakool": [
            "Hudur",
            "Wajid",
            "Rab Dhuure"
        ],

        "Gedo": [
            "Garbaharey",
            "Luuq",
            "Doolow",
            "Bardhere"
        ],

        "Middle Juba": [
            "Bu'aale",
            "Jilib",
            "Sakow"
        ],

        "Lower Juba": [
            "Kismayo",
            "Afmadow",
            "Jamame"
        ]
    }

    # ========================================================
    # RENDER FORM
    # ========================================================

    def render_form(branches=None):

        if branches is None:

            if user.institution_id:

                branches = load_branches(
                    user.institution_id
                )

            else:

                branches = []

        return render_template(
            "backend/pages/users/edit_user.html",

            user=user,

            roles=allowed_roles,

            institutions=(
                Institution.query
                .order_by(
                    Institution.name.asc()
                )
                .all()
            ),

            branches=branches,

            somalia_regions=somalia_regions
        )

    # ========================================================
    # GET
    # ========================================================

    if request.method == "GET":

        return render_form()

    # ========================================================
    # POST
    # ========================================================

    try:

        # ====================================================
        # ROLE
        # ====================================================

        role = (
            request.form.get("role") or ""
        ).strip().lower()

        if role not in allowed_roles:

            flash(
                "Invalid user role.",
                "danger"
            )

            return render_form()

        # ====================================================
        # INSTITUTION
        # ====================================================

        institution_raw = (
            request.form.get("institution_id") or ""
        ).strip()

        institution_id = None

        if institution_raw:

            try:

                institution_id = int(
                    institution_raw
                )

            except (TypeError, ValueError):

                flash(
                    "Invalid institution.",
                    "danger"
                )

                return render_form()

        # ====================================================
        # INSTITUTION REQUIREMENT
        # ====================================================

        if (
            role != UserRole.school_admin.value
            and not institution_id
        ):

            flash(
                "Institution is required for this role.",
                "danger"
            )

            return render_form()

        # ====================================================
        # CHECK INSTITUTION
        # ====================================================

        institution = None

        if institution_id:

            institution = (
                Institution.query
                .filter(
                    Institution.id == institution_id
                )
                .first()
            )

            if not institution:

                flash(
                    "Selected institution does not exist.",
                    "danger"
                )

                return render_form()

        # ====================================================
        # BRANCH
        # ====================================================

        branch_raw = (
            request.form.get("branch_id") or ""
        ).strip()

        branch_id = None

        if branch_raw:

            try:

                branch_id = int(
                    branch_raw
                )

            except (TypeError, ValueError):

                flash(
                    "Invalid branch.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        # ====================================================
        # BRANCH REQUIREMENT
        # ====================================================

        branch_required_roles = [

            UserRole.branch_admin.value,
            UserRole.teacher.value,
            UserRole.student.value,
            UserRole.parent.value,
        ]

        if (
            role in branch_required_roles
            and not branch_id
        ):

            flash(
                "Branch is required for this role.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # CHECK BRANCH
        # ====================================================

        branch = None

        if branch_id:

            branch = (
                Branch.query
                .filter(
                    Branch.id == branch_id,
                    Branch.institution_id == institution_id
                )
                .first()
            )

            if not branch:

                flash(
                    "Selected branch does not belong "
                    "to the selected institution.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        # ====================================================
        # FULL NAME
        # ====================================================

        fullname = (
            request.form.get("fullname") or ""
        ).strip()

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # USERNAME
        # ====================================================

        username = (
            request.form.get("username") or ""
        ).strip()

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        if len(username) < 3:

            flash(
                "Username must be at least 3 characters.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # DUPLICATE USERNAME
        # EXCLUDE CURRENT USER
        # ====================================================

        existing_username = (
            User.query
            .filter(
                User.username == username,
                User.id != user.id
            )
            .first()
        )

        if existing_username:

            flash(
                "Username is already in use.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # EMAIL
        # ====================================================

        email = (
            request.form.get("email") or ""
        ).strip().lower()

        if not email:

            flash(
                "Email is required.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        email_pattern = (
            r"^[A-Za-z0-9._%+-]+@"
            r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        )

        if not re.match(
            email_pattern,
            email
        ):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # DUPLICATE EMAIL
        # ====================================================

        existing_email = (
            User.query
            .filter(
                db.func.lower(User.email) == email,
                User.id != user.id
            )
            .first()
        )

        if existing_email:

            flash(
                "Email is already in use.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # PHONE COUNTRY
        # ====================================================

        phone_country_raw = (
            request.form.get("phone_country") or ""
        ).strip()

        phone_country = None
        phone_calling_code = None

        if phone_country_raw:

            normalized_phone_country = (
                phone_country_raw
                .upper()
                .strip()
            )

            # ----------------------------------------------
            # ISO CODE
            # ----------------------------------------------

            if normalized_phone_country in COUNTRY_CALLING_CODES:

                phone_country = (
                    normalized_phone_country
                )

                phone_calling_code = (
                    "+"
                    + COUNTRY_CALLING_CODES[
                        phone_country
                    ]
                )

            # ----------------------------------------------
            # LEGACY CALLING CODE
            # ----------------------------------------------

            else:

                numeric_code = re.sub(
                    r"\D",
                    "",
                    normalized_phone_country
                )

                if numeric_code:

                    matched_iso = next(
                        (
                            iso
                            for iso, code
                            in COUNTRY_CALLING_CODES.items()
                            if code == numeric_code
                        ),
                        None
                    )

                    if matched_iso:

                        phone_country = matched_iso

                        phone_calling_code = (
                            "+"
                            + numeric_code
                        )

                    else:

                        flash(
                            "Invalid phone country code.",
                            "danger"
                        )

                        return render_form(
                            load_branches(institution_id)
                        )

                else:

                    flash(
                        "Invalid phone country code.",
                        "danger"
                    )

                    return render_form(
                        load_branches(institution_id)
                    )

        # ====================================================
        # PHONE
        # ====================================================

        phone_raw = (
            request.form.get("phone") or ""
        ).strip()

        phone = None

        if phone_raw:

            # ----------------------------------------------
            # PHONE COUNTRY REQUIRED
            # ----------------------------------------------

            if not phone_country:

                flash(
                    "Please select a phone country.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            # ----------------------------------------------
            # REMOVE SPACES / FORMATTING
            # ----------------------------------------------

            phone_number = re.sub(
                r"[\s\-\(\)\.]",
                "",
                phone_raw
            )

            # ----------------------------------------------
            # ONLY DIGITS
            # ----------------------------------------------

            if not phone_number.isdigit():

                flash(
                    "Phone number must contain digits only.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            # ----------------------------------------------
            # LOCAL DIGIT LIMIT
            # ----------------------------------------------

            max_digits = PHONE_DIGIT_LIMITS.get(
                phone_country,
                DEFAULT_PHONE_DIGIT_LIMIT
            )

            # ----------------------------------------------
            # REMOVE OPTIONAL LEADING ZERO
            #
            # Example:
            # 0612345678 -> 612345678
            # ----------------------------------------------

            if (
                phone_number.startswith("0")
                and len(phone_number) == max_digits + 1
            ):

                phone_number = phone_number[1:]

            # ----------------------------------------------
            # COUNTRY CODE INSIDE LOCAL PHONE
            # ----------------------------------------------

            local_calling_code = (
                COUNTRY_CALLING_CODES[
                    phone_country
                ]
            )

            if (
                phone_number.startswith(
                    local_calling_code
                )
                and len(phone_number) > max_digits
            ):

                flash(
                    "Do not enter the country calling code "
                    "inside the phone number.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            # ----------------------------------------------
            # MAXIMUM LENGTH
            # ----------------------------------------------

            if len(phone_number) > max_digits:

                flash(
                    f"Phone number for "
                    f"{phone_country} cannot exceed "
                    f"{max_digits} digits.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            # ----------------------------------------------
            # MINIMUM BASIC VALIDATION
            # ----------------------------------------------

            if len(phone_number) < 4:

                flash(
                    "Please enter a valid phone number.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            # ----------------------------------------------
            # SAVE INTERNATIONAL FORMAT
            #
            # Example:
            # +252612345678
            # ----------------------------------------------

            phone = (
                phone_calling_code
                + phone_number
            )

        # ====================================================
        # DUPLICATE PHONE
        # ====================================================

        if phone:

            existing_phone = (
                User.query
                .filter(
                    User.phone == phone,
                    User.id != user.id
                )
                .first()
            )

            if existing_phone:

                flash(
                    "Phone number is already in use.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        # ====================================================
        # COUNTRY
        # ====================================================

        country = (
            request.form.get("country") or ""
        ).strip()

        if country == "__other__":

            country = ""

        # ====================================================
        # STATE
        # ====================================================

        state = (
            request.form.get("state") or ""
        ).strip()

        if state == "__other__":

            state = ""

        # ====================================================
        # CITY
        # ====================================================

        city = (
            request.form.get("city") or ""
        ).strip()

        if city == "__other__":

            city = ""

        # ====================================================
        # ADDRESS
        # ====================================================

        address = (
            request.form.get("address") or ""
        ).strip()

        # ====================================================
        # BIO
        # ====================================================

        bio = (
            request.form.get("bio") or ""
        ).strip()

        # ====================================================
        # GENDER
        # ====================================================

        gender = (
            request.form.get("gender") or ""
        ).strip()

        if gender == "__other__":

            gender = ""

        if gender not in ["", "Male", "Female"]:

            flash(
                "Invalid gender.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # PLACE OF BIRTH
        #
        # Template:
        # name="place_of_birth"
        # ====================================================

        pob = (
            request.form.get("place_of_birth") or ""
        ).strip()

        # ====================================================
        # DATE OF BIRTH
        #
        # Template:
        # name="date_of_birth"
        # ====================================================

        dob_raw = (
            request.form.get("date_of_birth") or ""
        ).strip()

        dob = None

        if dob_raw:

            try:

                dob = datetime.strptime(
                    dob_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                flash(
                    "Invalid date of birth.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        # ====================================================
        # ACTIVE ACCOUNT
        #
        # Template:
        # name="is_active"
        # checkbox value="1"
        # ====================================================

        is_active = (
            request.form.get("is_active") == "1"
        )

        # ====================================================
        # EMAIL VERIFIED
        #
        # Template:
        # name="email_verified"
        # checkbox value="1"
        # ====================================================

        email_verified = (
            request.form.get("email_verified") == "1"
        )

        # ====================================================
        # PHOTO VISIBILITY
        # ====================================================

        photo_visibility = (
            request.form.get("photo_visibility")
            or getattr(
                user,
                "photo_visibility",
                "everyone"
            )
            or "everyone"
        ).strip().lower()

        if photo_visibility not in [
            "everyone",
            "private"
        ]:

            photo_visibility = "everyone"

        # ====================================================
        # PASSWORD
        # OPTIONAL
        # ====================================================

        password = (
            request.form.get("password") or ""
        )

        confirm_password = (
            request.form.get("confirm_password") or ""
        )

        if password:

            if len(password) < 6:

                flash(
                    "Password must be at least 6 characters.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            if password != confirm_password:

                flash(
                    "Passwords do not match.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        elif confirm_password:

            flash(
                "Please enter a new password first.",
                "danger"
            )

            return render_form(
                load_branches(institution_id)
            )

        # ====================================================
        # PHOTO FILE
        # ====================================================

        photo_file = request.files.get("photo")

        # ====================================================
        # PHOTO VALIDATION
        # ====================================================

        if photo_file and photo_file.filename:

            allowed_extensions = {
                "jpg",
                "jpeg",
                "png",
                "webp"
            }

            filename = (
                photo_file.filename
                .strip()
                .lower()
            )

            if "." not in filename:

                flash(
                    "Invalid photo file.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

            extension = (
                filename.rsplit(".", 1)[1]
            )

            if extension not in allowed_extensions:

                flash(
                    "Invalid photo format. "
                    "Use JPG, JPEG, PNG or WEBP.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        # ====================================================
        # UPDATE BASIC FIELDS
        # ====================================================

        user.institution_id = institution_id
        user.branch_id = branch_id

        user.fullname = fullname
        user.username = username
        user.email = email

        user.phone = phone

        # Save ISO country code if model has phone_country
        if hasattr(user, "phone_country"):

            user.phone_country = phone_country

        user.country = country
        user.state = state
        user.city = city
        user.address = address

        user.bio = bio
        user.gender = gender

        # Template/model compatibility
        if hasattr(user, "dob"):
            user.dob = dob

        if hasattr(user, "date_of_birth"):
            user.date_of_birth = dob

        if hasattr(user, "pob"):
            user.pob = pob

        if hasattr(user, "place_of_birth"):
            user.place_of_birth = pob

        user.role = role
        user.status = is_active
        user.is_verified = email_verified

        if hasattr(user, "photo_visibility"):

            user.photo_visibility = photo_visibility

        # ====================================================
        # PASSWORD
        # ====================================================

        if password:

            user.set_password(password)

        # ====================================================
        # CLOUDINARY PHOTO UPLOAD
        # ====================================================

        if photo_file and photo_file.filename:

            try:

                # ------------------------------------------
                # Make sure stream starts at beginning
                # ------------------------------------------

                photo_file.stream.seek(0)

                # ------------------------------------------
                # Cloudinary upload
                # ------------------------------------------

                upload_result = (
                    cloudinary.uploader.upload(
                        photo_file,
                        folder="users",
                        resource_type="image",
                        unique_filename=True,
                        overwrite=False,
                        use_filename=False,
                        secure=True,
                        quality="auto",
                        fetch_format="auto",
                        transformation=[
                            {
                                "width": 600,
                                "height": 600,
                                "crop": "limit"
                            }
                        ]
                    )
                )

                # ------------------------------------------
                # Get secure URL
                # ------------------------------------------

                cloudinary_url = (
                    upload_result.get("secure_url")
                    or upload_result.get("url")
                )

                if not cloudinary_url:

                    raise RuntimeError(
                        "Cloudinary did not return "
                        "a valid image URL."
                    )

                # ------------------------------------------
                # SAVE PHOTO URL
                # ------------------------------------------

                user.photo = cloudinary_url

                # ------------------------------------------
                # SAVE PUBLIC ID IF AVAILABLE
                # ------------------------------------------

                if hasattr(
                    user,
                    "photo_public_id"
                ):

                    user.photo_public_id = (
                        upload_result.get(
                            "public_id"
                        )
                    )

            except Exception as photo_error:

                db.session.rollback()

                current_app.logger.exception(
                    "Cloudinary upload failed "
                    "for user_id=%s: %s",
                    user.id,
                    photo_error
                )

                flash(
                    "Unable to upload the profile photo. "
                    "Please try again.",
                    "danger"
                )

                return render_form(
                    load_branches(institution_id)
                )

        # ====================================================
        # UPDATED AT
        # ====================================================

        if hasattr(user, "updated_at"):

            user.updated_at = datetime.utcnow()

        # ====================================================
        # SAVE DATABASE
        # ====================================================

        db.session.commit()

        # ====================================================
        # LOG
        # ====================================================

        try:

            current_app.logger.info(
                "User updated successfully: "
                "user_id=%s username=%s edited_by=%s",
                user.id,
                user.username,
                current_user.id
            )

        except Exception:

            pass

        # ====================================================
        # SUCCESS
        # ====================================================

        flash(
            "User updated successfully.",
            "success"
        )

        return redirect(
            url_for("main.all_users")
        )

    # ========================================================
    # DATABASE / UNEXPECTED ERROR
    # ========================================================

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error updating user %s",
            user_id
        )

        flash(
            f"Unable to update user: {str(e)}",
            "danger"
        )

        return render_form(
            load_branches(
                request.form.get(
                    "institution_id"
                )
            )
        )

# ============================================================
# UPDATE SINGLE USER STATUS
# ============================================================

@bp.route("/update-user-status/<int:user_id>", methods=["POST"])
@login_required
def update_user_status(user_id):

    # --------------------------------------------------------
    # PERMISSION
    # --------------------------------------------------------
    if not current_user.is_authenticated:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    if not current_user.is_superadmin():
        return jsonify({
            "success": False,
            "message": "You do not have permission to update user status."
        }), 403

    # --------------------------------------------------------
    # FIND USER
    # --------------------------------------------------------
    user = User.query.get(user_id)

    if user is None:
        return jsonify({
            "success": False,
            "message": "User not found."
        }), 404

    # --------------------------------------------------------
    # PREVENT SELF STATUS CHANGE
    # --------------------------------------------------------
    if user.id == current_user.id:
        return jsonify({
            "success": False,
            "message": "You cannot change your own account status."
        }), 400

    # --------------------------------------------------------
    # GET JSON DATA
    # --------------------------------------------------------
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    raw_status = data.get("status")

    # --------------------------------------------------------
    # VALIDATE STATUS
    # --------------------------------------------------------
    if isinstance(raw_status, bool):

        new_status = raw_status

    elif isinstance(raw_status, int) and raw_status in (0, 1):

        new_status = bool(raw_status)

    elif isinstance(raw_status, str):

        value = raw_status.strip().lower()

        if value in {
            "true",
            "1",
            "active",
            "enabled",
            "on"
        }:
            new_status = True

        elif value in {
            "false",
            "0",
            "inactive",
            "disabled",
            "off"
        }:
            new_status = False

        else:
            return jsonify({
                "success": False,
                "message": "Invalid status value."
            }), 400

    else:

        return jsonify({
            "success": False,
            "message": "Status is required and must be true or false."
        }), 400

    # --------------------------------------------------------
    # OLD STATUS
    # --------------------------------------------------------
    old_status = bool(user.status)

    # --------------------------------------------------------
    # NOTHING TO CHANGE
    # --------------------------------------------------------
    if old_status == new_status:

        return jsonify({
            "success": True,
            "message": (
                "User is already active."
                if new_status
                else "User is already inactive."
            ),
            "user_id": user.id,
            "status": new_status
        }), 200

    # --------------------------------------------------------
    # UPDATE STATUS
    # --------------------------------------------------------
    user.status = new_status
    user.updated_at = datetime.utcnow()

    # --------------------------------------------------------
    # IF DEACTIVATED
    # LOG USER OUT
    # --------------------------------------------------------
    if not new_status:

        user.auth_status = "logout"
        user.session_token = None
        user.login_time = None

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------
    try:

        db.session.commit()

        username = (
            user.fullname
            or user.username
            or user.email
            or f"User #{user.id}"
        )

        if new_status:

            message = (
                f"{username} has been activated successfully."
            )

        else:

            message = (
                f"{username} has been deactivated successfully."
            )

        return jsonify({
            "success": True,
            "message": message,
            "user_id": user.id,
            "status": bool(user.status),
            "old_status": old_status
        }), 200

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error updating user status. User ID: %s",
            user_id
        )

        return jsonify({
            "success": False,
            "message": "An error occurred while updating user status."
        }), 500




# ============================================================
# HELPER
# ============================================================

def _utc_now():
    """
    Return current UTC datetime.
    """
    return datetime.utcnow()


def _get_online_threshold():
    """
    User is considered online when last_active
    is within the last 30 seconds.
    """
    return _utc_now() - timedelta(seconds=30)


def _is_user_online(user):
    """
    Determine whether a user is currently online.
    """

    if not user:
        return False

    if not user.status:
        return False

    if not user.last_active:
        return False

    threshold = _get_online_threshold()

    return user.last_active >= threshold


def _format_last_seen_ago(last_seen):
    """
    Convert last_seen datetime into a human-readable
    relative time.
    """

    if not last_seen:
        return "Never"


    now = _utc_now()


    # Prevent negative values caused by small clock differences.
    seconds = max(
        0,
        int((now - last_seen).total_seconds())
    )


    # Just now
    if seconds < 10:
        return "Just now"


    # Seconds
    if seconds < 60:
        return f"{seconds} seconds ago"


    # Minutes
    minutes = seconds // 60

    if minutes < 60:

        if minutes == 1:
            return "1 minute ago"

        return f"{minutes} minutes ago"


    # Hours
    hours = minutes // 60

    if hours < 24:

        if hours == 1:
            return "1 hour ago"

        return f"{hours} hours ago"


    # Days
    days = hours // 24

    if days == 1:
        return "Yesterday"

    if days < 30:
        return f"{days} days ago"


    # Months
    months = days // 30

    if months == 1:
        return "1 month ago"

    if months < 12:
        return f"{months} months ago"


    # Years
    years = days // 365

    if years == 1:
        return "1 year ago"

    return f"{years} years ago"


def _format_last_active_time(last_active):
    """
    Return formatted UTC datetime.
    The frontend can display this directly.
    """

    if not last_active:
        return "Never"


    return last_active.strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


# ============================================================
# 1. USER HEARTBEAT
# ============================================================

@bp.route("/api/heartbeat", methods=["POST"])
@login_required
def user_heartbeat():

    try:

        now = _utc_now()


        # ----------------------------------------------------
        # Update currently authenticated user
        # ----------------------------------------------------

        current_user.last_active = now
        current_user.last_seen = now

        current_user.auth_status = "login"


        # ----------------------------------------------------
        # Make sure inactive accounts cannot heartbeat
        # ----------------------------------------------------

        if not current_user.status:

            current_user.auth_status = "logout"

            current_user.session_token = None

            current_user.login_time = None

            db.session.commit()

            return jsonify({
                "success": False,
                "message": "Your account is inactive.",
                "is_online": False
            }), 403


        db.session.commit()


        return jsonify({
            "success": True,
            "message": "Heartbeat updated successfully.",
            "user_id": current_user.id,
            "is_online": True,
            "timestamp": now.strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        }), 200


    except Exception as e:

        db.session.rollback()


        current_app.logger.exception(
            "Heartbeat error for user ID %s: %s",
            current_user.id,
            e
        )


        return jsonify({
            "success": False,
            "message": "Unable to update heartbeat."
        }), 500


# ============================================================
# 2. ALL USERS ONLINE STATUS
# ============================================================

@bp.route("/api/online-status", methods=["GET"])
@login_required
def online_status():

    # --------------------------------------------------------
    # Only superadmin can view all users' online status.
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        return jsonify({
            "success": False,
            "message": "You do not have permission to view user status."
        }), 403


    try:

        users = (
            User.query
            .order_by(
                User.last_active.desc(),
                User.id.desc()
            )
            .all()
        )


        threshold = _get_online_threshold()


        result = []


        for user in users:

            is_online = (
                bool(user.status)
                and user.last_active is not None
                and user.last_active >= threshold
            )


            result.append({

                "id": user.id,

                "username": (
                    user.username
                    or ""
                ),

                "fullname": (
                    user.fullname
                    or ""
                ),

                "role": (
                    user.role
                    or ""
                ),

                "is_active": bool(
                    user.status
                ),

                "is_online": bool(
                    is_online
                ),

                "auth_status": (
                    user.auth_status
                    or "logout"
                ),

                "last_active": (
                    user.last_active.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    if user.last_active
                    else None
                ),

                "last_seen": (
                    user.last_seen.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    if user.last_seen
                    else None
                ),

                "last_seen_ago": (
                    "Online"
                    if is_online
                    else _format_last_seen_ago(
                        user.last_seen
                        or user.last_active
                    )
                )

            })


        return jsonify(result), 200


    except Exception as e:

        current_app.logger.exception(
            "Online status API error: %s",
            e
        )


        return jsonify({
            "success": False,
            "message": "Unable to load online status."
        }), 500


# ============================================================
# 3. SINGLE USER LAST ACTIVE
# ============================================================

@bp.route(
    "/api/user-last-active/<int:user_id>",
    methods=["GET"]
)
@login_required
def user_last_active(user_id):

    # --------------------------------------------------------
    # Only superadmin can inspect another user's activity.
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        return jsonify({
            "success": False,
            "message": "You do not have permission to view this user."
        }), 403


    try:

        user = User.query.get(user_id)


        if user is None:

            return jsonify({
                "success": False,
                "message": "User not found."
            }), 404


        is_online = _is_user_online(user)


        last_active = user.last_active


        last_seen = user.last_seen or user.last_active


        return jsonify({

            "success": True,

            "id": user.id,

            "username": (
                user.username
                or ""
            ),

            "fullname": (
                user.fullname
                or ""
            ),

            "role": (
                user.role
                or ""
            ),

            "is_active": bool(
                user.status
            ),

            "is_online": bool(
                is_online
            ),

            "auth_status": (
                user.auth_status
                or "logout"
            ),

            "last_active": (
                last_active.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                if last_active
                else None
            ),

            "formatted_time": (
                _format_last_active_time(
                    last_active
                )
            ),

            "last_seen": (
                last_seen.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                if last_seen
                else None
            ),

            "last_seen_ago": (
                "Online"
                if is_online
                else _format_last_seen_ago(
                    last_seen
                )
            )

        }), 200


    except Exception as e:

        current_app.logger.exception(
            "Single user activity API error. User ID: %s",
            user_id
        )


        return jsonify({
            "success": False,
            "message": "Unable to load user activity."
        }), 500



# ============================================================
# ALL INSTITUTIONS
# ============================================================

@bp.route("/all-institutions")
@login_required
def all_institutions():

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------
    if not current_user.is_authenticated:
        flash(
            "Authentication required.",
            "danger"
        )
        return redirect(
            url_for("main.login")
        )

    if not current_user.is_superadmin():
        flash(
            "You do not have permission to access this page.",
            "danger"
        )
        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------------
    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        10,
        type=int
    )

    # --------------------------------------------------------
    # LIMIT PER PAGE
    # --------------------------------------------------------
    allowed_per_page = [
        10,
        25,
        50,
        100
    ]

    if per_page not in allowed_per_page:
        per_page = 10

    # --------------------------------------------------------
    # BASE QUERY
    # --------------------------------------------------------
    query = Institution.query

    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------
    if search:

        search_pattern = f"%{search}%"

        search_filters = [
            Institution.name.ilike(search_pattern)
        ]

        # Add optional columns only when they exist
        if hasattr(Institution, "short_name"):
            search_filters.append(
                Institution.short_name.ilike(
                    search_pattern
                )
            )

        if hasattr(Institution, "email"):
            search_filters.append(
                Institution.email.ilike(
                    search_pattern
                )
            )

        if hasattr(Institution, "phone"):
            search_filters.append(
                Institution.phone.ilike(
                    search_pattern
                )
            )

        if hasattr(Institution, "city"):
            search_filters.append(
                Institution.city.ilike(
                    search_pattern
                )
            )

        if hasattr(Institution, "country"):
            search_filters.append(
                Institution.country.ilike(
                    search_pattern
                )
            )

        if hasattr(Institution, "code"):
            search_filters.append(
                Institution.code.ilike(
                    search_pattern
                )
            )

        query = query.filter(
            db.or_(*search_filters)
        )

    # --------------------------------------------------------
    # STATUS FILTER
    # --------------------------------------------------------
    if status:

        if hasattr(Institution, "status"):

            query = query.filter(
                db.func.lower(
                    Institution.status
                ) == status
            )

    # --------------------------------------------------------
    # ORDER
    # --------------------------------------------------------
    if hasattr(Institution, "created_at"):

        query = query.order_by(
            Institution.created_at.desc()
        )

    else:

        query = query.order_by(
            Institution.id.desc()
        )

    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------
    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    institutions = pagination.items

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------
    total_institutions = Institution.query.count()

    # Active
    if hasattr(Institution, "status"):

        active_institutions = Institution.query.filter(
            db.func.lower(
                Institution.status
            ) == "active"
        ).count()

        inactive_institutions = Institution.query.filter(
            db.func.lower(
                Institution.status
            ) == "inactive"
        ).count()

        suspended_institutions = Institution.query.filter(
            db.func.lower(
                Institution.status
            ) == "suspended"
        ).count()

    else:

        active_institutions = 0
        inactive_institutions = 0
        suspended_institutions = 0

    # --------------------------------------------------------
    # BRANCH COUNT
    # --------------------------------------------------------
    total_branches = 0

    try:

        total_branches = Branch.query.count()

    except Exception:

        total_branches = 0

    # --------------------------------------------------------
    # USER COUNT
    # --------------------------------------------------------
    total_users = 0

    try:

        total_users = User.query.count()

    except Exception:

        total_users = 0

    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------
    return render_template(
        "backend/pages/institutions/all_institutions.html",

        # Data
        institutions=institutions,
        pagination=pagination,

        # Filters
        search=search,
        selected_status=status,
        per_page=per_page,

        # Statistics
        total_institutions=total_institutions,
        active_institutions=active_institutions,
        inactive_institutions=inactive_institutions,
        suspended_institutions=suspended_institutions,

        # Related statistics
        total_branches=total_branches,
        total_users=total_users,
         user=current_user
    )


# ============================================================
# ADD INSTITUTION
# ============================================================

@bp.route("/add-institution", methods=["GET", "POST"])
@login_required
def add_institution():

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------
    if not current_user.is_authenticated:
        flash(
            "Authentication required.",
            "danger"
        )
        return redirect(
            url_for("main.login")
        )

    if not current_user.is_superadmin():
        flash(
            "You do not have permission to create an institution.",
            "danger"
        )
        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------
    if request.method == "POST":

        try:

            # ------------------------------------------------
            # FORM DATA
            # ------------------------------------------------

            name = request.form.get(
                "name",
                ""
            ).strip()

            short_name = request.form.get(
                "short_name",
                ""
            ).strip()

            code = request.form.get(
                "code",
                ""
            ).strip()

            email = request.form.get(
                "email",
                ""
            ).strip()

            phone = request.form.get(
                "phone",
                ""
            ).strip()

            country = request.form.get(
                "country",
                ""
            ).strip()

            state = request.form.get(
                "state",
                ""
            ).strip()

            city = request.form.get(
                "city",
                ""
            ).strip()

            address = request.form.get(
                "address",
                ""
            ).strip()

            website = request.form.get(
                "website",
                ""
            ).strip()

            description = request.form.get(
                "description",
                ""
            ).strip()

            status = request.form.get(
                "status",
                "active"
            ).strip().lower()

            # ------------------------------------------------
            # VALIDATION
            # ------------------------------------------------

            if not name:

                flash(
                    "Institution name is required.",
                    "danger"
                )

                return render_template(
                    "backend/institutions/add_institution.html"
                )

            # ------------------------------------------------
            # VALID STATUS
            # ------------------------------------------------

            allowed_statuses = {
                "active",
                "inactive",
                "suspended"
            }

            if status not in allowed_statuses:

                status = "active"

            # ------------------------------------------------
            # DUPLICATE NAME
            # ------------------------------------------------

            existing_name = Institution.query.filter(
                db.func.lower(
                    Institution.name
                ) == name.lower()
            ).first()

            if existing_name:

                flash(
                    "An institution with this name already exists.",
                    "danger"
                )

                return render_template(
                    "backend/institutions/add_institution.html"
                )

            # ------------------------------------------------
            # DUPLICATE CODE
            # ------------------------------------------------

            if code and hasattr(
                Institution,
                "code"
            ):

                existing_code = Institution.query.filter(
                    db.func.lower(
                        Institution.code
                    ) == code.lower()
                ).first()

                if existing_code:

                    flash(
                        "An institution with this code already exists.",
                        "danger"
                    )

                    return render_template(
                        "backend/institutions/add_institution.html",
                         user=current_user
                    )

            # ------------------------------------------------
            # CREATE INSTITUTION
            # ------------------------------------------------

            institution = Institution(
                name=name
            )

            # ------------------------------------------------
            # OPTIONAL FIELDS
            # ------------------------------------------------

            if hasattr(
                Institution,
                "short_name"
            ):
                institution.short_name = (
                    short_name or None
                )

            if hasattr(
                Institution,
                "code"
            ):
                institution.code = (
                    code or None
                )

            if hasattr(
                Institution,
                "email"
            ):
                institution.email = (
                    email or None
                )

            if hasattr(
                Institution,
                "phone"
            ):
                institution.phone = (
                    phone or None
                )

            if hasattr(
                Institution,
                "country"
            ):
                institution.country = (
                    country or None
                )

            if hasattr(
                Institution,
                "state"
            ):
                institution.state = (
                    state or None
                )

            if hasattr(
                Institution,
                "city"
            ):
                institution.city = (
                    city or None
                )

            if hasattr(
                Institution,
                "address"
            ):
                institution.address = (
                    address or None
                )

            if hasattr(
                Institution,
                "website"
            ):
                institution.website = (
                    website or None
                )

            if hasattr(
                Institution,
                "description"
            ):
                institution.description = (
                    description or None
                )

            if hasattr(
                Institution,
                "status"
            ):
                institution.status = status

            # ------------------------------------------------
            # SAVE
            # ------------------------------------------------

            db.session.add(institution)
            db.session.commit()

            flash(
                f"Institution '{name}' was created successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.all_institutions"
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to create institution because "
                "some information already exists.",
                "danger"
            )

        except Exception as e:

            db.session.rollback()

            print(
                "ADD INSTITUTION ERROR:",
                e
            )

            flash(
                "An unexpected error occurred while creating "
                "the institution.",
                "danger"
            )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/institutions/add_institution.html"
    )


# ============================================================
# VIEW INSTITUTION
# ============================================================

@bp.route(
    "/view-institution/<int:institution_id>"
)
@login_required
def view_institution(institution_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_authenticated:
        flash(
            "Authentication required.",
            "danger"
        )
        return redirect(
            url_for("main.login")
        )

    if not current_user.is_superadmin():
        flash(
            "You do not have permission to view this institution.",
            "danger"
        )
        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # FIND INSTITUTION
    # --------------------------------------------------------

    institution = Institution.query.get_or_404(
        institution_id
    )

    # --------------------------------------------------------
    # RELATED COUNTS
    # --------------------------------------------------------

    branch_count = 0
    user_count = 0

    try:

        branch_count = Branch.query.filter(
            Branch.institution_id == institution.id
        ).count()

    except Exception as e:

        print(
            "BRANCH COUNT ERROR:",
            e
        )

    try:

        user_count = User.query.filter(
            User.institution_id == institution.id
        ).count()

    except Exception as e:

        print(
            "USER COUNT ERROR:",
            e
        )

    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/institutions/view_institution.html",
        institution=institution,
        branch_count=branch_count,
        user_count=user_count,
         user=current_user
    )


# ============================================================
# EDIT INSTITUTION
# ============================================================

@bp.route(
    "/edit-institution/<int:institution_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_institution(institution_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_authenticated:
        flash(
            "Authentication required.",
            "danger"
        )
        return redirect(
            url_for("main.login")
        )

    if not current_user.is_superadmin():
        flash(
            "You do not have permission to edit this institution.",
            "danger"
        )
        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # FIND INSTITUTION
    # --------------------------------------------------------

    institution = Institution.query.get_or_404(
        institution_id
    )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        try:

            # ------------------------------------------------
            # FORM DATA
            # ------------------------------------------------

            name = request.form.get(
                "name",
                ""
            ).strip()

            short_name = request.form.get(
                "short_name",
                ""
            ).strip()

            code = request.form.get(
                "code",
                ""
            ).strip()

            email = request.form.get(
                "email",
                ""
            ).strip()

            phone = request.form.get(
                "phone",
                ""
            ).strip()

            country = request.form.get(
                "country",
                ""
            ).strip()

            state = request.form.get(
                "state",
                ""
            ).strip()

            city = request.form.get(
                "city",
                ""
            ).strip()

            address = request.form.get(
                "address",
                ""
            ).strip()

            website = request.form.get(
                "website",
                ""
            ).strip()

            description = request.form.get(
                "description",
                ""
            ).strip()

            status = request.form.get(
                "status",
                "active"
            ).strip().lower()

            # ------------------------------------------------
            # VALIDATION
            # ------------------------------------------------

            if not name:

                flash(
                    "Institution name is required.",
                    "danger"
                )

                return render_template(
                    "backend/institutions/edit_institution.html",
                    institution=institution
                )

            # ------------------------------------------------
            # VALID STATUS
            # ------------------------------------------------

            allowed_statuses = {
                "active",
                "inactive",
                "suspended"
            }

            if status not in allowed_statuses:

                status = "active"

            # ------------------------------------------------
            # DUPLICATE NAME
            # ------------------------------------------------

            existing_name = Institution.query.filter(
                db.func.lower(
                    Institution.name
                ) == name.lower(),
                Institution.id != institution.id
            ).first()

            if existing_name:

                flash(
                    "Another institution with this name already exists.",
                    "danger"
                )

                return render_template(
                    "backend/institutions/edit_institution.html",
                    institution=institution
                )

            # ------------------------------------------------
            # DUPLICATE CODE
            # ------------------------------------------------

            if code and hasattr(
                Institution,
                "code"
            ):

                existing_code = Institution.query.filter(
                    db.func.lower(
                        Institution.code
                    ) == code.lower(),
                    Institution.id != institution.id
                ).first()

                if existing_code:

                    flash(
                        "Another institution with this code already exists.",
                        "danger"
                    )

                    return render_template(
                        "backend/institutions/edit_institution.html",
                        institution=institution
                    )

            # ------------------------------------------------
            # UPDATE BASIC INFORMATION
            # ------------------------------------------------

            institution.name = name

            # ------------------------------------------------
            # OPTIONAL FIELDS
            # ------------------------------------------------

            if hasattr(
                Institution,
                "short_name"
            ):
                institution.short_name = (
                    short_name or None
                )

            if hasattr(
                Institution,
                "code"
            ):
                institution.code = (
                    code or None
                )

            if hasattr(
                Institution,
                "email"
            ):
                institution.email = (
                    email or None
                )

            if hasattr(
                Institution,
                "phone"
            ):
                institution.phone = (
                    phone or None
                )

            if hasattr(
                Institution,
                "country"
            ):
                institution.country = (
                    country or None
                )

            if hasattr(
                Institution,
                "state"
            ):
                institution.state = (
                    state or None
                )

            if hasattr(
                Institution,
                "city"
            ):
                institution.city = (
                    city or None
                )

            if hasattr(
                Institution,
                "address"
            ):
                institution.address = (
                    address or None
                )

            if hasattr(
                Institution,
                "website"
            ):
                institution.website = (
                    website or None
                )

            if hasattr(
                Institution,
                "description"
            ):
                institution.description = (
                    description or None
                )

            if hasattr(
                Institution,
                "status"
            ):
                institution.status = status

            # ------------------------------------------------
            # SAVE
            # ------------------------------------------------

            db.session.commit()

            flash(
                f"Institution '{institution.name}' was updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.all_institutions"
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to update institution because "
                "some information already exists.",
                "danger"
            )

        except Exception as e:

            db.session.rollback()

            print(
                "EDIT INSTITUTION ERROR:",
                e
            )

            flash(
                "An unexpected error occurred while updating "
                "the institution.",
                "danger"
            )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/institutions/edit_institution.html",
        institution=institution,
        user=current_user
    )


# ============================================================
# DELETE INSTITUTION
# ============================================================

@bp.route(
    "/delete-institution/<int:institution_id>",
    methods=["POST"]
)
@login_required
def delete_institution(institution_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_authenticated:

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    if not current_user.is_superadmin():

        return jsonify({
            "success": False,
            "message": "You do not have permission to delete institutions."
        }), 403

    # --------------------------------------------------------
    # FIND INSTITUTION
    # --------------------------------------------------------

    institution = Institution.query.get(
        institution_id
    )

    if not institution:

        return jsonify({
            "success": False,
            "message": "Institution not found."
        }), 404

    # --------------------------------------------------------
    # PREVENT UNEXPECTED SELF/OWNER ISSUES
    # --------------------------------------------------------

    institution_name = institution.name

    try:

        # ----------------------------------------------------
        # DELETE
        #
        # Your FK definitions should handle related records
        # according to their ON DELETE rules.
        # ----------------------------------------------------

        db.session.delete(
            institution
        )

        db.session.commit()

        return jsonify({
            "success": True,
            "message": (
                f"Institution '{institution_name}' "
                "was deleted successfully."
            )
        }), 200

    except IntegrityError as e:

        db.session.rollback()

        print(
            "DELETE INSTITUTION INTEGRITY ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": (
                "This institution cannot be deleted because "
                "related records still depend on it. "
                "Please remove or reassign the related records first."
            )
        }), 409

    except Exception as e:

        db.session.rollback()

        print(
            "DELETE INSTITUTION ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": (
                "An unexpected error occurred while deleting "
                "the institution."
            )
        }), 500



# ============================================================
# ALL BRANCHES
# ============================================================

@bp.route("/all-branches")
@login_required
def all_branches():

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )


    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )


    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()


    status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()


    institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()


    page = request.args.get(
        "page",
        1,
        type=int
    )


    per_page = request.args.get(
        "per_page",
        10,
        type=int
    )


    # --------------------------------------------------------
    # VALIDATE PER PAGE
    # --------------------------------------------------------

    allowed_per_page = [
        10,
        25,
        50,
        100
    ]


    if per_page not in allowed_per_page:

        per_page = 10


    # --------------------------------------------------------
    # BASE QUERY
    # --------------------------------------------------------

    query = Branch.query


    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------

    if search:

        search_pattern = f"%{search}%"


        query = query.filter(
            or_(
                Branch.name.ilike(search_pattern),
                Branch.code.ilike(search_pattern),
                Branch.phone.ilike(search_pattern),
                Branch.email.ilike(search_pattern),
                Branch.address.ilike(search_pattern),
                Branch.city.ilike(search_pattern),
                Branch.description.ilike(search_pattern)
            )
        )


    # --------------------------------------------------------
    # STATUS FILTER
    # --------------------------------------------------------

    if status:

        query = query.filter(
            db.func.lower(
                Branch.status
            ) == status
        )


    # --------------------------------------------------------
    # INSTITUTION FILTER
    # --------------------------------------------------------

    if institution_id:

        try:

            institution_id_int = int(
                institution_id
            )

            query = query.filter(
                Branch.institution_id
                == institution_id_int
            )

        except (ValueError, TypeError):

            institution_id = ""


    # --------------------------------------------------------
    # ORDER
    # --------------------------------------------------------

    query = query.order_by(
        Branch.created_at.desc(),
        Branch.id.desc()
    )


    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )


    branches = pagination.items


    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    total_branches = Branch.query.count()


    active_branches = Branch.query.filter(
        db.func.lower(
            Branch.status
        ) == "active"
    ).count()


    inactive_branches = Branch.query.filter(
        db.func.lower(
            Branch.status
        ) == "inactive"
    ).count()


    suspended_branches = Branch.query.filter(
        db.func.lower(
            Branch.status
        ) == "suspended"
    ).count()


    # --------------------------------------------------------
    # INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(Institution.name.asc())
        .all()
    )


    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/branches/all_branches.html",

        branches=branches,

        pagination=pagination,

        institutions=institutions,

        search=search,

        selected_status=status,

        selected_institution_id=institution_id,

        per_page=per_page,

        total_branches=total_branches,

        active_branches=active_branches,

        inactive_branches=inactive_branches,

        suspended_branches=suspended_branches,
        user=current_user
    )

# ============================================================
# ADD BRANCH
# ============================================================


# ============================================================
# BRANCH IMAGE UPLOAD HELPER
# ============================================================
def upload_branch_image(file, folder="branches"):
    """
    Upload one branch image to Cloudinary.

    Cloudinary configuration is expected to be configured
    globally elsewhere in the application.

    Returns:
        secure_url or None

    Raises:
        ValueError for invalid files
        RuntimeError for upload/configuration errors
    """

    # ========================================================
    # NO FILE
    # ========================================================

    if not file:
        return None

    if not file.filename:
        return None


    # ========================================================
    # ALLOWED EXTENSIONS
    # ========================================================

    allowed_extensions = {
        "jpg",
        "jpeg",
        "png",
        "webp",
        "gif"
    }


    filename = file.filename.strip()


    if "." not in filename:

        raise ValueError(
            "Invalid image file."
        )


    extension = (
        filename
        .rsplit(".", 1)[1]
        .lower()
    )


    if extension not in allowed_extensions:

        raise ValueError(
            "Only JPG, JPEG, PNG, WEBP and GIF images are allowed."
        )


    # ========================================================
    # ALLOWED MIME TYPES
    # ========================================================

    allowed_mimetypes = {
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif"
    }


    if file.mimetype not in allowed_mimetypes:

        raise ValueError(
            "Invalid image type."
        )


    # ========================================================
    # UPLOAD TO GLOBAL CLOUDINARY CONFIGURATION
    # ========================================================

    try:

        result = cloudinary.uploader.upload(

            file,

            folder=folder,

            resource_type="image",

            use_filename=True,

            unique_filename=True,

            overwrite=False,

            transformation=[
                {
                    "quality": "auto",
                    "fetch_format": "auto"
                }
            ]
        )


    except Exception as e:

        raise RuntimeError(
            f"Cloudinary upload failed: {str(e)}"
        )


    # ========================================================
    # GET SECURE URL
    # ========================================================

    secure_url = result.get(
        "secure_url"
    )


    if not secure_url:

        raise RuntimeError(
            "Cloudinary upload completed but no secure URL was returned."
        )


    return secure_url


# ============================================================
# ADD BRANCH
# ============================================================

@bp.route(
    "/add-branch",
    methods=["GET", "POST"]
)
@login_required
def add_branch():

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )


    # ========================================================
    # LOAD INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM DATA
        # ====================================================

        institution_id_raw = request.form.get(
            "institution_id",
            "",
            type=str
        ).strip()


        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()


        code = request.form.get(
            "code",
            "",
            type=str
        ).strip()


        phone = request.form.get(
            "phone",
            "",
            type=str
        ).strip()


        email = request.form.get(
            "email",
            "",
            type=str
        ).strip()


        address = request.form.get(
            "address",
            "",
            type=str
        ).strip()


        city = request.form.get(
            "city",
            "",
            type=str
        ).strip()


        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()


        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()


        # ====================================================
        # FILE DATA
        # IMPORTANT:
        # Images come from request.files
        # ====================================================

        main_logo_file = request.files.get(
            "main_logo"
        )


        sub_logo_file = request.files.get(
            "sub_logo"
        )


        signature_photo_file = request.files.get(
            "signature_photo"
        )


        # ====================================================
        # VALIDATE REQUIRED FIELDS
        # ====================================================

        if not institution_id_raw:

            flash(
                "Please select an institution.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        if not name:

            flash(
                "Branch name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        if not code:

            flash(
                "Branch code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CONVERT INSTITUTION ID
        # ====================================================

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid institution selected.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CHECK INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )


        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # NORMALIZE CODE
        # ====================================================

        code = code.upper()


        # ====================================================
        # VALID STATUS
        # ====================================================

        allowed_statuses = {
            "active",
            "inactive",
            "suspended"
        }


        if status not in allowed_statuses:

            status = "active"


        # ====================================================
        # DUPLICATE BRANCH CODE
        #
        # Branch.code is globally UNIQUE
        # ====================================================

        existing_code = (
            Branch.query
            .filter(
                db.func.lower(
                    Branch.code
                ) == code.lower()
            )
            .first()
        )


        if existing_code:

            flash(
                "A branch with this code already exists.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # DUPLICATE BRANCH NAME
        #
        # Same institution cannot have same branch name
        # ====================================================

        existing_name = (
            Branch.query
            .filter(
                Branch.institution_id == institution_id,
                db.func.lower(
                    Branch.name
                ) == name.lower()
            )
            .first()
        )


        if existing_name:

            flash(
                "A branch with this name already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CLOUDINARY UPLOADS
        # ====================================================

        main_logo_url = None
        sub_logo_url = None
        signature_photo_url = None


        try:

            # ------------------------------------------------
            # MAIN LOGO
            # ------------------------------------------------

            if (
                main_logo_file
                and main_logo_file.filename
            ):

                main_logo_url = upload_branch_image(
                    main_logo_file,
                    folder="branches/main_logos"
                )


            # ------------------------------------------------
            # SUB LOGO
            # ------------------------------------------------

            if (
                sub_logo_file
                and sub_logo_file.filename
            ):

                sub_logo_url = upload_branch_image(
                    sub_logo_file,
                    folder="branches/sub_logos"
                )


            # ------------------------------------------------
            # SIGNATURE
            # ------------------------------------------------

            if (
                signature_photo_file
                and signature_photo_file.filename
            ):

                signature_photo_url = upload_branch_image(
                    signature_photo_file,
                    folder="branches/signatures"
                )


        except ValueError as e:

            flash(
                str(e),
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        except Exception as e:

            flash(
                f"Unable to upload branch image: {str(e)}",
                "danger"
            )

            return render_template(
                "backend/pages/branches/add_branch.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CREATE BRANCH
        # ====================================================

        branch = Branch(

            institution_id=institution_id,

            name=name,

            code=code,

            phone=phone or None,

            email=email or None,

            address=address or None,

            city=city or None,

            main_logo=main_logo_url,

            sub_logo=sub_logo_url,

            signature_photo=signature_photo_url,

            status=status,

            description=description or None
        )


        # ====================================================
        # SAVE DATABASE
        # ====================================================

        try:

            db.session.add(
                branch
            )

            db.session.commit()


            flash(
                f"Branch '{branch.name}' has been created successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "main.all_branches"
                )
            )


        # ====================================================
        # DATABASE INTEGRITY ERROR
        # ====================================================

        except IntegrityError:

            db.session.rollback()


            flash(
                "Unable to create branch because one of the unique values already exists.",
                "danger"
            )


        # ====================================================
        # GENERAL ERROR
        # ====================================================

        except Exception as e:

            db.session.rollback()


            flash(
                f"Unable to create branch: {str(e)}",
                "danger"
            )


    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/branches/add_branch.html",
        institutions=institutions,
        user=current_user
    )

# ============================================================
# VIEW BRANCH
# ============================================================

@bp.route(
    "/view-branch/<int:branch_id>"
)
@login_required
def view_branch(branch_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )


    # --------------------------------------------------------
    # GET BRANCH
    # --------------------------------------------------------

    branch = Branch.query.get_or_404(
        branch_id
    )


    # --------------------------------------------------------
    # INSTITUTION
    # --------------------------------------------------------

    institution = Institution.query.get(
        branch.institution_id
    )


    # --------------------------------------------------------
    # USER COUNT
    # --------------------------------------------------------

    try:

        total_users = User.query.filter(
            User.branch_id == branch.id
        ).count()

    except Exception:

        total_users = 0


    # --------------------------------------------------------
    # ACTIVE USERS
    # --------------------------------------------------------

    try:

        active_users = User.query.filter(
            User.branch_id == branch.id,
            db.func.lower(
                User.status
            ) == "active"
        ).count()

    except Exception:

        active_users = 0


    # --------------------------------------------------------
    # INACTIVE USERS
    # --------------------------------------------------------

    try:

        inactive_users = User.query.filter(
            User.branch_id == branch.id,
            db.func.lower(
                User.status
            ) == "inactive"
        ).count()

    except Exception:

        inactive_users = 0


    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/branches/view_branch.html",

        branch=branch,

        institution=institution,

        total_users=total_users,

        active_users=active_users,

        inactive_users=inactive_users,
         user=current_user
    )



# ============================================================
# EDIT BRANCH
# ============================================================

# ============================================================
# EDIT BRANCH
# ============================================================

@bp.route(
    "/edit-branch/<int:branch_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_branch(branch_id):

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )


    # ========================================================
    # GET BRANCH
    # ========================================================

    branch = (
        Branch.query
        .filter(
            Branch.id == branch_id
        )
        .first()
    )


    if not branch:

        flash(
            "Branch not found.",
            "danger"
        )

        return redirect(
            url_for("main.all_branches")
        )


    # ========================================================
    # LOAD INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM DATA
        # ====================================================

        institution_id_raw = request.form.get(
            "institution_id",
            "",
            type=str
        ).strip()


        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()


        code = request.form.get(
            "code",
            "",
            type=str
        ).strip()


        phone = request.form.get(
            "phone",
            "",
            type=str
        ).strip()


        email = request.form.get(
            "email",
            "",
            type=str
        ).strip()


        address = request.form.get(
            "address",
            "",
            type=str
        ).strip()


        city = request.form.get(
            "city",
            "",
            type=str
        ).strip()


        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()


        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()


        # ====================================================
        # FILE DATA
        #
        # IMPORTANT:
        # Images are uploaded through request.files
        # ====================================================

        main_logo_file = request.files.get(
            "main_logo"
        )


        sub_logo_file = request.files.get(
            "sub_logo"
        )


        signature_photo_file = request.files.get(
            "signature_photo"
        )


        # ====================================================
        # REQUIRED FIELD VALIDATION
        # ====================================================

        if not institution_id_raw:

            flash(
                "Please select an institution.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        if not name:

            flash(
                "Branch name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        if not code:

            flash(
                "Branch code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # INSTITUTION ID
        # ====================================================

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid institution selected.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CHECK INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )


        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # NORMALIZE CODE
        # ====================================================

        code = code.upper()


        # ====================================================
        # VALID STATUS
        # ====================================================

        allowed_statuses = {
            "active",
            "inactive",
            "suspended"
        }


        if status not in allowed_statuses:

            status = "active"


        # ====================================================
        # DUPLICATE CODE
        #
        # Branch.code is globally UNIQUE
        #
        # Exclude current branch
        # ====================================================

        existing_code = (
            Branch.query
            .filter(
                db.func.lower(
                    Branch.code
                ) == code.lower(),

                Branch.id != branch.id
            )
            .first()
        )


        if existing_code:

            flash(
                "A branch with this code already exists.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # DUPLICATE NAME
        #
        # Same institution cannot have same name
        #
        # Exclude current branch
        # ====================================================

        existing_name = (
            Branch.query
            .filter(
                Branch.institution_id == institution_id,

                db.func.lower(
                    Branch.name
                ) == name.lower(),

                Branch.id != branch.id
            )
            .first()
        )


        if existing_name:

            flash(
                "A branch with this name already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # NEW IMAGE URLS
        #
        # Existing images are preserved by default.
        # ====================================================

        new_main_logo = None
        new_sub_logo = None
        new_signature_photo = None


        # ====================================================
        # CLOUDINARY UPLOADS
        # ====================================================

        try:

            # ------------------------------------------------
            # MAIN LOGO
            # ------------------------------------------------

            if (
                main_logo_file
                and main_logo_file.filename
            ):

                new_main_logo = upload_branch_image(
                    main_logo_file,
                    folder="branches/main_logos"
                )


            # ------------------------------------------------
            # SUB LOGO
            # ------------------------------------------------

            if (
                sub_logo_file
                and sub_logo_file.filename
            ):

                new_sub_logo = upload_branch_image(
                    sub_logo_file,
                    folder="branches/sub_logos"
                )


            # ------------------------------------------------
            # SIGNATURE PHOTO
            # ------------------------------------------------

            if (
                signature_photo_file
                and signature_photo_file.filename
            ):

                new_signature_photo = upload_branch_image(
                    signature_photo_file,
                    folder="branches/signatures"
                )


        except ValueError as e:

            flash(
                str(e),
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        except Exception as e:

            flash(
                f"Unable to upload branch image: {str(e)}",
                "danger"
            )

            return render_template(
                "backend/pages/branches/edit_branch.html",
                branch=branch,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # UPDATE BRANCH DATA
        # ====================================================

        branch.institution_id = institution_id

        branch.name = name

        branch.code = code

        branch.phone = phone or None

        branch.email = email or None

        branch.address = address or None

        branch.city = city or None

        branch.status = status

        branch.description = (
            description
            or None
        )


        # ====================================================
        # UPDATE MAIN LOGO
        #
        # If a new image was uploaded:
        # replace old URL.
        #
        # If no new image:
        # keep existing URL.
        # ====================================================

        if new_main_logo:

            branch.main_logo = (
                new_main_logo
            )


        # ====================================================
        # UPDATE SUB LOGO
        # ====================================================

        if new_sub_logo:

            branch.sub_logo = (
                new_sub_logo
            )


        # ====================================================
        # UPDATE SIGNATURE PHOTO
        # ====================================================

        if new_signature_photo:

            branch.signature_photo = (
                new_signature_photo
            )


        # ====================================================
        # SAVE
        # ========================================================

        try:

            db.session.commit()


            flash(
                f"Branch '{branch.name}' has been updated successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "main.view_branch",
                    branch_id=branch.id
                )
            )


        # ====================================================
        # INTEGRITY ERROR
        # ====================================================

        except IntegrityError:

            db.session.rollback()


            flash(
                "Unable to update branch because one of the unique values already exists.",
                "danger"
            )


        # ====================================================
        # GENERAL ERROR
        # ====================================================

        except Exception as e:

            db.session.rollback()


            flash(
                f"Unable to update branch: {str(e)}",
                "danger"
            )


    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/branches/edit_branch.html",
        branch=branch,
        institutions=institutions,
        user=current_user
    )


# ============================================================
# DELETE BRANCH
# ============================================================

@bp.route(
    "/delete-branch/<int:branch_id>",
    methods=["POST"]
)
@login_required
def delete_branch(branch_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_authenticated:

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401


    if not current_user.is_superadmin():

        return jsonify({
            "success": False,
            "message": "You do not have permission to delete branches."
        }), 403


    # --------------------------------------------------------
    # GET BRANCH
    # --------------------------------------------------------

    branch = Branch.query.get(
        branch_id
    )


    if not branch:

        return jsonify({
            "success": False,
            "message": "Branch not found."
        }), 404


    # --------------------------------------------------------
    # SAVE NAME FOR RESPONSE
    # --------------------------------------------------------

    branch_name = branch.name


    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    try:

        db.session.delete(
            branch
        )

        db.session.commit()


        return jsonify({
            "success": True,
            "message": (
                f"Branch '{branch_name}' "
                "has been deleted successfully."
            )
        }), 200


    except IntegrityError:

        db.session.rollback()


        return jsonify({
            "success": False,
            "message": (
                "This branch cannot be deleted because "
                "related records still depend on it."
            )
        }), 409


    except Exception as e:

        db.session.rollback()


        return jsonify({
            "success": False,
            "message": (
                f"Unable to delete branch: {str(e)}"
            )
        }), 500


# ============================================================
# ALL ACADEMIC YEARS
# ============================================================

@bp.route(
    "/all-academic-years",
    methods=["GET"]
)
@login_required
def all_academic_years():

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )


    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )


    # ========================================================
    # QUERY PARAMETERS
    # ========================================================

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()


    selected_status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()


    selected_institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()


    selected_current = request.args.get(
        "is_current",
        "",
        type=str
    ).strip().lower()


    # ========================================================
    # PER PAGE
    # ========================================================

    allowed_per_page = {
        10,
        25,
        50,
        100
    }


    try:

        per_page = int(
            request.args.get(
                "per_page",
                25
            )
        )

    except (
        ValueError,
        TypeError
    ):

        per_page = 25


    if per_page not in allowed_per_page:

        per_page = 25


    # ========================================================
    # PAGE
    # ========================================================

    try:

        page = int(
            request.args.get(
                "page",
                1
            )
        )

    except (
        ValueError,
        TypeError
    ):

        page = 1


    if page < 1:

        page = 1


    # ========================================================
    # BASE QUERY
    # ========================================================

    query = AcademicYear.query


    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        search_pattern = (
            f"%{search}%"
        )


        query = query.filter(

            db.or_(

                AcademicYear.name.ilike(
                    search_pattern
                ),

                AcademicYear.code.ilike(
                    search_pattern
                ),

                AcademicYear.description.ilike(
                    search_pattern
                )

            )

        )


    # ========================================================
    # STATUS FILTER
    # ========================================================

    allowed_statuses = {
        "active",
        "inactive",
        "closed"
    }


    if selected_status in allowed_statuses:

        query = query.filter(
            AcademicYear.status ==
            selected_status
        )

    else:

        selected_status = ""


    # ========================================================
    # INSTITUTION FILTER
    # ========================================================

    institution_filter_id = None


    if selected_institution_id:

        try:

            institution_filter_id = int(
                selected_institution_id
            )

        except (
            ValueError,
            TypeError
        ):

            institution_filter_id = None


        if institution_filter_id:

            query = query.filter(
                AcademicYear.institution_id ==
                institution_filter_id
            )

        else:

            selected_institution_id = ""


    # ========================================================
    # CURRENT YEAR FILTER
    # ========================================================

    if selected_current == "current":

        query = query.filter(
            AcademicYear.is_current.is_(True)
        )

    elif selected_current == "not_current":

        query = query.filter(
            AcademicYear.is_current.is_(False)
        )

    else:

        selected_current = ""


    # ========================================================
    # ORDER
    # ========================================================

    query = query.order_by(

        AcademicYear.is_current.desc(),

        AcademicYear.start_date.desc(),

        AcademicYear.created_at.desc(),

        AcademicYear.id.desc()

    )


    # ========================================================
    # PAGINATION
    # ========================================================

    pagination = query.paginate(

        page=page,

        per_page=per_page,

        error_out=False

    )


    academic_years = pagination.items


    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # ========================================================
    # STATISTICS
    # ========================================================

    total_academic_years = (
        AcademicYear.query.count()
    )


    active_academic_years = (
        AcademicYear.query
        .filter(
            AcademicYear.status == "active"
        )
        .count()
    )


    inactive_academic_years = (
        AcademicYear.query
        .filter(
            AcademicYear.status == "inactive"
        )
        .count()
    )


    closed_academic_years = (
        AcademicYear.query
        .filter(
            AcademicYear.status == "closed"
        )
        .count()
    )


    current_academic_years = (
        AcademicYear.query
        .filter(
            AcademicYear.is_current.is_(True)
        )
        .count()
    )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(

        "backend/pages/academic_years/all_academic_years.html",

        academic_years=academic_years,

        pagination=pagination,

        institutions=institutions,

        search=search,

        selected_status=selected_status,

        selected_institution_id=selected_institution_id,

        selected_current=selected_current,

        per_page=per_page,

        total_academic_years=total_academic_years,

        active_academic_years=active_academic_years,

        inactive_academic_years=inactive_academic_years,

        closed_academic_years=closed_academic_years,

        current_academic_years=current_academic_years,

        user=current_user

    )


# ============================================================
# ADD ACADEMIC YEAR
# ============================================================

@bp.route(
    "/add-academic-year",
    methods=["GET", "POST"]
)
@login_required
def add_academic_year():

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )

    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM DATA
        # ====================================================

        institution_id_raw = request.form.get(
            "institution_id",
            "",
            type=str
        ).strip()


        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()


        code = request.form.get(
            "code",
            "",
            type=str
        ).strip()


        start_date_raw = request.form.get(
            "start_date",
            "",
            type=str
        ).strip()


        end_date_raw = request.form.get(
            "end_date",
            "",
            type=str
        ).strip()


        is_current_raw = request.form.get(
            "is_current",
            "false",
            type=str
        ).strip().lower()


        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()


        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()


        # ====================================================
        # REQUIRED FIELDS
        # ====================================================

        if not institution_id_raw:

            flash(
                "Please select an institution.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        if not name:

            flash(
                "Academic year name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        if not code:

            flash(
                "Academic year code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        if not start_date_raw:

            flash(
                "Start date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        if not end_date_raw:

            flash(
                "End date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # INSTITUTION ID
        # ====================================================

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid institution selected.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CHECK INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )


        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # PARSE START DATE
        # ====================================================

        try:

            start_date = datetime.strptime(
                start_date_raw,
                "%Y-%m-%d"
            ).date()

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid start date.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # PARSE END DATE
        # ====================================================

        try:

            end_date = datetime.strptime(
                end_date_raw,
                "%Y-%m-%d"
            ).date()

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid end date.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # DATE VALIDATION
        # ====================================================

        if end_date <= start_date:

            flash(
                "End date must be after the start date.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # NORMALIZE CODE
        # ====================================================

        code = code.upper()


        # ====================================================
        # STATUS
        # ====================================================

        allowed_statuses = {
            "active",
            "inactive",
            "closed"
        }


        if status not in allowed_statuses:

            status = "active"


        # ====================================================
        # IS CURRENT
        # ====================================================

        is_current = (
            is_current_raw
            in {
                "true",
                "1",
                "yes",
                "on"
            }
        )


        # ====================================================
        # DUPLICATE CODE
        #
        # Unique within the same institution
        # ====================================================

        existing_code = (
            AcademicYear.query
            .filter(

                AcademicYear.institution_id ==
                institution_id,

                db.func.lower(
                    AcademicYear.code
                ) == code.lower()

            )
            .first()
        )


        if existing_code:

            flash(
                "An academic year with this code already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # DUPLICATE NAME
        #
        # Unique within the same institution
        # ====================================================

        existing_name = (
            AcademicYear.query
            .filter(

                AcademicYear.institution_id ==
                institution_id,

                db.func.lower(
                    AcademicYear.name
                ) == name.lower()

            )
            .first()
        )


        if existing_name:

            flash(
                "An academic year with this name already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/add_academic_year.html",
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CREATE ACADEMIC YEAR
        # ====================================================

        academic_year = AcademicYear(

            institution_id=institution_id,

            name=name,

            code=code,

            start_date=start_date,

            end_date=end_date,

            is_current=is_current,

            status=status,

            description=description or None

        )


        # ====================================================
        # CURRENT YEAR LOGIC
        #
        # Only one current academic year per institution.
        # ====================================================

        try:

            if is_current:

                (
                    AcademicYear.query
                    .filter(

                        AcademicYear.institution_id ==
                        institution_id,

                        AcademicYear.is_current.is_(True)

                    )
                    .update(

                        {
                            AcademicYear.is_current: False
                        },

                        synchronize_session=False

                    )
                )


            # ------------------------------------------------
            # SAVE
            # ------------------------------------------------

            db.session.add(
                academic_year
            )

            db.session.commit()


            flash(
                f"Academic year '{academic_year.name}' has been created successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "main.all_academic_years"
                )
            )


        except IntegrityError:

            db.session.rollback()


            flash(
                "Unable to create academic year because one of the unique values already exists.",
                "danger"
            )


        except Exception as e:

            db.session.rollback()


            flash(
                f"Unable to create academic year: {str(e)}",
                "danger"
            )


    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/academic_years/add_academic_year.html",
        institutions=institutions,
        user=current_user
    )


# ============================================================
# VIEW ACADEMIC YEAR
# ============================================================

@bp.route(
    "/view-academic-year/<int:academic_year_id>",
    methods=["GET"]
)
@login_required
def view_academic_year(academic_year_id):

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )


    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # GET ACADEMIC YEAR
    # ========================================================

    academic_year = (
        AcademicYear.query
        .filter(
            AcademicYear.id ==
            academic_year_id
        )
        .first()
    )


    if not academic_year:

        flash(
            "Academic year not found.",
            "danger"
        )

        return redirect(
            url_for(
                "main.all_academic_years"
            )
        )


    # ========================================================
    # INSTITUTION
    # ========================================================

    institution = (
        Institution.query
        .filter(
            Institution.id ==
            academic_year.institution_id
        )
        .first()
    )


    # ========================================================
    # OTHER YEARS IN SAME INSTITUTION
    # ========================================================

    institution_years_count = (
        AcademicYear.query
        .filter(
            AcademicYear.institution_id ==
            academic_year.institution_id
        )
        .count()
    )


    institution_current_year = (
        AcademicYear.query
        .filter(

            AcademicYear.institution_id ==
            academic_year.institution_id,

            AcademicYear.is_current.is_(True)

        )
        .first()
    )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(

        "backend/pages/academic_years/view_academic_year.html",

        academic_year=academic_year,

        institution=institution,

        institution_years_count=
            institution_years_count,

        institution_current_year=
            institution_current_year,

        user=current_user

    )


# ============================================================
# EDIT ACADEMIC YEAR
# ============================================================

@bp.route(
    "/edit-academic-year/<int:academic_year_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_academic_year(academic_year_id):

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        flash(
            "Authentication required.",
            "danger"
        )

        return redirect(
            url_for("main.login")
        )

    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # GET ACADEMIC YEAR
    # ========================================================

    academic_year = (
        AcademicYear.query
        .filter(
            AcademicYear.id ==
            academic_year_id
        )
        .first()
    )


    if not academic_year:

        flash(
            "Academic year not found.",
            "danger"
        )

        return redirect(
            url_for(
                "main.all_academic_years"
            )
        )


    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM DATA
        # ====================================================

        institution_id_raw = request.form.get(
            "institution_id",
            "",
            type=str
        ).strip()


        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()


        code = request.form.get(
            "code",
            "",
            type=str
        ).strip()


        start_date_raw = request.form.get(
            "start_date",
            "",
            type=str
        ).strip()


        end_date_raw = request.form.get(
            "end_date",
            "",
            type=str
        ).strip()


        is_current_raw = request.form.get(
            "is_current",
            "false",
            type=str
        ).strip().lower()


        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()


        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()


        # ====================================================
        # REQUIRED FIELDS
        # ====================================================

        if not institution_id_raw:

            flash(
                "Please select an institution.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        if not name:

            flash(
                "Academic year name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        if not code:

            flash(
                "Academic year code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        if not start_date_raw:

            flash(
                "Start date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        if not end_date_raw:

            flash(
                "End date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # INSTITUTION ID
        # ====================================================

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid institution selected.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # CHECK INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )


        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # PARSE START DATE
        # ====================================================

        try:

            start_date = datetime.strptime(
                start_date_raw,
                "%Y-%m-%d"
            ).date()

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid start date.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # PARSE END DATE
        # ====================================================

        try:

            end_date = datetime.strptime(
                end_date_raw,
                "%Y-%m-%d"
            ).date()

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Invalid end date.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # DATE VALIDATION
        # ====================================================

        if end_date <= start_date:

            flash(
                "End date must be after the start date.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # NORMALIZE CODE
        # ====================================================

        code = code.upper()


        # ====================================================
        # STATUS
        # ====================================================

        allowed_statuses = {
            "active",
            "inactive",
            "closed"
        }


        if status not in allowed_statuses:

            status = "active"


        # ====================================================
        # IS CURRENT
        # ====================================================

        is_current = (
            is_current_raw
            in {
                "true",
                "1",
                "yes",
                "on"
            }
        )


        # ====================================================
        # DUPLICATE CODE
        #
        # Exclude current academic year
        # ====================================================

        existing_code = (
            AcademicYear.query
            .filter(

                AcademicYear.institution_id ==
                institution_id,

                db.func.lower(
                    AcademicYear.code
                ) == code.lower(),

                AcademicYear.id !=
                academic_year.id

            )
            .first()
        )


        if existing_code:

            flash(
                "An academic year with this code already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # DUPLICATE NAME
        #
        # Exclude current academic year
        # ====================================================

        existing_name = (
            AcademicYear.query
            .filter(

                AcademicYear.institution_id ==
                institution_id,

                db.func.lower(
                    AcademicYear.name
                ) == name.lower(),

                AcademicYear.id !=
                academic_year.id

            )
            .first()
        )


        if existing_name:

            flash(
                "An academic year with this name already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/academic_years/edit_academic_year.html",
                academic_year=academic_year,
                institutions=institutions,
                user=current_user
            )


        # ====================================================
        # UPDATE FIELDS
        # ====================================================

        academic_year.institution_id = (
            institution_id
        )

        academic_year.name = name

        academic_year.code = code

        academic_year.start_date = (
            start_date
        )

        academic_year.end_date = (
            end_date
        )

        academic_year.is_current = (
            is_current
        )

        academic_year.status = status

        academic_year.description = (
            description
            or None
        )


        # ====================================================
        # CURRENT YEAR LOGIC
        #
        # If current:
        # unset other current years in selected institution.
        #
        # Important:
        # This also handles moving the academic year
        # from one institution to another.
        # ====================================================

        try:

            if is_current:

                (
                    AcademicYear.query
                    .filter(

                        AcademicYear.institution_id ==
                        institution_id,

                        AcademicYear.is_current.is_(True),

                        AcademicYear.id !=
                        academic_year.id

                    )
                    .update(

                        {
                            AcademicYear.is_current:
                                False
                        },

                        synchronize_session=False

                    )
                )


            # ------------------------------------------------
            # SAVE
            # ------------------------------------------------

            db.session.commit()


            flash(
                f"Academic year '{academic_year.name}' has been updated successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "main.view_academic_year",
                    academic_year_id=
                        academic_year.id
                )
            )


        except IntegrityError:

            db.session.rollback()


            flash(
                "Unable to update academic year because one of the unique values already exists.",
                "danger"
            )


        except Exception as e:

            db.session.rollback()


            flash(
                f"Unable to update academic year: {str(e)}",
                "danger"
            )


    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/academic_years/edit_academic_year.html",
        academic_year=academic_year,
        institutions=institutions,
        user=current_user
    )


# ============================================================
# DELETE ACADEMIC YEAR
# ============================================================

@bp.route(
    "/delete-academic-year/<int:academic_year_id>",
    methods=["POST"]
)
@login_required
def delete_academic_year(academic_year_id):

    # ========================================================
    # SUPERADMIN ONLY
    # ========================================================

    if not current_user.is_authenticated:

        return jsonify({

            "success": False,

            "message":
                "Authentication required."

        }), 401


   # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )


    # ========================================================
    # GET ACADEMIC YEAR
    # ========================================================

    academic_year = (
        AcademicYear.query
        .filter(
            AcademicYear.id ==
            academic_year_id
        )
        .first()
    )


    if not academic_year:

        return jsonify({

            "success": False,

            "message":
                "Academic year not found."

        }), 404


    # ========================================================
    # PREVENT DELETING CURRENT YEAR
    #
    # This is safer because other records may depend on
    # the current academic year.
    # ========================================================

    if academic_year.is_current:

        return jsonify({

            "success": False,

            "message":
                "The current academic year cannot be deleted. "
                "Set another academic year as current first."

        }), 400


    # ========================================================
    # SAVE NAME FOR RESPONSE
    # ========================================================

    academic_year_name = (
        academic_year.name
    )


    # ========================================================
    # DELETE
    # ========================================================

    try:

        db.session.delete(
            academic_year
        )

        db.session.commit()


        return jsonify({

            "success": True,

            "message":
                f"Academic year '{academic_year_name}' "
                "has been deleted successfully."

        }), 200


    except IntegrityError:

        db.session.rollback()


        return jsonify({

            "success": False,

            "message":
                "This academic year cannot be deleted because "
                "other records are still linked to it."

        }), 409


    except Exception as e:

        db.session.rollback()


        return jsonify({

            "success": False,

            "message":
                f"Unable to delete academic year: {str(e)}"

        }), 500




# ============================================================
# ALL TERMS
# ============================================================

@bp.route("/all-terms")
@login_required
def all_terms():

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------
 # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # --------------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------------

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    selected_status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    selected_institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()

    selected_academic_year_id = request.args.get(
        "academic_year_id",
        "",
        type=str
    ).strip()

    selected_current = request.args.get(
        "is_current",
        "",
        type=str
    ).strip().lower()


    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------

    allowed_per_page = [
        10,
        25,
        50,
        100
    ]

    per_page = request.args.get(
        "per_page",
        25,
        type=int
    )

    if per_page not in allowed_per_page:

        per_page = 25


    page = request.args.get(
        "page",
        1,
        type=int
    )


    # --------------------------------------------------------
    # BASE QUERY
    # --------------------------------------------------------

    query = Term.query


    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------

    if search:

        search_pattern = f"%{search}%"

        query = query.filter(
            or_(
                Term.name.ilike(search_pattern),
                Term.code.ilike(search_pattern),
                Term.description.ilike(search_pattern)
            )
        )


    # --------------------------------------------------------
    # STATUS FILTER
    # --------------------------------------------------------

    allowed_statuses = {
        "active",
        "inactive",
        "closed"
    }

    if selected_status in allowed_statuses:

        query = query.filter(
            Term.status == selected_status
        )

    else:

        selected_status = ""


    # --------------------------------------------------------
    # INSTITUTION FILTER
    # --------------------------------------------------------

    if selected_institution_id:

        try:

            institution_id = int(
                selected_institution_id
            )

            query = query.filter(
                Term.institution_id == institution_id
            )

        except (
            ValueError,
            TypeError
        ):

            selected_institution_id = ""


    # --------------------------------------------------------
    # ACADEMIC YEAR FILTER
    # --------------------------------------------------------

    if selected_academic_year_id:

        try:

            academic_year_id = int(
                selected_academic_year_id
            )

            query = query.filter(
                Term.academic_year_id ==
                academic_year_id
            )

        except (
            ValueError,
            TypeError
        ):

            selected_academic_year_id = ""


    # --------------------------------------------------------
    # CURRENT TERM FILTER
    # --------------------------------------------------------

    if selected_current == "current":

        query = query.filter(
            Term.is_current.is_(True)
        )

    elif selected_current == "not_current":

        query = query.filter(
            Term.is_current.is_(False)
        )

    else:

        selected_current = ""


    # --------------------------------------------------------
    # ORDERING
    # --------------------------------------------------------

    query = query.order_by(
        Term.is_current.desc(),
        Term.academic_year_id.desc(),
        Term.sequence.asc(),
        Term.start_date.asc(),
        Term.created_at.desc(),
        Term.id.desc()
    )


    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    terms = pagination.items


    # --------------------------------------------------------
    # INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # --------------------------------------------------------
    # ACADEMIC YEARS
    # --------------------------------------------------------

    academic_years = (
        AcademicYear.query
        .order_by(
            AcademicYear.is_current.desc(),
            AcademicYear.start_date.desc(),
            AcademicYear.name.asc()
        )
        .all()
    )


    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    total_terms = Term.query.count()


    active_terms = (
        Term.query
        .filter(
            Term.status == "active"
        )
        .count()
    )


    inactive_terms = (
        Term.query
        .filter(
            Term.status == "inactive"
        )
        .count()
    )


    closed_terms = (
        Term.query
        .filter(
            Term.status == "closed"
        )
        .count()
    )


    current_terms = (
        Term.query
        .filter(
            Term.is_current.is_(True)
        )
        .count()
    )


    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/terms/all_terms.html",

        terms=terms,

        pagination=pagination,

        institutions=institutions,

        academic_years=academic_years,

        search=search,

        selected_status=selected_status,

        selected_institution_id=
            selected_institution_id,

        selected_academic_year_id=
            selected_academic_year_id,

        selected_current=
            selected_current,

        per_page=per_page,

        total_terms=total_terms,

        active_terms=active_terms,

        inactive_terms=inactive_terms,

        closed_terms=closed_terms,

        current_terms=current_terms,

        user=current_user
    )

# ============================================================
# ADD TERM
# ============================================================

@bp.route(
    "/add-term",
    methods=["GET", "POST"]
)
@login_required
def add_term():

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------
 # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )



    # --------------------------------------------------------
    # LOAD INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # --------------------------------------------------------
    # LOAD ACADEMIC YEARS
    # --------------------------------------------------------

    academic_years = (
        AcademicYear.query
        .order_by(
            AcademicYear.is_current.desc(),
            AcademicYear.start_date.desc(),
            AcademicYear.name.asc()
        )
        .all()
    )


    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        institution_id_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        academic_year_id_raw = request.form.get(
            "academic_year_id",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        code = request.form.get(
            "code",
            ""
        ).strip().upper()

        sequence_raw = request.form.get(
            "sequence",
            "1"
        ).strip()

        start_date_raw = request.form.get(
            "start_date",
            ""
        ).strip()

        end_date_raw = request.form.get(
            "end_date",
            ""
        ).strip()

        is_current_raw = request.form.get(
            "is_current",
            ""
        ).strip().lower()

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        description = request.form.get(
            "description",
            ""
        ).strip()


        # ----------------------------------------------------
        # VALIDATE INSTITUTION ID
        # ----------------------------------------------------

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Please select a valid institution.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # VALIDATE ACADEMIC YEAR ID
        # ----------------------------------------------------

        try:

            academic_year_id = int(
                academic_year_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Please select a valid academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # VALIDATE REQUIRED FIELDS
        # ----------------------------------------------------

        if not name:

            flash(
                "Term name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if not code:

            flash(
                "Term code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if not start_date_raw:

            flash(
                "Start date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if not end_date_raw:

            flash(
                "End date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # INSTITUTION
        # ----------------------------------------------------

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )

        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # ACADEMIC YEAR
        # ----------------------------------------------------

        academic_year = (
            AcademicYear.query
            .filter(
                AcademicYear.id ==
                academic_year_id
            )
            .first()
        )

        if not academic_year:

            flash(
                "Selected academic year was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # VERIFY ACADEMIC YEAR BELONGS TO INSTITUTION
        # ----------------------------------------------------

        if (
            academic_year.institution_id
            != institution_id
        ):

            flash(
                "The selected academic year does not belong to the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # SEQUENCE
        # ----------------------------------------------------

        try:

            sequence = int(
                sequence_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Sequence must be a valid number.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if sequence < 1:

            flash(
                "Sequence must be greater than or equal to 1.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DATE PARSING
        # ----------------------------------------------------

        try:

            start_date = datetime.strptime(
                start_date_raw,
                "%Y-%m-%d"
            ).date()

            end_date = datetime.strptime(
                end_date_raw,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            flash(
                "Invalid date format.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DATE ORDER
        # ----------------------------------------------------

        if end_date <= start_date:

            flash(
                "End date must be later than start date.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        allowed_statuses = {
            "active",
            "inactive",
            "closed"
        }

        if status not in allowed_statuses:

            status = "active"


        # ----------------------------------------------------
        # CURRENT TERM
        # ----------------------------------------------------

        is_current = (
            is_current_raw
            in {
                "true",
                "1",
                "yes",
                "on"
            }
        )


        # ----------------------------------------------------
        # DUPLICATE CODE
        # ----------------------------------------------------

        existing_code = (
            Term.query
            .filter(
                Term.academic_year_id ==
                academic_year_id
            )
            .filter(
                Term.code.ilike(code)
            )
            .first()
        )

        if existing_code:

            flash(
                "This term code already exists in the selected academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DUPLICATE NAME
        # ----------------------------------------------------

        existing_name = (
            Term.query
            .filter(
                Term.academic_year_id ==
                academic_year_id
            )
            .filter(
                Term.name.ilike(name)
            )
            .first()
        )

        if existing_name:

            flash(
                "This term name already exists in the selected academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DUPLICATE SEQUENCE
        # ----------------------------------------------------

        existing_sequence = (
            Term.query
            .filter(
                Term.academic_year_id ==
                academic_year_id
            )
            .filter(
                Term.sequence == sequence
            )
            .first()
        )

        if existing_sequence:

            flash(
                f"Sequence {sequence} is already used in this academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/add_term.html",
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # CURRENT TERM
        #
        # Only one current term per academic year.
        # ----------------------------------------------------

        if is_current:

            (
                Term.query
                .filter(
                    Term.academic_year_id ==
                    academic_year_id
                )
                .filter(
                    Term.is_current.is_(True)
                )
                .update(
                    {
                        Term.is_current: False
                    },
                    synchronize_session=False
                )
            )


        # ----------------------------------------------------
        # CREATE TERM
        # ----------------------------------------------------

        term = Term(

            institution_id=institution_id,

            academic_year_id=academic_year_id,

            name=name,

            code=code,

            sequence=sequence,

            start_date=start_date,

            end_date=end_date,

            is_current=is_current,

            status=status,

            description=description or None
        )


        db.session.add(term)


        # ----------------------------------------------------
        # COMMIT
        # ----------------------------------------------------

        try:

            db.session.commit()

            flash(
                "Term created successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.all_terms"
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to create term. "
                "The code, name, or sequence may already exist.",
                "danger"
            )

        except Exception:

            db.session.rollback()

            flash(
                "An unexpected error occurred while creating the term.",
                "danger"
            )


    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/terms/add_term.html",

        institutions=institutions,

        academic_years=academic_years,

        user=current_user
    )

# ============================================================
# VIEW TERM
# ============================================================

@bp.route(
    "/view-term/<int:term_id>"
)
@login_required
def view_term(term_id):

   
    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # --------------------------------------------------------
    # GET TERM
    # --------------------------------------------------------

    term = (
        Term.query
        .filter(
            Term.id == term_id
        )
        .first()
    )


    if not term:

        flash(
            "Term not found.",
            "danger"
        )

        return redirect(
            url_for("main.all_terms")
        )


    # --------------------------------------------------------
    # INSTITUTION
    # --------------------------------------------------------

    institution = (
        Institution.query
        .filter(
            Institution.id ==
            term.institution_id
        )
        .first()
    )


    # --------------------------------------------------------
    # ACADEMIC YEAR
    # --------------------------------------------------------

    academic_year = (
        AcademicYear.query
        .filter(
            AcademicYear.id ==
            term.academic_year_id
        )
        .first()
    )


    # --------------------------------------------------------
    # TERMS IN SAME ACADEMIC YEAR
    # --------------------------------------------------------

    academic_year_terms_count = (
        Term.query
        .filter(
            Term.academic_year_id ==
            term.academic_year_id
        )
        .count()
    )


    # --------------------------------------------------------
    # CURRENT TERM
    # --------------------------------------------------------

    current_term = (
        Term.query
        .filter(
            Term.academic_year_id ==
            term.academic_year_id
        )
        .filter(
            Term.is_current.is_(True)
        )
        .first()
    )


    # --------------------------------------------------------
    # PREVIOUS TERM
    # --------------------------------------------------------

    previous_term = (
        Term.query
        .filter(
            Term.academic_year_id ==
            term.academic_year_id
        )
        .filter(
            Term.sequence < term.sequence
        )
        .order_by(
            Term.sequence.desc()
        )
        .first()
    )


    # --------------------------------------------------------
    # NEXT TERM
    # --------------------------------------------------------

    next_term = (
        Term.query
        .filter(
            Term.academic_year_id ==
            term.academic_year_id
        )
        .filter(
            Term.sequence > term.sequence
        )
        .order_by(
            Term.sequence.asc()
        )
        .first()
    )


    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/terms/view_term.html",

        term=term,

        institution=institution,

        academic_year=academic_year,

        academic_year_terms_count=
            academic_year_terms_count,

        current_term=current_term,

        previous_term=previous_term,

        next_term=next_term,

        user=current_user
    )


# ============================================================
# EDIT TERM
# ============================================================

@bp.route(
    "/edit-term/<int:term_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_term(term_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------
    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # --------------------------------------------------------
    # GET TERM
    # --------------------------------------------------------

    term = (
        Term.query
        .filter(
            Term.id == term_id
        )
        .first()
    )


    if not term:

        flash(
            "Term not found.",
            "danger"
        )

        return redirect(
            url_for("main.all_terms")
        )


    # --------------------------------------------------------
    # LOAD INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


    # --------------------------------------------------------
    # LOAD ACADEMIC YEARS
    # --------------------------------------------------------

    academic_years = (
        AcademicYear.query
        .order_by(
            AcademicYear.is_current.desc(),
            AcademicYear.start_date.desc(),
            AcademicYear.name.asc()
        )
        .all()
    )


    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        institution_id_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        academic_year_id_raw = request.form.get(
            "academic_year_id",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        code = request.form.get(
            "code",
            ""
        ).strip().upper()

        sequence_raw = request.form.get(
            "sequence",
            "1"
        ).strip()

        start_date_raw = request.form.get(
            "start_date",
            ""
        ).strip()

        end_date_raw = request.form.get(
            "end_date",
            ""
        ).strip()

        is_current_raw = request.form.get(
            "is_current",
            ""
        ).strip().lower()

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        description = request.form.get(
            "description",
            ""
        ).strip()


        # ----------------------------------------------------
        # INSTITUTION ID
        # ----------------------------------------------------

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Please select a valid institution.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # ACADEMIC YEAR ID
        # ----------------------------------------------------

        try:

            academic_year_id = int(
                academic_year_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Please select a valid academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not name:

            flash(
                "Term name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if not code:

            flash(
                "Term code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if not start_date_raw:

            flash(
                "Start date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if not end_date_raw:

            flash(
                "End date is required.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # INSTITUTION
        # ----------------------------------------------------

        institution = (
            Institution.query
            .filter(
                Institution.id ==
                institution_id
            )
            .first()
        )

        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # ACADEMIC YEAR
        # ----------------------------------------------------

        academic_year = (
            AcademicYear.query
            .filter(
                AcademicYear.id ==
                academic_year_id
            )
            .first()
        )

        if not academic_year:

            flash(
                "Selected academic year was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # VERIFY ACADEMIC YEAR BELONGS TO INSTITUTION
        # ----------------------------------------------------

        if (
            academic_year.institution_id
            != institution_id
        ):

            flash(
                "The selected academic year does not belong to the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # SEQUENCE
        # ----------------------------------------------------

        try:

            sequence = int(
                sequence_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Sequence must be a valid number.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        if sequence < 1:

            flash(
                "Sequence must be greater than or equal to 1.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DATE PARSING
        # ----------------------------------------------------

        try:

            start_date = datetime.strptime(
                start_date_raw,
                "%Y-%m-%d"
            ).date()

            end_date = datetime.strptime(
                end_date_raw,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            flash(
                "Invalid date format.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DATE ORDER
        # ----------------------------------------------------

        if end_date <= start_date:

            flash(
                "End date must be later than start date.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        allowed_statuses = {
            "active",
            "inactive",
            "closed"
        }

        if status not in allowed_statuses:

            status = "active"


        # ----------------------------------------------------
        # CURRENT TERM
        # ----------------------------------------------------

        is_current = (
            is_current_raw
            in {
                "true",
                "1",
                "yes",
                "on"
            }
        )


        # ----------------------------------------------------
        # DUPLICATE CODE
        # --------------------------------------------------------

        existing_code = (
            Term.query
            .filter(
                Term.academic_year_id ==
                academic_year_id
            )
            .filter(
                Term.code.ilike(code)
            )
            .filter(
                Term.id != term.id
            )
            .first()
        )

        if existing_code:

            flash(
                "This term code already exists in the selected academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DUPLICATE NAME
        # ----------------------------------------------------

        existing_name = (
            Term.query
            .filter(
                Term.academic_year_id ==
                academic_year_id
            )
            .filter(
                Term.name.ilike(name)
            )
            .filter(
                Term.id != term.id
            )
            .first()
        )

        if existing_name:

            flash(
                "This term name already exists in the selected academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # DUPLICATE SEQUENCE
        # ----------------------------------------------------

        existing_sequence = (
            Term.query
            .filter(
                Term.academic_year_id ==
                academic_year_id
            )
            .filter(
                Term.sequence == sequence
            )
            .filter(
                Term.id != term.id
            )
            .first()
        )

        if existing_sequence:

            flash(
                f"Sequence {sequence} is already used in this academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/terms/edit_term.html",
                term=term,
                institutions=institutions,
                academic_years=academic_years,
                user=current_user
            )


        # ----------------------------------------------------
        # CURRENT TERM HANDLING
        # ----------------------------------------------------

        if is_current:

            (
                Term.query
                .filter(
                    Term.academic_year_id ==
                    academic_year_id
                )
                .filter(
                    Term.id != term.id
                )
                .filter(
                    Term.is_current.is_(True)
                )
                .update(
                    {
                        Term.is_current: False
                    },
                    synchronize_session=False
                )
            )


        # ----------------------------------------------------
        # UPDATE TERM
        # ----------------------------------------------------

        term.institution_id = institution_id

        term.academic_year_id = academic_year_id

        term.name = name

        term.code = code

        term.sequence = sequence

        term.start_date = start_date

        term.end_date = end_date

        term.is_current = is_current

        term.status = status

        term.description = (
            description or None
        )


        # ----------------------------------------------------
        # COMMIT
        # ----------------------------------------------------

        try:

            db.session.commit()

            flash(
                "Term updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_term",
                    term_id=term.id
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to update term. "
                "The code, name, or sequence may already exist.",
                "danger"
            )

        except Exception:

            db.session.rollback()

            flash(
                "An unexpected error occurred while updating the term.",
                "danger"
            )


    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/terms/edit_term.html",

        term=term,

        institutions=institutions,

        academic_years=academic_years,

        user=current_user
    )

# ============================================================
# DELETE TERM
# ============================================================

@bp.route(
    "/delete-term/<int:term_id>",
    methods=["POST"]
)
@login_required
def delete_term(term_id):

     # ACCESS CONTROL
     # SUPERADMIN + INSTITUTION ADMIN
     # ========================================================
 
    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )
 
    # --------------------------------------------------------
    # GET TERM
    # --------------------------------------------------------

    term = (
        Term.query
        .filter(
            Term.id == term_id
        )
        .first()
    )


    if not term:

        return jsonify(
            {
                "success": False,
                "message": "Term not found."
            }
        ), 404


    # --------------------------------------------------------
    # CURRENT TERM PROTECTION
    # --------------------------------------------------------

    if term.is_current:

        return jsonify(
            {
                "success": False,
                "message": (
                    "This term is currently selected "
                    "as the current term. "
                    "Please set another term as current "
                    "before deleting it."
                )
            }
        ), 400


    # --------------------------------------------------------
    # SAVE INFO BEFORE DELETE
    # --------------------------------------------------------

    term_name = term.name

    term_id_value = term.id


    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    try:

        db.session.delete(term)

        db.session.commit()

        return jsonify(
            {
                "success": True,
                "message": (
                    f"Term '{term_name}' "
                    f"was deleted successfully."
                ),
                "term_id": term_id_value
            }
        ), 200


    except IntegrityError:

        db.session.rollback()

        return jsonify(
            {
                "success": False,
                "message": (
                    "This term cannot be deleted because "
                    "other records are linked to it."
                )
            }
        ), 409


    except Exception:

        db.session.rollback()

        return jsonify(
            {
                "success": False,
                "message": (
                    "An unexpected error occurred "
                    "while deleting the term."
                )
            }
        ), 500



# ============================================================
# PROGRAM ROUTES
# PostgreSQL / Neon
# ============================================================

# ============================================================
# ALL PROGRAMS
# ============================================================

@bp.route("/all-programs")
@login_required
def all_programs():

  
    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )


    # --------------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------------

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    selected_status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    selected_program_type = request.args.get(
        "program_type",
        "",
        type=str
    ).strip().lower()

    selected_institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()

    selected_branch_id = request.args.get(
        "branch_id",
        "",
        type=str
    ).strip()

    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------

    allowed_per_page = {
        10,
        25,
        50,
        100
    }

    per_page = request.args.get(
        "per_page",
        25,
        type=int
    )

    if per_page not in allowed_per_page:
        per_page = 25

    page = request.args.get(
        "page",
        1,
        type=int
    )

    if page < 1:
        page = 1

    # --------------------------------------------------------
    # BASE QUERY
    # --------------------------------------------------------

    query = Program.query

    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------

    if search:

        search_pattern = f"%{search}%"

        query = query.filter(
            or_(
                Program.name.ilike(search_pattern),
                Program.code.ilike(search_pattern),
                Program.short_name.ilike(search_pattern),
                Program.description.ilike(search_pattern),
                Program.program_type.ilike(search_pattern)
            )
        )

    # --------------------------------------------------------
    # STATUS FILTER
    # --------------------------------------------------------

    allowed_statuses = {
        "active",
        "inactive"
    }

    if selected_status:

        if selected_status in allowed_statuses:

            query = query.filter(
                Program.status == selected_status
            )

        else:

            selected_status = ""

    # --------------------------------------------------------
    # PROGRAM TYPE FILTER
    # --------------------------------------------------------

    if selected_program_type:

        query = query.filter(
            Program.program_type.ilike(
                selected_program_type
            )
        )

    # --------------------------------------------------------
    # INSTITUTION FILTER
    # --------------------------------------------------------

    if selected_institution_id:

        try:

            institution_id = int(
                selected_institution_id
            )

            query = query.filter(
                Program.institution_id == institution_id
            )

        except (
            ValueError,
            TypeError
        ):

            selected_institution_id = ""

    # --------------------------------------------------------
    # BRANCH FILTER
    # --------------------------------------------------------

    if selected_branch_id:

        try:

            branch_id = int(
                selected_branch_id
            )

            query = query.filter(
                Program.branch_id == branch_id
            )

        except (
            ValueError,
            TypeError
        ):

            selected_branch_id = ""

    # --------------------------------------------------------
    # ORDERING
    # --------------------------------------------------------

    query = query.order_by(
        Program.status.asc(),
        Program.name.asc(),
        Program.code.asc(),
        Program.created_at.desc(),
        Program.id.desc()
    )

    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    programs = pagination.items

    # --------------------------------------------------------
    # INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # BRANCHES
    # --------------------------------------------------------

    branches = (
        Branch.query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # PROGRAM TYPES
    # --------------------------------------------------------

    program_type_rows = (
        db.session.query(
            Program.program_type
        )
        .filter(
            Program.program_type.isnot(None)
        )
        .filter(
            Program.program_type != ""
        )
        .distinct()
        .order_by(
            Program.program_type.asc()
        )
        .all()
    )

    program_types = [
        row[0]
        for row in program_type_rows
        if row[0]
    ]

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    total_programs = (
        Program.query
        .count()
    )

    active_programs = (
        Program.query
        .filter(
            Program.status == "active"
        )
        .count()
    )

    inactive_programs = (
        Program.query
        .filter(
            Program.status == "inactive"
        )
        .count()
    )

    institution_wide_programs = (
        Program.query
        .filter(
            Program.branch_id.is_(None)
        )
        .count()
    )

    branch_programs = (
        Program.query
        .filter(
            Program.branch_id.isnot(None)
        )
        .count()
    )

    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/programs/all_programs.html",

        programs=programs,

        pagination=pagination,

        institutions=institutions,

        branches=branches,

        program_types=program_types,

        search=search,

        selected_status=selected_status,

        selected_program_type=selected_program_type,

        selected_institution_id=selected_institution_id,

        selected_branch_id=selected_branch_id,

        per_page=per_page,

        total_programs=total_programs,

        active_programs=active_programs,

        inactive_programs=inactive_programs,

        institution_wide_programs=institution_wide_programs,

        branch_programs=branch_programs,

        user=current_user
    )


# ============================================================
# ADD PROGRAM
# ============================================================

@bp.route(
    "/add-program",
    methods=["GET", "POST"]
)
@login_required
def add_program():

   
    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )


    # --------------------------------------------------------
    # LOAD INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # LOAD BRANCHES
    # --------------------------------------------------------

    branches = (
        Branch.query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        # ----------------------------------------------------
        # FORM VALUES
        # ----------------------------------------------------

        institution_id_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        branch_id_raw = request.form.get(
            "branch_id",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        code = request.form.get(
            "code",
            ""
        ).strip().upper()

        short_name = request.form.get(
            "short_name",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        program_type = request.form.get(
            "program_type",
            ""
        ).strip().lower()

        duration_months_raw = request.form.get(
            "duration_months",
            ""
        ).strip()

        price_raw = request.form.get(
            "price",
            "0"
        ).strip()

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        # ----------------------------------------------------
        # VALIDATE INSTITUTION ID
        # ----------------------------------------------------

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Please select a valid institution.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        if institution_id <= 0:

            flash(
                "Please select a valid institution.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # VALIDATE BRANCH
        # ----------------------------------------------------

        branch_id = None

        if branch_id_raw:

            try:

                branch_id = int(
                    branch_id_raw
                )

            except (
                ValueError,
                TypeError
            ):

                flash(
                    "Please select a valid branch.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/add_program.html",
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

            if branch_id <= 0:

                flash(
                    "Please select a valid branch.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/add_program.html",
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not name:

            flash(
                "Program name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        if not code:

            flash(
                "Program code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # INSTITUTION
        # ----------------------------------------------------

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )

        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # BRANCH
        # ----------------------------------------------------

        branch = None

        if branch_id is not None:

            branch = (
                Branch.query
                .filter(
                    Branch.id == branch_id
                )
                .first()
            )

            if not branch:

                flash(
                    "Selected branch was not found.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/add_program.html",
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

            if branch.institution_id != institution_id:

                flash(
                    "The selected branch does not belong to the selected institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/add_program.html",
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

        # ----------------------------------------------------
        # DURATION
        # ----------------------------------------------------

        duration_months = None

        if duration_months_raw:

            try:

                duration_months = int(
                    duration_months_raw
                )

            except (
                ValueError,
                TypeError
            ):

                flash(
                    "Duration must be a valid whole number.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/add_program.html",
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

            if duration_months < 1:

                flash(
                    "Duration must be greater than zero.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/add_program.html",
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

        # ----------------------------------------------------
        # PRICE
        # ----------------------------------------------------

        from decimal import Decimal, InvalidOperation

        try:

            price = Decimal(
                price_raw or "0"
            )

        except (
            InvalidOperation,
            ValueError,
            TypeError
        ):

            flash(
                "Price must be a valid number.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        if price < 0:

            flash(
                "Price cannot be negative.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        allowed_statuses = {
            "active",
            "inactive"
        }

        if status not in allowed_statuses:

            status = "active"

        # ----------------------------------------------------
        # DUPLICATE CODE
        # ----------------------------------------------------

        existing_code = (
            Program.query
            .filter(
                Program.institution_id == institution_id
            )
            .filter(
                Program.code.ilike(code)
            )
            .first()
        )

        if existing_code:

            flash(
                "This program code already exists in the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/add_program.html",
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # CREATE PROGRAM
        # ----------------------------------------------------

        program = Program(

            institution_id=institution_id,

            branch_id=branch_id,

            name=name,

            code=code,

            short_name=short_name or None,

            description=description or None,

            program_type=program_type or None,

            duration_months=duration_months,

            price=price,

            status=status
        )

        db.session.add(program)

        # ----------------------------------------------------
        # COMMIT
        # ----------------------------------------------------

        try:

            db.session.commit()

            flash(
                "Program created successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_program",
                    program_id=program.id
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to create program. "
                "The program code may already exist.",
                "danger"
            )

        except Exception:

            db.session.rollback()

            flash(
                "An unexpected error occurred while creating the program.",
                "danger"
            )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/programs/add_program.html",

        institutions=institutions,

        branches=branches,

        user=current_user
    )


# ============================================================
# VIEW PROGRAM
# ============================================================

@bp.route(
    "/view-program/<int:program_id>"
)
@login_required
def view_program(program_id):

   
    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # --------------------------------------------------------
    # GET PROGRAM
    # --------------------------------------------------------

    program = (
        Program.query
        .filter(
            Program.id == program_id
        )
        .first()
    )

    if not program:

        flash(
            "Program not found.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # --------------------------------------------------------
    # INSTITUTION
    # --------------------------------------------------------

    institution = (
        Institution.query
        .filter(
            Institution.id == program.institution_id
        )
        .first()
    )

    # --------------------------------------------------------
    # BRANCH
    # --------------------------------------------------------

    branch = None

    if program.branch_id is not None:

        branch = (
            Branch.query
            .filter(
                Branch.id == program.branch_id
            )
            .first()
        )

    # --------------------------------------------------------
    # SAME INSTITUTION PROGRAM COUNT
    # --------------------------------------------------------

    institution_programs_count = (
        Program.query
        .filter(
            Program.institution_id ==
            program.institution_id
        )
        .count()
    )

    # --------------------------------------------------------
    # SAME BRANCH PROGRAM COUNT
    # --------------------------------------------------------

    branch_programs_count = 0

    if program.branch_id is not None:

        branch_programs_count = (
            Program.query
            .filter(
                Program.branch_id ==
                program.branch_id
            )
            .count()
        )

    # --------------------------------------------------------
    # SAME PROGRAM TYPE COUNT
    # --------------------------------------------------------

    program_type_count = 0

    if program.program_type:

        program_type_count = (
            Program.query
            .filter(
                Program.institution_id ==
                program.institution_id
            )
            .filter(
                Program.program_type.ilike(
                    program.program_type
                )
            )
            .count()
        )

    # --------------------------------------------------------
    # RELATED PROGRAMS
    # --------------------------------------------------------

    related_programs = (
        Program.query
        .filter(
            Program.institution_id ==
            program.institution_id
        )
        .filter(
            Program.id != program.id
        )
        .order_by(
            Program.name.asc(),
            Program.code.asc()
        )
        .limit(10)
        .all()
    )

    # --------------------------------------------------------
    # RELATIONSHIP COUNTS
    # --------------------------------------------------------

    assessment_plans_count = (
        len(program.assessment_plans)
        if program.assessment_plans
        else 0
    )

    classes_count = (
        len(program.classes)
        if program.classes
        else 0
    )

    subjects_count = (
        len(program.subjects)
        if program.subjects
        else 0
    )

    teacher_subjects_count = (
        len(program.teacher_subjects)
        if program.teacher_subjects
        else 0
    )

    student_enrollments_count = (
        len(program.student_enrollments)
        if program.student_enrollments
        else 0
    )

    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template(
        "backend/pages/programs/view_program.html",

        program=program,

        institution=institution,

        branch=branch,

        institution_programs_count=
            institution_programs_count,

        branch_programs_count=
            branch_programs_count,

        program_type_count=
            program_type_count,

        related_programs=
            related_programs,

        assessment_plans_count=
            assessment_plans_count,

        classes_count=
            classes_count,

        subjects_count=
            subjects_count,

        teacher_subjects_count=
            teacher_subjects_count,

        student_enrollments_count=
            student_enrollments_count,

        user=current_user
    )


# ============================================================
# EDIT PROGRAM
# ============================================================

@bp.route(
    "/edit-program/<int:program_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_program(program_id):

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )
   

    # --------------------------------------------------------
    # GET PROGRAM
    # --------------------------------------------------------

    program = (
        Program.query
        .filter(
            Program.id == program_id
        )
        .first()
    )

    if not program:

        flash(
            "Program not found.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # --------------------------------------------------------
    # LOAD INSTITUTIONS
    # --------------------------------------------------------

    institutions = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # LOAD BRANCHES
    # --------------------------------------------------------

    branches = (
        Branch.query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        # ----------------------------------------------------
        # FORM VALUES
        # ----------------------------------------------------

        institution_id_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        branch_id_raw = request.form.get(
            "branch_id",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        code = request.form.get(
            "code",
            ""
        ).strip().upper()

        short_name = request.form.get(
            "short_name",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        program_type = request.form.get(
            "program_type",
            ""
        ).strip().lower()

        duration_months_raw = request.form.get(
            "duration_months",
            ""
        ).strip()

        price_raw = request.form.get(
            "price",
            "0"
        ).strip()

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        # ----------------------------------------------------
        # VALIDATE INSTITUTION ID
        # ----------------------------------------------------

        try:

            institution_id = int(
                institution_id_raw
            )

        except (
            ValueError,
            TypeError
        ):

            flash(
                "Please select a valid institution.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        if institution_id <= 0:

            flash(
                "Please select a valid institution.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # VALIDATE BRANCH
        # ----------------------------------------------------

        branch_id = None

        if branch_id_raw:

            try:

                branch_id = int(
                    branch_id_raw
                )

            except (
                ValueError,
                TypeError
            ):

                flash(
                    "Please select a valid branch.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/edit_program.html",
                    program=program,
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

            if branch_id <= 0:

                flash(
                    "Please select a valid branch.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/edit_program.html",
                    program=program,
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not name:

            flash(
                "Program name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        if not code:

            flash(
                "Program code is required.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # INSTITUTION
        # ----------------------------------------------------

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )

        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # BRANCH
        # ----------------------------------------------------

        branch = None

        if branch_id is not None:

            branch = (
                Branch.query
                .filter(
                    Branch.id == branch_id
                )
                .first()
            )

            if not branch:

                flash(
                    "Selected branch was not found.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/edit_program.html",
                    program=program,
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

            if branch.institution_id != institution_id:

                flash(
                    "The selected branch does not belong to the selected institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/edit_program.html",
                    program=program,
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

        # ----------------------------------------------------
        # DURATION
        # ----------------------------------------------------

        duration_months = None

        if duration_months_raw:

            try:

                duration_months = int(
                    duration_months_raw
                )

            except (
                ValueError,
                TypeError
            ):

                flash(
                    "Duration must be a valid whole number.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/edit_program.html",
                    program=program,
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

            if duration_months < 1:

                flash(
                    "Duration must be greater than zero.",
                    "danger"
                )

                return render_template(
                    "backend/pages/programs/edit_program.html",
                    program=program,
                    institutions=institutions,
                    branches=branches,
                    user=current_user
                )

        # ----------------------------------------------------
        # PRICE
        # ----------------------------------------------------

        from decimal import Decimal, InvalidOperation

        try:

            price = Decimal(
                price_raw or "0"
            )

        except (
            InvalidOperation,
            ValueError,
            TypeError
        ):

            flash(
                "Price must be a valid number.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        if price < 0:

            flash(
                "Price cannot be negative.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        allowed_statuses = {
            "active",
            "inactive"
        }

        if status not in allowed_statuses:

            status = "active"

        # ----------------------------------------------------
        # DUPLICATE CODE
        # ----------------------------------------------------

        existing_code = (
            Program.query
            .filter(
                Program.institution_id ==
                institution_id
            )
            .filter(
                Program.code.ilike(code)
            )
            .filter(
                Program.id != program.id
            )
            .first()
        )

        if existing_code:

            flash(
                "This program code already exists in the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # UPDATE PROGRAM
        # ----------------------------------------------------

        program.institution_id = institution_id

        program.branch_id = branch_id

        program.name = name

        program.code = code

        program.short_name = (
            short_name or None
        )

        program.description = (
            description or None
        )

        program.program_type = (
            program_type or None
        )

        program.duration_months = (
            duration_months
        )

        program.price = price

        program.status = status

        # ----------------------------------------------------
        # COMMIT
        # ----------------------------------------------------

        try:

            db.session.commit()

            flash(
                "Program updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_program",
                    program_id=program.id
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to update program. "
                "The program code may already exist.",
                "danger"
            )

        except Exception:

            db.session.rollback()

            flash(
                "An unexpected error occurred while updating the program.",
                "danger"
            )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/programs/edit_program.html",

        program=program,

        institutions=institutions,

        branches=branches,

        user=current_user
    )



# ============================================================
# DELETE PROGRAM
# ============================================================

@bp.route(
    "/delete-program/<int:program_id>",
    methods=["POST"]
)
@login_required
def delete_program(program_id):

    # ========================================================
    # ACCESS CONTROL
    # SUPERADMIN + INSTITUTION ADMIN
    # ========================================================

    is_superadmin = current_user.is_superadmin()

    is_institution_admin = (
        hasattr(current_user, "is_institution_admin")
        and current_user.is_institution_admin()
    )

    if not is_superadmin and not is_institution_admin:

        flash(
            "You do not have permission to delete programs.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # GET PROGRAM
    # ========================================================

    program_query = Program.query.filter(
        Program.id == program_id
    )

    # ========================================================
    # INSTITUTION ADMIN
    # CAN ONLY DELETE PROGRAMS FROM HIS/HER INSTITUTION
    # ========================================================

    if is_institution_admin and not is_superadmin:

        if not getattr(current_user, "institution_id", None):

            flash(
                "Your account is not linked to an institution.",
                "danger"
            )

            return redirect(
                url_for("main.all_programs")
            )

        program_query = program_query.filter(
            Program.institution_id
            == current_user.institution_id
        )

    # ========================================================
    # FIND PROGRAM
    # ========================================================

    program = program_query.first()

    if not program:

        flash(
            "Program not found or you do not have permission "
            "to delete this program.",
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # SAVE INFORMATION BEFORE DELETE
    # ========================================================

    program_name = program.name
    program_code = program.code
    program_id_value = program.id

    # ========================================================
    # DELETE PROGRAM
    # ========================================================

    try:

        db.session.delete(program)

        db.session.commit()

        # ====================================================
        # SUCCESS
        # ====================================================

        flash(
            (
                f"Program '{program_name}' "
                f"({program_code}) was deleted successfully."
            ),
            "success"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # FOREIGN KEY / INTEGRITY ERROR
    # ========================================================

    except IntegrityError:

        db.session.rollback()

        flash(
            (
                f"Program '{program_name}' cannot be deleted "
                "because other records are linked to it."
            ),
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

    # ========================================================
    # UNEXPECTED ERROR
    # ========================================================

    except Exception:

        db.session.rollback()

        flash(
            (
                "An unexpected error occurred while "
                "deleting the program."
            ),
            "danger"
        )

        return redirect(
            url_for("main.all_programs")
        )

# ============================================================
# HELPER: CURRENT USER INSTITUTION
# ============================================================

def _get_user_institution_id():
    """
    Returns the institution ID assigned to the current user.

    Superadmin:
        Can work across institutions.

    Other users:
        Must have institution_id.
    """

    if getattr(current_user, "role", None) == "superadmin":
        return None

    return getattr(current_user, "institution_id", None)


# ============================================================
# HELPER: AVAILABLE FREQUENCIES
# ============================================================

def _assessment_frequencies():
    return [
        ("monthly", "Monthly"),
        ("bi_monthly", "Bi-Monthly"),
        ("quarterly", "Quarterly"),
        ("semester", "Semester"),
        ("custom", "Custom"),
    ]


# ============================================================
# HELPER: DEFAULT INTERVAL
# ============================================================

def _frequency_interval(frequency):

    intervals = {
        "monthly": 1,
        "bi_monthly": 2,
        "quarterly": 3,
        "semester": 6,
    }

    return intervals.get(frequency, 1)


# ============================================================
# ALL ASSESSMENT PLANS
# ============================================================

@bp.route(
    "/assessment-plans",
    methods=["GET"]
)
@login_required
def all_assessment_plans():

    # ========================================================
    # REQUEST FILTERS
    # ========================================================

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    selected_institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()

    selected_program_id = request.args.get(
        "program_id",
        "",
        type=str
    ).strip()

    selected_academic_year_id = request.args.get(
        "academic_year_id",
        "",
        type=str
    ).strip()

    selected_frequency = request.args.get(
        "frequency",
        "",
        type=str
    ).strip()

    selected_status = request.args.get(
        "status",
        "",
        type=str
    ).strip()

    selected_auto_generate = request.args.get(
        "auto_generate",
        "",
        type=str
    ).strip()

    # ========================================================
    # PAGINATION
    # ========================================================

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        20,
        type=int
    )

    # Safe limits
    if page < 1:
        page = 1

    allowed_per_page = {
        10,
        20,
        50,
        100
    }

    if per_page not in allowed_per_page:
        per_page = 20

    # ========================================================
    # USER INSTITUTION SECURITY
    # ========================================================

    user_institution_id = _get_user_institution_id()

    # ========================================================
    # BASE QUERY
    # ========================================================

    query = (
        AssessmentPlan.query
        .join(
            Institution,
            AssessmentPlan.institution_id
            == Institution.id
        )
        .outerjoin(
            Program,
            AssessmentPlan.program_id
            == Program.id
        )
        .outerjoin(
            AcademicYear,
            AssessmentPlan.academic_year_id
            == AcademicYear.id
        )
    )

    # ========================================================
    # INSTITUTION SECURITY
    #
    # Institution-level users only see their own plans.
    # Superadmin / unrestricted users see all.
    # ========================================================

    if user_institution_id is not None:

        query = query.filter(
            AssessmentPlan.institution_id
            == user_institution_id
        )

    # ========================================================
    # SEARCH
    #
    # Search:
    #   - Plan name
    #   - Code
    #   - Description
    #   - Program name
    #   - Program code
    #   - Institution name
    # ========================================================

    if search:

        search_pattern = f"%{search}%"

        query = query.filter(
            or_(
                AssessmentPlan.name.ilike(
                    search_pattern
                ),

                AssessmentPlan.code.ilike(
                    search_pattern
                ),

                AssessmentPlan.description.ilike(
                    search_pattern
                ),

                Program.name.ilike(
                    search_pattern
                ),

                Program.code.ilike(
                    search_pattern
                ),

                Institution.name.ilike(
                    search_pattern
                )
            )
        )

    # ========================================================
    # INSTITUTION FILTER
    # ========================================================

    if selected_institution_id:

        try:

            institution_id = int(
                selected_institution_id
            )

            query = query.filter(
                AssessmentPlan.institution_id
                == institution_id
            )

        except (TypeError, ValueError):

            selected_institution_id = ""

    # ========================================================
    # PROGRAM FILTER
    # ========================================================

    if selected_program_id:

        try:

            program_id = int(
                selected_program_id
            )

            query = query.filter(
                AssessmentPlan.program_id
                == program_id
            )

        except (TypeError, ValueError):

            selected_program_id = ""

    # ========================================================
    # ACADEMIC YEAR FILTER
    # ========================================================

    if selected_academic_year_id:

        try:

            academic_year_id = int(
                selected_academic_year_id
            )

            query = query.filter(
                AssessmentPlan.academic_year_id
                == academic_year_id
            )

        except (TypeError, ValueError):

            selected_academic_year_id = ""

    # ========================================================
    # FREQUENCY FILTER
    # ========================================================

    allowed_frequencies = {
        "monthly",
        "bi_monthly",
        "quarterly",
        "semester",
        "custom"
    }

    if selected_frequency:

        if selected_frequency in allowed_frequencies:

            query = query.filter(
                AssessmentPlan.frequency
                == selected_frequency
            )

        else:

            selected_frequency = ""

    # ========================================================
    # STATUS FILTER
    # ========================================================

    allowed_statuses = {
        "active",
        "inactive",
        "completed"
    }

    if selected_status:

        if selected_status in allowed_statuses:

            query = query.filter(
                AssessmentPlan.status
                == selected_status
            )

        else:

            selected_status = ""

    # ========================================================
    # AUTO GENERATE FILTER
    # ========================================================

    if selected_auto_generate in {
        "0",
        "1"
    }:

        query = query.filter(
            AssessmentPlan.auto_generate
            == (
                selected_auto_generate == "1"
            )
        )

    elif selected_auto_generate:

        selected_auto_generate = ""

    # ========================================================
    # ORDERING
    # ========================================================

    query = query.order_by(
        AssessmentPlan.start_date.desc(),
        AssessmentPlan.id.desc()
    )

    # ========================================================
    # PAGINATE
    # ========================================================

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    assessment_plans = pagination.items

    # ========================================================
    # STATISTICS BASE QUERY
    #
    # IMPORTANT:
    # Statistics respect institution security,
    # but NOT the current search/filter parameters.
    #
    # Therefore cards show global statistics for the
    # user's accessible institutions.
    # ========================================================

    stats_query = AssessmentPlan.query

    if user_institution_id is not None:

        stats_query = stats_query.filter(
            AssessmentPlan.institution_id
            == user_institution_id
        )

    # ========================================================
    # TOTAL
    # ========================================================

    total_assessment_plans = (
        stats_query
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    # ========================================================
    # ACTIVE
    # ========================================================

    active_assessment_plans = (
        stats_query
        .filter(
            AssessmentPlan.status
            == "active"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    # ========================================================
    # INACTIVE
    # ========================================================

    inactive_assessment_plans = (
        stats_query
        .filter(
            AssessmentPlan.status
            == "inactive"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    # ========================================================
    # COMPLETED
    # ========================================================

    completed_assessment_plans = (
        stats_query
        .filter(
            AssessmentPlan.status
            == "completed"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    # ========================================================
    # AUTO GENERATE
    # ========================================================

    auto_generate_plans = (
        stats_query
        .filter(
            AssessmentPlan.auto_generate.is_(True)
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    # ========================================================
    # FREQUENCY STATISTICS
    # ========================================================

    monthly_plans = (
        stats_query
        .filter(
            AssessmentPlan.frequency
            == "monthly"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    bi_monthly_plans = (
        stats_query
        .filter(
            AssessmentPlan.frequency
            == "bi_monthly"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    quarterly_plans = (
        stats_query
        .filter(
            AssessmentPlan.frequency
            == "quarterly"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    semester_plans = (
        stats_query
        .filter(
            AssessmentPlan.frequency
            == "semester"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    custom_plans = (
        stats_query
        .filter(
            AssessmentPlan.frequency
            == "custom"
        )
        .with_entities(
            func.count(AssessmentPlan.id)
        )
        .scalar()
        or 0
    )

    # ========================================================
    # FILTER DATA
    # ========================================================

    # --------------------------------------------------------
    # Institutions
    # --------------------------------------------------------

    institutions_query = (
        Institution.query
        .order_by(
            Institution.name.asc()
        )
    )

    if user_institution_id is not None:

        institutions_query = institutions_query.filter(
            Institution.id
            == user_institution_id
        )

    institutions = institutions_query.all()

    # --------------------------------------------------------
    # Programs
    # --------------------------------------------------------

    programs_query = (
        Program.query
        .order_by(
            Program.name.asc()
        )
    )

    if user_institution_id is not None:

        # Only filter if Program has institution_id.
        if hasattr(Program, "institution_id"):

            programs_query = programs_query.filter(
                Program.institution_id
                == user_institution_id
            )

    programs = programs_query.all()

    # --------------------------------------------------------
    # Academic Years
    # --------------------------------------------------------

    academic_years_query = (
        AcademicYear.query
        .order_by(
            AcademicYear.id.desc()
        )
    )

    # Only apply institution filtering if the model
    # actually has institution_id.
    if (
        user_institution_id is not None
        and hasattr(
            AcademicYear,
            "institution_id"
        )
    ):

        academic_years_query = (
            academic_years_query
            .filter(
                AcademicYear.institution_id
                == user_institution_id
            )
        )

    academic_years = (
        academic_years_query.all()
    )

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/assessment_plans/all_assessment_plans.html",

        # ----------------------------------------------------
        # Main data
        # ----------------------------------------------------

        assessment_plans=assessment_plans,
        pagination=pagination,

        # ----------------------------------------------------
        # Filter data
        # ----------------------------------------------------

        institutions=institutions,
        programs=programs,
        academic_years=academic_years,

        # ----------------------------------------------------
        # Current filters
        # ----------------------------------------------------

        search=search,

        selected_institution_id=(
            selected_institution_id
        ),

        selected_program_id=(
            selected_program_id
        ),

        selected_academic_year_id=(
            selected_academic_year_id
        ),

        selected_frequency=(
            selected_frequency
        ),

        selected_status=(
            selected_status
        ),

        selected_auto_generate=(
            selected_auto_generate
        ),

        # ----------------------------------------------------
        # Pagination settings
        # ----------------------------------------------------

        per_page=per_page,

        # ----------------------------------------------------
        # Main statistics
        # ----------------------------------------------------

        total_assessment_plans=(
            total_assessment_plans
        ),

        active_assessment_plans=(
            active_assessment_plans
        ),

        inactive_assessment_plans=(
            inactive_assessment_plans
        ),

        completed_assessment_plans=(
            completed_assessment_plans
        ),

        auto_generate_plans=(
            auto_generate_plans
        ),

        # ----------------------------------------------------
        # Frequency statistics
        # ----------------------------------------------------

        monthly_plans=monthly_plans,
        bi_monthly_plans=bi_monthly_plans,
        quarterly_plans=quarterly_plans,
        semester_plans=semester_plans,
        custom_plans=custom_plans,

        # ----------------------------------------------------
        # Current user
        # ----------------------------------------------------

        user=current_user
    )



# ============================================================
# 2. ADD ASSESSMENT PLAN
# ============================================================

@bp.route("/assessment-plans/add", methods=["GET", "POST"])
@login_required
def add_assessment_plan():

    user_institution_id = _get_user_institution_id()

    # --------------------------------------------------------
    # DROPDOWN DATA
    # --------------------------------------------------------

    if user_institution_id is not None:

        institutions = (
            Institution.query
            .filter(
                Institution.id == user_institution_id
            )
            .order_by(Institution.name.asc())
            .all()
        )

        programs = (
            Program.query
            .filter(
                Program.institution_id
                == user_institution_id
            )
            .order_by(Program.name.asc())
            .all()
        )

        academic_years = (
            AcademicYear.query
            .filter(
                AcademicYear.institution_id
                == user_institution_id
            )
            .order_by(
                AcademicYear.start_date.desc(),
                AcademicYear.id.desc()
            )
            .all()
        )

    else:

        institutions = (
            Institution.query
            .order_by(Institution.name.asc())
            .all()
        )

        programs = (
            Program.query
            .order_by(Program.name.asc())
            .all()
        )

        academic_years = (
            AcademicYear.query
            .order_by(
                AcademicYear.start_date.desc(),
                AcademicYear.id.desc()
            )
            .all()
        )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        code = request.form.get(
            "code",
            ""
        ).strip().upper()

        description = request.form.get(
            "description",
            ""
        ).strip()

        frequency = request.form.get(
            "frequency",
            "monthly"
        ).strip().lower()

        interval_months_raw = request.form.get(
            "interval_months",
            ""
        ).strip()

        start_date_raw = request.form.get(
            "start_date",
            ""
        ).strip()

        end_date_raw = request.form.get(
            "end_date",
            ""
        ).strip()

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        auto_generate = (
            request.form.get("auto_generate")
            == "1"
        )

        institution_id_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        program_id_raw = request.form.get(
            "program_id",
            ""
        ).strip()

        academic_year_id_raw = request.form.get(
            "academic_year_id",
            ""
        ).strip()

        errors = []

        # ----------------------------------------------------
        # BASIC VALIDATION
        # ----------------------------------------------------

        if not name:

            errors.append(
                "Assessment plan name is required."
            )

        if not code:

            errors.append(
                "Assessment plan code is required."
            )

        if len(code) > 50:

            errors.append(
                "Assessment plan code cannot exceed 50 characters."
            )

        if not frequency:

            errors.append(
                "Assessment frequency is required."
            )

        allowed_frequencies = {
            "monthly",
            "bi_monthly",
            "quarterly",
            "semester",
            "custom",
        }

        if frequency not in allowed_frequencies:

            errors.append(
                "Invalid assessment frequency."
            )

        allowed_statuses = {
            "active",
            "inactive",
            "completed",
        }

        if status not in allowed_statuses:

            errors.append(
                "Invalid assessment plan status."
            )

        # ----------------------------------------------------
        # INSTITUTION
        # ----------------------------------------------------

        try:

            institution_id = int(
                institution_id_raw
            )

        except (ValueError, TypeError):

            institution_id = None

            errors.append(
                "Please select a valid institution."
            )

        if (
            user_institution_id is not None
            and institution_id is not None
            and institution_id != user_institution_id
        ):

            errors.append(
                "You cannot create an assessment plan for another institution."
            )

        # ----------------------------------------------------
        # PROGRAM
        # ----------------------------------------------------

        try:

            program_id = int(
                program_id_raw
            )

        except (ValueError, TypeError):

            program_id = None

            errors.append(
                "Please select a valid program."
            )

        # ----------------------------------------------------
        # ACADEMIC YEAR
        # ----------------------------------------------------

        try:

            academic_year_id = int(
                academic_year_id_raw
            )

        except (ValueError, TypeError):

            academic_year_id = None

            errors.append(
                "Please select a valid academic year."
            )

        # ----------------------------------------------------
        # INTERVAL
        # ----------------------------------------------------

        if interval_months_raw:

            try:

                interval_months = int(
                    interval_months_raw
                )

                if interval_months <= 0:

                    errors.append(
                        "Interval months must be greater than zero."
                    )

            except (ValueError, TypeError):

                interval_months = None

                errors.append(
                    "Interval months must be a valid number."
                )

        else:

            interval_months = _frequency_interval(
                frequency
            )

        # ----------------------------------------------------
        # DATES
        # ----------------------------------------------------

        start_date = None
        end_date = None

        if not start_date_raw:

            errors.append(
                "Start date is required."
            )

        else:

            try:

                start_date = datetime.strptime(
                    start_date_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                errors.append(
                    "Invalid start date."
                )

        if end_date_raw:

            try:

                end_date = datetime.strptime(
                    end_date_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                errors.append(
                    "Invalid end date."
                )

        if (
            start_date
            and end_date
            and end_date < start_date
        ):

            errors.append(
                "End date cannot be earlier than start date."
            )

        # ----------------------------------------------------
        # LOAD PROGRAM
        # ----------------------------------------------------

        program = None

        if program_id is not None:

            program = Program.query.get(
                program_id
            )

            if not program:

                errors.append(
                    "Selected program was not found."
                )

            else:

                if (
                    institution_id is not None
                    and program.institution_id
                    != institution_id
                ):

                    errors.append(
                        "Selected program does not belong to the selected institution."
                    )

        # ----------------------------------------------------
        # LOAD ACADEMIC YEAR
        # ----------------------------------------------------

        academic_year = None

        if academic_year_id is not None:

            academic_year = AcademicYear.query.get(
                academic_year_id
            )

            if not academic_year:

                errors.append(
                    "Selected academic year was not found."
                )

            else:

                if (
                    institution_id is not None
                    and academic_year.institution_id
                    != institution_id
                ):

                    errors.append(
                        "Selected academic year does not belong to the selected institution."
                    )

        # ----------------------------------------------------
        # DUPLICATE CODE
        # ----------------------------------------------------

        if institution_id is not None and code:

            existing = (
                AssessmentPlan.query
                .filter(
                    AssessmentPlan.institution_id
                    == institution_id,
                    func.lower(
                        AssessmentPlan.code
                    )
                    == code.lower()
                )
                .first()
            )

            if existing:

                errors.append(
                    "An assessment plan with this code already exists in this institution."
                )

        # ----------------------------------------------------
        # PROGRAM + ACADEMIC YEAR + CODE
        # ----------------------------------------------------

        if (
            program_id is not None
            and academic_year_id is not None
            and code
        ):

            existing_program_year = (
                AssessmentPlan.query
                .filter(
                    AssessmentPlan.program_id
                    == program_id,
                    AssessmentPlan.academic_year_id
                    == academic_year_id,
                    func.lower(
                        AssessmentPlan.code
                    )
                    == code.lower()
                )
                .first()
            )

            if existing_program_year:

                errors.append(
                    "This program already has an assessment plan with this code for the selected academic year."
                )

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        if not errors:

            try:

                assessment_plan = AssessmentPlan(
                    institution_id=institution_id,
                    program_id=program_id,
                    academic_year_id=academic_year_id,

                    name=name,
                    code=code,
                    description=description or None,

                    frequency=frequency,
                    interval_months=interval_months,

                    start_date=start_date,
                    end_date=end_date,

                    auto_generate=auto_generate,
                    status=status,
                )

                db.session.add(
                    assessment_plan
                )

                db.session.commit()

                flash(
                    "Assessment plan created successfully.",
                    "success"
                )

                return redirect(
                    url_for(
                        "main.view_assessment_plan",
                        plan_id=assessment_plan.id
                    )
                )

            except Exception as exc:

                db.session.rollback()

                flash(
                    f"Unable to create assessment plan: {exc}",
                    "danger"
                )

        else:

            for error in errors:

                flash(
                    error,
                    "danger"
                )

    # --------------------------------------------------------
    # GET / FAILED POST
    # --------------------------------------------------------

    return render_template(
        "backend/pages/assessment_plans/add_assessment_plan.html",

        institutions=institutions,
        programs=programs,
        academic_years=academic_years,

        frequencies=_assessment_frequencies(),
        user=current_user
    )


# ============================================================
# 3. VIEW ASSESSMENT PLAN
# ============================================================
# ============================================================
# VIEW ASSESSMENT PLAN
# ============================================================

@bp.route(
    "/assessment-plans/<int:assessment_plan_id>",
    methods=["GET"]
)
@login_required
def view_assessment_plan(assessment_plan_id):

    # ========================================================
    # GET ASSESSMENT PLAN
    # ========================================================

    assessment_plan = (
        AssessmentPlan.query
        .filter(
            AssessmentPlan.id == assessment_plan_id
        )
        .first_or_404()
    )

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    user_institution_id = _get_user_institution_id()

    if (
        user_institution_id is not None
        and assessment_plan.institution_id != user_institution_id
    ):

        flash(
            "You are not authorized to view this assessment plan.",
            "danger"
        )

        return redirect(
            url_for(
                "main.all_assessment_plans"
            )
        )

    # ========================================================
    # RELATED DATA
    # ========================================================

    institution = assessment_plan.institution
    program = assessment_plan.program
    academic_year = assessment_plan.academic_year

    # ========================================================
    # RELATED PLANS
    #
    # Same:
    #   - Institution
    #   - Program
    #   - Academic Year
    #
    # Exclude current plan
    # ========================================================

    related_query = (
        AssessmentPlan.query
        .filter(
            AssessmentPlan.institution_id
            == assessment_plan.institution_id,

            AssessmentPlan.program_id
            == assessment_plan.program_id,

            AssessmentPlan.academic_year_id
            == assessment_plan.academic_year_id,

            AssessmentPlan.id
            != assessment_plan.id
        )
    )

    # ========================================================
    # INSTITUTION SECURITY FOR RELATED PLANS
    # ========================================================

    if user_institution_id is not None:

        related_query = related_query.filter(
            AssessmentPlan.institution_id
            == user_institution_id
        )

    # ========================================================
    # LOAD RELATED PLANS
    # ========================================================

    related_plans = (
        related_query
        .order_by(
            AssessmentPlan.start_date.asc(),
            AssessmentPlan.id.asc()
        )
        .all()
    )

    # ========================================================
    # PLAN STATISTICS
    # ========================================================

    total_related_plans = (
        len(related_plans) + 1
    )

    # ========================================================
    # FREQUENCY LABEL
    # ========================================================

    frequency_labels = {
        "monthly": "Monthly",
        "bi_monthly": "Bi-Monthly",
        "quarterly": "Quarterly",
        "semester": "Semester",
        "custom": "Custom"
    }

    frequency_label = frequency_labels.get(
        assessment_plan.frequency,
        assessment_plan.frequency.replace(
            "_",
            " "
        ).title()
        if assessment_plan.frequency
        else "—"
    )

    # ========================================================
    # STATUS LABEL
    # ========================================================

    status_labels = {
        "active": "Active",
        "inactive": "Inactive",
        "completed": "Completed"
    }

    status_label = status_labels.get(
        assessment_plan.status,
        assessment_plan.status.replace(
            "_",
            " "
        ).title()
        if assessment_plan.status
        else "—"
    )

    # ========================================================
    # INTERVAL LABEL
    # ========================================================

    interval_months = (
        assessment_plan.interval_months or 1
    )

    interval_label = (
        f"{interval_months} Month"
        if interval_months == 1
        else f"{interval_months} Months"
    )

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/assessment_plans/view_assessment_plan.html",

        # Main object
        assessment_plan=assessment_plan,

        # Related objects
        institution=institution,
        program=program,
        academic_year=academic_year,

        # Related plans
        related_plans=related_plans,
        total_related_plans=total_related_plans,

        # Display helpers
        frequency_label=frequency_label,
        status_label=status_label,
        interval_label=interval_label,

        # Current user
        user=current_user
    )

# ============================================================
# 4. EDIT ASSESSMENT PLAN
# ============================================================
# ============================================================
# EDIT ASSESSMENT PLAN
# ============================================================

@bp.route(
    "/assessment-plans/edit/<int:assessment_plan_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_assessment_plan(assessment_plan_id):

    # --------------------------------------------------------
    # GET ASSESSMENT PLAN
    # --------------------------------------------------------
    assessment_plan = AssessmentPlan.query.get_or_404(
        assessment_plan_id
    )

    # --------------------------------------------------------
    # GET SUPPORTING DATA
    # --------------------------------------------------------
    institutions = Institution.query.order_by(
        Institution.name.asc()
    ).all()

    programs = Program.query.order_by(
        Program.name.asc()
    ).all()

    academic_years = AcademicYear.query.order_by(
        AcademicYear.name.desc()
    ).all()

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------
    if request.method == "POST":

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        program_id = request.form.get(
            "program_id",
            type=int
        )

        academic_year_id = request.form.get(
            "academic_year_id",
            type=int
        )

        name = request.form.get(
            "name",
            ""
        ).strip()

        code = request.form.get(
            "code",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        frequency = request.form.get(
            "frequency",
            "monthly"
        ).strip()

        interval_months = request.form.get(
            "interval_months",
            type=int
        )

        start_date = request.form.get(
            "start_date",
            ""
        ).strip()

        end_date = request.form.get(
            "end_date",
            ""
        ).strip()

        auto_generate = request.form.get(
            "auto_generate"
        ) == "1"

        status = request.form.get(
            "status",
            "active"
        ).strip()

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if not institution_id:
            flash(
                "Please select an institution.",
                "danger"
            )
            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        if not program_id:
            flash(
                "Please select a program.",
                "danger"
            )
            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        if not academic_year_id:
            flash(
                "Please select an academic year.",
                "danger"
            )
            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        if not name:
            flash(
                "Assessment plan name is required.",
                "danger"
            )
            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        if not code:
            flash(
                "Assessment plan code is required.",
                "danger"
            )
            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # NORMALIZE CODE
        # ----------------------------------------------------

        code = code.upper()

        # ----------------------------------------------------
        # VALIDATE FREQUENCY
        # ----------------------------------------------------

        allowed_frequencies = {
            "monthly": 1,
            "bi_monthly": 2,
            "quarterly": 3,
            "semester": 6,
            "custom": interval_months
        }

        if frequency not in allowed_frequencies:
            flash(
                "Invalid assessment frequency.",
                "danger"
            )
            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # AUTO INTERVAL
        # ----------------------------------------------------

        if frequency != "custom":

            interval_months = allowed_frequencies[
                frequency
            ]

        else:

            if not interval_months or interval_months <= 0:
                flash(
                    "Custom interval must be greater than zero.",
                    "danger"
                )
                return render_template(
                    "backend/pages/assessment_plans/edit_assessment_plan.html",
                    assessment_plan=assessment_plan,
                    institutions=institutions,
                    programs=programs,
                    academic_years=academic_years
                )

        # ----------------------------------------------------
        # DATE VALIDATION
        # ----------------------------------------------------

        parsed_start_date = None
        parsed_end_date = None

        try:

            if not start_date:
                raise ValueError(
                    "Start date is required."
                )

            parsed_start_date = datetime.strptime(
                start_date,
                "%Y-%m-%d"
            ).date()

            if end_date:
                parsed_end_date = datetime.strptime(
                    end_date,
                    "%Y-%m-%d"
                ).date()

        except ValueError as exc:

            flash(
                str(exc),
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        if (
            parsed_end_date
            and parsed_end_date < parsed_start_date
        ):
            flash(
                "End date cannot be earlier than start date.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years,
                user=current_user
            )

        # ----------------------------------------------------
        # VALIDATE STATUS
        # ----------------------------------------------------

        allowed_statuses = {
            "active",
            "inactive",
            "completed"
        }

        if status not in allowed_statuses:

            flash(
                "Invalid assessment plan status.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # CHECK INSTITUTION
        # ----------------------------------------------------

        institution = Institution.query.get(
            institution_id
        )

        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # CHECK PROGRAM
        # ----------------------------------------------------

        program = Program.query.get(
            program_id
        )

        if not program:

            flash(
                "Selected program was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # CHECK ACADEMIC YEAR
        # ----------------------------------------------------

        academic_year = AcademicYear.query.get(
            academic_year_id
        )

        if not academic_year:

            flash(
                "Selected academic year was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # CHECK PROGRAM BELONGS TO INSTITUTION
        # ----------------------------------------------------

        if hasattr(program, "institution_id"):

            if program.institution_id != institution_id:

                flash(
                    "The selected program does not belong to the selected institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/assessment_plans/edit_assessment_plan.html",
                    assessment_plan=assessment_plan,
                    institutions=institutions,
                    programs=programs,
                    academic_years=academic_years
                )

        # ----------------------------------------------------
        # CHECK DUPLICATE CODE
        #
        # Exclude current assessment plan.
        # ----------------------------------------------------

        duplicate = AssessmentPlan.query.filter(
            AssessmentPlan.institution_id == institution_id,
            AssessmentPlan.code == code,
            AssessmentPlan.id != assessment_plan.id
        ).first()

        if duplicate:

            flash(
                f"Assessment plan code '{code}' already exists in this institution.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # CHECK PROGRAM + ACADEMIC YEAR + CODE
        # ----------------------------------------------------

        duplicate_program_year = AssessmentPlan.query.filter(
            AssessmentPlan.program_id == program_id,
            AssessmentPlan.academic_year_id == academic_year_id,
            AssessmentPlan.code == code,
            AssessmentPlan.id != assessment_plan.id
        ).first()

        if duplicate_program_year:

            flash(
                "This assessment plan code already exists for the selected program and academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/assessment_plans/edit_assessment_plan.html",
                assessment_plan=assessment_plan,
                institutions=institutions,
                programs=programs,
                academic_years=academic_years
            )

        # ----------------------------------------------------
        # UPDATE ASSESSMENT PLAN
        # ----------------------------------------------------

        assessment_plan.institution_id = institution_id
        assessment_plan.program_id = program_id
        assessment_plan.academic_year_id = academic_year_id

        assessment_plan.name = name
        assessment_plan.code = code
        assessment_plan.description = description or None

        assessment_plan.frequency = frequency
        assessment_plan.interval_months = interval_months

        assessment_plan.start_date = parsed_start_date
        assessment_plan.end_date = parsed_end_date

        assessment_plan.auto_generate = auto_generate
        assessment_plan.status = status

        assessment_plan.updated_at = datetime.utcnow()

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        try:

            db.session.commit()

            flash(
                "Assessment plan updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_assessment_plan",
                    assessment_plan_id=assessment_plan.id
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to update assessment plan because the code already exists.",
                "danger"
            )

        except Exception as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Error updating assessment plan: %s",
                exc
            )

            flash(
                "An unexpected error occurred while updating the assessment plan.",
                "danger"
            )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "backend/pages/assessment_plans/edit_assessment_plan.html",
        assessment_plan=assessment_plan,
        institutions=institutions,
        programs=programs,
        academic_years=academic_years,
        user=current_user
    )


# ============================================================
# 5. DELETE ASSESSMENT PLAN
# ============================================================

@bp.route(
    "/assessment-plans/delete/<int:assessment_plan_id>",
    methods=["POST"]
)
@login_required
def delete_assessment_plan(assessment_plan_id):

    assessment_plan = AssessmentPlan.query.get_or_404(
        assessment_plan_id
    )

    try:
        db.session.delete(assessment_plan)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "Assessment plan deleted successfully."
        })

    except IntegrityError as exc:

        db.session.rollback()

        current_app.logger.exception(
            "Integrity error deleting assessment plan: %s",
            exc
        )

        return jsonify({
            "success": False,
            "message": (
                "This assessment plan cannot be deleted because "
                "it is already being used by other records."
            )
        }), 409

    except Exception as exc:

        db.session.rollback()

        current_app.logger.exception(
            "Error deleting assessment plan: %s",
            exc
        )

        return jsonify({
            "success": False,
            "message": "An unexpected error occurred while deleting the assessment plan."
        }), 500


# ============================================================
# CLASS ROUTES
# PostgreSQL / Neon
# ============================================================

# ============================================================
# HELPER
# GET CURRENT USER INSTITUTION
# ============================================================

def _get_user_institution_id():

    # --------------------------------------------------------
    # Keep using your existing helper if already defined.
    # --------------------------------------------------------

    if hasattr(current_user, "institution_id"):
        return current_user.institution_id

    return None


# ============================================================
# ALL CLASSES
# ============================================================

@bp.route("/classes")
@login_required
def all_classes():

    # ========================================================
    # USER INSTITUTION
    # ========================================================

    user_institution_id = _get_user_institution_id()

    # ========================================================
    # REQUEST FILTERS
    # ========================================================

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    selected_institution_id = request.args.get(
        "institution_id",
        type=int
    )

    selected_branch_id = request.args.get(
        "branch_id",
        type=int
    )

    selected_program_id = request.args.get(
        "program_id",
        type=int
    )

    selected_academic_year_id = request.args.get(
        "academic_year_id",
        type=int
    )

    selected_status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    # ========================================================
    # PAGINATION
    # ========================================================

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        20,
        type=int
    )

    # --------------------------------------------------------
    # Prevent invalid values
    # --------------------------------------------------------

    if per_page not in [10, 20, 50, 100]:
        per_page = 20

    if page < 1:
        page = 1

    # ========================================================
    # BASE QUERY
    # ========================================================

    base_query = Class.query

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    if user_institution_id is not None:

        base_query = base_query.filter(
            Class.institution_id
            == user_institution_id
        )

    # ========================================================
    # STATISTICS
    # ========================================================

    total_classes = (
        base_query
        .count()
    )

    active_classes = (
        base_query
        .filter(
            Class.status == "active"
        )
        .count()
    )

    inactive_classes = (
        base_query
        .filter(
            Class.status == "inactive"
        )
        .count()
    )

    completed_classes = (
        base_query
        .filter(
            Class.status == "completed"
        )
        .count()
    )

    # ========================================================
    # CAPACITY STATISTICS
    # ========================================================

    classes_with_capacity = (
        base_query
        .filter(
            Class.capacity.isnot(None)
        )
        .count()
    )

    classes_without_capacity = (
        base_query
        .filter(
            Class.capacity.is_(None)
        )
        .count()
    )

    # ========================================================
    # FILTERED QUERY
    # ========================================================

    query = base_query

    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        search_term = f"%{search}%"

        query = query.filter(
            or_(

                Class.name.ilike(
                    search_term
                ),

                Class.code.ilike(
                    search_term
                ),

                Class.level.ilike(
                    search_term
                ),

                Class.description.ilike(
                    search_term
                ),

                Class.institution.has(
                    Institution.name.ilike(
                        search_term
                    )
                ),

                Class.branch.has(
                    Branch.name.ilike(
                        search_term
                    )
                ),

                Class.program.has(
                    Program.name.ilike(
                        search_term
                    )
                ),

                Class.program.has(
                    Program.code.ilike(
                        search_term
                    )
                ),

                Class.academic_year.has(
                    AcademicYear.name.ilike(
                        search_term
                    )
                )

            )
        )

    # ========================================================
    # INSTITUTION FILTER
    # ========================================================

    if selected_institution_id:

        query = query.filter(
            Class.institution_id
            == selected_institution_id
        )

    # ========================================================
    # BRANCH FILTER
    # ========================================================

    if selected_branch_id:

        query = query.filter(
            Class.branch_id
            == selected_branch_id
        )

    # ========================================================
    # PROGRAM FILTER
    # ========================================================

    if selected_program_id:

        query = query.filter(
            Class.program_id
            == selected_program_id
        )

    # ========================================================
    # ACADEMIC YEAR FILTER
    # ========================================================

    if selected_academic_year_id:

        query = query.filter(
            Class.academic_year_id
            == selected_academic_year_id
        )

    # ========================================================
    # STATUS FILTER
    # ========================================================

    allowed_statuses = {
        "active",
        "inactive",
        "completed"
    }

    if selected_status in allowed_statuses:

        query = query.filter(
            Class.status
            == selected_status
        )

    else:

        selected_status = ""

    # ========================================================
    # ORDERING
    # ========================================================

    query = query.order_by(
        Class.created_at.desc(),
        Class.id.desc()
    )

    # ========================================================
    # PAGINATION
    # ========================================================

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    classes = pagination.items

    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institution_query = (
        Institution.query
    )

    if user_institution_id is not None:

        institution_query = (
            institution_query
            .filter(
                Institution.id
                == user_institution_id
            )
        )

    institutions = (
        institution_query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )

    # ========================================================
    # BRANCHES
    # ========================================================

    branch_query = (
        Branch.query
    )

    if user_institution_id is not None:

        branch_query = (
            branch_query
            .filter(
                Branch.institution_id
                == user_institution_id
            )
        )

    branches = (
        branch_query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )

    # ========================================================
    # PROGRAMS
    # ========================================================

    program_query = (
        Program.query
    )

    if user_institution_id is not None:

        program_query = (
            program_query
            .filter(
                Program.institution_id
                == user_institution_id
            )
        )

    programs = (
        program_query
        .order_by(
            Program.name.asc()
        )
        .all()
    )

    # ========================================================
    # ACADEMIC YEARS
    # ========================================================

    academic_year_query = (
        AcademicYear.query
    )

    # --------------------------------------------------------
    # If AcademicYear has institution_id,
    # apply institution security.
    # --------------------------------------------------------

    if (
        user_institution_id is not None
        and hasattr(
            AcademicYear,
            "institution_id"
        )
    ):

        academic_year_query = (
            academic_year_query
            .filter(
                AcademicYear.institution_id
                == user_institution_id
            )
        )

    academic_years = (
        academic_year_query
        .order_by(
            AcademicYear.id.desc()
        )
        .all()
    )

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/classes/all_classes.html",

        classes=classes,
        pagination=pagination,

        institutions=institutions,
        branches=branches,
        programs=programs,
        academic_years=academic_years,

        search=search,

        selected_institution_id=(
            selected_institution_id
            if selected_institution_id
            else ""
        ),

        selected_branch_id=(
            selected_branch_id
            if selected_branch_id
            else ""
        ),

        selected_program_id=(
            selected_program_id
            if selected_program_id
            else ""
        ),

        selected_academic_year_id=(
            selected_academic_year_id
            if selected_academic_year_id
            else ""
        ),

        selected_status=selected_status,

        per_page=per_page,

        total_classes=total_classes,
        active_classes=active_classes,
        inactive_classes=inactive_classes,
        completed_classes=completed_classes,

        classes_with_capacity=classes_with_capacity,
        classes_without_capacity=classes_without_capacity,

        user=current_user
    )


# ============================================================
# ADD CLASS
# ============================================================

@bp.route(
    "/classes/add",
    methods=["GET", "POST"]
)
@login_required
def add_class():

    # ========================================================
    # USER INSTITUTION
    # ========================================================

    user_institution_id = (
        _get_user_institution_id()
    )

    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institution_query = (
        Institution.query
    )

    if user_institution_id is not None:

        institution_query = (
            institution_query
            .filter(
                Institution.id
                == user_institution_id
            )
        )

    institutions = (
        institution_query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ----------------------------------------------------
        # FORM VALUES
        # ----------------------------------------------------

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        branch_id = request.form.get(
            "branch_id",
            type=int
        )

        program_id = request.form.get(
            "program_id",
            type=int
        )

        academic_year_id = request.form.get(
            "academic_year_id",
            type=int
        )

        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()

        code = request.form.get(
            "code",
            "",
            type=str
        ).strip()

        level = request.form.get(
            "level",
            "",
            type=str
        ).strip()

        capacity_raw = request.form.get(
            "capacity",
            "",
            type=str
        ).strip()

        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()

        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()

        # ----------------------------------------------------
        # NORMALIZE
        # ----------------------------------------------------

        code = code.upper()

        if not level:
            level = None

        if not description:
            description = None

        # ====================================================
        # VALIDATION
        # ====================================================

        if not institution_id:

            flash(
                "Institution is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        if not branch_id:

            flash(
                "Branch is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        if not program_id:

            flash(
                "Program is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        if not academic_year_id:

            flash(
                "Academic year is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        if not name:

            flash(
                "Class name is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        if not code:

            flash(
                "Class code is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # STATUS VALIDATION
        # ====================================================

        allowed_statuses = {
            "active",
            "inactive",
            "completed"
        }

        if status not in allowed_statuses:

            flash(
                "Invalid class status.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # CAPACITY
        # ====================================================

        capacity = None

        if capacity_raw:

            try:

                capacity = int(
                    capacity_raw
                )

            except ValueError:

                flash(
                    "Capacity must be a valid number.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "main.add_class"
                    )
                )

            if capacity < 0:

                flash(
                    "Capacity cannot be negative.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "main.add_class"
                    )
                )

        # ====================================================
        # INSTITUTION SECURITY
        # ====================================================

        if (
            user_institution_id is not None
            and institution_id
            != user_institution_id
        ):

            flash(
                "You are not authorized to create a class for this institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.all_classes"
                )
            )

        # ====================================================
        # VERIFY INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id
                == institution_id
            )
            .first()
        )

        if institution is None:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # VERIFY BRANCH
        # ========================================================

        branch = (
            Branch.query
            .filter(
                Branch.id == branch_id
            )
            .first()
        )

        if (
            branch is None
            or branch.institution_id
            != institution_id
        ):

            flash(
                "Selected branch does not belong to the selected institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # VERIFY PROGRAM
        # ========================================================

        program = (
            Program.query
            .filter(
                Program.id
                == program_id
            )
            .first()
        )

        if (
            program is None
            or program.institution_id
            != institution_id
        ):

            flash(
                "Selected program does not belong to the selected institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # VERIFY ACADEMIC YEAR
        # ========================================================

        academic_year = (
            AcademicYear.query
            .filter(
                AcademicYear.id
                == academic_year_id
            )
            .first()
        )

        if academic_year is None:

            flash(
                "Selected academic year was not found.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ----------------------------------------------------
        # If AcademicYear has institution_id,
        # verify ownership.
        # ----------------------------------------------------

        if (
            hasattr(
                AcademicYear,
                "institution_id"
            )
            and getattr(
                academic_year,
                "institution_id",
                None
            ) is not None
            and academic_year.institution_id
            != institution_id
        ):

            flash(
                "Selected academic year does not belong to the selected institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # DUPLICATE CODE CHECK
        # ====================================================

        existing_code = (
            Class.query
            .filter(
                Class.branch_id
                == branch_id,

                Class.academic_year_id
                == academic_year_id,

                Class.code
                == code
            )
            .first()
        )

        if existing_code:

            flash(
                "A class with this code already exists in this branch and academic year.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # DUPLICATE NAME CHECK
        # ====================================================

        existing_name = (
            Class.query
            .filter(
                Class.branch_id
                == branch_id,

                Class.academic_year_id
                == academic_year_id,

                Class.name
                == name
            )
            .first()
        )

        if existing_name:

            flash(
                "A class with this name already exists in this branch and academic year.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        # ====================================================
        # CREATE CLASS
        # ====================================================

        new_class = Class(

            institution_id=institution_id,

            branch_id=branch_id,

            program_id=program_id,

            academic_year_id=academic_year_id,

            name=name,

            code=code,

            level=level,

            capacity=capacity,

            description=description,

            status=status
        )

        try:

            db.session.add(
                new_class
            )

            db.session.commit()

            flash(
                "Class created successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_class",
                    class_id=new_class.id
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to create class. The class code or name may already exist.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

        except Exception:

            db.session.rollback()

            current_app.logger.exception(
                "Error creating class"
            )

            flash(
                "An unexpected error occurred while creating the class.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.add_class"
                )
            )

    # ========================================================
    # GET DATA
    # ========================================================

    branch_query = Branch.query

    if user_institution_id is not None:

        branch_query = (
            branch_query
            .filter(
                Branch.institution_id
                == user_institution_id
            )
        )

    branches = (
        branch_query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )

    program_query = Program.query

    if user_institution_id is not None:

        program_query = (
            program_query
            .filter(
                Program.institution_id
                == user_institution_id
            )
        )

    programs = (
        program_query
        .order_by(
            Program.name.asc()
        )
        .all()
    )

    academic_year_query = (
        AcademicYear.query
    )

    if (
        user_institution_id is not None
        and hasattr(
            AcademicYear,
            "institution_id"
        )
    ):

        academic_year_query = (
            academic_year_query
            .filter(
                AcademicYear.institution_id
                == user_institution_id
            )
        )

    academic_years = (
        academic_year_query
        .order_by(
            AcademicYear.id.desc()
        )
        .all()
    )

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/classes/add_class.html",

        institutions=institutions,

        branches=branches,

        programs=programs,

        academic_years=academic_years,

        user=current_user
    )


# ============================================================
# VIEW CLASS
# ============================================================

@bp.route(
    "/classes/<int:class_id>"
)
@login_required
def view_class(class_id):

    # ========================================================
    # FIND CLASS
    # ========================================================

    class_obj = (
        Class.query
        .filter(
            Class.id == class_id
        )
        .first_or_404()
    )

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    user_institution_id = (
        _get_user_institution_id()
    )

    if (
        user_institution_id is not None
        and class_obj.institution_id
        != user_institution_id
    ):

        flash(
            "You are not authorized to view this class.",
            "danger"
        )

        return redirect(
            url_for(
                "main.all_classes"
            )
        )

    # ========================================================
    # RELATED DATA
    # ========================================================

    institution = (
        class_obj.institution
    )

    branch = (
        class_obj.branch
    )

    program = (
        class_obj.program
    )

    academic_year = (
        class_obj.academic_year
    )

    # ========================================================
    # RELATED CLASSES
    # SAME BRANCH + ACADEMIC YEAR
    # ========================================================

    related_classes = (
        Class.query
        .filter(

            Class.branch_id
            == class_obj.branch_id,

            Class.academic_year_id
            == class_obj.academic_year_id,

            Class.id
            != class_obj.id
        )
        .order_by(
            Class.name.asc(),
            Class.id.asc()
        )
        .all()
    )

    # ========================================================
    # PROGRAM CLASSES
    # ========================================================

    program_classes = (
        Class.query
        .filter(

            Class.program_id
            == class_obj.program_id,

            Class.id
            != class_obj.id
        )
        .order_by(
            Class.name.asc()
        )
        .all()
    )

    # ========================================================
    # CLASS STATS
    # ========================================================

    total_related_classes = (
        len(related_classes) + 1
    )

    total_program_classes = (
        len(program_classes) + 1
    )

    return render_template(
        "backend/pages/classes/view_class.html",

        class_obj=class_obj,

        institution=institution,

        branch=branch,

        program=program,

        academic_year=academic_year,

        related_classes=related_classes,

        program_classes=program_classes,

        total_related_classes=(
            total_related_classes
        ),

        total_program_classes=(
            total_program_classes
        ),

        user=current_user
    )


# ============================================================
# EDIT CLASS
# ============================================================

@bp.route(
    "/classes/<int:class_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_class(class_id):

    # ========================================================
    # FIND CLASS
    # ========================================================

    class_obj = (
        Class.query
        .filter(
            Class.id == class_id
        )
        .first_or_404()
    )

    # ========================================================
    # USER INSTITUTION
    # ========================================================

    user_institution_id = _get_user_institution_id()

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    if (
        user_institution_id is not None
        and class_obj.institution_id != user_institution_id
    ):
        flash(
            "You are not authorized to edit this class.",
            "danger"
        )

        return redirect(
            url_for("main.all_classes")
        )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM VALUES
        # ====================================================

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        branch_id = request.form.get(
            "branch_id",
            type=int
        )

        program_id = request.form.get(
            "program_id",
            type=int
        )

        academic_year_id = request.form.get(
            "academic_year_id",
            type=int
        )

        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()

        level = request.form.get(
            "level",
            "",
            type=str
        ).strip()

        capacity_raw = request.form.get(
            "capacity",
            "",
            type=str
        ).strip()

        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()

        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()

        # ====================================================
        # NORMALIZE
        # ====================================================

        if not level:
            level = None

        if not description:
            description = None

        # ====================================================
        # REQUIRED FIELDS
        # ====================================================

        if not institution_id:
            flash(
                "Institution is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        if not branch_id:
            flash(
                "Branch is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        if not program_id:
            flash(
                "Program is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        if not academic_year_id:
            flash(
                "Academic year is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        if not name:
            flash(
                "Class name is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # AUTO GENERATE CLASS CODE
        # ====================================================

        import re
        import unicodedata

        def generate_class_code(value):

            value = unicodedata.normalize(
                "NFD",
                value
            ).encode(
                "ascii",
                "ignore"
            ).decode("ascii")

            value = value.upper()

            value = value.replace(
                "&",
                " AND "
            )

            value = value.replace(
                "+",
                " PLUS "
            )

            value = re.sub(
                r"[^A-Z0-9\s-]",
                "",
                value
            )

            value = re.sub(
                r"\s+",
                "-",
                value.strip()
            )

            value = re.sub(
                r"-+",
                "-",
                value
            )

            value = value.strip("-")

            return value[:50]

        code = generate_class_code(name)

        # ====================================================
        # CODE VALIDATION
        # ====================================================

        if not code:
            flash(
                "Unable to generate a valid class code from the class name.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # STATUS
        # ====================================================

        allowed_statuses = {
            "active",
            "inactive",
            "completed"
        }

        if status not in allowed_statuses:

            flash(
                "Invalid class status.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # CAPACITY
        # ====================================================

        capacity = None

        if capacity_raw:

            try:
                capacity = int(
                    capacity_raw
                )

            except (ValueError, TypeError):

                flash(
                    "Capacity must be a valid whole number.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "main.edit_class",
                        class_id=class_id
                    )
                )

            if capacity < 0:

                flash(
                    "Capacity cannot be negative.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "main.edit_class",
                        class_id=class_id
                    )
                )

        # ====================================================
        # INSTITUTION SECURITY
        # ====================================================

        if (
            user_institution_id is not None
            and institution_id != user_institution_id
        ):

            flash(
                "You are not authorized to move this class to another institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.all_classes"
                )
            )

        # ====================================================
        # VERIFY INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .first()
        )

        if institution is None:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # VERIFY BRANCH
        # ====================================================

        branch = (
            Branch.query
            .filter(
                Branch.id == branch_id
            )
            .first()
        )

        if (
            branch is None
            or branch.institution_id != institution_id
        ):

            flash(
                "Selected branch does not belong to the selected institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # VERIFY PROGRAM
        # ====================================================

        program = (
            Program.query
            .filter(
                Program.id == program_id
            )
            .first()
        )

        if (
            program is None
            or program.institution_id != institution_id
        ):

            flash(
                "Selected program does not belong to the selected institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # VERIFY ACADEMIC YEAR
        # ====================================================

        academic_year = (
            AcademicYear.query
            .filter(
                AcademicYear.id == academic_year_id
            )
            .first()
        )

        if academic_year is None:

            flash(
                "Selected academic year was not found.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # ACADEMIC YEAR INSTITUTION SECURITY
        # ====================================================

        if (
            hasattr(
                AcademicYear,
                "institution_id"
            )
            and getattr(
                academic_year,
                "institution_id",
                None
            ) is not None
            and academic_year.institution_id != institution_id
        ):

            flash(
                "Selected academic year does not belong to the selected institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # DUPLICATE CODE
        # ====================================================

        duplicate_code = (
            Class.query
            .filter(
                Class.branch_id == branch_id,
                Class.academic_year_id == academic_year_id,
                Class.code == code,
                Class.id != class_obj.id
            )
            .first()
        )

        if duplicate_code:

            flash(
                f'Another class with code "{code}" already exists in this branch and academic year.',
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # DUPLICATE NAME
        # ====================================================

        duplicate_name = (
            Class.query
            .filter(
                Class.branch_id == branch_id,
                Class.academic_year_id == academic_year_id,
                Class.name == name,
                Class.id != class_obj.id
            )
            .first()
        )

        if duplicate_name:

            flash(
                f'Another class named "{name}" already exists in this branch and academic year.',
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        # ====================================================
        # UPDATE CLASS
        # ====================================================

        class_obj.institution_id = institution_id

        class_obj.branch_id = branch_id

        class_obj.program_id = program_id

        class_obj.academic_year_id = academic_year_id

        class_obj.name = name

        class_obj.code = code

        class_obj.level = level

        # ====================================================
        # CAPACITY
        # ====================================================

        class_obj.capacity = capacity

        class_obj.description = description

        class_obj.status = status

        # ====================================================
        # COMMIT
        # ====================================================

        try:

            db.session.commit()

            flash(
                "Class updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_class",
                    class_id=class_obj.id
                )
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to update class. The class code or name may already exist.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

        except Exception:

            db.session.rollback()

            current_app.logger.exception(
                "Error updating class"
            )

            flash(
                "An unexpected error occurred while updating the class.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_class",
                    class_id=class_id
                )
            )

    # ========================================================
    # GET DATA
    # ========================================================

    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institution_query = Institution.query

    if user_institution_id is not None:

        institution_query = (
            institution_query
            .filter(
                Institution.id == user_institution_id
            )
        )

    institutions = (
        institution_query
        .order_by(
            Institution.name.asc()
        )
        .all()
    )

    # ========================================================
    # BRANCHES
    # ========================================================

    branch_query = Branch.query

    if user_institution_id is not None:

        branch_query = (
            branch_query
            .filter(
                Branch.institution_id
                == user_institution_id
            )
        )

    branches = (
        branch_query
        .order_by(
            Branch.name.asc()
        )
        .all()
    )

    # ========================================================
    # PROGRAMS
    # ========================================================

    program_query = Program.query

    if user_institution_id is not None:

        program_query = (
            program_query
            .filter(
                Program.institution_id
                == user_institution_id
            )
        )

    programs = (
        program_query
        .order_by(
            Program.name.asc()
        )
        .all()
    )

    # ========================================================
    # ACADEMIC YEARS
    # ========================================================

    academic_year_query = AcademicYear.query

    if (
        user_institution_id is not None
        and hasattr(
            AcademicYear,
            "institution_id"
        )
    ):

        academic_year_query = (
            academic_year_query
            .filter(
                AcademicYear.institution_id
                == user_institution_id
            )
        )

    academic_years = (
        academic_year_query
        .order_by(
            AcademicYear.id.desc()
        )
        .all()
    )

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/classes/edit_class.html",

        class_obj=class_obj,

        institutions=institutions,

        branches=branches,

        programs=programs,

        academic_years=academic_years,

        user=current_user
    )


# ============================================================
# DELETE CLASS
# ============================================================

@bp.route(
    "/classes/<int:class_id>/delete",
    methods=["POST"]
)
@login_required
def delete_class(class_id):

    # ========================================================
    # FIND CLASS
    # ========================================================

    class_obj = (
        Class.query
        .filter(
            Class.id == class_id
        )
        .first_or_404()
    )

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    user_institution_id = (
        _get_user_institution_id()
    )

    if (
        user_institution_id is not None
        and class_obj.institution_id
        != user_institution_id
    ):

        return jsonify(
            {
                "success": False,
                "message": (
                    "You are not authorized "
                    "to delete this class."
                )
            }
        ), 403

    # ========================================================
    # DELETE
    # ========================================================

    try:

        db.session.delete(
            class_obj
        )

        db.session.commit()

        return jsonify(
            {
                "success": True,
                "message": (
                    "Class deleted successfully."
                )
            }
        )

    except IntegrityError:

        db.session.rollback()

        return jsonify(
            {
                "success": False,
                "message": (
                    "This class cannot be deleted "
                    "because it is linked to other "
                    "records."
                )
            }
        ), 409

    except Exception:

        db.session.rollback()

        current_app.logger.exception(
            "Error deleting class"
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "An unexpected error occurred "
                    "while deleting the class."
                )
            }
        ), 500



# ============================================================
# SECTION ROUTES
# PostgreSQL / Neon
# ============================================================

# ============================================================
# SECTION CODE GENERATOR
# ============================================================

def generate_section_code(name):
    """
    Generate automatic section code.

    Examples:
        A           -> A
        B           -> B
        Morning A   -> MORNING-A
        Evening B   -> EVENING-B
        Section 1   -> SECTION-1
    """

    if not name:
        return ""

    value = unicodedata.normalize(
        "NFD",
        name
    ).encode(
        "ascii",
        "ignore"
    ).decode("ascii")

    value = value.upper()

    value = value.replace(
        "&",
        " AND "
    )

    value = value.replace(
        "+",
        " PLUS "
    )

    value = re.sub(
        r"[^A-Z0-9\s-]",
        "",
        value
    )

    value = re.sub(
        r"\s+",
        "-",
        value.strip()
    )

    value = re.sub(
        r"-+",
        "-",
        value
    )

    value = value.strip("-")

    return value[:50]


# ============================================================
# USER INSTITUTION HELPER
# ============================================================

def _section_user_institution_id():
    """
    Use the existing application institution helper.

    Superadmin/global users:
        returns None

    Institution-scoped users:
        returns institution ID
    """

    return _get_user_institution_id()


# ============================================================
# COMMON SECTION TEMPLATE CONTEXT
# ============================================================

def _section_template_context(
    institutions=None,
    branches=None,
    classes=None,
    academic_years=None,
):
    """
    Common template context.

    IMPORTANT:
        user=current_user is intentionally passed to every
        Section template.
    """

    return {
        "institutions": institutions or [],
        "branches": branches or [],
        "classes": classes or [],
        "academic_years": academic_years or [],
        "user": current_user,
    }


# ============================================================
# GET SECTION
# Institution scoped
# ============================================================

def _get_section_or_404(section_id):

    institution_id = _section_user_institution_id()

    query = Section.query

    # --------------------------------------------------------
    # Institution security
    # --------------------------------------------------------

    if institution_id is not None:

        query = query.filter(
            Section.institution_id == institution_id
        )

    return query.filter(
        Section.id == section_id
    ).first_or_404()


# ============================================================
# GET ALLOWED INSTITUTIONS
# ============================================================

def _section_allowed_institutions():

    institution_id = _section_user_institution_id()

    # --------------------------------------------------------
    # Superadmin / global user
    # --------------------------------------------------------

    if institution_id is None:

        return (
            Institution.query
            .order_by(
                Institution.name.asc()
            )
            .all()
        )

    # --------------------------------------------------------
    # Institution-scoped user
    # --------------------------------------------------------

    return (
        Institution.query
        .filter(
            Institution.id == institution_id
        )
        .order_by(
            Institution.name.asc()
        )
        .all()
    )


# ============================================================
# GET SECTION FORM DATA
# ============================================================

def _get_section_form_data():

    user_institution_id = (
        _section_user_institution_id()
    )

    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institutions = (
        _section_allowed_institutions()
    )

    allowed_institution_ids = [
        item.id
        for item in institutions
    ]

    # ========================================================
    # BRANCHES
    # ========================================================

    if allowed_institution_ids:

        branches = (
            Branch.query
            .filter(
                Branch.institution_id.in_(
                    allowed_institution_ids
                )
            )
            .order_by(
                Branch.name.asc()
            )
            .all()
        )

    else:

        branches = []

    # ========================================================
    # CLASSES
    # ========================================================

    if allowed_institution_ids:

        classes = (
            Class.query
            .filter(
                Class.institution_id.in_(
                    allowed_institution_ids
                )
            )
            .order_by(
                Class.name.asc()
            )
            .all()
        )

    else:

        classes = []

    # ========================================================
    # ACADEMIC YEARS
    # ========================================================

    academic_year_query = AcademicYear.query

    if (
        hasattr(
            AcademicYear,
            "institution_id"
        )
        and user_institution_id is not None
    ):

        academic_year_query = (
            academic_year_query.filter(
                AcademicYear.institution_id
                == user_institution_id
            )
        )

    academic_years = (
        academic_year_query
        .order_by(
            AcademicYear.id.desc()
        )
        .all()
    )

    return (
        institutions,
        branches,
        classes,
        academic_years,
    )


# ============================================================
# ALL SECTIONS
# ============================================================

@bp.route(
    "/sections",
    methods=["GET"]
)
@login_required
def all_sections():

    user_institution_id = (
        _section_user_institution_id()
    )

    # ========================================================
    # FILTERS
    # ========================================================

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()

    branch_id = request.args.get(
        "branch_id",
        "",
        type=str
    ).strip()

    class_id = request.args.get(
        "class_id",
        "",
        type=str
    ).strip()

    academic_year_id = request.args.get(
        "academic_year_id",
        "",
        type=str
    ).strip()

    # ========================================================
    # QUERY
    # ========================================================

    query = Section.query

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    if user_institution_id is not None:

        query = query.filter(
            Section.institution_id
            == user_institution_id
        )

        # Prevent institution user from manipulating
        # institution filter through URL.

        institution_id = str(
            user_institution_id
        )

    elif institution_id:

        try:

            institution_id_int = int(
                institution_id
            )

            query = query.filter(
                Section.institution_id
                == institution_id_int
            )

        except (
            ValueError,
            TypeError
        ):

            institution_id = ""

    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        pattern = f"%{search}%"

        query = query.filter(
            db.or_(
                Section.name.ilike(pattern),
                Section.code.ilike(pattern),
                Section.description.ilike(pattern),
            )
        )

    # ========================================================
    # STATUS
    # ========================================================

    if status in {
        "active",
        "inactive",
        "suspended",
    }:

        query = query.filter(
            Section.status == status
        )

    # ========================================================
    # BRANCH
    # ========================================================

    if branch_id:

        try:

            query = query.filter(
                Section.branch_id
                == int(branch_id)
            )

        except (
            ValueError,
            TypeError
        ):

            branch_id = ""

    # ========================================================
    # CLASS
    # ========================================================

    if class_id:

        try:

            query = query.filter(
                Section.class_id
                == int(class_id)
            )

        except (
            ValueError,
            TypeError
        ):

            class_id = ""

    # ========================================================
    # ACADEMIC YEAR
    # ========================================================

    if academic_year_id:

        try:

            query = query.filter(
                Section.academic_year_id
                == int(academic_year_id)
            )

        except (
            ValueError,
            TypeError
        ):

            academic_year_id = ""

    # ========================================================
    # ORDER
    # ========================================================

    query = query.order_by(
        Section.created_at.desc(),
        Section.id.desc()
    )

    # ========================================================
    # PAGINATION
    # ========================================================

    page = request.args.get(
        "page",
        1,
        type=int
    )

    if page < 1:
        page = 1

    per_page = request.args.get(
        "per_page",
        20,
        type=int
    )

    if per_page not in [
        10,
        20,
        50,
        100,
    ]:

        per_page = 20

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    sections = pagination.items

    # ========================================================
    # FORM / FILTER DATA
    # ========================================================

    (
        institutions,
        branches,
        classes,
        academic_years,
    ) = _get_section_form_data()

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/sections/all_sections.html",

        sections=sections,

        pagination=pagination,

        institutions=institutions,

        branches=branches,

        classes=classes,

        academic_years=academic_years,

        search=search,

        status=status,

        institution_filter=institution_id,

        branch_filter=branch_id,

        class_filter=class_id,

        academic_year_filter=academic_year_id,

        per_page=per_page,

        # IMPORTANT
        user=current_user,
    )


# ============================================================
# ADD SECTION
# ============================================================

# ============================================================
# SECTION ROUTES
# PostgreSQL / Neon
# ============================================================

# ============================================================
# SECTION CODE GENERATOR
# ============================================================

# ============================================================
# USER INSTITUTION HELPER
# ============================================================

def _get_user_institution_id():
    """
    Return institution ID for institution-scoped users.

    Global users / superadmins:
        None

    Institution-scoped users:
        their institution ID
    """

    role = getattr(current_user, "role", None)

    # Global users
    if role in [
        "superadmin",
        "super_admin",
        "admin",
        "system_admin",
    ]:
        return None

    return getattr(
        current_user,
        "institution_id",
        None
    )


# ============================================================
# ALLOWED INSTITUTIONS
# ============================================================

def _get_allowed_institutions():
    """
    Return institutions visible to current user.
    """

    institution_id = _get_user_institution_id()

    query = Institution.query

    if institution_id:
        query = query.filter(
            Institution.id == institution_id
        )

    return query.order_by(
        Institution.name.asc()
    ).all()


# ============================================================
# SECTION FORM DATA
# ============================================================

def _get_section_form_data():
    """
    Load all data required by add/edit section forms.
    """

    institution_id = _get_user_institution_id()

    # --------------------------------------------------------
    # Institutions
    # --------------------------------------------------------

    institution_query = Institution.query

    if institution_id:
        institution_query = institution_query.filter(
            Institution.id == institution_id
        )

    institutions = institution_query.order_by(
        Institution.name.asc()
    ).all()

    # --------------------------------------------------------
    # Branches
    # --------------------------------------------------------

    branch_query = Branch.query

    if institution_id:
        branch_query = branch_query.filter(
            Branch.institution_id == institution_id
        )

    branches = branch_query.order_by(
        Branch.name.asc()
    ).all()

    # --------------------------------------------------------
    # Classes
    # --------------------------------------------------------

    class_query = Class.query

    if institution_id:
        class_query = class_query.filter(
            Class.institution_id == institution_id
        )

    classes = class_query.order_by(
        Class.name.asc()
    ).all()

    # --------------------------------------------------------
    # Academic Years
    # --------------------------------------------------------

    academic_year_query = AcademicYear.query

    # Only apply institution filter when the model has
    # institution_id.
    if hasattr(AcademicYear, "institution_id"):
        if institution_id:
            academic_year_query = academic_year_query.filter(
                AcademicYear.institution_id == institution_id
            )

    academic_years = academic_year_query.order_by(
        AcademicYear.name.desc()
    ).all()

    return (
        institutions,
        branches,
        classes,
        academic_years,
    )


# ============================================================
# SECTION TEMPLATE CONTEXT
# ============================================================

def _section_template_context(**kwargs):

    (
        institutions,
        branches,
        classes,
        academic_years,
    ) = _get_section_form_data()

    context = {
        "institutions": institutions,
        "branches": branches,
        "classes": classes,
        "academic_years": academic_years,
        "user": current_user,
    }

    context.update(kwargs)

    return context


# ============================================================
# ADD SECTION
# ============================================================

@bp.route(
    "/sections/add",
    methods=["GET", "POST"]
)
@login_required
def add_section():

    # ========================================================
    # GET FORM DATA
    # ========================================================

    (
        institutions,
        branches,
        classes,
        academic_years,
    ) = _get_section_form_data()

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ----------------------------------------------------
        # FORM VALUES
        # ----------------------------------------------------

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        branch_id = request.form.get(
            "branch_id",
            type=int
        )

        class_id = request.form.get(
            "class_id",
            type=int
        )

        academic_year_id = request.form.get(
            "academic_year_id",
            type=int
        )

        name = (
            request.form.get("name", "")
            .strip()
        )

        capacity_raw = (
            request.form.get("capacity", "")
            .strip()
        )

        description = (
            request.form.get("description", "")
            .strip()
        )

        status = (
            request.form.get("status", "active")
            .strip()
            .lower()
        )

        # ----------------------------------------------------
        # USER INSTITUTION SECURITY
        # ----------------------------------------------------

        user_institution_id = _get_user_institution_id()

        if user_institution_id:

            if institution_id != user_institution_id:

                flash(
                    "You are not allowed to use another institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/add_section.html",
                    **_section_template_context(
                        institution_id=user_institution_id,
                        branch_id=branch_id,
                        class_id=class_id,
                        academic_year_id=academic_year_id,
                        name=name,
                        capacity=capacity_raw,
                        description=description,
                        status=status,
                    )
                )

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not institution_id:

            flash(
                "Please select an institution.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        if not branch_id:

            flash(
                "Please select a branch.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        if not class_id:

            flash(
                "Please select a class.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        if not academic_year_id:

            flash(
                "Please select an academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        if not name:

            flash(
                "Section name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ----------------------------------------------------
        # NAME LENGTH
        # ----------------------------------------------------

        if len(name) > 150:

            flash(
                "Section name cannot exceed 150 characters.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ----------------------------------------------------
        # STATUS VALIDATION
        # ----------------------------------------------------

        allowed_statuses = {
            "active",
            "inactive",
            "suspended",
        }

        if status not in allowed_statuses:

            flash(
                "Invalid section status.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status="active",
                )
            )

        # ----------------------------------------------------
        # CAPACITY
        # ----------------------------------------------------

        capacity = None

        if capacity_raw:

            try:

                capacity = int(capacity_raw)

            except (TypeError, ValueError):

                flash(
                    "Capacity must be a valid whole number.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/add_section.html",
                    **_section_template_context(
                        institution_id=institution_id,
                        branch_id=branch_id,
                        class_id=class_id,
                        academic_year_id=academic_year_id,
                        name=name,
                        capacity=capacity_raw,
                        description=description,
                        status=status,
                    )
                )

            if capacity < 0:

                flash(
                    "Capacity cannot be negative.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/add_section.html",
                    **_section_template_context(
                        institution_id=institution_id,
                        branch_id=branch_id,
                        class_id=class_id,
                        academic_year_id=academic_year_id,
                        name=name,
                        capacity=capacity_raw,
                        description=description,
                        status=status,
                    )
                )

        # ====================================================
        # INSTITUTION VALIDATION
        # ====================================================

        institution = Institution.query.filter(
            Institution.id == institution_id
        ).first()

        if not institution:

            flash(
                "Selected institution was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # BRANCH VALIDATION
        # ====================================================

        branch = Branch.query.filter(
            Branch.id == branch_id
        ).first()

        if not branch:

            flash(
                "Selected branch was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        if branch.institution_id != institution_id:

            flash(
                "Selected branch does not belong to the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # CLASS VALIDATION
        # ====================================================

        class_obj = Class.query.filter(
            Class.id == class_id
        ).first()

        if not class_obj:

            flash(
                "Selected class was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # Class institution
        if class_obj.institution_id != institution_id:

            flash(
                "Selected class does not belong to the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # Class branch
        if class_obj.branch_id != branch_id:

            flash(
                "Selected class does not belong to the selected branch.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # ACADEMIC YEAR VALIDATION
        # ====================================================

        academic_year = AcademicYear.query.filter(
            AcademicYear.id == academic_year_id
        ).first()

        if not academic_year:

            flash(
                "Selected academic year was not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ----------------------------------------------------
        # Academic year institution
        # ----------------------------------------------------

        if hasattr(
            AcademicYear,
            "institution_id"
        ):

            if academic_year.institution_id != institution_id:

                flash(
                    "Selected academic year does not belong to the selected institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/add_section.html",
                    **_section_template_context(
                        institution_id=institution_id,
                        branch_id=branch_id,
                        class_id=class_id,
                        academic_year_id=academic_year_id,
                        name=name,
                        capacity=capacity_raw,
                        description=description,
                        status=status,
                    )
                )

        # ====================================================
        # CLASS / ACADEMIC YEAR MATCH
        # ====================================================

        if hasattr(
            Class,
            "academic_year_id"
        ):

            if class_obj.academic_year_id != academic_year_id:

                flash(
                    "Selected class does not belong to the selected academic year.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/add_section.html",
                    **_section_template_context(
                        institution_id=institution_id,
                        branch_id=branch_id,
                        class_id=class_id,
                        academic_year_id=academic_year_id,
                        name=name,
                        capacity=capacity_raw,
                        description=description,
                        status=status,
                    )
                )

        # ====================================================
        # AUTO GENERATE CODE
        # ====================================================

        code = generate_section_code(name)

        if not code:

            flash(
                "Unable to generate section code from the section name.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # DUPLICATE CHECK
        # ====================================================

        duplicate_query = Section.query.filter(
            Section.class_id == class_id,
            Section.academic_year_id == academic_year_id,
            func.lower(Section.name) == name.lower()
        )

        existing_section = duplicate_query.first()

        if existing_section:

            flash(
                "A section with this name already exists for the selected class and academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # DUPLICATE CODE CHECK
        # ====================================================

        existing_code = Section.query.filter(
            Section.class_id == class_id,
            Section.academic_year_id == academic_year_id,
            func.upper(Section.code) == code.upper()
        ).first()

        if existing_code:

            flash(
                f"The generated section code '{code}' already exists for this class and academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # CREATE SECTION
        # ====================================================

        section = Section(
            institution_id=institution_id,
            branch_id=branch_id,
            class_id=class_id,
            academic_year_id=academic_year_id,
            name=name,
            code=code,
            capacity=capacity,
            description=description or None,
            status=status,
        )

        # ====================================================
        # SAVE
        # ====================================================

        try:

            db.session.add(section)

            db.session.commit()

        except Exception as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Error creating section: %s",
                exc
            )

            flash(
                "An error occurred while creating the section. Please try again.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/add_section.html",
                **_section_template_context(
                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,
                )
            )

        # ====================================================
        # SUCCESS
        # ====================================================

        flash(
            f"Section '{section.name}' ({section.code}) was created successfully.",
            "success"
        )

        return redirect(
            url_for(
                "main.view_section",
                section_id=section.id
            )
        )

    # ========================================================
    # GET
    # ========================================================

    default_institution_id = _get_user_institution_id()

    # If user is scoped to one institution, preselect it.
    if (
        not default_institution_id
        and len(institutions) == 1
    ):
        default_institution_id = institutions[0].id

    return render_template(
        "backend/pages/sections/add_section.html",
        **_section_template_context(
            institution_id=default_institution_id,
            branch_id=None,
            class_id=None,
            academic_year_id=None,
            name="",
            capacity="",
            description="",
            status="active",
        )
    )




# ============================================================
# VIEW SECTION
# ============================================================

@bp.route(
    "/sections/<int:section_id>",
    methods=["GET"]
)
@login_required
def view_section(section_id):

    section = _get_section_or_404(
        section_id
    )

    return render_template(
        "backend/pages/sections/view_section.html",

        section=section,

        # IMPORTANT
        user=current_user,
    )


# ============================================================
# EDIT SECTION
# ============================================================

@bp.route(
    "/sections/<int:section_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_section(section_id):

    section = _get_section_or_404(
        section_id
    )

    user_institution_id = (
        _section_user_institution_id()
    )

    # ========================================================
    # FORM DATA
    # ========================================================

    (
        institutions,
        branches,
        classes,
        academic_years,
    ) = _get_section_form_data()

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        branch_id = request.form.get(
            "branch_id",
            type=int
        )

        class_id = request.form.get(
            "class_id",
            type=int
        )

        academic_year_id = request.form.get(
            "academic_year_id",
            type=int
        )

        name = request.form.get(
            "name",
            "",
            type=str
        ).strip()

        capacity_raw = request.form.get(
            "capacity",
            "",
            type=str
        ).strip()

        description = request.form.get(
            "description",
            "",
            type=str
        ).strip()

        status = request.form.get(
            "status",
            "active",
            type=str
        ).strip().lower()

        # ====================================================
        # INSTITUTION SECURITY
        # ====================================================

        if (
            user_institution_id is not None
            and institution_id
            != user_institution_id
        ):

            flash(
                "You are not allowed to move this section to another institution.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.view_section",
                    section_id=section.id
                )
            )

        # ====================================================
        # REQUIRED
        # ====================================================

        if not institution_id:

            flash(
                "Institution is required.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        if not branch_id:

            flash(
                "Branch is required.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        if not class_id:

            flash(
                "Class is required.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        if not academic_year_id:

            flash(
                "Academic year is required.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        if not name:

            flash(
                "Section name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # STATUS
        # ====================================================

        if status not in {
            "active",
            "inactive",
            "suspended",
        }:

            flash(
                "Invalid section status.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # CAPACITY
        # ====================================================

        capacity = None

        if capacity_raw:

            try:

                capacity = int(
                    capacity_raw
                )

            except (
                ValueError,
                TypeError
            ):

                flash(
                    "Capacity must be a valid number.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/edit_section.html",

                    section=section,

                    **_section_template_context(
                        institutions,
                        branches,
                        classes,
                        academic_years,
                    ),

                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,

                    user=current_user,
                )

            if capacity < 0:

                flash(
                    "Capacity cannot be negative.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/edit_section.html",

                    section=section,

                    **_section_template_context(
                        institutions,
                        branches,
                        classes,
                        academic_years,
                    ),

                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,

                    user=current_user,
                )

        # ====================================================
        # INSTITUTION
        # ====================================================

        institution = (
            Institution.query
            .filter(
                Institution.id
                == institution_id
            )
            .first()
        )

        if not institution:

            flash(
                "Institution not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # BRANCH
        # ====================================================

        branch = (
            Branch.query
            .filter(
                Branch.id == branch_id
            )
            .first()
        )

        if not branch:

            flash(
                "Branch not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # BRANCH → INSTITUTION
        # ====================================================

        if branch.institution_id != institution_id:

            flash(
                "Selected branch does not belong to the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # CLASS
        # ====================================================

        class_obj = (
            Class.query
            .filter(
                Class.id == class_id
            )
            .first()
        )

        if not class_obj:

            flash(
                "Class not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # CLASS → INSTITUTION
        # ====================================================

        if class_obj.institution_id != institution_id:

            flash(
                "Selected class does not belong to the selected institution.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # CLASS → BRANCH
        # ====================================================

        if class_obj.branch_id != branch_id:

            flash(
                "Selected class does not belong to the selected branch.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # ACADEMIC YEAR
        # ====================================================

        academic_year = (
            AcademicYear.query
            .filter(
                AcademicYear.id
                == academic_year_id
            )
            .first()
        )

        if not academic_year:

            flash(
                "Academic year not found.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # ACADEMIC YEAR → INSTITUTION
        # ====================================================

        if hasattr(
            AcademicYear,
            "institution_id"
        ):

            if (
                academic_year.institution_id
                != institution_id
            ):

                flash(
                    "Selected academic year does not belong to the selected institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/sections/edit_section.html",

                    section=section,

                    **_section_template_context(
                        institutions,
                        branches,
                        classes,
                        academic_years,
                    ),

                    institution_id=institution_id,
                    branch_id=branch_id,
                    class_id=class_id,
                    academic_year_id=academic_year_id,
                    name=name,
                    capacity=capacity_raw,
                    description=description,
                    status=status,

                    user=current_user,
                )

        # ====================================================
        # CLASS → ACADEMIC YEAR
        # ====================================================

        if (
            class_obj.academic_year_id
            != academic_year_id
        ):

            flash(
                "Selected class belongs to a different academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # AUTO CODE
        # ====================================================

        code = generate_section_code(
            name
        )

        if not code:

            flash(
                "Unable to generate section code.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # DUPLICATE NAME
        # ====================================================

        existing_name = (
            Section.query
            .filter(
                Section.class_id
                == class_id,

                Section.academic_year_id
                == academic_year_id,

                db.func.lower(
                    Section.name
                )
                == name.lower(),

                Section.id != section.id,
            )
            .first()
        )

        if existing_name:

            flash(
                "Another section with this name already exists in this class and academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # DUPLICATE CODE
        # ====================================================

        existing_code = (
            Section.query
            .filter(
                Section.class_id
                == class_id,

                Section.academic_year_id
                == academic_year_id,

                db.func.lower(
                    Section.code
                )
                == code.lower(),

                Section.id != section.id,
            )
            .first()
        )

        if existing_code:

            flash(
                "Another section with this code already exists in this class and academic year.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # UPDATE
        # ====================================================

        section.institution_id = (
            institution_id
        )

        section.branch_id = (
            branch_id
        )

        section.class_id = (
            class_id
        )

        section.academic_year_id = (
            academic_year_id
        )

        section.name = name

        section.code = code

        section.capacity = capacity

        section.description = (
            description or None
        )

        section.status = status

        # ====================================================
        # COMMIT
        # ====================================================

        try:

            db.session.commit()

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to update section because of a duplicate or database constraint.",
                "danger"
            )

            return render_template(
                "backend/pages/sections/edit_section.html",

                section=section,

                **_section_template_context(
                    institutions,
                    branches,
                    classes,
                    academic_years,
                ),

                institution_id=institution_id,
                branch_id=branch_id,
                class_id=class_id,
                academic_year_id=academic_year_id,
                name=name,
                capacity=capacity_raw,
                description=description,
                status=status,

                user=current_user,
            )

        # ====================================================
        # SUCCESS
        # ====================================================

        flash(
            f'Section "{section.name}" was updated successfully.',
            "success"
        )

        return redirect(
            url_for(
                "main.view_section",
                section_id=section.id
            )
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/sections/edit_section.html",

        section=section,

        **_section_template_context(
            institutions,
            branches,
            classes,
            academic_years,
        ),

        # IMPORTANT
        user=current_user,
    )


# ============================================================
# DELETE SECTION
# ============================================================

@bp.route(
    "/sections/<int:section_id>/delete",
    methods=["POST"]
)
@login_required
def delete_section(section_id):

    section = _get_section_or_404(
        section_id
    )

    section_name = section.name

    # ========================================================
    # DELETE
    # ========================================================

    try:

        db.session.delete(
            section
        )

        db.session.commit()

    except IntegrityError:

        db.session.rollback()

        flash(
            (
                f'Unable to delete section "{section_name}". '
                "This section may already be connected to "
                "other academic records. Please set it to "
                "inactive instead."
            ),
            "danger"
        )

        return redirect(
            url_for(
                "main.view_section",
                section_id=section.id
            )
        )

    # ========================================================
    # SUCCESS
    # ========================================================

    flash(
        f'Section "{section_name}" was deleted successfully.',
        "success"
    )

    return redirect(
        url_for(
            "main.all_sections"
        )
    )



# ============================================================
# SUBJECT ROUTES
# PostgreSQL / Neon
# ============================================================


# ============================================================
# SUBJECT CONSTANTS
# ============================================================

SUBJECT_TYPES = [
    "academic",
    "practical",
    "language",
    "religious",
    "vocational",
    "elective",
    "compulsory",
    "skill",
]

SUBJECT_STATUSES = [
    "active",
    "inactive",
    "suspended",
]


# ============================================================
# USER / INSTITUTION HELPERS
# ============================================================

def _subject_is_global_user():
    """
    Returns True when the current user is allowed to
    manage data across all institutions.
    """

    role = (
        getattr(current_user, "role", None)
        or ""
    ).lower().strip()

    return role in {
        "superadmin",
        "super_admin",
        "admin",
        "system_admin",
    }


def _subject_get_user_institution_id():
    """
    Returns the institution ID belonging to the current user.

    Global users return None.
    """

    if _subject_is_global_user():
        return None

    institution_id = getattr(
        current_user,
        "institution_id",
        None
    )

    if institution_id is None:
        return None

    try:
        return int(institution_id)
    except (TypeError, ValueError):
        return None


def _subject_get_user_branch_id():
    """
    Returns the user's branch ID when available.
    """

    branch_id = getattr(
        current_user,
        "branch_id",
        None
    )

    if branch_id is None:
        return None

    try:
        return int(branch_id)
    except (TypeError, ValueError):
        return None


def _subject_can_manage_global():
    """
    Determines whether the user can see/manage subjects
    belonging to all branches of their institution.

    Institution admins generally can manage all branches.
    Branch admins are restricted to their branch.
    """

    role = (
        getattr(current_user, "role", None)
        or ""
    ).lower().strip()

    return role in {
        "superadmin",
        "super_admin",
        "admin",
        "system_admin",
        "institution_admin",
    }


# ============================================================
# SUBJECT SCOPE
# ============================================================

def _subject_scope_query(query):
    """
    Apply institution/branch security to a Subject query.

    Global users:
        all institutions.

    Institution admins:
        only their institution.

    Branch admins / teachers:
        their institution + branch.

    Other scoped users:
        their institution and, when available, branch.
    """

    institution_id = _subject_get_user_institution_id()

    # Global user
    if institution_id is None:
        return query

    query = query.filter(
        Subject.institution_id == institution_id
    )

    # Institution-level administrators can manage
    # all branches inside their institution.
    if _subject_can_manage_global():
        return query

    branch_id = _subject_get_user_branch_id()

    if branch_id is not None:
        query = query.filter(
            Subject.branch_id == branch_id
        )

    return query


# ============================================================
# GET ALLOWED INSTITUTIONS
# ============================================================

def _subject_allowed_institutions():
    """
    Returns institutions available to current user.
    """

    institution_id = _subject_get_user_institution_id()

    if institution_id is None:

        return (
            Institution.query
            .order_by(Institution.name.asc())
            .all()
        )

    institution = Institution.query.get(
        institution_id
    )

    if institution:
        return [institution]

    return []


# ============================================================
# GET ALLOWED BRANCHES
# ============================================================

def _subject_allowed_branches(
    institution_id=None
):
    """
    Returns branches available to current user.

    Optional institution_id filters branches further.
    """

    query = Branch.query

    user_institution_id = (
        _subject_get_user_institution_id()
    )

    if user_institution_id is not None:

        query = query.filter(
            Branch.institution_id ==
            user_institution_id
        )

    elif institution_id is not None:

        query = query.filter(
            Branch.institution_id ==
            institution_id
        )


    # Branch-scoped users
    if not _subject_can_manage_global():

        user_branch_id = (
            _subject_get_user_branch_id()
        )

        if user_branch_id is not None:

            query = query.filter(
                Branch.id == user_branch_id
            )


    return (
        query
        .order_by(Branch.name.asc())
        .all()
    )


# ============================================================
# GET ALLOWED PROGRAMS
# ============================================================

def _subject_allowed_programs(
    institution_id=None
):
    """
    Returns programs available for subject assignment.
    """

    query = Program.query

    user_institution_id = (
        _subject_get_user_institution_id()
    )

    if user_institution_id is not None:

        query = query.filter(
            Program.institution_id ==
            user_institution_id
        )

    elif institution_id is not None:

        query = query.filter(
            Program.institution_id ==
            institution_id
        )

    return (
        query
        .order_by(Program.name.asc())
        .all()
    )


# ============================================================
# SUBJECT FORM CONTEXT
# ============================================================

def _subject_form_context(
    institution_id=None
):
    """
    Common context used by add/edit templates.
    """

    institutions = (
        _subject_allowed_institutions()
    )

    branches = (
        _subject_allowed_branches(
            institution_id=institution_id
        )
    )

    programs = (
        _subject_allowed_programs(
            institution_id=institution_id
        )
    )

    return {
        "institutions": institutions,
        "branches": branches,
        "programs": programs,
        "subject_types": SUBJECT_TYPES,
        "subject_statuses": SUBJECT_STATUSES,
        "user": current_user,
    }


# ============================================================
# PARSE DECIMAL
# ============================================================

def _subject_parse_decimal(
    value,
    field_name,
    errors,
    allow_empty=True
):
    """
    Safely parse Decimal values.
    """

    value = (
        str(value).strip()
        if value is not None
        else ""
    )

    if not value:

        if allow_empty:
            return None

        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} "
            "is required."
        )

        return None

    try:

        return Decimal(value)

    except (InvalidOperation, ValueError):

        errors[field_name] = (
            f"Invalid {field_name.replace('_', ' ')}."
        )

        return None


# ============================================================
# VALIDATE SUBJECT RELATIONSHIPS
# ============================================================

def _validate_subject_relationships(
    institution_id,
    branch_id,
    program_id,
    errors
):
    """
    Validates institution, branch and program relationships.
    """

    institution = None
    branch = None
    program = None


    # --------------------------------------------------------
    # Institution
    # --------------------------------------------------------

    if not institution_id:

        errors["institution_id"] = (
            "Institution is required."
        )

    else:

        try:
            institution_id = int(institution_id)

        except (TypeError, ValueError):

            errors["institution_id"] = (
                "Invalid institution."
            )

        else:

            institution = Institution.query.get(
                institution_id
            )

            if not institution:

                errors["institution_id"] = (
                    "Selected institution was not found."
                )


    # --------------------------------------------------------
    # Security: institution
    # --------------------------------------------------------

    user_institution_id = (
        _subject_get_user_institution_id()
    )

    if (
        user_institution_id is not None
        and institution_id is not None
        and institution_id != user_institution_id
    ):

        errors["institution_id"] = (
            "You are not allowed to use this institution."
        )


    # --------------------------------------------------------
    # Branch
    # --------------------------------------------------------

    if branch_id:

        try:
            branch_id = int(branch_id)

        except (TypeError, ValueError):

            errors["branch_id"] = (
                "Invalid branch."
            )

        else:

            branch = Branch.query.get(
                branch_id
            )

            if not branch:

                errors["branch_id"] = (
                    "Selected branch was not found."
                )

            elif (
                institution_id is not None
                and branch.institution_id != institution_id
            ):

                errors["branch_id"] = (
                    "Selected branch does not belong "
                    "to the selected institution."
                )


            # Branch security
            user_branch_id = (
                _subject_get_user_branch_id()
            )

            if (
                not _subject_can_manage_global()
                and user_branch_id is not None
                and branch_id != user_branch_id
            ):

                errors["branch_id"] = (
                    "You are not allowed to use this branch."
                )


    # --------------------------------------------------------
    # Program
    # --------------------------------------------------------

    if program_id:

        try:
            program_id = int(program_id)

        except (TypeError, ValueError):

            errors["program_id"] = (
                "Invalid program."
            )

        else:

            program = Program.query.get(
                program_id
            )

            if not program:

                errors["program_id"] = (
                    "Selected program was not found."
                )

            elif (
                institution_id is not None
                and program.institution_id != institution_id
            ):

                errors["program_id"] = (
                    "Selected program does not belong "
                    "to the selected institution."
                )

    return institution, branch, program


# ============================================================
# ALL SUBJECTS
# ============================================================

@bp.route("/subjects", methods=["GET"])
@login_required
def all_subjects():

    # ========================================================
    # FILTERS
    # ========================================================

    search = (
        request.args.get("search", "")
        .strip()
    )

    institution_filter = (
        request.args.get(
            "institution_id",
            ""
        ).strip()
    )

    branch_filter = (
        request.args.get(
            "branch_id",
            ""
        ).strip()
    )

    program_filter = (
        request.args.get(
            "program_id",
            ""
        ).strip()
    )

    subject_type_filter = (
        request.args.get(
            "subject_type",
            ""
        ).strip()
    )

    status_filter = (
        request.args.get(
            "status",
            ""
        ).strip()
    )

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        25,
        type=int
    )

    if page < 1:
        page = 1

    if per_page not in {
        10,
        25,
        50,
        100
    }:
        per_page = 25


    # ========================================================
    # BASE QUERY
    # ========================================================

    query = Subject.query


    # ========================================================
    # SECURITY SCOPE
    # ========================================================

    query = _subject_scope_query(
        query
    )


    # ========================================================
    # INSTITUTION FILTER
    # ========================================================

    if institution_filter:

        try:
            institution_id = int(
                institution_filter
            )

            query = query.filter(
                Subject.institution_id ==
                institution_id
            )

        except (TypeError, ValueError):

            pass


    # ========================================================
    # BRANCH FILTER
    # ========================================================

    if branch_filter:

        try:
            branch_id = int(
                branch_filter
            )

            query = query.filter(
                Subject.branch_id ==
                branch_id
            )

        except (TypeError, ValueError):

            pass


    # ========================================================
    # PROGRAM FILTER
    # ========================================================

    if program_filter:

        try:
            program_id = int(
                program_filter
            )

            query = query.filter(
                Subject.program_id ==
                program_id
            )

        except (TypeError, ValueError):

            pass


    # ========================================================
    # TYPE FILTER
    # ========================================================

    if subject_type_filter:

        query = query.filter(
            Subject.subject_type ==
            subject_type_filter
        )


    # ========================================================
    # STATUS FILTER
    # ========================================================

    if status_filter:

        query = query.filter(
            Subject.status ==
            status_filter
        )


    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        search_pattern = (
            f"%{search}%"
        )

        query = query.filter(
            or_(
                Subject.name.ilike(
                    search_pattern
                ),
                Subject.code.ilike(
                    search_pattern
                ),
                Subject.short_name.ilike(
                    search_pattern
                )
            )
        )


    # ========================================================
    # ORDER
    # ========================================================

    query = query.order_by(
        Subject.name.asc(),
        Subject.id.desc()
    )


    # ========================================================
    # PAGINATION
    # ========================================================

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    subjects = pagination.items


    # ========================================================
    # FILTER DATA
    # ========================================================

    institutions = (
        _subject_allowed_institutions()
    )

    branches = (
        _subject_allowed_branches()
    )

    programs = (
        _subject_allowed_programs()
    )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/subjects/all_subjects.html",
        subjects=subjects,
        pagination=pagination,
        institutions=institutions,
        branches=branches,
        programs=programs,
        subject_types=SUBJECT_TYPES,
        subject_statuses=SUBJECT_STATUSES,
        search=search,
        institution_filter=institution_filter,
        branch_filter=branch_filter,
        program_filter=program_filter,
        subject_type_filter=subject_type_filter,
        status_filter=status_filter,
        user=current_user
    )


# ============================================================
# ADD SUBJECT
# ============================================================
@bp.route("/subjects/add", methods=["GET", "POST"])
@login_required
def add_subject():

    # ========================================================
    # PERMISSION
    # ========================================================

    if not _subject_can_manage_global():

        flash(
            "You do not have permission to create subjects.",
            "danger"
        )

        return redirect(
            url_for("main.all_subjects")
        )

    # ========================================================
    # SELECTED INSTITUTION
    # ========================================================

    selected_institution_id = None

    if request.method == "POST":

        selected_institution_id = (
            request.form.get("institution_id") or None
        )

    else:

        if not _subject_is_global_user():

            selected_institution_id = (
                _subject_get_user_institution_id()
            )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        errors = {}

        # ----------------------------------------------------
        # FORM VALUES
        # ----------------------------------------------------

        institution_id = (
            request.form.get("institution_id") or ""
        ).strip()

        branch_id = (
            request.form.get("branch_id") or ""
        ).strip()

        program_id = (
            request.form.get("program_id") or ""
        ).strip()

        name = (
            request.form.get("name") or ""
        ).strip()

        code = (
            request.form.get("code") or ""
        ).strip()

        short_name = (
            request.form.get("short_name") or ""
        ).strip()

        subject_type = (
            request.form.get("subject_type")
            or "academic"
        ).strip().lower()

        weekly_hours_raw = (
            request.form.get("weekly_hours") or ""
        ).strip()

        credit_hours_raw = (
            request.form.get("credit_hours") or ""
        ).strip()

        max_marks_raw = (
            request.form.get("max_marks")
            or "100"
        ).strip()

        pass_marks_raw = (
            request.form.get("pass_marks")
            or "50"
        ).strip()

        description = (
            request.form.get("description") or ""
        ).strip()

        status = (
            request.form.get("status")
            or "active"
        ).strip().lower()

        # ----------------------------------------------------
        # OPTIONAL VALUES
        # ----------------------------------------------------

        branch_id = branch_id or None
        program_id = program_id or None
        short_name = short_name or None
        description = description or None

        selected_institution_id = institution_id or None

        # ====================================================
        # NAME
        # ====================================================

        if not name:

            errors["name"] = (
                "Subject name is required."
            )

        elif len(name) > 150:

            errors["name"] = (
                "Subject name cannot exceed 150 characters."
            )

        # ====================================================
        # CODE
        # ====================================================

        if not code:

            errors["code"] = (
                "Subject code is required."
            )

        elif len(code) > 50:

            errors["code"] = (
                "Subject code cannot exceed 50 characters."
            )

        else:

            code = code.upper()

        # ====================================================
        # SHORT NAME
        # ====================================================

        if short_name and len(short_name) > 100:

            errors["short_name"] = (
                "Short name cannot exceed 100 characters."
            )

        # ====================================================
        # SUBJECT TYPE
        # ====================================================

        if subject_type not in SUBJECT_TYPES:

            errors["subject_type"] = (
                "Invalid subject type selected."
            )

        # ====================================================
        # STATUS
        # ====================================================

        if status not in SUBJECT_STATUSES:

            errors["status"] = (
                "Invalid subject status selected."
            )

        # ====================================================
        # DECIMAL VALUES
        # ====================================================

        weekly_hours = _subject_parse_decimal(
            weekly_hours_raw,
            "weekly_hours",
            errors,
            allow_empty=True
        )

        credit_hours = _subject_parse_decimal(
            credit_hours_raw,
            "credit_hours",
            errors,
            allow_empty=True
        )

        max_marks = _subject_parse_decimal(
            max_marks_raw,
            "max_marks",
            errors,
            allow_empty=False
        )

        pass_marks = _subject_parse_decimal(
            pass_marks_raw,
            "pass_marks",
            errors,
            allow_empty=False
        )

        # ====================================================
        # HOURS VALIDATION
        # ====================================================

        if (
            weekly_hours is not None
            and weekly_hours < Decimal("0")
        ):

            errors["weekly_hours"] = (
                "Weekly hours cannot be negative."
            )

        if (
            credit_hours is not None
            and credit_hours < Decimal("0")
        ):

            errors["credit_hours"] = (
                "Credit hours cannot be negative."
            )

        # ====================================================
        # MARKS VALIDATION
        # ====================================================

        if (
            max_marks is not None
            and max_marks <= Decimal("0")
        ):

            errors["max_marks"] = (
                "Maximum marks must be greater than 0."
            )

        if (
            pass_marks is not None
            and pass_marks < Decimal("0")
        ):

            errors["pass_marks"] = (
                "Pass marks cannot be negative."
            )

        if (
            max_marks is not None
            and pass_marks is not None
            and pass_marks > max_marks
        ):

            errors["pass_marks"] = (
                "Pass marks cannot be greater than "
                "maximum marks."
            )

        # ====================================================
        # RELATIONSHIPS
        # ====================================================

        institution = None
        branch = None
        program = None

        (
            institution,
            branch,
            program
        ) = _validate_subject_relationships(
            institution_id,
            branch_id,
            program_id,
            errors
        )

        # ====================================================
        # DUPLICATE NAME
        # ====================================================

        if (
            institution_id
            and name
            and not errors.get("institution_id")
        ):

            query = Subject.query.filter(
                Subject.institution_id == institution_id
            )

            if branch_id:

                query = query.filter(
                    Subject.branch_id == branch_id
                )

            else:

                query = query.filter(
                    Subject.branch_id.is_(None)
                )

            query = query.filter(
                db.func.lower(Subject.name)
                == name.lower()
            )

            if query.first():

                errors["name"] = (
                    "A subject with this name already "
                    "exists for the selected institution "
                    "and branch."
                )

        # ====================================================
        # DUPLICATE CODE
        # ====================================================

        if (
            institution_id
            and code
            and not errors.get("institution_id")
        ):

            query = Subject.query.filter(
                Subject.institution_id == institution_id
            )

            if branch_id:

                query = query.filter(
                    Subject.branch_id == branch_id
                )

            else:

                query = query.filter(
                    Subject.branch_id.is_(None)
                )

            query = query.filter(
                db.func.upper(Subject.code)
                == code.upper()
            )

            if query.first():

                errors["code"] = (
                    "A subject with this code already "
                    "exists for the selected institution "
                    "and branch."
                )

        # ====================================================
        # CREATE
        # ====================================================

        if not errors:

            try:

                subject = Subject(
                    institution_id=int(
                        institution_id
                    ),

                    branch_id=(
                        int(branch_id)
                        if branch_id
                        else None
                    ),

                    program_id=(
                        int(program_id)
                        if program_id
                        else None
                    ),

                    name=name,

                    code=code,

                    short_name=short_name,

                    subject_type=subject_type,

                    weekly_hours=weekly_hours,

                    credit_hours=credit_hours,

                    max_marks=max_marks,

                    pass_marks=pass_marks,

                    description=description,

                    status=status,
                )

                db.session.add(subject)

                db.session.commit()

                flash(
                    f'Subject "{subject.name}" '
                    f'was created successfully.',
                    "success"
                )

                return redirect(
                    url_for(
                        "main.view_subject",
                        subject_id=subject.id
                    )
                )

            except IntegrityError as exc:

                db.session.rollback()

                current_app.logger.exception(
                    "Subject integrity error"
                )

                error_text = str(
                    getattr(exc, "orig", exc)
                ).lower()

                if "code" in error_text:

                    flash(
                        "A subject with this code already "
                        "exists for the selected institution "
                        "and branch.",
                        "danger"
                    )

                elif "name" in error_text:

                    flash(
                        "A subject with this name already "
                        "exists for the selected institution "
                        "and branch.",
                        "danger"
                    )

                else:

                    flash(
                        "Unable to create the subject because "
                        "of a database constraint.",
                        "danger"
                    )

            except Exception:

                db.session.rollback()

                current_app.logger.exception(
                    "Unexpected error while creating subject"
                )

                flash(
                    "An unexpected error occurred while "
                    "creating the subject.",
                    "danger"
                )

        # ====================================================
        # VALIDATION ERRORS
        # ====================================================

        if errors:

            for message in errors.values():

                flash(
                    message,
                    "danger"
                )

    # ========================================================
    # FORM CONTEXT
    # ========================================================

    context = _subject_form_context(
        selected_institution_id
    )

    # ========================================================
    # IMPORTANT:
    # DO NOT PASS user=current_user HERE.
    #
    # _subject_form_context() ALREADY CONTAINS user.
    # ========================================================

    return render_template(
        "backend/pages/subjects/add_subject.html",
        **context
    )

# ============================================================
# VIEW SUBJECT
# ============================================================

@bp.route(
    "/subjects/<int:subject_id>",
    methods=["GET"]
)
@login_required
def view_subject(subject_id):

    # ========================================================
    # GET SUBJECT
    # ========================================================

    query = Subject.query.filter(
        Subject.id == subject_id
    )

    query = _subject_scope_query(
        query
    )

    subject = query.first()


    # ========================================================
    # NOT FOUND
    # ========================================================

    if not subject:

        flash(
            "Subject not found or you do not have permission to view it.",
            "warning"
        )

        return redirect(
            url_for("main.all_subjects")
        )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/subjects/view_subject.html",
        subject=subject,
        user=current_user
    )


# ============================================================
# EDIT SUBJECT
# ============================================================
@bp.route("/subjects/<int:subject_id>/edit", methods=["GET", "POST"])
@login_required
def edit_subject(subject_id):

    # ============================================================
    # GET SUBJECT
    # ============================================================

    subject = Subject.query.get_or_404(subject_id)

    # ============================================================
    # PERMISSION
    # ============================================================

    if not _subject_can_manage_global():
        flash(
            "You do not have permission to edit subjects.",
            "danger"
        )
        return redirect(
            url_for("main.all_subjects")
        )

    # ============================================================
    # SCOPE SECURITY
    # ============================================================

    user_institution_id = (
        _subject_get_user_institution_id()
    )

    user_branch_id = (
        _subject_get_user_branch_id()
    )

    is_global_user = _subject_is_global_user()

    # ------------------------------------------------------------
    # Institution scope
    # ------------------------------------------------------------

    if (
        user_institution_id is not None
        and subject.institution_id != user_institution_id
    ):
        flash(
            "You are not authorized to edit this subject.",
            "danger"
        )
        return redirect(
            url_for("main.all_subjects")
        )

    # ------------------------------------------------------------
    # Branch scope
    # ------------------------------------------------------------

    if (
        not is_global_user
        and user_branch_id is not None
        and subject.branch_id is not None
        and subject.branch_id != user_branch_id
    ):
        flash(
            "You are not authorized to edit this subject.",
            "danger"
        )
        return redirect(
            url_for("main.all_subjects")
        )

    # ============================================================
    # POST
    # ============================================================

    if request.method == "POST":

        errors = {}

        # ========================================================
        # INSTITUTION
        # ========================================================

        institution_raw = (
            request.form.get("institution_id") or ""
        ).strip()

        institution_id = None

        if not institution_raw:
            errors["institution_id"] = (
                "Institution is required."
            )
        else:
            try:
                institution_id = int(
                    institution_raw
                )

                if institution_id <= 0:
                    raise ValueError

            except (TypeError, ValueError):
                errors["institution_id"] = (
                    "Invalid institution."
                )

        # ========================================================
        # BRANCH
        # ========================================================

        branch_raw = (
            request.form.get("branch_id") or ""
        ).strip()

        branch_id = None

        if branch_raw:
            try:
                branch_id = int(branch_raw)

                if branch_id <= 0:
                    raise ValueError

            except (TypeError, ValueError):
                errors["branch_id"] = (
                    "Invalid branch."
                )

        # ========================================================
        # PROGRAM
        # ========================================================

        program_raw = (
            request.form.get("program_id") or ""
        ).strip()

        program_id = None

        if program_raw:
            try:
                program_id = int(program_raw)

                if program_id <= 0:
                    raise ValueError

            except (TypeError, ValueError):
                errors["program_id"] = (
                    "Invalid program."
                )

        # ========================================================
        # SUBJECT NAME
        # ========================================================

        name = (
            request.form.get("name") or ""
        ).strip()

        if not name:
            errors["name"] = (
                "Subject name is required."
            )

        elif len(name) > 150:
            errors["name"] = (
                "Subject name cannot exceed 150 characters."
            )

        # ========================================================
        # IMPORTANT:
        # CODE IS NOT TAKEN FROM USER
        # KEEP EXISTING DATABASE CODE
        # ========================================================

        code = (
            subject.code or ""
        ).strip().upper()

        if not code:
            errors["code"] = (
                "This subject does not have a valid subject code."
            )

        # ========================================================
        # SHORT NAME
        # ========================================================

        short_name = (
            request.form.get("short_name") or ""
        ).strip()

        if short_name:
            if len(short_name) > 100:
                errors["short_name"] = (
                    "Short name cannot exceed 100 characters."
                )

        else:
            short_name = None

        # ========================================================
        # SUBJECT TYPE
        # ========================================================

        subject_type = (
            request.form.get("subject_type")
            or "academic"
        ).strip().lower()

        if subject_type not in SUBJECT_TYPES:
            errors["subject_type"] = (
                "Invalid subject type."
            )

        # ========================================================
        # STATUS
        # ========================================================

        status = (
            request.form.get("status")
            or "active"
        ).strip().lower()

        if status not in SUBJECT_STATUSES:
            errors["status"] = (
                "Invalid subject status."
            )

        # ========================================================
        # WEEKLY HOURS
        # ========================================================

        weekly_hours = _subject_parse_decimal(
            request.form.get("weekly_hours"),
            "weekly_hours",
            errors,
            allow_empty=True
        )

        if (
            weekly_hours is not None
            and weekly_hours < Decimal("0")
        ):
            errors["weekly_hours"] = (
                "Weekly hours cannot be negative."
            )

        # ========================================================
        # CREDIT HOURS
        # ========================================================

        credit_hours = _subject_parse_decimal(
            request.form.get("credit_hours"),
            "credit_hours",
            errors,
            allow_empty=True
        )

        if (
            credit_hours is not None
            and credit_hours < Decimal("0")
        ):
            errors["credit_hours"] = (
                "Credit hours cannot be negative."
            )

        # ========================================================
        # MAX MARKS
        # ========================================================

        max_marks = _subject_parse_decimal(
            request.form.get("max_marks"),
            "max_marks",
            errors,
            allow_empty=False
        )

        if (
            max_marks is not None
            and max_marks <= Decimal("0")
        ):
            errors["max_marks"] = (
                "Maximum marks must be greater than 0."
            )

        # ========================================================
        # PASS MARKS
        # ========================================================

        pass_marks = _subject_parse_decimal(
            request.form.get("pass_marks"),
            "pass_marks",
            errors,
            allow_empty=False
        )

        if (
            pass_marks is not None
            and pass_marks < Decimal("0")
        ):
            errors["pass_marks"] = (
                "Pass marks cannot be negative."
            )

        # ========================================================
        # PASS <= MAX
        # ========================================================

        if (
            max_marks is not None
            and pass_marks is not None
            and pass_marks > max_marks
        ):
            errors["pass_marks"] = (
                "Pass marks cannot be greater than maximum marks."
            )

        # ========================================================
        # DESCRIPTION
        # ========================================================

        description = (
            request.form.get("description") or ""
        ).strip()

        if not description:
            description = None

        # ========================================================
        # RELATIONSHIP VALIDATION
        # ========================================================

        if institution_id is not None:

            relationship_errors = (
                _validate_subject_relationships(
                    institution_id,
                    branch_id,
                    program_id,
                    errors
                )
            )

        # ========================================================
        # USER SCOPE VALIDATION
        # ========================================================

        if institution_id is not None:

            if (
                user_institution_id is not None
                and institution_id != user_institution_id
            ):
                errors["institution_id"] = (
                    "You cannot move this subject to another institution."
                )

        if (
            not is_global_user
            and user_branch_id is not None
            and branch_id is not None
            and branch_id != user_branch_id
        ):
            errors["branch_id"] = (
                "You cannot move this subject to another branch."
            )

        # ========================================================
        # DUPLICATE NAME
        # ========================================================

        if (
            institution_id is not None
            and name
        ):

            duplicate_name_query = Subject.query.filter(
                Subject.id != subject.id,
                Subject.institution_id == institution_id,
                db.func.lower(
                    Subject.name
                ) == name.lower()
            )

            if branch_id is not None:

                duplicate_name_query = (
                    duplicate_name_query.filter(
                        Subject.branch_id == branch_id
                    )
                )

            else:

                duplicate_name_query = (
                    duplicate_name_query.filter(
                        Subject.branch_id.is_(None)
                    )
                )

            duplicate_name = (
                duplicate_name_query.first()
            )

            if duplicate_name:
                errors["name"] = (
                    "Another subject with this name already exists "
                    "in the selected institution and branch."
                )

        # ========================================================
        # DUPLICATE CODE
        #
        # Existing code is preserved, but relationship scope
        # may change. Therefore check code in new scope.
        # ========================================================

        if (
            institution_id is not None
            and code
        ):

            duplicate_code_query = Subject.query.filter(
                Subject.id != subject.id,
                Subject.institution_id == institution_id,
                db.func.upper(
                    Subject.code
                ) == code.upper()
            )

            if branch_id is not None:

                duplicate_code_query = (
                    duplicate_code_query.filter(
                        Subject.branch_id == branch_id
                    )
                )

            else:

                duplicate_code_query = (
                    duplicate_code_query.filter(
                        Subject.branch_id.is_(None)
                    )
                )

            duplicate_code = (
                duplicate_code_query.first()
            )

            if duplicate_code:
                errors["code"] = (
                    "The existing subject code is already used "
                    "in the selected institution and branch."
                )

        # ========================================================
        # VALIDATION FAILED
        # ========================================================

        if errors:

            for message in errors.values():
                flash(message, "danger")

            context = _subject_form_context(
                institution_id
                if institution_id is not None
                else subject.institution_id
            )

            return render_template(
                "backend/pages/subjects/edit_subject.html",
                **context,
                subject=subject
            )

        # ========================================================
        # UPDATE SUBJECT
        # ========================================================

        try:

            # ----------------------------------------------------
            # IMPORTANT:
            # DO NOT CHANGE subject.code
            # ----------------------------------------------------

            subject.institution_id = (
                institution_id
            )

            subject.branch_id = (
                branch_id
            )

            subject.program_id = (
                program_id
            )

            subject.name = (
                name
            )

            subject.short_name = (
                short_name
            )

            subject.subject_type = (
                subject_type
            )

            subject.weekly_hours = (
                weekly_hours
            )

            subject.credit_hours = (
                credit_hours
            )

            subject.max_marks = (
                max_marks
            )

            subject.pass_marks = (
                pass_marks
            )

            subject.description = (
                description
            )

            subject.status = (
                status
            )

            # Explicit update timestamp
            subject.updated_at = datetime.utcnow()

            db.session.commit()

            flash(
                f'Subject "{subject.name}" updated successfully.',
                "success"
            )

            return redirect(
                url_for(
                    "main.view_subject",
                    subject_id=subject.id
                )
            )

        # ========================================================
        # DATABASE INTEGRITY ERROR
        # ========================================================

        except IntegrityError as exc:

            db.session.rollback()

            current_app.logger.exception(
                "IntegrityError while editing subject ID %s",
                subject.id
            )

            flash(
                "Unable to update the subject because of a "
                "database constraint conflict. Please check "
                "the institution, branch, program, name, and code.",
                "danger"
            )

        # ========================================================
        # GENERAL ERROR
        # ========================================================

        except Exception as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Unexpected error while editing subject ID %s: %s",
                subject.id,
                exc
            )

            flash(
                "An unexpected error occurred while updating the subject.",
                "danger"
            )

    # ============================================================
    # GET / FAILED POST
    # ============================================================

    context = _subject_form_context(
        subject.institution_id
    )

    return render_template(
        "backend/pages/subjects/edit_subject.html",
        **context,
        subject=subject
    )


# ============================================================
# DELETE SUBJECT
# ============================================================

@bp.route(
    "/subjects/<int:subject_id>/delete",
    methods=["POST"]
)
@login_required
def delete_subject(subject_id):

    # ========================================================
    # GET SUBJECT WITH SECURITY SCOPE
    # ========================================================

    query = Subject.query.filter(
        Subject.id == subject_id
    )

    query = _subject_scope_query(
        query
    )

    subject = query.first()


    # ========================================================
    # NOT FOUND
    # ========================================================

    if not subject:

        flash(
            "Subject not found or you do not have permission to delete it.",
            "warning"
        )

        return redirect(
            url_for("main.all_subjects")
        )


    subject_name = (
        subject.name
    )


    # ========================================================
    # DELETE
    # ========================================================

    try:

        db.session.delete(
            subject
        )

        db.session.commit()

        flash(
            f'Subject "{subject_name}" was deleted successfully.',
            "success"
        )


    except IntegrityError:

        db.session.rollback()

        flash(
            "This subject cannot be deleted because it is "
            "currently referenced by other academic records.",
            "danger"
        )


    except Exception:

        db.session.rollback()

        flash(
            "An unexpected error occurred while deleting the subject.",
            "danger"
        )


    return redirect(
        url_for(
            "main.all_subjects"
        )
    )


# ============================================================
# TEACHER ROUTES
# PostgreSQL / Neon
# ============================================================

# ============================================================
# TEACHER CONSTANTS
# ============================================================

TEACHER_GENDERS = [
    "male",
    "female",
    "other",
]

TEACHER_STATUSES = [
    "active",
    "inactive",
    "suspended",
    "resigned",
]


# ============================================================
# TEACHER ACCESS HELPERS
# ============================================================

def _teacher_is_global_user():
    """
    Global users can manage teachers across institutions.
    """

    return (
        getattr(current_user, "role", None)
        in {
            "superadmin",
            "super_admin",
            "admin",
            "system_admin",
        }
    )


def _teacher_get_user_institution_id():
    """
    Return current user's institution ID.

    Global users:
        None

    Institution-scoped users:
        institution_id
    """

    if _teacher_is_global_user():
        return None

    institution_id = getattr(
        current_user,
        "institution_id",
        None
    )

    if institution_id:
        try:
            return int(institution_id)
        except (TypeError, ValueError):
            return None

    return None


def _teacher_get_user_branch_id():
    """
    Return current user's branch ID.
    """

    branch_id = getattr(
        current_user,
        "branch_id",
        None
    )

    if branch_id:
        try:
            return int(branch_id)
        except (TypeError, ValueError):
            return None

    return None


def _teacher_can_manage():
    """
    Roles allowed to manage teachers.
    """

    return (
        getattr(current_user, "role", None)
        in {
            "superadmin",
            "super_admin",
            "admin",
            "system_admin",
            "institution_admin",
            "branch_admin",
        }
    )


def _teacher_scope_query(query):
    """
    Apply institution / branch security.
    """

    if _teacher_is_global_user():
        return query

    institution_id = _teacher_get_user_institution_id()

    if institution_id is None:
        return query.filter(
            db.literal(False)
        )

    query = query.filter(
        Teacher.institution_id == institution_id
    )

    # Branch admins are restricted to their branch.
    if getattr(current_user, "role", None) == "branch_admin":

        branch_id = _teacher_get_user_branch_id()

        if branch_id is None:
            return query.filter(
                db.literal(False)
            )

        query = query.filter(
            Teacher.branch_id == branch_id
        )

    return query


# ============================================================
# ALLOWED INSTITUTIONS
# ============================================================

def _teacher_allowed_institutions():

    if _teacher_is_global_user():

        return Institution.query.order_by(
            Institution.name.asc()
        ).all()

    institution_id = _teacher_get_user_institution_id()

    if institution_id is None:
        return []

    institution = Institution.query.filter(
        Institution.id == institution_id
    ).first()

    return [institution] if institution else []


# ============================================================
# ALLOWED BRANCHES
# ============================================================

def _teacher_allowed_branches(institution_id=None):

    query = Branch.query

    if institution_id is not None:

        query = query.filter(
            Branch.institution_id == institution_id
        )

    if not _teacher_is_global_user():

        user_institution_id = (
            _teacher_get_user_institution_id()
        )

        if user_institution_id is None:
            return []

        query = query.filter(
            Branch.institution_id == user_institution_id
        )

        if getattr(current_user, "role", None) == "branch_admin":

            user_branch_id = (
                _teacher_get_user_branch_id()
            )

            if user_branch_id is None:
                return []

            query = query.filter(
                Branch.id == user_branch_id
            )

    return query.order_by(
        Branch.name.asc()
    ).all()


# ============================================================
# TEACHER FORM CONTEXT
# ============================================================

def _teacher_form_context(institution_id=None):

    return {
        "user": current_user,

        "institutions":
            _teacher_allowed_institutions(),

        "branches":
            _teacher_allowed_branches(institution_id),

        "teacher_genders":
            TEACHER_GENDERS,

        "teacher_statuses":
            TEACHER_STATUSES,
    }


# ============================================================
# VALIDATE INSTITUTION / BRANCH
# ============================================================

def _validate_teacher_relationships(
    institution_id,
    branch_id,
    errors
):

    if not institution_id:
        errors.append(
            "Institution is required."
        )
        return

    institution = Institution.query.filter(
        Institution.id == institution_id
    ).first()

    if not institution:
        errors.append(
            "Selected institution was not found."
        )
        return

    # --------------------------------------------------------
    # Scoped user cannot select another institution
    # --------------------------------------------------------

    if not _teacher_is_global_user():

        user_institution_id = (
            _teacher_get_user_institution_id()
        )

        if (
            user_institution_id is None
            or institution_id != user_institution_id
        ):
            errors.append(
                "You are not allowed to use this institution."
            )

    # --------------------------------------------------------
    # Branch required
    # --------------------------------------------------------

    if not branch_id:

        errors.append(
            "Branch is required."
        )

        return

    branch = Branch.query.filter(
        Branch.id == branch_id
    ).first()

    if not branch:

        errors.append(
            "Selected branch was not found."
        )

        return

    # --------------------------------------------------------
    # Branch must belong to institution
    # --------------------------------------------------------

    if branch.institution_id != institution_id:

        errors.append(
            "Selected branch does not belong "
            "to the selected institution."
        )

    # --------------------------------------------------------
    # Branch-admin restriction
    # --------------------------------------------------------

    if (
        not _teacher_is_global_user()
        and getattr(current_user, "role", None)
        == "branch_admin"
    ):

        user_branch_id = (
            _teacher_get_user_branch_id()
        )

        if (
            user_branch_id is None
            or branch_id != user_branch_id
        ):

            errors.append(
                "You are not allowed to use this branch."
            )


# ============================================================
# AUTO GENERATE TEACHER ROLL NUMBER
# ============================================================

def _generate_teacher_roll_no(institution_id):
    """
    Generate:

        T001
        T002
        T003

    Roll number is unique within institution.
    """

    prefix = "T"

    teachers = Teacher.query.filter(
        Teacher.institution_id == institution_id
    ).all()

    used_numbers = set()

    for teacher in teachers:

        if not teacher.roll_no:
            continue

        roll = teacher.roll_no.strip().upper()

        if not roll.startswith(prefix):
            continue

        numeric_part = roll[len(prefix):]

        if numeric_part.isdigit():

            used_numbers.add(
                int(numeric_part)
            )

    number = 1

    while number in used_numbers:
        number += 1

    return f"{prefix}{number:03d}"


# ============================================================
# TEACHER DETAIL ACCESS
# ============================================================

def _teacher_can_access(teacher):

    if _teacher_is_global_user():
        return True

    institution_id = (
        _teacher_get_user_institution_id()
    )

    if (
        institution_id is None
        or teacher.institution_id != institution_id
    ):
        return False

    if getattr(current_user, "role", None) == "branch_admin":

        branch_id = _teacher_get_user_branch_id()

        if (
            branch_id is None
            or teacher.branch_id != branch_id
        ):
            return False

    return True


# ============================================================
# 1. ALL TEACHERS
# ============================================================

@bp.route("/teachers", methods=["GET"])
@login_required
def all_teachers():

    if not _teacher_can_manage():

        flash(
            "You are not authorized to manage teachers.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()

    branch_id = request.args.get(
        "branch_id",
        "",
        type=str
    ).strip()

    gender = request.args.get(
        "gender",
        "",
        type=str
    ).strip().lower()

    status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    active = request.args.get(
        "active",
        "",
        type=str
    ).strip().lower()

    verified = request.args.get(
        "verified",
        "",
        type=str
    ).strip().lower()

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        25,
        type=int
    )

    allowed_per_page = {
        10,
        25,
        50,
        100,
    }

    if per_page not in allowed_per_page:
        per_page = 25

    if page < 1:
        page = 1

    query = _teacher_scope_query(
        Teacher.query
    )

    # --------------------------------------------------------
    # Institution filter
    # --------------------------------------------------------

    if institution_id:

        try:
            selected_institution_id = int(
                institution_id
            )

            if _teacher_is_global_user():

                query = query.filter(
                    Teacher.institution_id
                    == selected_institution_id
                )

        except ValueError:

            institution_id = ""

    # --------------------------------------------------------
    # Branch filter
    # --------------------------------------------------------

    if branch_id:

        try:

            selected_branch_id = int(
                branch_id
            )

            query = query.filter(
                Teacher.branch_id
                == selected_branch_id
            )

        except ValueError:

            branch_id = ""

    # --------------------------------------------------------
    # Search
    # --------------------------------------------------------

    if search:

        search_value = f"%{search}%"

        query = query.filter(
            or_(
                Teacher.full_name.ilike(
                    search_value
                ),

                Teacher.username.ilike(
                    search_value
                ),

                Teacher.email.ilike(
                    search_value
                ),

                Teacher.roll_no.ilike(
                    search_value
                ),

                Teacher.phone.ilike(
                    search_value
                ),

                Teacher.qualification.ilike(
                    search_value
                ),

                Teacher.specialization.ilike(
                    search_value
                ),
            )
        )

    # --------------------------------------------------------
    # Gender
    # --------------------------------------------------------

    if gender in TEACHER_GENDERS:

        query = query.filter(
            func.lower(Teacher.gender)
            == gender
        )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    if status in TEACHER_STATUSES:

        query = query.filter(
            Teacher.status == status
        )

    # --------------------------------------------------------
    # Active
    # --------------------------------------------------------

    if active == "1":

        query = query.filter(
            Teacher.is_active.is_(True)
        )

    elif active == "0":

        query = query.filter(
            Teacher.is_active.is_(False)
        )

    # --------------------------------------------------------
    # Verified
    # --------------------------------------------------------

    if verified == "1":

        query = query.filter(
            Teacher.is_verified.is_(True)
        )

    elif verified == "0":

        query = query.filter(
            Teacher.is_verified.is_(False)
        )

    # --------------------------------------------------------
    # Ordering
    # --------------------------------------------------------

    query = query.order_by(
        Teacher.full_name.asc(),
        Teacher.id.desc()
    )

    # --------------------------------------------------------
    # Pagination
    # --------------------------------------------------------

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    teachers = pagination.items

    # --------------------------------------------------------
    # Filter dropdown data
    # --------------------------------------------------------

    selected_institution_for_branches = None

    if institution_id:

        try:

            selected_institution_for_branches = int(
                institution_id
            )

        except ValueError:
            pass

    elif not _teacher_is_global_user():

        selected_institution_for_branches = (
            _teacher_get_user_institution_id()
        )

    institutions = (
        _teacher_allowed_institutions()
    )

    branches = _teacher_allowed_branches(
        selected_institution_for_branches
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    scoped_query = _teacher_scope_query(
        Teacher.query
    )

    total_teachers = scoped_query.count()

    active_teachers = scoped_query.filter(
        Teacher.is_active.is_(True),
        Teacher.status == "active"
    ).count()

    inactive_teachers = scoped_query.filter(
        Teacher.is_active.is_(False)
    ).count()

    verified_teachers = scoped_query.filter(
        Teacher.is_verified.is_(True)
    ).count()

    suspended_teachers = scoped_query.filter(
        Teacher.status == "suspended"
    ).count()

    resigned_teachers = scoped_query.filter(
        Teacher.status == "resigned"
    ).count()

    return render_template(
        "backend/pages/teachers/all_teachers.html",

        teachers=teachers,
        pagination=pagination,

        institutions=institutions,
        branches=branches,

        teacher_genders=TEACHER_GENDERS,
        teacher_statuses=TEACHER_STATUSES,

        search=search,
        institution_id=institution_id,
        branch_id=branch_id,
        gender=gender,
        status=status,
        active=active,
        verified=verified,
        per_page=per_page,

        total_teachers=total_teachers,
        active_teachers=active_teachers,
        inactive_teachers=inactive_teachers,
        verified_teachers=verified_teachers,
        suspended_teachers=suspended_teachers,
        resigned_teachers=resigned_teachers,

        user=current_user,
    )

# ============================================================
# ADD TEACHER
# ============================================================
# ============================================================
# ADD TEACHER
# ============================================================

@bp.route("/teachers/add", methods=["GET", "POST"])
@login_required
def add_teacher():

    # --------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------
    if not _teacher_can_manage():
        flash(
            "You are not authorized to add teachers.",
            "danger"
        )
        return redirect(
            url_for("main.all_teachers")
        )

    # --------------------------------------------------------
    # DEFAULT INSTITUTION
    # --------------------------------------------------------
    default_institution_id = (
        _teacher_get_user_institution_id()
    )

    # Current institution used by the form
    institution_id = default_institution_id

    # ========================================================
    # POST
    # ========================================================
    if request.method == "POST":

        errors = []

        # ====================================================
        # INSTITUTION
        # ====================================================
        institution_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        try:

            institution_id = (
                int(institution_raw)
                if institution_raw
                else None
            )

        except (ValueError, TypeError):

            institution_id = None

            errors.append(
                "Invalid institution."
            )

        # ====================================================
        # BRANCH
        # ====================================================
        branch_raw = request.form.get(
            "branch_id",
            ""
        ).strip()

        try:

            branch_id = (
                int(branch_raw)
                if branch_raw
                else None
            )

        except (ValueError, TypeError):

            branch_id = None

            errors.append(
                "Invalid branch."
            )

        # ====================================================
        # BASIC INFORMATION
        # ====================================================
        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        gender = request.form.get(
            "gender",
            ""
        ).strip().lower()

        # ====================================================
        # PERSONAL INFORMATION
        # ====================================================
        date_of_birth_raw = request.form.get(
            "date_of_birth",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        address = request.form.get(
            "address",
            ""
        ).strip()

        city = request.form.get(
            "city",
            ""
        ).strip()

        # ====================================================
        # PROFESSIONAL INFORMATION
        # ====================================================
        qualification = request.form.get(
            "qualification",
            ""
        ).strip()

        specialization = request.form.get(
            "specialization",
            ""
        ).strip()

        experience_raw = request.form.get(
            "experience_years",
            ""
        ).strip()

        hire_date_raw = request.form.get(
            "hire_date",
            ""
        ).strip()

        # ====================================================
        # PASSWORD
        # ====================================================
        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ====================================================
        # STATUS
        # ====================================================
        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        # ====================================================
        # CHECKBOXES
        # ====================================================
        is_active = (
            request.form.get("is_active")
            in {
                "1",
                "true",
                "on",
                "yes"
            }
        )

        is_verified = (
            request.form.get("is_verified")
            in {
                "1",
                "true",
                "on",
                "yes"
            }
        )

        # ====================================================
        # NOTES
        # ====================================================
        notes = request.form.get(
            "notes",
            ""
        ).strip()

        # ====================================================
        # PHOTO
        # ====================================================
        photo = request.files.get("photo")

        if not photo:
            photo = request.files.get(
                "profile_image"
            )

        # ====================================================
        # VALIDATE FULL NAME
        # ====================================================
        if not full_name:

            errors.append(
                "Teacher full name is required."
            )

        elif len(full_name) > 200:

            errors.append(
                "Teacher name cannot exceed "
                "200 characters."
            )

        # ====================================================
        # VALIDATE USERNAME
        # ====================================================
        if not username:

            errors.append(
                "Username is required."
            )

        elif len(username) > 150:

            errors.append(
                "Username cannot exceed "
                "150 characters."
            )

        # ====================================================
        # VALIDATE EMAIL
        # ====================================================
        if email and len(email) > 150:

            errors.append(
                "Email cannot exceed "
                "150 characters."
            )

        # ====================================================
        # VALIDATE GENDER
        # ====================================================
        if gender and gender not in TEACHER_GENDERS:

            errors.append(
                "Invalid gender selected."
            )

        # ====================================================
        # VALIDATE STATUS
        # ====================================================
        if status not in TEACHER_STATUSES:

            errors.append(
                "Invalid teacher status."
            )

        # ====================================================
        # VALIDATE PASSWORD
        # ====================================================
        if not password:

            errors.append(
                "Password is required."
            )

        elif len(password) < 6:

            errors.append(
                "Password must contain at least "
                "6 characters."
            )

        if password != confirm_password:

            errors.append(
                "Password confirmation does not match."
            )

        # ====================================================
        # DATE OF BIRTH
        # ====================================================
        date_of_birth = None

        if date_of_birth_raw:

            try:

                date_of_birth = datetime.strptime(
                    date_of_birth_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                errors.append(
                    "Invalid date of birth."
                )

        # ====================================================
        # HIRE DATE
        # ====================================================
        hire_date = None

        if hire_date_raw:

            try:

                hire_date = datetime.strptime(
                    hire_date_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                errors.append(
                    "Invalid hire date."
                )

        # ====================================================
        # EXPERIENCE
        # ====================================================
        experience_years = None

        if experience_raw:

            try:

                experience_years = int(
                    experience_raw
                )

                if experience_years < 0:

                    errors.append(
                        "Experience years cannot "
                        "be negative."
                    )

            except (ValueError, TypeError):

                errors.append(
                    "Experience years must be "
                    "a valid number."
                )

        # ====================================================
        # INSTITUTION + BRANCH VALIDATION
        # ====================================================
        if not institution_id:

            errors.append(
                "Institution is required."
            )

        if not branch_id:

            errors.append(
                "Branch is required."
            )

        if institution_id and branch_id:

            _validate_teacher_relationships(
                institution_id,
                branch_id,
                errors
            )

        # ====================================================
        # USERNAME DUPLICATE CHECK
        # ====================================================
        if username:

            existing_teacher_username = (
                Teacher.query
                .filter(
                    func.lower(
                        Teacher.username
                    ) == username.lower()
                )
                .first()
            )

            if existing_teacher_username:

                errors.append(
                    "This username is already in use "
                    "by another teacher."
                )

            existing_user_username = (
                User.query
                .filter(
                    func.lower(
                        User.username
                    ) == username.lower()
                )
                .first()
            )

            if existing_user_username:

                errors.append(
                    "This username is already in use "
                    "by a user account."
                )

        # ====================================================
        # EMAIL DUPLICATE CHECK
        # ====================================================
        if email:

            existing_teacher_email = (
                Teacher.query
                .filter(
                    func.lower(
                        Teacher.email
                    ) == email.lower()
                )
                .first()
            )

            if existing_teacher_email:

                errors.append(
                    "This email is already in use "
                    "by another teacher."
                )

            existing_user_email = (
                User.query
                .filter(
                    func.lower(
                        User.email
                    ) == email.lower()
                )
                .first()
            )

            if existing_user_email:

                errors.append(
                    "This email is already in use "
                    "by a user account."
                )

        # ====================================================
        # VALIDATION ERRORS
        # ====================================================
        if errors:

            for error in errors:

                flash(
                    error,
                    "danger"
                )

        # ====================================================
        # CREATE TEACHER
        # ====================================================
        if not errors:

            # ------------------------------------------------
            # AUTO ROLL NUMBER
            # ------------------------------------------------
            roll_no = _generate_teacher_roll_no(
                institution_id
            )

            # ------------------------------------------------
            # TEACHER
            # ------------------------------------------------
            teacher = Teacher(

                institution_id=institution_id,

                branch_id=branch_id,

                username=username,

                email=email or None,

                role="teacher",

                roll_no=roll_no,

                full_name=full_name,

                gender=gender or None,

                date_of_birth=date_of_birth,

                phone=phone or None,

                address=address or None,

                city=city or None,

                qualification=qualification or None,

                specialization=specialization or None,

                experience_years=experience_years,

                hire_date=hire_date,

                is_active=is_active,

                is_verified=is_verified,

                status=status,

                notes=notes or None,

                created_at=datetime.utcnow(),

                updated_at=datetime.utcnow(),
            )

            # ------------------------------------------------
            # PASSWORD
            # ------------------------------------------------
            teacher.set_password(
                password
            )

            # =================================================
            # CLOUDINARY
            # =================================================
            if photo and photo.filename:

                try:

                    folder_name = (
                        f"teachers/"
                        f"institution_{institution_id}/"
                        f"branch_{branch_id}"
                    )

                    uploaded_photo = (
                        cloudinary.uploader.upload(

                            photo,

                            folder=folder_name,

                            resource_type="image",

                            transformation=[
                                {
                                    "width": 800,
                                    "height": 800,
                                    "crop": "limit",
                                    "quality": "auto",
                                    "fetch_format": "auto",
                                }
                            ]
                        )
                    )

                    teacher.profile_image = (
                        uploaded_photo.get(
                            "secure_url"
                        )
                    )

                    teacher.profile_image_public_id = (
                        uploaded_photo.get(
                            "public_id"
                        )
                    )

                except Exception as cloudinary_error:

                    current_app.logger.exception(
                        "Cloudinary teacher image "
                        "upload failed: %s",
                        cloudinary_error
                    )

                    flash(
                        "Teacher photo could not be "
                        "uploaded. Please try again.",
                        "danger"
                    )

                    # ----------------------------------------
                    # IMPORTANT:
                    # institution_id is passed here so
                    # _teacher_allowed_branches()
                    # returns correct branches.
                    # ----------------------------------------
                    context = _teacher_form_context(
                        institution_id
                    )

                    return render_template(
                        "backend/pages/teachers/"
                        "add_teacher.html",
                        **context
                    )

            # =================================================
            # DATABASE SAVE
            # =================================================
            try:

                db.session.add(
                    teacher
                )

                db.session.commit()

                flash(
                    f"Teacher {teacher.full_name} "
                    f"was created successfully. "
                    f"Roll No: {teacher.roll_no}",
                    "success"
                )

                return redirect(
                    url_for(
                        "main.view_teacher",
                        teacher_id=teacher.id
                    )
                )

            except IntegrityError as exc:

                db.session.rollback()

                current_app.logger.exception(
                    "Teacher integrity error: %s",
                    exc
                )

                flash(
                    "Unable to create teacher. "
                    "Username, email, roll number, "
                    "or another unique value may "
                    "already exist.",
                    "danger"
                )

            except Exception as exc:

                db.session.rollback()

                current_app.logger.exception(
                    "Error creating teacher: %s",
                    exc
                )

                flash(
                    "An unexpected error occurred "
                    "while creating the teacher.",
                    "danger"
                )

    # ========================================================
    # FORM CONTEXT
    # ========================================================
    context = _teacher_form_context(
        institution_id
    )

    # --------------------------------------------------------
    # Explicit values for template
    # --------------------------------------------------------
    context["institution_id"] = (
        institution_id
    )

    context["default_institution_id"] = (
        default_institution_id
    )

    # ========================================================
    # RENDER
    # ========================================================
    return render_template(
        "backend/pages/teachers/add_teacher.html",
        **context
    )


# ============================================================
# 3. VIEW TEACHER
# ============================================================
# ============================================================
# VIEW TEACHER
# ============================================================

@bp.route("/teachers/<int:teacher_id>", methods=["GET"])
@login_required
def view_teacher(teacher_id):

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    if not _teacher_can_manage():
        flash(
            "You are not authorized to view teachers.",
            "danger"
        )

        return redirect(
            url_for("main.all_teachers")
        )

    # ========================================================
    # GET TEACHER
    # ========================================================

    teacher = Teacher.query.get_or_404(teacher_id)

    # ========================================================
    # CURRENT USER SCOPE
    # ========================================================

    current_institution_id = (
        _teacher_get_user_institution_id()
    )

    # ========================================================
    # INSTITUTION SECURITY
    # ========================================================

    if current_institution_id is not None:

        if teacher.institution_id != current_institution_id:

            flash(
                "You are not authorized to view this teacher.",
                "danger"
            )

            return redirect(
                url_for("main.all_teachers")
            )

    # ========================================================
    # BRANCH SECURITY
    #
    # If your current user has a branch_id, make sure they
    # cannot view teachers belonging to another branch.
    # ========================================================

    current_branch_id = getattr(
        current_user,
        "branch_id",
        None
    )

    current_role = (
        getattr(current_user, "role", "") or ""
    ).strip().lower()

    branch_scoped_roles = {
        "branch_admin",
        "teacher"
    }

    if (
        current_branch_id is not None
        and current_role in branch_scoped_roles
    ):

        if teacher.branch_id != current_branch_id:

            flash(
                "You are not authorized to view "
                "this teacher from another branch.",
                "danger"
            )

            return redirect(
                url_for("main.all_teachers")
            )

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/teachers/view_teacher.html",
        teacher=teacher,
        user=current_user
    )



# ============================================================
# 4. EDIT TEACHER
# ============================================================
# ============================================================
# EDIT TEACHER
# ============================================================

@bp.route("/teachers/<int:teacher_id>/edit", methods=["GET", "POST"])
@login_required
def edit_teacher(teacher_id):

    # --------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------
    if not _teacher_can_manage():
        flash("You are not authorized to edit teachers.", "danger")
        return redirect(url_for("main.all_teachers"))

    # --------------------------------------------------------
    # GET TEACHER
    # --------------------------------------------------------
    teacher = Teacher.query.get_or_404(teacher_id)

    # --------------------------------------------------------
    # CURRENT USER INSTITUTION
    # --------------------------------------------------------
    current_institution_id = _teacher_get_user_institution_id()

    # --------------------------------------------------------
    # SECURITY:
    # Institution admins / branch admins should only edit
    # teachers belonging to their institution.
    # --------------------------------------------------------
    if current_institution_id is not None:
        if teacher.institution_id != current_institution_id:
            flash(
                "You are not authorized to edit this teacher.",
                "danger"
            )
            return redirect(url_for("main.all_teachers"))

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------
    if request.method == "POST":

        errors = []

        # ====================================================
        # FORM VALUES
        # ====================================================

        institution_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        branch_raw = request.form.get(
            "branch_id",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        gender = request.form.get(
            "gender",
            ""
        ).strip().lower()

        date_of_birth_raw = request.form.get(
            "date_of_birth",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        address = request.form.get(
            "address",
            ""
        ).strip()

        city = request.form.get(
            "city",
            ""
        ).strip()

        qualification = request.form.get(
            "qualification",
            ""
        ).strip()

        specialization = request.form.get(
            "specialization",
            ""
        ).strip()

        experience_raw = request.form.get(
            "experience_years",
            ""
        ).strip()

        hire_date_raw = request.form.get(
            "hire_date",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        is_active = request.form.get(
            "is_active"
        ) in {"1", "true", "on", "yes"}

        is_verified = request.form.get(
            "is_verified"
        ) in {"1", "true", "on", "yes"}

        notes = request.form.get(
            "notes",
            ""
        ).strip()

        # ====================================================
        # PHOTO
        # ====================================================

        photo_file = request.files.get("photo")

        # ====================================================
        # INSTITUTION ID
        # ====================================================

        institution_id = None

        try:
            if institution_raw:
                institution_id = int(institution_raw)
            else:
                errors.append("Institution is required.")
        except (TypeError, ValueError):
            errors.append("Invalid institution.")

        # ====================================================
        # BRANCH ID
        # ====================================================

        branch_id = None

        try:
            if branch_raw:
                branch_id = int(branch_raw)
            else:
                errors.append("Branch is required.")
        except (TypeError, ValueError):
            errors.append("Invalid branch.")

        # ====================================================
        # REQUIRED FIELDS
        # ====================================================

        if not username:
            errors.append("Username is required.")

        if not full_name:
            errors.append("Full name is required.")

        # ====================================================
        # USERNAME VALIDATION
        # ====================================================

        if username:

            existing_teacher = (
                Teacher.query
                .filter(
                    func.lower(Teacher.username) == username.lower(),
                    Teacher.id != teacher.id
                )
                .first()
            )

            if existing_teacher:
                errors.append(
                    "This username is already used by another teacher."
                )

            # ------------------------------------------------
            # CHECK LOGIN USERS TABLE
            # ------------------------------------------------

            existing_user = (
                User.query
                .filter(
                    func.lower(User.username) == username.lower()
                )
                .first()
            )

            if existing_user:
                errors.append(
                    "This username is already used by a login user."
                )

        # ====================================================
        # EMAIL VALIDATION
        # ====================================================

        if email:

            existing_teacher_email = (
                Teacher.query
                .filter(
                    func.lower(Teacher.email) == email.lower(),
                    Teacher.id != teacher.id
                )
                .first()
            )

            if existing_teacher_email:
                errors.append(
                    "This email is already used by another teacher."
                )

            # ------------------------------------------------
            # CHECK LOGIN USERS TABLE
            # ------------------------------------------------

            existing_user_email = (
                User.query
                .filter(
                    func.lower(User.email) == email.lower()
                )
                .first()
            )

            if existing_user_email:
                errors.append(
                    "This email is already used by a login user."
                )

        # ====================================================
        # GENDER
        # ====================================================

        if gender:

            valid_genders = {
                str(value).lower()
                for value in TEACHER_GENDERS
            }

            if gender not in valid_genders:
                errors.append("Invalid gender.")

        # ====================================================
        # STATUS
        # ====================================================

        if status:

            valid_statuses = {
                str(value).lower()
                for value in TEACHER_STATUSES
            }

            if status not in valid_statuses:
                errors.append("Invalid teacher status.")

        # ====================================================
        # DATE OF BIRTH
        # ====================================================

        date_of_birth = None

        if date_of_birth_raw:

            try:
                date_of_birth = datetime.strptime(
                    date_of_birth_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:
                errors.append(
                    "Invalid date of birth."
                )

        # ====================================================
        # HIRE DATE
        # ====================================================

        hire_date = None

        if hire_date_raw:

            try:
                hire_date = datetime.strptime(
                    hire_date_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:
                errors.append(
                    "Invalid hire date."
                )

        # ====================================================
        # EXPERIENCE YEARS
        # ====================================================

        experience_years = 0

        if experience_raw:

            try:
                experience_years = int(
                    experience_raw
                )

                if experience_years < 0:
                    errors.append(
                        "Experience years cannot be negative."
                    )

            except (TypeError, ValueError):

                errors.append(
                    "Experience years must be a valid number."
                )

        # ====================================================
        # PASSWORD
        # Only change password when user enters a new one.
        # ====================================================

        if password:

            if len(password) < 6:
                errors.append(
                    "Password must be at least 6 characters."
                )

            if password != confirm_password:
                errors.append(
                    "Password confirmation does not match."
                )

        # ====================================================
        # RELATIONSHIP VALIDATION
        # ====================================================

        if institution_id and branch_id:

            _validate_teacher_relationships(
                institution_id,
                branch_id,
                errors
            )

        # ====================================================
        # PHOTO VALIDATION
        # ====================================================

        photo_url = teacher.photo
        uploaded_public_id = None

        if photo_file and photo_file.filename:

            filename = secure_filename(
                photo_file.filename
            )

            extension = ""

            if "." in filename:
                extension = filename.rsplit(
                    ".",
                    1
                )[1].lower()

            allowed_extensions = {
                "jpg",
                "jpeg",
                "png",
                "webp"
            }

            allowed_mimetypes = {
                "image/jpeg",
                "image/png",
                "image/webp"
            }

            if extension not in allowed_extensions:
                errors.append(
                    "Invalid photo format. "
                    "Allowed: JPG, JPEG, PNG and WEBP."
                )

            if (
                photo_file.mimetype
                and photo_file.mimetype.lower()
                not in allowed_mimetypes
            ):
                errors.append(
                    "Invalid photo file type."
                )

            # ------------------------------------------------
            # MAX SIZE = 2 MB
            # ------------------------------------------------

            try:

                photo_file.stream.seek(
                    0,
                    os.SEEK_END
                )

                photo_size = (
                    photo_file.stream.tell()
                )

                photo_file.stream.seek(
                    0
                )

                max_photo_size = (
                    2 * 1024 * 1024
                )

                if photo_size > max_photo_size:
                    errors.append(
                        "Photo size must not exceed 2 MB."
                    )

            except Exception:
                errors.append(
                    "Unable to validate the photo."
                )

        # ====================================================
        # IF VALIDATION FAILED
        # ====================================================

        if errors:

            for error in errors:
                flash(error, "danger")

            context = _teacher_form_context(
                institution_id
                if institution_id
                else current_institution_id
            )

            return render_template(
                "backend/pages/teachers/edit_teacher.html",
                teacher=teacher,
                form_data=request.form,
                **context
            )

        # ====================================================
        # CLOUDINARY UPLOAD
        # ====================================================

        try:

            if photo_file and photo_file.filename:

                upload_result = (
                    cloudinary.uploader.upload(
                        photo_file,
                        folder="teachers",
                        resource_type="image",
                        use_filename=False,
                        unique_filename=True,
                        overwrite=False
                    )
                )

                photo_url = upload_result.get(
                    "secure_url"
                )

                uploaded_public_id = (
                    upload_result.get("public_id")
                )

                if not photo_url:
                    raise Exception(
                        "Cloudinary did not return a secure URL."
                    )

        except Exception as cloudinary_error:

            db.session.rollback()

            current_app.logger.exception(
                "Teacher photo upload failed: %s",
                cloudinary_error
            )

            flash(
                "Teacher photo upload failed. "
                "Please try again.",
                "danger"
            )

            context = _teacher_form_context(
                institution_id
                if institution_id
                else current_institution_id
            )

            return render_template(
                "backend/pages/teachers/edit_teacher.html",
                teacher=teacher,
                form_data=request.form,
                **context
            )

        # ====================================================
        # UPDATE TEACHER
        # ====================================================

        try:

            teacher.institution_id = institution_id
            teacher.branch_id = branch_id

            teacher.username = username
            teacher.email = email or None

            teacher.full_name = full_name
            teacher.gender = gender or None

            teacher.date_of_birth = date_of_birth

            teacher.phone = phone or None
            teacher.address = address or None
            teacher.city = city or None

            teacher.qualification = (
                qualification or None
            )

            teacher.specialization = (
                specialization or None
            )

            teacher.experience_years = (
                experience_years
            )

            teacher.hire_date = hire_date

            teacher.status = status

            teacher.is_active = is_active
            teacher.is_verified = is_verified

            teacher.notes = notes or None

            # ------------------------------------------------
            # UPDATE PHOTO ONLY IF NEW PHOTO WAS UPLOADED
            # ------------------------------------------------

            if photo_url:
                teacher.photo = photo_url

            # ------------------------------------------------
            # PASSWORD
            # Only update when provided.
            # ------------------------------------------------

            if password:
                teacher.set_password(password)

            # ------------------------------------------------
            # UPDATED AT
            # ------------------------------------------------

            teacher.updated_at = datetime.utcnow()

            db.session.commit()

            flash(
                f"Teacher '{teacher.full_name}' "
                "was updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "main.view_teacher",
                    teacher_id=teacher.id
                )
            )

        except IntegrityError as exc:

            db.session.rollback()

            # ------------------------------------------------
            # CLEAN UP NEW CLOUDINARY FILE IF DB FAILED
            # ------------------------------------------------

            if uploaded_public_id:

                try:

                    cloudinary.uploader.destroy(
                        uploaded_public_id,
                        resource_type="image"
                    )

                except Exception:

                    current_app.logger.exception(
                        "Failed to cleanup Cloudinary "
                        "teacher image after DB error."
                    )

            current_app.logger.exception(
                "Integrity error while updating teacher: %s",
                exc
            )

            flash(
                "Unable to update teacher because "
                "some information already exists.",
                "danger"
            )

        except Exception as exc:

            db.session.rollback()

            # ------------------------------------------------
            # CLEAN UP NEW CLOUDINARY FILE
            # ------------------------------------------------

            if uploaded_public_id:

                try:

                    cloudinary.uploader.destroy(
                        uploaded_public_id,
                        resource_type="image"
                    )

                except Exception:

                    current_app.logger.exception(
                        "Failed to cleanup Cloudinary "
                        "teacher image after update error."
                    )

            current_app.logger.exception(
                "Unexpected error while updating teacher: %s",
                exc
            )

            flash(
                "An unexpected error occurred "
                "while updating the teacher.",
                "danger"
            )

        # ====================================================
        # RENDER AGAIN AFTER DATABASE ERROR
        # ====================================================

        context = _teacher_form_context(
            institution_id
            if institution_id
            else current_institution_id
        )

        return render_template(
            "backend/pages/teachers/edit_teacher.html",
            teacher=teacher,
            form_data=request.form,
            **context
        )

    # ========================================================
    # GET
    # ========================================================

    context = _teacher_form_context(
        teacher.institution_id
        if teacher.institution_id
        else current_institution_id
    )

    return render_template(
        "backend/pages/teachers/edit_teacher.html",
        teacher=teacher,
        form_data=None,
        **context
    )


# ============================================================
# 5. DELETE TEACHER
# ============================================================

@bp.route(
    "/teachers/<int:teacher_id>/delete",
    methods=["POST"]
)
@login_required
def delete_teacher(teacher_id):

    if not _teacher_can_manage():

        flash(
            "You are not authorized to delete teachers.",
            "danger"
        )

        return redirect(
            url_for("main.all_teachers")
        )

    teacher = Teacher.query.get_or_404(
        teacher_id
    )

    if not _teacher_can_access(teacher):

        flash(
            "You are not authorized to delete this teacher.",
            "danger"
        )

        return redirect(
            url_for("main.all_teachers")
        )

    teacher_name = teacher.full_name
    teacher_roll = teacher.roll_no

    try:

        db.session.delete(
            teacher
        )

        db.session.commit()

        flash(
            f"Teacher {teacher_name} "
            f"({teacher_roll}) was deleted successfully.",
            "success"
        )

    except IntegrityError:

        db.session.rollback()

        flash(
            "This teacher cannot be deleted because "
            "other records are linked to this teacher.",
            "danger"
        )

    except Exception as exc:

        db.session.rollback()

        current_app.logger.exception(
            "Error deleting teacher: %s",
            exc
        )

        flash(
            "An unexpected error occurred "
            "while deleting the teacher.",
            "danger"
        )

    return redirect(
        url_for("main.all_teachers")
    )



# ============================================================
# TEACHER SUBJECT ROUTES
# PostgreSQL / Neon
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

TEACHER_SUBJECT_TYPES = [
    "teacher",
    "assistant",
    "coordinator",
    "substitute",
]

TEACHER_SUBJECT_STATUSES = [
    "active",
    "inactive",
    "suspended",
]


# ============================================================
# AUTHORIZATION
# ============================================================

def _teacher_subject_can_manage():
    """
    Users allowed to manage teacher-subject assignments.
    """

    if not current_user.is_authenticated:
        return False

    role = getattr(current_user, "role", None)

    return role in {
        "superadmin",
        "institution_admin",
        "branch_admin",
    }


# ============================================================
# CURRENT USER INSTITUTION
# ============================================================

def _teacher_subject_user_institution_id():
    """
    Return institution_id for institution/branch scoped users.
    Superadmin returns None.
    """

    role = getattr(current_user, "role", None)

    if role == "superadmin":
        return None

    return getattr(current_user, "institution_id", None)


# ============================================================
# CURRENT USER BRANCH
# ============================================================

def _teacher_subject_user_branch_id():
    """
    Return branch_id for branch scoped users.
    """

    role = getattr(current_user, "role", None)

    if role in {"superadmin", "institution_admin"}:
        return None

    return getattr(current_user, "branch_id", None)


# ============================================================
# ALLOWED INSTITUTIONS
# ============================================================

def _teacher_subject_allowed_institutions():

    query = Institution.query

    institution_id = _teacher_subject_user_institution_id()

    if institution_id:
        query = query.filter(
            Institution.id == institution_id
        )

    return query.order_by(
        Institution.name.asc()
    ).all()


# ============================================================
# ALLOWED BRANCHES
# ============================================================

def _teacher_subject_allowed_branches(institution_id=None):

    query = Branch.query

    role = getattr(current_user, "role", None)

    user_institution_id = _teacher_subject_user_institution_id()
    user_branch_id = _teacher_subject_user_branch_id()

    # --------------------------------------------------------
    # Institution filter
    # --------------------------------------------------------

    if institution_id:
        query = query.filter(
            Branch.institution_id == institution_id
        )
    elif user_institution_id:
        query = query.filter(
            Branch.institution_id == user_institution_id
        )

    # --------------------------------------------------------
    # Branch admin can only see own branch
    # --------------------------------------------------------

    if role == "branch_admin" and user_branch_id:
        query = query.filter(
            Branch.id == user_branch_id
        )

    return query.order_by(
        Branch.name.asc()
    ).all()


# ============================================================
# TEACHER SUBJECT FORM CONTEXT
# ============================================================

def _teacher_subject_form_context(
    institution_id=None,
    branch_id=None
):

    role = getattr(current_user, "role", None)

    user_institution_id = _teacher_subject_user_institution_id()
    user_branch_id = _teacher_subject_user_branch_id()

    # --------------------------------------------------------
    # Force scoped values
    # --------------------------------------------------------

    if user_institution_id:
        institution_id = user_institution_id

    if role == "branch_admin" and user_branch_id:
        branch_id = user_branch_id

    # ========================================================
    # INSTITUTIONS
    # ========================================================

    institutions = _teacher_subject_allowed_institutions()

    # ========================================================
    # BRANCHES
    #
    # IMPORTANT:
    # For superadmin/institution_admin, load ALL allowed
    # branches when no branch has been selected.
    # ========================================================

    branches = _teacher_subject_allowed_branches(
        institution_id
    )

    # ========================================================
    # TEACHERS
    #
    # IMPORTANT FIX:
    # Do NOT accidentally filter teachers only by branch when
    # branch is None.
    # ========================================================

    teacher_query = Teacher.query

    if institution_id:
        teacher_query = teacher_query.filter(
            Teacher.institution_id == institution_id
        )
    elif user_institution_id:
        teacher_query = teacher_query.filter(
            Teacher.institution_id == user_institution_id
        )

    if branch_id:
        teacher_query = teacher_query.filter(
            Teacher.branch_id == branch_id
        )
    elif role == "branch_admin" and user_branch_id:
        teacher_query = teacher_query.filter(
            Teacher.branch_id == user_branch_id
        )

    teacher_query = teacher_query.filter(
        or_(
            Teacher.is_active.is_(True),
            Teacher.status == "active"
        )
    )

    teachers = teacher_query.order_by(
        Teacher.full_name.asc()
    ).all()

    # ========================================================
    # SUBJECTS
    # ========================================================

    subject_query = Subject.query

    if institution_id:
        subject_query = subject_query.filter(
            Subject.institution_id == institution_id
        )
    elif user_institution_id:
        subject_query = subject_query.filter(
            Subject.institution_id == user_institution_id
        )

    # Branch filtering only when Subject actually has branch
    # relationship/data.
    if branch_id and hasattr(Subject, "branch_id"):
        subject_query = subject_query.filter(
            Subject.branch_id == branch_id
        )

    subjects = subject_query.order_by(
        Subject.name.asc()
    ).all()

    # ========================================================
    # PROGRAMS
    # ========================================================

    program_query = Program.query

    if institution_id:
        program_query = program_query.filter(
            Program.institution_id == institution_id
        )
    elif user_institution_id:
        program_query = program_query.filter(
            Program.institution_id == user_institution_id
        )

    if branch_id and hasattr(Program, "branch_id"):
        program_query = program_query.filter(
            Program.branch_id == branch_id
        )

    programs = program_query.order_by(
        Program.name.asc()
    ).all()

    # ========================================================
    # CLASSES
    # ========================================================

    class_query = Class.query

    if institution_id:
        class_query = class_query.filter(
            Class.institution_id == institution_id
        )
    elif user_institution_id:
        class_query = class_query.filter(
            Class.institution_id == user_institution_id
        )

    if branch_id and hasattr(Class, "branch_id"):
        class_query = class_query.filter(
            Class.branch_id == branch_id
        )

    classes = class_query.order_by(
        Class.name.asc()
    ).all()

    # ========================================================
    # SECTIONS
    # ========================================================

    section_query = Section.query

    if institution_id:
        section_query = section_query.filter(
            Section.institution_id == institution_id
        )
    elif user_institution_id:
        section_query = section_query.filter(
            Section.institution_id == user_institution_id
        )

    if branch_id and hasattr(Section, "branch_id"):
        section_query = section_query.filter(
            Section.branch_id == branch_id
        )

    sections = section_query.order_by(
        Section.name.asc()
    ).all()

    # ========================================================
    # ACADEMIC YEARS
    # ========================================================

    academic_year_query = AcademicYear.query

    if institution_id and hasattr(
        AcademicYear,
        "institution_id"
    ):
        academic_year_query = academic_year_query.filter(
            AcademicYear.institution_id == institution_id
        )

    academic_years = academic_year_query.order_by(
        AcademicYear.name.desc()
    ).all()

    # ========================================================
    # RETURN
    # ========================================================

    return {
        "user": current_user,

        "institutions": institutions,

        "branches": branches,

        "teachers": teachers,

        "subjects": subjects,

        "programs": programs,

        "classes": classes,

        "sections": sections,

        "academic_years": academic_years,

        "teacher_subject_types":
            TEACHER_SUBJECT_TYPES,

        "teacher_subject_statuses":
            TEACHER_SUBJECT_STATUSES,

        "institution_id": institution_id,

        "branch_id": branch_id,

        "default_institution_id":
            user_institution_id,

        "default_branch_id":
            user_branch_id,
    }


# ============================================================
# ALL TEACHER SUBJECTS
# ============================================================
# ============================================================
# ALL TEACHER SUBJECTS
# ============================================================

@bp.route("/teacher-subjects", methods=["GET"])
@login_required
def all_teacher_subjects():

    if not _teacher_subject_can_manage():
        flash(
            "You are not authorized to manage teacher subject assignments.",
            "danger"
        )
        return redirect(url_for("main.dashboard"))

    query = TeacherSubject.query

    role = getattr(current_user, "role", None)

    user_institution_id = _teacher_subject_user_institution_id()
    user_branch_id = _teacher_subject_user_branch_id()

    # ========================================================
    # SECURITY SCOPE
    # ========================================================

    if user_institution_id:
        query = query.filter(
            TeacherSubject.institution_id == user_institution_id
        )

    if role == "branch_admin" and user_branch_id:
        query = query.filter(
            TeacherSubject.branch_id == user_branch_id
        )

    # ========================================================
    # FILTER VALUES
    # ========================================================

    institution_id = request.args.get(
        "institution_id",
        type=int
    )

    branch_id = request.args.get(
        "branch_id",
        type=int
    )

    teacher_id = request.args.get(
        "teacher_id",
        type=int
    )

    subject_id = request.args.get(
        "subject_id",
        type=int
    )

    program_id = request.args.get(
        "program_id",
        type=int
    )

    class_id = request.args.get(
        "class_id",
        type=int
    )

    section_id = request.args.get(
        "section_id",
        type=int
    )

    academic_year_id = request.args.get(
        "academic_year_id",
        type=int
    )

    teaching_type = request.args.get(
        "teaching_type",
        "",
        type=str
    ).strip()

    status = request.args.get(
        "status",
        "",
        type=str
    ).strip()

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    # ========================================================
    # SECURITY: INSTITUTION
    # ========================================================

    if user_institution_id:
        institution_id = user_institution_id

    elif institution_id:
        query = query.filter(
            TeacherSubject.institution_id == institution_id
        )

    # ========================================================
    # BRANCH
    # ========================================================

    if role == "branch_admin":
        branch_id = user_branch_id

    if branch_id:
        query = query.filter(
            TeacherSubject.branch_id == branch_id
        )

    # ========================================================
    # TEACHER
    # ========================================================

    if teacher_id:
        query = query.filter(
            TeacherSubject.teacher_id == teacher_id
        )

    # ========================================================
    # SUBJECT
    # ========================================================

    if subject_id:
        query = query.filter(
            TeacherSubject.subject_id == subject_id
        )

    # ========================================================
    # PROGRAM
    # ========================================================

    if program_id:
        query = query.filter(
            TeacherSubject.program_id == program_id
        )

    # ========================================================
    # CLASS
    # ========================================================

    if class_id:
        query = query.filter(
            TeacherSubject.class_id == class_id
        )

    # ========================================================
    # SECTION
    # ========================================================

    if section_id:
        query = query.filter(
            TeacherSubject.section_id == section_id
        )

    # ========================================================
    # ACADEMIC YEAR
    # ========================================================

    if academic_year_id:
        query = query.filter(
            TeacherSubject.academic_year_id ==
            academic_year_id
        )

    # ========================================================
    # TEACHING TYPE
    # ========================================================

    if teaching_type:
        query = query.filter(
            TeacherSubject.teaching_type ==
            teaching_type
        )

    # ========================================================
    # STATUS
    # ========================================================

    if status:
        query = query.filter(
            TeacherSubject.status == status
        )

    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        query = query.join(
            Teacher,
            Teacher.id == TeacherSubject.teacher_id
        ).join(
            Subject,
            Subject.id == TeacherSubject.subject_id
        ).filter(
            or_(
                Teacher.full_name.ilike(
                    f"%{search}%"
                ),
                Teacher.username.ilike(
                    f"%{search}%"
                ),
                Subject.name.ilike(
                    f"%{search}%"
                ),
                Subject.code.ilike(
                    f"%{search}%"
                )
            )
        )

    # ========================================================
    # RESULTS
    # ========================================================

    teacher_subjects = query.order_by(
        TeacherSubject.created_at.desc()
    ).all()

    # ========================================================
    # FORM/FILTER DATA
    # ========================================================

    institutions = _teacher_subject_allowed_institutions()

    branches = _teacher_subject_allowed_branches(
        institution_id
    )

    # ========================================================
    # TEACHERS
    # ========================================================

    teacher_query = Teacher.query

    if institution_id:
        teacher_query = teacher_query.filter(
            Teacher.institution_id == institution_id
        )

    if branch_id:
        teacher_query = teacher_query.filter(
            Teacher.branch_id == branch_id
        )

    teachers = teacher_query.order_by(
        Teacher.full_name.asc()
    ).all()

    # ========================================================
    # SUBJECTS
    # ========================================================

    subject_query = Subject.query

    if institution_id:
        subject_query = subject_query.filter(
            Subject.institution_id == institution_id
        )

    if branch_id and hasattr(Subject, "branch_id"):
        subject_query = subject_query.filter(
            Subject.branch_id == branch_id
        )

    subjects = subject_query.order_by(
        Subject.name.asc()
    ).all()

    # ========================================================
    # PROGRAMS
    # ========================================================

    program_query = Program.query

    if institution_id:
        program_query = program_query.filter(
            Program.institution_id == institution_id
        )

    if branch_id and hasattr(Program, "branch_id"):
        program_query = program_query.filter(
            Program.branch_id == branch_id
        )

    programs = program_query.order_by(
        Program.name.asc()
    ).all()

    # ========================================================
    # CLASSES
    # ========================================================

    class_query = Class.query

    if institution_id:
        class_query = class_query.filter(
            Class.institution_id == institution_id
        )

    if branch_id and hasattr(Class, "branch_id"):
        class_query = class_query.filter(
            Class.branch_id == branch_id
        )

    classes = class_query.order_by(
        Class.name.asc()
    ).all()

    # ========================================================
    # SECTIONS
    # ========================================================

    section_query = Section.query

    if institution_id:
        section_query = section_query.filter(
            Section.institution_id == institution_id
        )

    if branch_id and hasattr(Section, "branch_id"):
        section_query = section_query.filter(
            Section.branch_id == branch_id
        )

    sections = section_query.order_by(
        Section.name.asc()
    ).all()

    # ========================================================
    # ACADEMIC YEARS
    # ========================================================

    academic_year_query = AcademicYear.query

    if (
        institution_id
        and hasattr(AcademicYear, "institution_id")
    ):
        academic_year_query = academic_year_query.filter(
            AcademicYear.institution_id == institution_id
        )

    academic_years = academic_year_query.order_by(
        AcademicYear.id.desc()
    ).all()

    # ========================================================
    # FILTER OBJECT
    # ========================================================

    filters = {
        "institution_id": institution_id,
        "branch_id": branch_id,
        "teacher_id": teacher_id,
        "subject_id": subject_id,
        "program_id": program_id,
        "class_id": class_id,
        "section_id": section_id,
        "academic_year_id": academic_year_id,
        "teaching_type": teaching_type,
        "status": status,
        "search": search,
    }

    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/teacher_subjects/all_teacher_subjects.html",

        user=current_user,

        teacher_subjects=teacher_subjects,

        institutions=institutions,
        branches=branches,
        teachers=teachers,
        subjects=subjects,
        programs=programs,
        classes=classes,
        sections=sections,
        academic_years=academic_years,

        teacher_subject_types=
            TEACHER_SUBJECT_TYPES,

        teacher_subject_statuses=
            TEACHER_SUBJECT_STATUSES,

        filters=filters,
    )


# ============================================================
# ADD TEACHER SUBJECT
# ============================================================
# ============================================================
# ADD TEACHER SUBJECT ASSIGNMENTS
# MULTI ASSIGNMENT VERSION
# ============================================================

@bp.route(
    "/teacher-subjects/add",
    methods=["GET", "POST"]
)
@login_required
def add_teacher_subject():

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    if not _teacher_subject_can_manage():

        flash(
            "You are not authorized to create teacher subject assignments.",
            "danger"
        )

        return redirect(
            url_for("main.all_teacher_subjects")
        )

    role = getattr(
        current_user,
        "role",
        None
    )

    user_institution_id = \
        _teacher_subject_user_institution_id()

    user_branch_id = \
        _teacher_subject_user_branch_id()

    # ========================================================
    # DEFAULT VALUES
    # ========================================================

    institution_id = (
        user_institution_id
        or request.args.get(
            "institution_id",
            type=int
        )
    )

    branch_id = (
        user_branch_id
        if role == "branch_admin"
        else request.args.get(
            "branch_id",
            type=int
        )
    )

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # SHARED FIELDS
        # These are common to ALL assignment rows
        # ====================================================

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        branch_id = request.form.get(
            "branch_id",
            type=int
        )

        # ====================================================
        # SECURITY OVERRIDE
        # ====================================================

        if user_institution_id:

            institution_id = user_institution_id

        if role == "branch_admin":

            branch_id = user_branch_id

        # ====================================================
        # MULTIPLE ROW DATA
        # ====================================================

        teacher_ids = request.form.getlist(
            "teacher_id[]"
        )

        subject_ids = request.form.getlist(
            "subject_id[]"
        )

        teaching_types = request.form.getlist(
            "teaching_type[]"
        )

        statuses = request.form.getlist(
            "status[]"
        )

        is_primaries = request.form.getlist(
            "is_primary[]"
        )

        program_ids = request.form.getlist(
            "program_id[]"
        )

        class_ids = request.form.getlist(
            "class_id[]"
        )

        section_ids = request.form.getlist(
            "section_id[]"
        )

        academic_year_ids = request.form.getlist(
            "academic_year_id[]"
        )

        start_dates = request.form.getlist(
            "start_date[]"
        )

        end_dates = request.form.getlist(
            "end_date[]"
        )

        notes_list = request.form.getlist(
            "notes[]"
        )

        # ====================================================
        # NUMBER OF ASSIGNMENT ROWS
        # ====================================================

        row_count = len(teacher_ids)

        errors = []

        # ====================================================
        # REQUIRED SHARED FIELDS
        # ====================================================

        if not institution_id:

            errors.append(
                "Institution is required."
            )

        if not branch_id:

            errors.append(
                "Branch is required."
            )

        if row_count == 0:

            errors.append(
                "Please add at least one teacher subject assignment."
            )

        # ====================================================
        # ARRAY LENGTH VALIDATION
        # ====================================================

        arrays = {
            "subject_ids": subject_ids,
            "teaching_types": teaching_types,
            "statuses": statuses,
            "is_primaries": is_primaries,
            "program_ids": program_ids,
            "class_ids": class_ids,
            "section_ids": section_ids,
            "academic_year_ids": academic_year_ids,
            "start_dates": start_dates,
            "end_dates": end_dates,
            "notes_list": notes_list,
        }

        for field_name, values in arrays.items():

            if len(values) != row_count:

                errors.append(
                    f"Invalid multi-assignment data for {field_name}."
                )

        # ====================================================
        # INSTITUTION
        # ====================================================

        institution = None

        if institution_id:

            institution = Institution.query.filter(
                Institution.id == institution_id
            ).first()

            if not institution:

                errors.append(
                    "Selected institution does not exist."
                )

        # ====================================================
        # BRANCH
        # ====================================================

        branch = None

        if branch_id and institution_id:

            branch = Branch.query.filter(
                Branch.id == branch_id,
                Branch.institution_id == institution_id
            ).first()

            if not branch:

                errors.append(
                    "Selected branch does not belong to the selected institution."
                )

        # ====================================================
        # PROCESS EACH ASSIGNMENT
        # ========================================================

        prepared_assignments = []

        if not errors:

            for index in range(row_count):

                assignment_number = index + 1

                row_errors = []

                # ==================================================
                # REQUIRED IDS
                # ==================================================

                teacher_id = None
                subject_id = None
                academic_year_id = None

                try:

                    teacher_id = (
                        int(teacher_ids[index])
                        if teacher_ids[index]
                        else None
                    )

                except (TypeError, ValueError):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid teacher."
                    )

                try:

                    subject_id = (
                        int(subject_ids[index])
                        if subject_ids[index]
                        else None
                    )

                except (TypeError, ValueError):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid subject."
                    )

                try:

                    academic_year_id = (
                        int(academic_year_ids[index])
                        if academic_year_ids[index]
                        else None
                    )

                except (TypeError, ValueError):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid academic year."
                    )

                # ==================================================
                # REQUIRED VALIDATION
                # ==================================================

                if not teacher_id:

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Teacher is required."
                    )

                if not subject_id:

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Subject is required."
                    )

                if not academic_year_id:

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Academic Year is required."
                    )

                # ==================================================
                # OPTIONAL IDS
                # ==================================================

                program_id = None
                class_id = None
                section_id = None

                try:

                    program_id = (
                        int(program_ids[index])
                        if program_ids[index]
                        else None
                    )

                except (TypeError, ValueError):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid program."
                    )

                try:

                    class_id = (
                        int(class_ids[index])
                        if class_ids[index]
                        else None
                    )

                except (TypeError, ValueError):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid class."
                    )

                try:

                    section_id = (
                        int(section_ids[index])
                        if section_ids[index]
                        else None
                    )

                except (TypeError, ValueError):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid section."
                    )

                # ==================================================
                # TEACHING TYPE
                # ==================================================

                teaching_type = (
                    teaching_types[index].strip().lower()
                    if teaching_types[index]
                    else "teacher"
                )

                if teaching_type not in \
                        TEACHER_SUBJECT_TYPES:

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid teaching type."
                    )

                # ==================================================
                # STATUS
                # ==================================================

                status = (
                    statuses[index].strip().lower()
                    if statuses[index]
                    else "active"
                )

                if status not in \
                        TEACHER_SUBJECT_STATUSES:

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"Invalid assignment status."
                    )

                # ==================================================
                # PRIMARY
                # ==================================================

                is_primary = (
                    str(is_primaries[index]).lower()
                    in {
                        "1",
                        "true",
                        "on",
                        "yes",
                    }
                )

                # ==================================================
                # START DATE
                # ==================================================

                start_date_raw = (
                    start_dates[index].strip()
                    if start_dates[index]
                    else ""
                )

                start_date = None

                if start_date_raw:

                    try:

                        start_date = datetime.strptime(
                            start_date_raw,
                            "%Y-%m-%d"
                        ).date()

                    except ValueError:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Invalid start date."
                        )

                # ==================================================
                # END DATE
                # ==================================================

                end_date_raw = (
                    end_dates[index].strip()
                    if end_dates[index]
                    else ""
                )

                end_date = None

                if end_date_raw:

                    try:

                        end_date = datetime.strptime(
                            end_date_raw,
                            "%Y-%m-%d"
                        ).date()

                    except ValueError:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Invalid end date."
                        )

                # ==================================================
                # DATE RANGE
                # ==================================================

                if (
                    start_date
                    and end_date
                    and end_date < start_date
                ):

                    row_errors.append(
                        f"Assignment #{assignment_number}: "
                        f"End date cannot be before start date."
                    )

                # ==================================================
                # NOTES
                # ==================================================

                notes = (
                    notes_list[index].strip()
                    if notes_list[index]
                    else ""
                )

                # ==================================================
                # TEACHER
                # ==================================================

                teacher = None

                if (
                    teacher_id
                    and institution_id
                    and branch_id
                ):

                    teacher = Teacher.query.filter(
                        Teacher.id == teacher_id,
                        Teacher.institution_id ==
                        institution_id,
                        Teacher.branch_id ==
                        branch_id
                    ).first()

                    if not teacher:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Selected teacher does not belong "
                            f"to the selected branch."
                        )

                # ==================================================
                # SUBJECT
                # ==================================================

                subject = None

                if subject_id and institution_id:

                    subject_query = Subject.query.filter(
                        Subject.id == subject_id,
                        Subject.institution_id ==
                        institution_id
                    )

                    if hasattr(
                        Subject,
                        "branch_id"
                    ):

                        subject_query = \
                            subject_query.filter(
                                Subject.branch_id ==
                                branch_id
                            )

                    subject = subject_query.first()

                    if not subject:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Selected subject does not belong "
                            f"to the selected institution/branch."
                        )

                # ==================================================
                # PROGRAM
                # ==================================================

                program = None

                if program_id:

                    program_query = Program.query.filter(
                        Program.id == program_id,
                        Program.institution_id ==
                        institution_id
                    )

                    if hasattr(
                        Program,
                        "branch_id"
                    ):

                        program_query = \
                            program_query.filter(
                                Program.branch_id ==
                                branch_id
                            )

                    program = program_query.first()

                    if not program:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Selected program is invalid."
                        )

                # ==================================================
                # CLASS
                # ==================================================

                class_obj = None

                if class_id:

                    class_query = Class.query.filter(
                        Class.id == class_id,
                        Class.institution_id ==
                        institution_id
                    )

                    if hasattr(
                        Class,
                        "branch_id"
                    ):

                        class_query = \
                            class_query.filter(
                                Class.branch_id ==
                                branch_id
                            )

                    class_obj = class_query.first()

                    if not class_obj:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Selected class is invalid."
                        )

                # ==================================================
                # SECTION
                # ==================================================

                section = None

                if section_id:

                    section_query = Section.query.filter(
                        Section.id == section_id,
                        Section.institution_id ==
                        institution_id
                    )

                    if hasattr(
                        Section,
                        "branch_id"
                    ):

                        section_query = \
                            section_query.filter(
                                Section.branch_id ==
                                branch_id
                            )

                    if (
                        class_id
                        and hasattr(
                            Section,
                            "class_id"
                        )
                    ):

                        section_query = \
                            section_query.filter(
                                Section.class_id ==
                                class_id
                            )

                    section = section_query.first()

                    if not section:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Selected section is invalid "
                            f"for the selected class."
                        )

                # ==================================================
                # ACADEMIC YEAR
                # ==================================================

                academic_year = None

                if academic_year_id:

                    academic_year_query = \
                        AcademicYear.query.filter(
                            AcademicYear.id ==
                            academic_year_id
                        )

                    if hasattr(
                        AcademicYear,
                        "institution_id"
                    ):

                        academic_year_query = \
                            academic_year_query.filter(
                                AcademicYear.institution_id ==
                                institution_id
                            )

                    academic_year = \
                        academic_year_query.first()

                    if not academic_year:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"Selected academic year is invalid."
                        )

                # ==================================================
                # DUPLICATE CHECK
                #
                # Explicit NULL handling for PostgreSQL
                # ==================================================

                duplicate = None

                if (
                    teacher_id
                    and subject_id
                    and academic_year_id
                    and not row_errors
                ):

                    duplicate_query = TeacherSubject.query.filter(
                        TeacherSubject.institution_id ==
                        institution_id,

                        TeacherSubject.branch_id ==
                        branch_id,

                        TeacherSubject.teacher_id ==
                        teacher_id,

                        TeacherSubject.subject_id ==
                        subject_id,

                        TeacherSubject.academic_year_id ==
                        academic_year_id
                    )

                    # ------------------------------------------
                    # PROGRAM
                    # ------------------------------------------

                    if program_id is None:

                        duplicate_query = \
                            duplicate_query.filter(
                                TeacherSubject.program_id.is_(None)
                            )

                    else:

                        duplicate_query = \
                            duplicate_query.filter(
                                TeacherSubject.program_id ==
                                program_id
                            )

                    # ------------------------------------------
                    # CLASS
                    # ------------------------------------------

                    if class_id is None:

                        duplicate_query = \
                            duplicate_query.filter(
                                TeacherSubject.class_id.is_(None)
                            )

                    else:

                        duplicate_query = \
                            duplicate_query.filter(
                                TeacherSubject.class_id ==
                                class_id
                            )

                    # ------------------------------------------
                    # SECTION
                    # ------------------------------------------

                    if section_id is None:

                        duplicate_query = \
                            duplicate_query.filter(
                                TeacherSubject.section_id.is_(None)
                            )

                    else:

                        duplicate_query = \
                            duplicate_query.filter(
                                TeacherSubject.section_id ==
                                section_id
                            )

                    duplicate = duplicate_query.first()

                    if duplicate:

                        row_errors.append(
                            f"Assignment #{assignment_number}: "
                            f"This teacher is already assigned "
                            f"to this subject for the selected "
                            f"program, class, section and "
                            f"academic year."
                        )

                # ==================================================
                # ADD ROW ERRORS
                # ==================================================

                if row_errors:

                    errors.extend(
                        row_errors
                    )

                else:

                    prepared_assignments.append({
                        "teacher_id": teacher_id,
                        "subject_id": subject_id,
                        "program_id": program_id,
                        "class_id": class_id,
                        "section_id": section_id,
                        "academic_year_id": academic_year_id,
                        "teaching_type": teaching_type,
                        "is_primary": is_primary,
                        "status": status,
                        "start_date": start_date,
                        "end_date": end_date,
                        "notes": notes or None,
                    })

        # ====================================================
        # SAVE ALL ASSIGNMENTS
        # ====================================================

        if not errors:

            try:

                created_assignments = []

                for data in prepared_assignments:

                    assignment = TeacherSubject(
                        institution_id=
                            institution_id,

                        branch_id=
                            branch_id,

                        teacher_id=
                            data["teacher_id"],

                        subject_id=
                            data["subject_id"],

                        program_id=
                            data["program_id"],

                        class_id=
                            data["class_id"],

                        section_id=
                            data["section_id"],

                        academic_year_id=
                            data["academic_year_id"],

                        teaching_type=
                            data["teaching_type"],

                        is_primary=
                            data["is_primary"],

                        status=
                            data["status"],

                        start_date=
                            data["start_date"],

                        end_date=
                            data["end_date"],

                        notes=
                            data["notes"],
                    )

                    db.session.add(
                        assignment
                    )

                    created_assignments.append(
                        assignment
                    )

                # --------------------------------------------
                # ONE COMMIT FOR ALL ROWS
                # --------------------------------------------

                db.session.commit()

                created_count = len(
                    created_assignments
                )

                # ==================================================
                # SUCCESS
                # ==================================================

                flash(
                    f"{created_count} teacher subject "
                    f"assignment"
                    f"{'s' if created_count != 1 else ''} "
                    f"created successfully.",
                    "success"
                )

                # ==================================================
                # SINGLE ASSIGNMENT
                # Redirect to VIEW
                # ==================================================

                if created_count == 1:

                    return redirect(
                        url_for(
                            "main.view_teacher_subject",
                            teacher_subject_id=
                                created_assignments[0].id
                        )
                    )

                # ==================================================
                # MULTIPLE ASSIGNMENTS
                # Redirect to ALL
                # ==================================================

                return redirect(
                    url_for(
                        "main.all_teacher_subjects"
                    )
                )

            # ====================================================
            # INTEGRITY ERROR
            # ====================================================

            except IntegrityError as e:

                db.session.rollback()

                current_app.logger.exception(
                    "IntegrityError creating multiple "
                    "TeacherSubject assignments: %s",
                    e
                )

                flash(
                    "Unable to create assignments. "
                    "A duplicate or invalid relationship "
                    "was detected.",
                    "danger"
                )

            # ====================================================
            # GENERAL ERROR
            # ====================================================

            except Exception as e:

                db.session.rollback()

                current_app.logger.exception(
                    "Error creating multiple "
                    "TeacherSubject assignments: %s",
                    e
                )

                flash(
                    "An unexpected error occurred while "
                    "creating the assignments.",
                    "danger"
                )

        # ====================================================
        # DISPLAY VALIDATION ERRORS
        # ====================================================

        else:

            for error in errors:

                flash(
                    error,
                    "danger"
                )

    # ========================================================
    # FORM CONTEXT
    # ========================================================

    context = _teacher_subject_form_context(
        institution_id=institution_id,
        branch_id=branch_id
    )

    return render_template(
        "backend/pages/teacher_subjects/add_teacher_subject.html",
        **context
    )


# ============================================================
# VIEW TEACHER SUBJECT
# ============================================================
# ============================================================
# VIEW TEACHER SUBJECT ASSIGNMENT
# ============================================================

# ============================================================
# VIEW TEACHER SUBJECT
# ============================================================

# ============================================================
# VIEW TEACHER SUBJECT
# ============================================================

@bp.route(
    "/teacher-subjects/<int:teacher_subject_id>",
    methods=["GET"]
)
@login_required
def view_teacher_subject(teacher_subject_id):

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    allowed_roles = {
        "superadmin",
        "institution_admin",
        "branch_admin",
        "teacher",
    }

    if (
        not _teacher_can_manage()
        and getattr(current_user, "role", None)
        not in allowed_roles
    ):
        flash(
            "You are not authorized to view teacher assignments.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # ========================================================
    # LOAD ASSIGNMENT
    # ========================================================

    assignment = (
        TeacherSubject.query
        .options(
            db.joinedload(
                TeacherSubject.institution
            ),

            db.joinedload(
                TeacherSubject.branch
            ),

            db.joinedload(
                TeacherSubject.teacher
            ),

            db.joinedload(
                TeacherSubject.subject
            ),

            db.joinedload(
                TeacherSubject.program
            ),

            db.joinedload(
                TeacherSubject.class_
            ),

            db.joinedload(
                TeacherSubject.section
            ),

            db.joinedload(
                TeacherSubject.academic_year
            ),
        )
        .filter(
            TeacherSubject.id == teacher_subject_id
        )
        .first()
    )

    # ========================================================
    # NOT FOUND
    # ========================================================

    if not assignment:

        flash(
            "Teacher subject assignment was not found.",
            "warning"
        )

        return redirect(
            url_for("main.all_teacher_subjects")
        )

    # ========================================================
    # CURRENT USER ROLE
    # ========================================================

    role = getattr(
        current_user,
        "role",
        None
    )

    # ========================================================
    # SUPERADMIN
    # ========================================================

    if role == "superadmin":

        pass

    # ========================================================
    # INSTITUTION ADMIN
    # ========================================================

    elif role == "institution_admin":

        user_institution_id = getattr(
            current_user,
            "institution_id",
            None
        )

        if (
            not user_institution_id
            or assignment.institution_id
            != user_institution_id
        ):

            flash(
                "You are not authorized to view this assignment.",
                "danger"
            )

            return redirect(
                url_for("main.all_teacher_subjects")
            )

    # ========================================================
    # BRANCH ADMIN
    # ========================================================

    elif role == "branch_admin":

        user_institution_id = getattr(
            current_user,
            "institution_id",
            None
        )

        user_branch_id = getattr(
            current_user,
            "branch_id",
            None
        )

        if (
            not user_institution_id
            or not user_branch_id
            or assignment.institution_id
            != user_institution_id
            or assignment.branch_id
            != user_branch_id
        ):

            flash(
                "You are not authorized to view this assignment.",
                "danger"
            )

            return redirect(
                url_for("main.all_teacher_subjects")
            )

    # ========================================================
    # TEACHER
    # ========================================================

    elif role == "teacher":

        current_teacher_id = getattr(
            current_user,
            "teacher_id",
            None
        )

        # ----------------------------------------------------
        # Teacher must have a linked teacher record
        # ----------------------------------------------------

        if current_teacher_id is None:

            flash(
                "Your teacher account is not linked to a teacher record.",
                "danger"
            )

            return redirect(
                url_for("main.all_teacher_subjects")
            )

        # ----------------------------------------------------
        # Only own assignment
        # ----------------------------------------------------

        if (
            assignment.teacher_id
            != current_teacher_id
        ):

            flash(
                "You are not authorized to view this assignment.",
                "danger"
            )

            return redirect(
                url_for("main.all_teacher_subjects")
            )

    # ========================================================
    # OTHER ROLES
    # ========================================================

    else:

        flash(
            "You are not authorized to view teacher assignments.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # ========================================================
    # RENDER TEMPLATE
    # ========================================================

    return render_template(
        "backend/pages/teacher_subjects/view_teacher_subject.html",
        assignment=assignment,
        user=current_user,
    )

# ============================================================
# EDIT TEACHER SUBJECT
# ============================================================

@bp.route(
    "/teacher-subjects/<int:teacher_subject_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_teacher_subject(teacher_subject_id):

    # ========================================================
    # PERMISSION
    # ========================================================

    if not _teacher_subject_can_manage():
        flash(
            "You are not authorized to edit teacher subject assignments.",
            "danger"
        )

        return redirect(
            url_for("main.all_teacher_subjects")
        )

    # ========================================================
    # GET EXISTING ASSIGNMENT
    # ========================================================

    assignment = (
        TeacherSubject.query
        .filter(
            TeacherSubject.id == teacher_subject_id
        )
        .first_or_404()
    )

    # ========================================================
    # CURRENT USER SCOPE
    # ========================================================

    user_institution_id = (
        _teacher_subject_user_institution_id()
    )

    user_branch_id = (
        _teacher_subject_user_branch_id()
    )

    role = getattr(
        current_user,
        "role",
        None
    )

    # ========================================================
    # SECURITY:
    # INSTITUTION
    # ========================================================

    if (
        user_institution_id
        and assignment.institution_id
        != user_institution_id
    ):
        abort(403)

    # ========================================================
    # SECURITY:
    # BRANCH ADMIN
    # ========================================================

    if (
        role == "branch_admin"
        and user_branch_id
        and assignment.branch_id
        != user_branch_id
    ):
        abort(403)

    # ========================================================
    # DEFAULT CURRENT VALUES
    # ========================================================

    institution_id = assignment.institution_id
    branch_id = assignment.branch_id

    # ========================================================
    # POST REQUEST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # FORM VALUES
        # ====================================================

        institution_id = request.form.get(
            "institution_id",
            type=int
        )

        branch_id = request.form.get(
            "branch_id",
            type=int
        )

        teacher_id = request.form.get(
            "teacher_id",
            type=int
        )

        subject_id = request.form.get(
            "subject_id",
            type=int
        )

        program_id = request.form.get(
            "program_id",
            type=int
        )

        class_id = request.form.get(
            "class_id",
            type=int
        )

        section_id = request.form.get(
            "section_id",
            type=int
        )

        academic_year_id = request.form.get(
            "academic_year_id",
            type=int
        )

        teaching_type = request.form.get(
            "teaching_type",
            "teacher"
        ).strip().lower()

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

        is_primary = (
            request.form.get("is_primary")
            in {
                "1",
                "true",
                "on",
                "yes"
            }
        )

        start_date_raw = request.form.get(
            "start_date",
            ""
        ).strip()

        end_date_raw = request.form.get(
            "end_date",
            ""
        ).strip()

        notes = request.form.get(
            "notes",
            ""
        ).strip()

        # ====================================================
        # ERROR COLLECTION
        # ====================================================

        errors = []

        # ====================================================
        # FORCE USER INSTITUTION
        # ====================================================

        if user_institution_id:
            institution_id = user_institution_id

        # ====================================================
        # FORCE BRANCH ADMIN BRANCH
        # ====================================================

        if role == "branch_admin":
            branch_id = user_branch_id

        # ====================================================
        # REQUIRED FIELDS
        # ====================================================

        if not institution_id:
            errors.append(
                "Institution is required."
            )

        if not branch_id:
            errors.append(
                "Branch is required."
            )

        if not teacher_id:
            errors.append(
                "Teacher is required."
            )

        if not subject_id:
            errors.append(
                "Subject is required."
            )

        if not academic_year_id:
            errors.append(
                "Academic Year is required."
            )

        # ====================================================
        # TEACHING TYPE
        # ====================================================

        if teaching_type not in TEACHER_SUBJECT_TYPES:
            errors.append(
                "Invalid teaching type."
            )

        # ====================================================
        # STATUS
        # ====================================================

        if status not in TEACHER_SUBJECT_STATUSES:
            errors.append(
                "Invalid assignment status."
            )

        # ====================================================
        # DATE PARSING
        # ====================================================

        start_date = None
        end_date = None

        if start_date_raw:

            try:

                start_date = datetime.strptime(
                    start_date_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                errors.append(
                    "Invalid start date."
                )

        if end_date_raw:

            try:

                end_date = datetime.strptime(
                    end_date_raw,
                    "%Y-%m-%d"
                ).date()

            except ValueError:

                errors.append(
                    "Invalid end date."
                )

        # ====================================================
        # DATE ORDER
        # ====================================================

        if (
            start_date
            and end_date
            and end_date < start_date
        ):

            errors.append(
                "End date cannot be before start date."
            )

        # ====================================================
        # BRANCH VALIDATION
        # ====================================================

        branch = None

        if (
            institution_id
            and branch_id
        ):

            branch = (
                Branch.query
                .filter(
                    Branch.id == branch_id,
                    Branch.institution_id
                    == institution_id
                )
                .first()
            )

            if not branch:

                errors.append(
                    "Selected branch is invalid."
                )

        # ====================================================
        # TEACHER VALIDATION
        # ====================================================

        teacher = None

        if (
            institution_id
            and branch_id
            and teacher_id
        ):

            teacher = (
                Teacher.query
                .filter(
                    Teacher.id == teacher_id,
                    Teacher.institution_id
                    == institution_id,
                    Teacher.branch_id
                    == branch_id
                )
                .first()
            )

            if not teacher:

                errors.append(
                    "Selected teacher does not belong "
                    "to the selected branch."
                )

        # ====================================================
        # SUBJECT VALIDATION
        # ====================================================

        subject = None

        if (
            institution_id
            and branch_id
            and subject_id
        ):

            subject_query = (
                Subject.query
                .filter(
                    Subject.id == subject_id,
                    Subject.institution_id
                    == institution_id
                )
            )

            if hasattr(
                Subject,
                "branch_id"
            ):

                subject_query = (
                    subject_query.filter(
                        Subject.branch_id
                        == branch_id
                    )
                )

            subject = subject_query.first()

            if not subject:

                errors.append(
                    "Selected subject is invalid."
                )

        # ====================================================
        # PROGRAM VALIDATION
        # ====================================================

        if program_id:

            program_query = (
                Program.query
                .filter(
                    Program.id == program_id,
                    Program.institution_id
                    == institution_id
                )
            )

            if hasattr(
                Program,
                "branch_id"
            ):

                program_query = (
                    program_query.filter(
                        Program.branch_id
                        == branch_id
                    )
                )

            if not program_query.first():

                errors.append(
                    "Selected program is invalid."
                )

        # ====================================================
        # CLASS VALIDATION
        # ====================================================

        if class_id:

            class_query = (
                Class.query
                .filter(
                    Class.id == class_id,
                    Class.institution_id
                    == institution_id
                )
            )

            if hasattr(
                Class,
                "branch_id"
            ):

                class_query = (
                    class_query.filter(
                        Class.branch_id
                        == branch_id
                    )
                )

            if not class_query.first():

                errors.append(
                    "Selected class is invalid."
                )

        # ====================================================
        # SECTION VALIDATION
        # ====================================================

        if section_id:

            section_query = (
                Section.query
                .filter(
                    Section.id == section_id,
                    Section.institution_id
                    == institution_id
                )
            )

            if hasattr(
                Section,
                "branch_id"
            ):

                section_query = (
                    section_query.filter(
                        Section.branch_id
                        == branch_id
                    )
                )

            if (
                class_id
                and hasattr(
                    Section,
                    "class_id"
                )
            ):

                section_query = (
                    section_query.filter(
                        Section.class_id
                        == class_id
                    )
                )

            if not section_query.first():

                errors.append(
                    "Selected section is invalid."
                )

        # ====================================================
        # ACADEMIC YEAR VALIDATION
        # ====================================================

        academic_year_query = (
            AcademicYear.query
            .filter(
                AcademicYear.id
                == academic_year_id
            )
        )

        if hasattr(
            AcademicYear,
            "institution_id"
        ):

            academic_year_query = (
                academic_year_query.filter(
                    AcademicYear.institution_id
                    == institution_id
                )
            )

        if not academic_year_query.first():

            errors.append(
                "Selected academic year is invalid."
            )

        # ====================================================
        # DUPLICATE CHECK
        # ====================================================

        if (
            teacher_id
            and subject_id
            and academic_year_id
            and not errors
        ):

            duplicate_query = (
                TeacherSubject.query
                .filter(
                    TeacherSubject.id
                    != assignment.id,

                    TeacherSubject.teacher_id
                    == teacher_id,

                    TeacherSubject.subject_id
                    == subject_id,

                    TeacherSubject.academic_year_id
                    == academic_year_id
                )
            )

            # ------------------------------------------------
            # CLASS
            # ------------------------------------------------

            if class_id is None:

                duplicate_query = (
                    duplicate_query.filter(
                        TeacherSubject.class_id.is_(None)
                    )
                )

            else:

                duplicate_query = (
                    duplicate_query.filter(
                        TeacherSubject.class_id
                        == class_id
                    )
                )

            # ------------------------------------------------
            # SECTION
            # ------------------------------------------------

            if section_id is None:

                duplicate_query = (
                    duplicate_query.filter(
                        TeacherSubject.section_id.is_(None)
                    )
                )

            else:

                duplicate_query = (
                    duplicate_query.filter(
                        TeacherSubject.section_id
                        == section_id
                    )
                )

            if duplicate_query.first():

                errors.append(
                    "Another assignment with the same "
                    "teacher, subject, class, section "
                    "and academic year already exists."
                )

        # ====================================================
        # SAVE
        # ====================================================

        if not errors:

            try:

                assignment.institution_id = (
                    institution_id
                )

                assignment.branch_id = (
                    branch_id
                )

                assignment.teacher_id = (
                    teacher_id
                )

                assignment.subject_id = (
                    subject_id
                )

                assignment.program_id = (
                    program_id
                )

                assignment.class_id = (
                    class_id
                )

                assignment.section_id = (
                    section_id
                )

                assignment.academic_year_id = (
                    academic_year_id
                )

                assignment.teaching_type = (
                    teaching_type
                )

                assignment.is_primary = (
                    is_primary
                )

                assignment.status = (
                    status
                )

                assignment.start_date = (
                    start_date
                )

                assignment.end_date = (
                    end_date
                )

                assignment.notes = (
                    notes or None
                )

                # SQLAlchemy onupdate ayaa sidoo kale
                # qaban kara updated_at.
                # Haddii column-ku jiro:
                if hasattr(
                    assignment,
                    "updated_at"
                ):
                    assignment.updated_at = (
                        datetime.utcnow()
                    )

                db.session.commit()

                flash(
                    "Teacher subject assignment updated successfully.",
                    "success"
                )

                return redirect(
                    url_for(
                        "main.view_teacher_subject",
                        teacher_subject_id=assignment.id
                    )
                )

            except IntegrityError:

                db.session.rollback()

                flash(
                    "Unable to update assignment because "
                    "of a duplicate or invalid relationship.",
                    "danger"
                )

            except Exception as e:

                db.session.rollback()

                current_app.logger.exception(
                    "Error updating TeacherSubject: %s",
                    e
                )

                flash(
                    "An unexpected error occurred while "
                    "updating the assignment.",
                    "danger"
                )

        else:

            for error in errors:

                flash(
                    error,
                    "danger"
                )

    # ========================================================
    # FORM CONTEXT
    # ========================================================

    context = _teacher_subject_form_context(
        institution_id=institution_id,
        branch_id=branch_id
    )

    # ========================================================
    # RENDER TEMPLATE
    #
    # IMPORTANT:
    # Ha ku darin user=current_user halkan.
    #
    # Sababta:
    # _teacher_subject_form_context() wuxuu u muuqdaa inuu
    # horey u soo celinayo "user".
    # ========================================================

    return render_template(
        "backend/pages/teacher_subjects/edit_teacher_subject.html",
        assignment=assignment,
        **context
    )

# ============================================================
# DELETE TEACHER SUBJECT
# ============================================================

@bp.route(
    "/teacher-subjects/<int:teacher_subject_id>/delete",
    methods=["POST"]
)
@login_required
def delete_teacher_subject(teacher_subject_id):

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    if not _teacher_subject_can_manage():
        flash(
            "You are not authorized to delete assignments.",
            "danger"
        )
        return redirect(
            url_for("main.all_teacher_subjects")
        )

    # ========================================================
    # LOAD
    # ========================================================

    teacher_subject = (
        TeacherSubject.query
        .filter(
            TeacherSubject.id == teacher_subject_id
        )
        .first_or_404()
    )

    # ========================================================
    # SECURITY
    # ========================================================

    user_institution_id = (
        _teacher_subject_user_institution_id()
    )

    user_branch_id = (
        _teacher_subject_user_branch_id()
    )

    role = getattr(
        current_user,
        "role",
        None
    )

    if (
        role != "superadmin"
        and user_institution_id
        and teacher_subject.institution_id
        != user_institution_id
    ):
        abort(403)

    if (
        role == "branch_admin"
        and user_branch_id
        and teacher_subject.branch_id
        != user_branch_id
    ):
        abort(403)

    # ========================================================
    # DELETE
    # ========================================================

    try:

        db.session.delete(
            teacher_subject
        )

        db.session.commit()

        flash(
            "Teacher subject assignment deleted successfully.",
            "success"
        )

    except IntegrityError:

        db.session.rollback()

        flash(
            "Unable to delete this assignment because it is being used by another record.",
            "danger"
        )

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error deleting TeacherSubject: %s",
            e
        )

        flash(
            "Unable to delete the teacher subject assignment.",
            "danger"
        )

    return redirect(
        url_for(
            "main.all_teacher_subjects"
        )
    )


# ============================================================
# TOGGLE TEACHER SUBJECT STATUS
# ============================================================

@bp.route(
    "/teacher-subjects/<int:teacher_subject_id>/toggle-status",
    methods=["POST"]
)
@login_required
def toggle_teacher_subject_status(teacher_subject_id):

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    if not _teacher_subject_can_manage():
        flash(
            "You are not authorized to change assignment status.",
            "danger"
        )
        return redirect(
            url_for("main.all_teacher_subjects")
        )

    # ========================================================
    # LOAD
    # ========================================================

    teacher_subject = (
        TeacherSubject.query
        .filter(
            TeacherSubject.id == teacher_subject_id
        )
        .first_or_404()
    )

    # ========================================================
    # SECURITY
    # ========================================================

    user_institution_id = (
        _teacher_subject_user_institution_id()
    )

    user_branch_id = (
        _teacher_subject_user_branch_id()
    )

    role = getattr(
        current_user,
        "role",
        None
    )

    if (
        role != "superadmin"
        and user_institution_id
        and teacher_subject.institution_id
        != user_institution_id
    ):
        abort(403)

    if (
        role == "branch_admin"
        and user_branch_id
        and teacher_subject.branch_id
        != user_branch_id
    ):
        abort(403)

    # ========================================================
    # TOGGLE
    # ========================================================

    try:

        if teacher_subject.status == "active":

            teacher_subject.status = "inactive"

            message = (
                "Teacher subject assignment "
                "deactivated successfully."
            )

        else:

            teacher_subject.status = "active"

            message = (
                "Teacher subject assignment "
                "activated successfully."
            )

        db.session.commit()

        flash(
            message,
            "success"
        )

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error toggling TeacherSubject status: %s",
            e
        )

        flash(
            "Unable to change assignment status.",
            "danger"
        )

    return redirect(
        request.referrer
        or url_for(
            "main.all_teacher_subjects"
        )
    )


# ============================================================
# TOGGLE TEACHER SUBJECT PRIMARY
# ============================================================

@bp.route(
    "/teacher-subjects/<int:teacher_subject_id>/toggle-primary",
    methods=["POST"]
)
@login_required
def toggle_teacher_subject_primary(
    teacher_subject_id
):

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    if not _teacher_subject_can_manage():
        flash(
            "You are not authorized to change primary assignment.",
            "danger"
        )
        return redirect(
            url_for("main.all_teacher_subjects")
        )

    # ========================================================
    # LOAD
    # ========================================================

    teacher_subject = (
        TeacherSubject.query
        .filter(
            TeacherSubject.id == teacher_subject_id
        )
        .first_or_404()
    )

    # ========================================================
    # SECURITY
    # ========================================================

    user_institution_id = (
        _teacher_subject_user_institution_id()
    )

    user_branch_id = (
        _teacher_subject_user_branch_id()
    )

    role = getattr(
        current_user,
        "role",
        None
    )

    if (
        role != "superadmin"
        and user_institution_id
        and teacher_subject.institution_id
        != user_institution_id
    ):
        abort(403)

    if (
        role == "branch_admin"
        and user_branch_id
        and teacher_subject.branch_id
        != user_branch_id
    ):
        abort(403)

    # ========================================================
    # TOGGLE
    # ========================================================

    try:

        teacher_subject.is_primary = (
            not teacher_subject.is_primary
        )

        db.session.commit()

        if teacher_subject.is_primary:

            flash(
                "Teacher subject assignment is now Primary.",
                "success"
            )

        else:

            flash(
                "Teacher subject assignment is now Secondary.",
                "info"
            )

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Error toggling TeacherSubject primary: %s",
            e
        )

        flash(
            "Unable to change primary assignment.",
            "danger"
        )

    return redirect(
        request.referrer
        or url_for(
            "main.view_teacher_subject",
            teacher_subject_id=teacher_subject.id
        )
    )


# ============================================================
# STUDENT MANAGEMENT ROUTES
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

STUDENT_STATUSES = [
    "active",
    "inactive",
    "graduated",
    "transferred",
    "suspended",
    "withdrawn",
]

ALLOWED_IMAGE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp",
}

ALLOWED_IMAGE_MIMETYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
}

MAX_PHOTO_SIZE = 5 * 1024 * 1024


# ============================================================
# AUTHORIZATION
# ============================================================

def _student_can_manage():
    """
    Student CRUD maamulka waxaa geli kara:
    superadmin
    institution_admin
    branch_admin
    """

    role = getattr(current_user, "role", None)

    return role in {
        "superadmin",
        "institution_admin",
        "branch_admin",
    }


def _student_is_superadmin():
    return getattr(current_user, "role", None) == "superadmin"


def _student_user_institution_id():
    return getattr(current_user, "institution_id", None)


def _student_user_branch_id():
    return getattr(current_user, "branch_id", None)


# ============================================================
# ACCESS CHECK
# ============================================================

def _student_has_access(student):
    """
    Hubi in current admin uu arki/khanayn karo student-ka.
    """

    role = getattr(current_user, "role", None)

    if role == "superadmin":
        return True

    user_institution_id = _student_user_institution_id()
    user_branch_id = _student_user_branch_id()

    if role == "institution_admin":
        return (
            student.institution_id == user_institution_id
        )

    if role == "branch_admin":
        return (
            student.institution_id == user_institution_id
            and
            student.branch_id == user_branch_id
        )

    return False


# ============================================================
# IMAGE VALIDATION
# ============================================================

def _allowed_student_photo(file):

    if not file or not file.filename:
        return False

    filename = file.filename.lower().strip()

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1]

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return False

    content_type = getattr(file, "mimetype", None)

    if content_type and content_type not in ALLOWED_IMAGE_MIMETYPES:
        return False

    return True


# ============================================================
# CLOUDINARY UPLOAD
# ============================================================

def _upload_student_photo(file, student_id=None, institution_id=None, branch_id=None):
    """
    Upload student photo to Cloudinary.

    Folder:
    students/institution_{id}/branch_{id}
    """

    if not file or not file.filename:
        return None, None

    if not _allowed_student_photo(file):
        raise ValueError(
            "Only JPG, JPEG, PNG and WEBP images are allowed."
        )

    # --------------------------------------------------------
    # File size check
    # --------------------------------------------------------

    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_PHOTO_SIZE:
        raise ValueError(
            "Student photo must not exceed 5 MB."
        )

    # --------------------------------------------------------
    # Cloudinary folder
    # --------------------------------------------------------

    folder = (
        f"students/"
        f"institution_{institution_id}/"
        f"branch_{branch_id}"
    )

    # --------------------------------------------------------
    # Public ID
    # --------------------------------------------------------

    if student_id:
        public_id = f"student_{student_id}"
    else:
        public_id = f"student_{int(datetime.utcnow().timestamp())}"

    result = cloudinary.uploader.upload(
        file,
        folder=folder,
        public_id=public_id,
        overwrite=True,
        invalidate=True,
        resource_type="image",
        transformation=[
            {
                "width": 600,
                "height": 600,
                "crop": "fill",
                "gravity": "face",
                "quality": "auto",
                "fetch_format": "auto",
            }
        ],
    )

    secure_url = result.get("secure_url")
    returned_public_id = result.get("public_id")

    if not secure_url:
        raise ValueError(
            "Cloudinary did not return a secure image URL."
        )

    return secure_url, returned_public_id


# ============================================================
# CLOUDINARY DELETE
# ============================================================

def _delete_student_photo(public_id):

    if not public_id:
        return

    try:

        cloudinary.uploader.destroy(
            public_id,
            invalidate=True,
            resource_type="image",
        )

    except Exception as exc:

        current_app.logger.warning(
            "Unable to delete Cloudinary student image %s: %s",
            public_id,
            exc,
        )


# ============================================================
# DATE PARSER
# ============================================================

def _parse_student_date(value):

    if not value:
        return None

    if hasattr(value, "date"):
        try:
            return value.date()
        except Exception:
            pass

    if hasattr(value, "year") and hasattr(value, "month"):
        return value

    value = str(value).strip()

    if not value:
        return None

    formats = [
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%Y/%m/%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(
                value,
                fmt
            ).date()
        except ValueError:
            continue

    raise ValueError(
        f"Invalid date format: {value}"
    )


# ============================================================
# INSTITUTIONS / BRANCHES CONTEXT
# ============================================================

def _student_form_context():

    role = getattr(current_user, "role", None)

    if role == "superadmin":

        institutions = (
            Institution.query
            .order_by(Institution.name.asc())
            .all()
        )

        branches = (
            Branch.query
            .order_by(Branch.name.asc())
            .all()
        )

    elif role == "institution_admin":

        institution_id = _student_user_institution_id()

        institutions = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .all()
        )

        branches = (
            Branch.query
            .filter(
                Branch.institution_id == institution_id
            )
            .order_by(Branch.name.asc())
            .all()
        )

    elif role == "branch_admin":

        institution_id = _student_user_institution_id()
        branch_id = _student_user_branch_id()

        institutions = (
            Institution.query
            .filter(
                Institution.id == institution_id
            )
            .all()
        )

        branches = (
            Branch.query
            .filter(
                Branch.id == branch_id,
                Branch.institution_id == institution_id
            )
            .all()
        )

    else:

        institutions = []
        branches = []

    return {
        "institutions": institutions,
        "branches": branches,
        "statuses": STUDENT_STATUSES,
    }


# ============================================================
# STUDENT QUERY ACCESS
# ============================================================

def _student_scoped_query():

    query = Student.query

    role = getattr(current_user, "role", None)

    if role == "superadmin":
        return query

    institution_id = _student_user_institution_id()
    branch_id = _student_user_branch_id()

    if role == "institution_admin":

        return query.filter(
            Student.institution_id == institution_id
        )

    if role == "branch_admin":

        return query.filter(
            Student.institution_id == institution_id,
            Student.branch_id == branch_id,
        )

    return query.filter(db.false())


# ============================================================
# ALL STUDENTS
# ============================================================
# ============================================================
# ALL STUDENTS
# ============================================================

@bp.route("/students", methods=["GET"])
@login_required
def all_students():

    # ========================================================
    # ACCESS CONTROL
    # ========================================================

    allowed_roles = {
        "superadmin",
        "institution_admin",
        "branch_admin",
    }

    if getattr(current_user, "role", None) not in allowed_roles:
        flash(
            "You do not have permission to manage students.",
            "danger"
        )
        return redirect(url_for("main.dashboard"))


    # ========================================================
    # CURRENT USER SCOPE
    # ========================================================

    current_role = getattr(
        current_user,
        "role",
        None
    )

    current_institution_id = getattr(
        current_user,
        "institution_id",
        None
    )

    current_branch_id = getattr(
        current_user,
        "branch_id",
        None
    )


    # ========================================================
    # REQUEST FILTERS
    # ========================================================

    search = request.args.get(
        "search",
        "",
        type=str
    ).strip()

    institution_id = request.args.get(
        "institution_id",
        "",
        type=str
    ).strip()

    branch_id = request.args.get(
        "branch_id",
        "",
        type=str
    ).strip()

    status = request.args.get(
        "status",
        "",
        type=str
    ).strip().lower()

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = request.args.get(
        "per_page",
        20,
        type=int
    )


    # ========================================================
    # VALIDATE PAGINATION
    # ========================================================

    if page < 1:
        page = 1

    allowed_per_page = {
        10,
        20,
        50,
        100
    }

    if per_page not in allowed_per_page:
        per_page = 20


    # ========================================================
    # VALID STATUS VALUES
    # ========================================================

    allowed_statuses = {
        "active",
        "inactive",
        "graduated",
        "transferred",
        "suspended",
        "withdrawn"
    }

    if status not in allowed_statuses:
        status = ""


    # ========================================================
    # BASE QUERY
    # ========================================================

    query = Student.query


    # ========================================================
    # ROLE-BASED DATA SCOPE
    # ========================================================

    if current_role == "superadmin":

        # Superadmin can see everything.
        pass


    elif current_role == "institution_admin":

        if not current_institution_id:

            flash(
                "Your account is not linked to an institution.",
                "warning"
            )

            return redirect(
                url_for("main.dashboard")
            )

        query = query.filter(
            Student.institution_id ==
            current_institution_id
        )


    elif current_role == "branch_admin":

        if not current_institution_id or not current_branch_id:

            flash(
                "Your account is not linked to an institution and branch.",
                "warning"
            )

            return redirect(
                url_for("main.dashboard")
            )

        query = query.filter(
            Student.institution_id ==
            current_institution_id,
            Student.branch_id ==
            current_branch_id
        )


    # ========================================================
    # SEARCH
    # ========================================================

    if search:

        search_pattern = f"%{search}%"

        query = query.filter(
            db.or_(
                Student.full_name.ilike(
                    search_pattern
                ),

                Student.username.ilike(
                    search_pattern
                ),

                Student.email.ilike(
                    search_pattern
                ),

                Student.admission_no.ilike(
                    search_pattern
                ),

                Student.roll_no.ilike(
                    search_pattern
                ),

                Student.phone.ilike(
                    search_pattern
                ),

                Student.parent_name.ilike(
                    search_pattern
                ),

                Student.parent_phone.ilike(
                    search_pattern
                )
            )
        )


    # ========================================================
    # INSTITUTION FILTER
    # ========================================================

    if institution_id:

        try:

            selected_institution_id = int(
                institution_id
            )

            # Institution admin cannot select
            # another institution.

            if (
                current_role == "institution_admin"
                and
                selected_institution_id !=
                current_institution_id
            ):

                selected_institution_id = (
                    current_institution_id
                )

            elif (
                current_role == "branch_admin"
                and
                selected_institution_id !=
                current_institution_id
            ):

                selected_institution_id = (
                    current_institution_id
                )


            query = query.filter(
                Student.institution_id ==
                selected_institution_id
            )

        except (
            ValueError,
            TypeError
        ):

            institution_id = ""


    else:

        selected_institution_id = None

        if current_role in {
            "institution_admin",
            "branch_admin"
        }:

            selected_institution_id = (
                current_institution_id
            )


    # ========================================================
    # BRANCH FILTER
    # ========================================================

    if branch_id:

        try:

            selected_branch_id = int(
                branch_id
            )

            # Branch admin is restricted
            # to his own branch.

            if (
                current_role == "branch_admin"
                and
                selected_branch_id !=
                current_branch_id
            ):

                selected_branch_id = (
                    current_branch_id
                )


            query = query.filter(
                Student.branch_id ==
                selected_branch_id
            )

        except (
            ValueError,
            TypeError
        ):

            branch_id = ""

    else:

        selected_branch_id = None

        if current_role == "branch_admin":

            selected_branch_id = (
                current_branch_id
            )


    # ========================================================
    # STATUS FILTER
    # ========================================================

    if status:

        query = query.filter(
            Student.status == status
        )


    # ========================================================
    # ORDERING
    # ========================================================

    query = query.order_by(
        Student.full_name.asc(),
        Student.id.desc()
    )


    # ========================================================
    # PAGINATION
    # ========================================================

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    students = pagination.items


    # ========================================================
    # STATISTICS
    # ========================================================

    # Use the scoped query BEFORE pagination so the statistics
    # represent the current user's accessible students.

    statistics_query = query.with_entities(
        Student.id,
        Student.status
    ).all()


    total_students = len(
        statistics_query
    )


    active_students = sum(
        1
        for student in statistics_query
        if student.status == "active"
    )


    inactive_students = sum(
        1
        for student in statistics_query
        if student.status == "inactive"
    )


    graduated_students = sum(
        1
        for student in statistics_query
        if student.status == "graduated"
    )


    transferred_students = sum(
        1
        for student in statistics_query
        if student.status == "transferred"
    )


    suspended_students = sum(
        1
        for student in statistics_query
        if student.status == "suspended"
    )


    withdrawn_students = sum(
        1
        for student in statistics_query
        if student.status == "withdrawn"
    )


    # ========================================================
    # INSTITUTIONS
    # ========================================================

    if current_role == "superadmin":

        institutions = (
            Institution.query
            .order_by(
                Institution.name.asc()
            )
            .all()
        )

    else:

        institutions = (
            Institution.query
            .filter(
                Institution.id ==
                current_institution_id
            )
            .order_by(
                Institution.name.asc()
            )
            .all()
        )


    # ========================================================
    # BRANCHES
    # ========================================================

    if current_role == "superadmin":

        branches = (
            Branch.query
            .order_by(
                Branch.name.asc()
            )
            .all()
        )

    elif current_role == "institution_admin":

        branches = (
            Branch.query
            .filter(
                Branch.institution_id ==
                current_institution_id
            )
            .order_by(
                Branch.name.asc()
            )
            .all()
        )

    else:

        branches = (
            Branch.query
            .filter(
                Branch.id ==
                current_branch_id
            )
            .order_by(
                Branch.name.asc()
            )
            .all()
        )


    # ========================================================
    # SELECTED FILTER VALUES
    # ========================================================

    if current_role == "institution_admin":

        selected_institution_id = (
            current_institution_id
        )

    elif current_role == "branch_admin":

        selected_institution_id = (
            current_institution_id
        )

        selected_branch_id = (
            current_branch_id
        )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/students/all_students.html",

        students=students,

        pagination=pagination,

        institutions=institutions,

        branches=branches,

        search=search,

        selected_institution_id=
            selected_institution_id,

        selected_branch_id=
            selected_branch_id,

        selected_status=status,

        per_page=per_page,

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        total_students=total_students,

        active_students=active_students,

        inactive_students=inactive_students,

        graduated_students=graduated_students,

        transferred_students=transferred_students,

        suspended_students=suspended_students,

        withdrawn_students=withdrawn_students,

        # ----------------------------------------------------
        # CURRENT USER
        # ----------------------------------------------------

        user=current_user
    )


# ============================================================
# ADD STUDENT
# ============================================================

@bp.route(
    "/students/add",
    methods=["GET", "POST"]
)
@login_required
def add_student():

    # ========================================================
    # PERMISSION
    # ========================================================

    if not _student_can_manage():

        flash(
            "You are not authorized to create students.",
            "danger",
        )

        return redirect(
            url_for("main.all_students")
        )

    # ========================================================
    # FORM CONTEXT
    # ========================================================

    context = _student_form_context()

    if request.method == "POST":

        # ====================================================
        # BASIC FORM VALUES
        # ====================================================

        institution_id = request.form.get(
            "institution_id",
            type=int,
        )

        branch_id = request.form.get(
            "branch_id",
            type=int,
        )

        username = request.form.get(
            "username",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower() or None

        raw_password = request.form.get(
            "password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        admission_no = request.form.get(
            "admission_no",
            "",
        ).strip()

        roll_no = request.form.get(
            "roll_no",
            "",
        ).strip() or None

        full_name = request.form.get(
            "full_name",
            "",
        ).strip()

        gender = request.form.get(
            "gender",
            "",
        ).strip() or None

        date_of_birth_raw = request.form.get(
            "date_of_birth",
            "",
        ).strip()

        place_of_birth = request.form.get(
            "place_of_birth",
            "",
        ).strip() or None

        nationality = request.form.get(
            "nationality",
            "",
        ).strip() or None

        phone = request.form.get(
            "phone",
            "",
        ).strip() or None

        address = request.form.get(
            "address",
            "",
        ).strip() or None

        city = request.form.get(
            "city",
            "",
        ).strip() or None

        parent_name = request.form.get(
            "parent_name",
            "",
        ).strip() or None

        parent_phone = request.form.get(
            "parent_phone",
            "",
        ).strip() or None

        parent_email = request.form.get(
            "parent_email",
            "",
        ).strip().lower() or None

        parent_address = request.form.get(
            "parent_address",
            "",
        ).strip() or None

        relationship_to_student = request.form.get(
            "relationship_to_student",
            "",
        ).strip() or None

        status = request.form.get(
            "status",
            "active",
        ).strip().lower()

        notes = request.form.get(
            "notes",
            "",
        ).strip() or None

        # ====================================================
        # CHECKBOXES
        # ====================================================

        is_active = (
            request.form.get("is_active")
            in ("1", "true", "on", "yes")
        )

        is_verified = (
            request.form.get("is_verified")
            in ("1", "true", "on", "yes")
        )

        # ====================================================
        # ROLE
        # ====================================================

        role = "student"

        # ====================================================
        # PHOTO
        # ====================================================

        photo_file = request.files.get(
            "photo"
        )

        # ====================================================
        # VALIDATION
        # ====================================================

        errors = []

        if not institution_id:
            errors.append(
                "Institution is required."
            )

        if not branch_id:
            errors.append(
                "Branch is required."
            )

        if not username:
            errors.append(
                "Username is required."
            )

        if not admission_no:
            errors.append(
                "Admission number is required."
            )

        if not full_name:
            errors.append(
                "Full name is required."
            )

        if not raw_password:
            errors.append(
                "Password is required."
            )

        if not confirm_password:
            errors.append(
                "Password confirmation is required."
            )

        if (
            raw_password
            and confirm_password
            and raw_password != confirm_password
        ):
            errors.append(
                "Password and confirmation password do not match."
            )

        # ====================================================
        # STATUS
        # ====================================================

        if status not in STUDENT_STATUSES:

            errors.append(
                "Invalid student status."
            )

        # ====================================================
        # GENDER
        # ====================================================

        allowed_genders = {
            "male",
            "female",
        }

        if gender and gender.lower() not in allowed_genders:

            errors.append(
                "Invalid gender."
            )

        # ====================================================
        # EMAIL VALIDATION
        # ====================================================

        if email:

            if (
                "@" not in email
                or "." not in email.split("@")[-1]
            ):
                errors.append(
                    "Please enter a valid student email address."
                )

        if parent_email:

            if (
                "@" not in parent_email
                or "." not in parent_email.split("@")[-1]
            ):
                errors.append(
                    "Please enter a valid parent email address."
                )

        # ====================================================
        # ROLE / USER SCOPE
        # ====================================================

        current_role = getattr(
            current_user,
            "role",
            None,
        )

        current_institution_id = (
            _student_user_institution_id()
        )

        current_branch_id = (
            _student_user_branch_id()
        )

        # ----------------------------------------------------
        # INSTITUTION ADMIN
        # ----------------------------------------------------

        if current_role == "institution_admin":

            if (
                institution_id
                and current_institution_id
                and institution_id
                != current_institution_id
            ):

                errors.append(
                    "You cannot create a student outside your institution."
                )

        # ----------------------------------------------------
        # BRANCH ADMIN
        # ----------------------------------------------------

        elif current_role == "branch_admin":

            if (
                institution_id
                and current_institution_id
                and institution_id
                != current_institution_id
            ):

                errors.append(
                    "You cannot create a student outside your institution."
                )

            if (
                branch_id
                and current_branch_id
                and branch_id
                != current_branch_id
            ):

                errors.append(
                    "You cannot create a student outside your branch."
                )

        # ====================================================
        # INSTITUTION
        # ====================================================

        institution = None

        if institution_id:

            institution = (
                Institution.query
                .filter(
                    Institution.id
                    == institution_id
                )
                .first()
            )

            if not institution:

                errors.append(
                    "Selected institution does not exist."
                )

        # ====================================================
        # BRANCH
        # ====================================================

        branch = None

        if branch_id:

            branch = (
                Branch.query
                .filter(
                    Branch.id
                    == branch_id
                )
                .first()
            )

            if not branch:

                errors.append(
                    "Selected branch does not exist."
                )

            elif (
                institution_id
                and branch.institution_id
                != institution_id
            ):

                errors.append(
                    "Selected branch does not belong to the selected institution."
                )

        # ====================================================
        # USERNAME DUPLICATE
        # ====================================================

        if username:

            existing_username = (
                Student.query
                .filter(
                    func.lower(
                        Student.username
                    )
                    == username.lower()
                )
                .first()
            )

            if existing_username:

                errors.append(
                    "Username already exists."
                )

        # ====================================================
        # EMAIL DUPLICATE
        # ====================================================

        if email:

            existing_email = (
                Student.query
                .filter(
                    func.lower(
                        Student.email
                    )
                    == email.lower()
                )
                .first()
            )

            if existing_email:

                errors.append(
                    "Email already exists."
                )

        # ====================================================
        # ADMISSION NUMBER DUPLICATE
        # ====================================================

        if (
            institution_id
            and admission_no
        ):

            existing_admission = (
                Student.query
                .filter(
                    Student.institution_id
                    == institution_id,

                    func.lower(
                        Student.admission_no
                    )
                    == admission_no.lower(),
                )
                .first()
            )

            if existing_admission:

                errors.append(
                    "Admission number already exists in this institution."
                )

        # ====================================================
        # DATE OF BIRTH
        # ====================================================

        date_of_birth = None

        if date_of_birth_raw:

            try:

                date_of_birth = _parse_student_date(
                    date_of_birth_raw
                )

            except ValueError as exc:

                errors.append(
                    str(exc)
                )

        # ====================================================
        # PHOTO VALIDATION
        # ====================================================

        if (
            photo_file
            and photo_file.filename
        ):

            if not _allowed_student_photo(
                photo_file
            ):

                errors.append(
                    "Photo must be JPG, JPEG, PNG or WEBP."
                )

        # ====================================================
        # STOP IF VALIDATION FAILED
        # ====================================================

        if errors:

            # Remove duplicate messages while preserving order
            errors = list(
                dict.fromkeys(errors)
            )

            for error in errors:

                flash(
                    error,
                    "danger",
                )

            return render_template(
                "backend/pages/students/add_student.html",
                user=current_user,
                **context,
            )

        # ====================================================
        # CREATE STUDENT
        # ====================================================

        student = Student(

            institution_id=institution_id,

            branch_id=branch_id,

            username=username,

            email=email,

            role=role,

            is_active=is_active,

            is_verified=is_verified,

            admission_no=admission_no,

            roll_no=roll_no,

            full_name=full_name,

            gender=gender,

            date_of_birth=date_of_birth,

            place_of_birth=place_of_birth,

            nationality=nationality,

            phone=phone,

            address=address,

            city=city,

            parent_name=parent_name,

            parent_phone=parent_phone,

            parent_email=parent_email,

            parent_address=parent_address,

            relationship_to_student=(
                relationship_to_student
            ),

            status=status,

            notes=notes,
        )

        # ====================================================
        # PASSWORD HASH
        # ====================================================

        student.set_password(
            raw_password
        )

        # ====================================================
        # ADD TO SESSION
        # ====================================================

        db.session.add(
            student
        )

        try:

            # =================================================
            # FLUSH
            # Get student.id before Cloudinary upload
            # =================================================

            db.session.flush()

            # =================================================
            # CLOUDINARY PHOTO UPLOAD
            # =================================================

            if (
                photo_file
                and photo_file.filename
            ):

                photo_url, public_id = (
                    _upload_student_photo(
                        photo_file,
                        student_id=student.id,
                        institution_id=institution_id,
                        branch_id=branch_id,
                    )
                )

                if not photo_url:

                    raise ValueError(
                        "Student photo upload failed."
                    )

                student.photo = photo_url

                # ------------------------------------------------
                # IMPORTANT:
                # Your current Student model does not show
                # photo_public_id.
                #
                # Therefore we only save student.photo here.
                #
                # If you later add:
                #
                # photo_public_id = db.Column(...)
                #
                # then you can use:
                #
                # student.photo_public_id = public_id
                # ------------------------------------------------

            # =================================================
            # COMMIT
            # =================================================

            db.session.commit()

            # =================================================
            # SUCCESS
            # =================================================

            flash(
                f"Student {student.full_name} created successfully.",
                "success",
            )

            return redirect(
                url_for(
                    "main.view_student",
                    student_id=student.id,
                )
            )

        # ====================================================
        # VALUE ERROR
        # ====================================================

        except ValueError as exc:

            db.session.rollback()

            current_app.logger.warning(
                "Student creation validation/upload error: %s",
                exc,
            )

            flash(
                str(exc),
                "danger",
            )

        # ====================================================
        # DATABASE INTEGRITY ERROR
        # ====================================================

        except IntegrityError as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Student integrity error: %s",
                exc,
            )

            flash(
                "Student could not be created because username, email or admission number already exists.",
                "danger",
            )

        # ====================================================
        # GENERAL ERROR
        # ====================================================

        except Exception as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Student creation failed: %s",
                exc,
            )

            flash(
                "Unable to create student. Please try again.",
                "danger",
            )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/students/add_student.html",
        user=current_user,
        **context,
    )

# ============================================================
# VIEW STUDENT
# ============================================================

@bp.route(
    "/students/<int:student_id>"
)
@login_required
def view_student(student_id):

    if not _student_can_manage():

        flash(
            "You are not authorized to view students.",
            "danger",
        )

        return redirect(
            url_for("main.dashboard")
        )

    student = (
        Student.query
        .filter(
            Student.id == student_id
        )
        .first_or_404()
    )

    if not _student_has_access(student):

        abort(403)

    return render_template(
        "backend/pages/students/view_student.html",
        student=student,
    )


# ============================================================
# EDIT STUDENT
# ============================================================

@bp.route(
    "/students/<int:student_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_student(student_id):

    if not _student_can_manage():

        flash(
            "You are not authorized to edit students.",
            "danger",
        )

        return redirect(
            url_for("main.all_students")
        )

    student = (
        Student.query
        .filter(
            Student.id == student_id
        )
        .first_or_404()
    )

    if not _student_has_access(student):

        abort(403)

    context = _student_form_context()

    if request.method == "POST":

        institution_id = request.form.get(
            "institution_id",
            type=int,
        )

        branch_id = request.form.get(
            "branch_id",
            type=int,
        )

        username = request.form.get(
            "username",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip() or None

        raw_password = request.form.get(
            "password",
            "",
        )

        admission_no = request.form.get(
            "admission_no",
            "",
        ).strip()

        roll_no = request.form.get(
            "roll_no",
            "",
        ).strip() or None

        full_name = request.form.get(
            "full_name",
            "",
        ).strip()

        gender = request.form.get(
            "gender",
            "",
        ).strip() or None

        place_of_birth = request.form.get(
            "place_of_birth",
            "",
        ).strip() or None

        nationality = request.form.get(
            "nationality",
            "",
        ).strip() or None

        phone = request.form.get(
            "phone",
            "",
        ).strip() or None

        address = request.form.get(
            "address",
            "",
        ).strip() or None

        city = request.form.get(
            "city",
            "",
        ).strip() or None

        parent_name = request.form.get(
            "parent_name",
            "",
        ).strip() or None

        parent_phone = request.form.get(
            "parent_phone",
            "",
        ).strip() or None

        parent_email = request.form.get(
            "parent_email",
            "",
        ).strip() or None

        parent_address = request.form.get(
            "parent_address",
            "",
        ).strip() or None

        relationship_to_student = request.form.get(
            "relationship_to_student",
            "",
        ).strip() or None

        status = request.form.get(
            "status",
            "active",
        ).strip()

        notes = request.form.get(
            "notes",
            "",
        ).strip() or None

        is_active = (
            request.form.get("is_active")
            == "1"
        )

        is_verified = (
            request.form.get("is_verified")
            == "1"
        )

        errors = []

        # ----------------------------------------------------
        # Required
        # ----------------------------------------------------

        if not institution_id:
            errors.append(
                "Institution is required."
            )

        if not branch_id:
            errors.append(
                "Branch is required."
            )

        if not username:
            errors.append(
                "Username is required."
            )

        if not admission_no:
            errors.append(
                "Admission number is required."
            )

        if not full_name:
            errors.append(
                "Full name is required."
            )

        if status not in STUDENT_STATUSES:

            errors.append(
                "Invalid student status."
            )

        # ----------------------------------------------------
        # Role security
        # ----------------------------------------------------

        role = getattr(
            current_user,
            "role",
            None,
        )

        if role == "institution_admin":

            if institution_id != _student_user_institution_id():

                errors.append(
                    "You cannot move a student outside your institution."
                )

        elif role == "branch_admin":

            if institution_id != _student_user_institution_id():

                errors.append(
                    "Invalid institution."
                )

            if branch_id != _student_user_branch_id():

                errors.append(
                    "You cannot move a student outside your branch."
                )

        # ----------------------------------------------------
        # Branch belongs to institution
        # ----------------------------------------------------

        branch = (
            Branch.query
            .filter(
                Branch.id == branch_id
            )
            .first()
        )

        if not branch:

            errors.append(
                "Selected branch does not exist."
            )

        elif branch.institution_id != institution_id:

            errors.append(
                "Selected branch does not belong to selected institution."
            )

        # ----------------------------------------------------
        # Username duplicate
        # ----------------------------------------------------

        existing_username = (
            Student.query
            .filter(
                func.lower(Student.username)
                == username.lower(),
                Student.id != student.id,
            )
            .first()
        )

        if existing_username:

            errors.append(
                "Username already exists."
            )

        # ----------------------------------------------------
        # Email duplicate
        # ----------------------------------------------------

        if email:

            existing_email = (
                Student.query
                .filter(
                    func.lower(Student.email)
                    == email.lower(),
                    Student.id != student.id,
                )
                .first()
            )

            if existing_email:

                errors.append(
                    "Email already exists."
                )

        # ----------------------------------------------------
        # Admission duplicate
        # ----------------------------------------------------

        existing_admission = (
            Student.query
            .filter(
                Student.institution_id ==
                institution_id,

                func.lower(Student.admission_no)
                == admission_no.lower(),

                Student.id != student.id,
            )
            .first()
        )

        if existing_admission:

            errors.append(
                "Admission number already exists in this institution."
            )

        # ----------------------------------------------------
        # Date
        # ----------------------------------------------------

        date_of_birth = None

        try:

            date_of_birth = _parse_student_date(
                request.form.get(
                    "date_of_birth"
                )
            )

        except ValueError as exc:

            errors.append(str(exc))

        # ----------------------------------------------------
        # PHOTO
        # ----------------------------------------------------

        photo_file = request.files.get(
            "photo"
        )

        if photo_file and photo_file.filename:

            if not _allowed_student_photo(
                photo_file
            ):

                errors.append(
                    "Photo must be JPG, JPEG, PNG or WEBP."
                )

        if errors:

            for error in errors:
                flash(error, "danger")

            return render_template(
                "backend/pages/students/edit_student.html",
                student=student,
                **context,
            )

        # ----------------------------------------------------
        # Save old Cloudinary ID
        # ----------------------------------------------------

        old_public_id = student.photo_public_id

        # ----------------------------------------------------
        # Update fields
        # ----------------------------------------------------

        student.institution_id = institution_id
        student.branch_id = branch_id
        student.username = username
        student.email = email
        student.admission_no = admission_no
        student.roll_no = roll_no
        student.full_name = full_name
        student.gender = gender
        student.date_of_birth = date_of_birth
        student.place_of_birth = place_of_birth
        student.nationality = nationality
        student.phone = phone
        student.address = address
        student.city = city
        student.parent_name = parent_name
        student.parent_phone = parent_phone
        student.parent_email = parent_email
        student.parent_address = parent_address
        student.relationship_to_student = (
            relationship_to_student
        )
        student.status = status
        student.is_active = is_active
        student.is_verified = is_verified
        student.notes = notes

        if raw_password:

            student.set_password(
                raw_password
            )

        try:

            # ------------------------------------------------
            # New Cloudinary image
            # ------------------------------------------------

            if photo_file and photo_file.filename:

                photo_url, public_id = (
                    _upload_student_photo(
                        photo_file,
                        student_id=student.id,
                        institution_id=institution_id,
                        branch_id=branch_id,
                    )
                )

                student.photo = photo_url
                student.photo_public_id = public_id

            db.session.commit()

            # ------------------------------------------------
            # Delete old image after DB commit
            # ------------------------------------------------

            if (
                photo_file
                and photo_file.filename
                and old_public_id
                and old_public_id != student.photo_public_id
            ):

                _delete_student_photo(
                    old_public_id
                )

            flash(
                "Student updated successfully.",
                "success",
            )

            return redirect(
                url_for(
                    "main.view_student",
                    student_id=student.id,
                )
            )

        except ValueError as exc:

            db.session.rollback()

            flash(
                str(exc),
                "danger",
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Student could not be updated because username, email or admission number already exists.",
                "danger",
            )

        except Exception as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Student update failed: %s",
                exc,
            )

            flash(
                "Unable to update student.",
                "danger",
            )

    return render_template(
        "backend/pages/students/edit_student.html",
        student=student,
        user=current_user,
        **context,
    )



# ============================================================
# TOGGLE STUDENT ACCOUNT STATUS
# ============================================================

@bp.route(
    "/students/<int:student_id>/toggle-status",
    methods=["POST"]
)
@login_required
def toggle_student_status(student_id):

    # ========================================================
    # ACCESS CONTROL
    # ========================================================

    allowed_roles = {
        "superadmin",
        "institution_admin",
        "branch_admin",
    }

    if getattr(current_user, "role", None) not in allowed_roles:

        flash(
            "You do not have permission to change student status.",
            "danger"
        )

        return redirect(
            url_for("main.all_students")
        )


    # ========================================================
    # GET STUDENT
    # ========================================================

    student = Student.query.get_or_404(student_id)


    # ========================================================
    # CURRENT USER
    # ========================================================

    current_role = getattr(
        current_user,
        "role",
        None
    )

    current_institution_id = getattr(
        current_user,
        "institution_id",
        None
    )

    current_branch_id = getattr(
        current_user,
        "branch_id",
        None
    )


    # ========================================================
    # INSTITUTION ADMIN ACCESS
    # ========================================================

    if current_role == "institution_admin":

        if student.institution_id != current_institution_id:

            flash(
                "You cannot change the status of a student from another institution.",
                "danger"
            )

            return redirect(
                url_for("main.all_students")
            )


    # ========================================================
    # BRANCH ADMIN ACCESS
    # ========================================================

    if current_role == "branch_admin":

        if (
            student.institution_id != current_institution_id
            or
            student.branch_id != current_branch_id
        ):

            flash(
                "You cannot change the status of this student.",
                "danger"
            )

            return redirect(
                url_for("main.all_students")
            )


    # ========================================================
    # TOGGLE ACCOUNT STATUS
    # ========================================================

    student.is_active = not student.is_active

    student.updated_at = datetime.utcnow()


    # ========================================================
    # SAVE
    # ========================================================

    try:

        db.session.commit()

        if student.is_active:

            flash(
                f"{student.full_name} account has been activated.",
                "success"
            )

        else:

            flash(
                f"{student.full_name} account has been deactivated.",
                "warning"
            )

    except Exception as e:

        db.session.rollback()

        current_app.logger.exception(
            "Failed to toggle student status: %s",
            e
        )

        flash(
            "Unable to update student account status.",
            "danger"
        )


    # ========================================================
    # RETURN
    # ========================================================

    return redirect(
        url_for("main.all_students")
    )


# ============================================================
# DELETE STUDENT
# ============================================================

@bp.route(
    "/students/<int:student_id>/delete",
    methods=["POST"]
)
@login_required
def delete_student(student_id):

    if not _student_can_manage():

        abort(403)

    student = (
        Student.query
        .filter(
            Student.id == student_id
        )
        .first_or_404()
    )

    if not _student_has_access(student):

        abort(403)

    old_public_id = student.photo_public_id

    student_name = student.full_name

    try:

        db.session.delete(student)

        db.session.commit()

        if old_public_id:

            _delete_student_photo(
                old_public_id
            )

        flash(
            f"Student {student_name} deleted successfully.",
            "success",
        )

    except IntegrityError:

        db.session.rollback()

        flash(
            "Student cannot be deleted because related records exist.",
            "danger",
        )

    except Exception as exc:

        db.session.rollback()

        current_app.logger.exception(
            "Student deletion failed: %s",
            exc,
        )

        flash(
            "Unable to delete student.",
            "danger",
        )

    return redirect(
        url_for("main.all_students")
    )


# ============================================================
# IMPORT STUDENTS
# ============================================================

@bp.route(
    "/students/import",
    methods=["GET", "POST"]
)
@login_required
def import_students():

    if not _student_can_manage():

        flash(
            "You are not authorized to import students.",
            "danger",
        )

        return redirect(
            url_for("main.all_students")
        )

    context = _student_form_context()

    if request.method == "POST":

        uploaded_file = request.files.get(
            "student_file"
        )

        if not uploaded_file or not uploaded_file.filename:

            flash(
                "Please select a CSV or XLSX file.",
                "danger",
            )

            return render_template(
                "backend/pages/students/import_students.html",
                **context,
            )

        filename = uploaded_file.filename.lower()

        try:

            rows = []

            # =================================================
            # CSV
            # =================================================

            if filename.endswith(".csv"):

                content = (
                    uploaded_file
                    .read()
                    .decode("utf-8-sig")
                )

                reader = csv.DictReader(
                    StringIO(content)
                )

                rows = list(reader)

            # =================================================
            # XLSX
            # =================================================

            elif filename.endswith(".xlsx"):

                workbook = load_workbook(
                    uploaded_file,
                    read_only=True,
                    data_only=True,
                )

                sheet = workbook.active

                values = list(
                    sheet.iter_rows(
                        values_only=True
                    )
                )

                if not values:

                    raise ValueError(
                        "The Excel file is empty."
                    )

                headers = [
                    str(value).strip()
                    if value is not None
                    else ""
                    for value in values[0]
                ]

                for row in values[1:]:

                    item = {}

                    for index, header in enumerate(headers):

                        if not header:
                            continue

                        item[header] = (
                            row[index]
                            if index < len(row)
                            else None
                        )

                    rows.append(item)

            else:

                raise ValueError(
                    "Only CSV and XLSX files are supported."
                )

            if not rows:

                raise ValueError(
                    "No student records were found."
                )

            created_count = 0
            skipped_count = 0
            errors = []

            role = getattr(
                current_user,
                "role",
                None,
            )

            for row_number, row in enumerate(
                rows,
                start=2,
            ):

                # ---------------------------------------------
                # Case-insensitive headers
                # ---------------------------------------------

                normalized = {
                    str(key).strip().lower():
                    value
                    for key, value in row.items()
                    if key is not None
                }

                def value(*names):

                    for name in names:

                        val = normalized.get(
                            name.lower()
                        )

                        if val is not None:
                            return str(val).strip()

                    return ""

                institution_id_raw = value(
                    "institution_id"
                )

                branch_id_raw = value(
                    "branch_id"
                )

                username = value(
                    "username"
                )

                email = value(
                    "email"
                ) or None

                admission_no = value(
                    "admission_no",
                    "admission no",
                    "admission_number",
                )

                roll_no = value(
                    "roll_no",
                    "roll no",
                ) or None

                full_name = value(
                    "full_name",
                    "full name",
                    "name",
                )

                gender = value(
                    "gender"
                ) or None

                date_of_birth_raw = value(
                    "date_of_birth",
                    "date of birth",
                    "dob",
                )

                place_of_birth = value(
                    "place_of_birth",
                    "place of birth",
                ) or None

                nationality = value(
                    "nationality"
                ) or None

                phone = value(
                    "phone"
                ) or None

                address = value(
                    "address"
                ) or None

                city = value(
                    "city"
                ) or None

                parent_name = value(
                    "parent_name",
                    "parent name",
                ) or None

                parent_phone = value(
                    "parent_phone",
                    "parent phone",
                ) or None

                parent_email = value(
                    "parent_email",
                    "parent email",
                ) or None

                parent_address = value(
                    "parent_address",
                    "parent address",
                ) or None

                relationship = value(
                    "relationship_to_student",
                    "relationship",
                ) or None

                status = (
                    value("status")
                    or "active"
                ).lower()

                password = (
                    value("password")
                    or admission_no
                    or username
                )

                photo_url = value(
                    "photo",
                    "photo_url",
                    "photo url",
                ) or None

                # ---------------------------------------------
                # Institution
                # ---------------------------------------------

                if institution_id_raw.isdigit():

                    institution_id = int(
                        institution_id_raw
                    )

                else:

                    institution_id = (
                        _student_user_institution_id()
                    )

                # ---------------------------------------------
                # Branch
                # ---------------------------------------------

                if branch_id_raw.isdigit():

                    branch_id = int(
                        branch_id_raw
                    )

                else:

                    branch_id = (
                        _student_user_branch_id()
                    )

                # ---------------------------------------------
                # Required
                # ---------------------------------------------

                if not full_name:

                    errors.append(
                        f"Row {row_number}: Full name is required."
                    )

                    continue

                if not username:

                    username = admission_no.lower()

                if not admission_no:

                    errors.append(
                        f"Row {row_number}: Admission number is required."
                    )

                    continue

                # ---------------------------------------------
                # Role restriction
                # ---------------------------------------------

                if role == "institution_admin":

                    if institution_id != _student_user_institution_id():

                        errors.append(
                            f"Row {row_number}: Institution access denied."
                        )

                        continue

                if role == "branch_admin":

                    if (
                        institution_id
                        != _student_user_institution_id()
                    ):

                        errors.append(
                            f"Row {row_number}: Institution access denied."
                        )

                        continue

                    if (
                        branch_id
                        != _student_user_branch_id()
                    ):

                        errors.append(
                            f"Row {row_number}: Branch access denied."
                        )

                        continue

                # ---------------------------------------------
                # Branch validation
                # ---------------------------------------------

                branch = (
                    Branch.query
                    .filter(
                        Branch.id == branch_id
                    )
                    .first()
                )

                if not branch:

                    errors.append(
                        f"Row {row_number}: Branch not found."
                    )

                    continue

                if branch.institution_id != institution_id:

                    errors.append(
                        f"Row {row_number}: Branch does not belong to institution."
                    )

                    continue

                # ---------------------------------------------
                # Duplicate username
                # ---------------------------------------------

                if (
                    Student.query
                    .filter(
                        func.lower(Student.username)
                        == username.lower()
                    )
                    .first()
                ):

                    skipped_count += 1

                    errors.append(
                        f"Row {row_number}: Username already exists: {username}"
                    )

                    continue

                # ---------------------------------------------
                # Duplicate email
                # ---------------------------------------------

                if email:

                    if (
                        Student.query
                        .filter(
                            func.lower(Student.email)
                            == email.lower()
                        )
                        .first()
                    ):

                        skipped_count += 1

                        errors.append(
                            f"Row {row_number}: Email already exists: {email}"
                        )

                        continue

                # ---------------------------------------------
                # Duplicate admission
                # ---------------------------------------------

                if (
                    Student.query
                    .filter(
                        Student.institution_id ==
                        institution_id,
                        func.lower(
                            Student.admission_no
                        )
                        == admission_no.lower(),
                    )
                    .first()
                ):

                    skipped_count += 1

                    errors.append(
                        f"Row {row_number}: Admission number already exists: {admission_no}"
                    )

                    continue

                # ---------------------------------------------
                # Date
                # ---------------------------------------------

                try:

                    date_of_birth = (
                        _parse_student_date(
                            date_of_birth_raw
                        )
                    )

                except ValueError:

                    errors.append(
                        f"Row {row_number}: Invalid date of birth."
                    )

                    continue

                # ---------------------------------------------
                # Student
                # ---------------------------------------------

                student = Student(

                    institution_id=institution_id,

                    branch_id=branch_id,

                    username=username,

                    email=email,

                    role="student",

                    is_active=(
                        status == "active"
                    ),

                    is_verified=False,

                    admission_no=admission_no,

                    roll_no=roll_no,

                    full_name=full_name,

                    gender=gender,

                    date_of_birth=date_of_birth,

                    place_of_birth=place_of_birth,

                    nationality=nationality,

                    phone=phone,

                    address=address,

                    city=city,

                    parent_name=parent_name,

                    parent_phone=parent_phone,

                    parent_email=parent_email,

                    parent_address=parent_address,

                    relationship_to_student=relationship,

                    photo=photo_url,

                    status=(
                        status
                        if status in STUDENT_STATUSES
                        else "active"
                    ),

                )

                student.set_password(
                    password
                )

                db.session.add(student)

                created_count += 1

            # -------------------------------------------------
            # Commit all
            # -------------------------------------------------

            db.session.commit()

            flash(
                f"{created_count} students imported successfully.",
                "success",
            )

            if skipped_count:

                flash(
                    f"{skipped_count} students were skipped because of duplicate data.",
                    "warning",
                )

            if errors:

                # Show only first 10 errors
                for error in errors[:10]:

                    flash(
                        error,
                        "warning",
                    )

                if len(errors) > 10:

                    flash(
                        f"{len(errors) - 10} additional import errors were hidden.",
                        "warning",
                    )

            return redirect(
                url_for(
                    "main.all_students"
                )
            )

        except Exception as exc:

            db.session.rollback()

            current_app.logger.exception(
                "Student import failed: %s",
                exc,
            )

            flash(
                f"Student import failed: {exc}",
                "danger",
            )

    return render_template(
        "backend/pages/students/import_students.html",
        **context,
    )




















#---------------------------------------
#---- Route: Ending |  Logout Sections ----
#---------------------------------------
@bp.route("/logout")
def logout():

    if current_user.is_authenticated:

        user = User.query.get(current_user.id)

        if user:
            user.auth_status = "logout"
            user.session_token = None
            user.last_seen = datetime.utcnow()

            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                current_app.logger.exception("Logout update error")

        logout_user()

        flash(
            "You have been logged out successfully.",
            "success"
        )

    else:

        flash(
            "You are already logged out.",
            "info"
        )

    return redirect(
        url_for("main.login")
    )




