from datetime import datetime, timedelta
from functools import wraps
import os
import re
import secrets
from uuid import uuid4
import uuid
import bcrypt
import cloudinary
from cloudinary import uploader
from flask import Blueprint, abort, current_app, flash, json, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Message
import pytz
from slugify import slugify
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app import ALLOWED_EXTENSIONS
from app.model import AcademicYear, AssessmentPlan, Branch, Class, Institution, Program, Term, User, UserRole, db

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


# ============================================================
# ADD USER
# PostgreSQL / Neon
#
# HIERARCHY:
#
# Institution
#      │
#      └── Multiple Branches
#                │
#                └── Users
#
# ACCESS:
# Superadmin only
# ============================================================

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
        UserRole.parent.value
    ]

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
    # DEFAULT BRANCHES
    # ========================================================

    branches = []

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ====================================================
        # INSTITUTION
        # ====================================================

        institution_id_raw = request.form.get(
            "institution_id",
            ""
        ).strip()

        institution = None
        institution_id = None

        if institution_id_raw:

            try:

                institution_id = int(
                    institution_id_raw
                )

            except (TypeError, ValueError):

                flash(
                    "Invalid institution selected.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

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

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

            # ================================================
            # LOAD BRANCHES FOR SELECTED INSTITUTION
            # ================================================

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

        # ====================================================
        # BRANCH
        # ====================================================

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

            except (TypeError, ValueError):

                flash(
                    "Invalid branch selected.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

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

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

            # ================================================
            # SECURITY:
            # BRANCH MUST BELONG TO SELECTED INSTITUTION
            # ================================================

            if (
                institution is None
                or branch.institution_id != institution.id
            ):

                flash(
                    "The selected branch does not belong "
                    "to the selected institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
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

        fullname = request.form.get(
            "fullname",
            ""
        ).strip()

        # ====================================================
        # PHONE
        # ====================================================

        phone_country = request.form.get(
            "phone_country",
            ""
        ).strip()

        phone_number = request.form.get(
            "phone",
            ""
        ).strip()

        # Remove spaces, hyphens and brackets
        phone_number = (
            phone_number
            .replace(" ", "")
            .replace("-", "")
            .replace("(", "")
            .replace(")", "")
        )

        phone = None

        if phone_number:

            if phone_country:

                phone_country = (
                    phone_country
                    .replace(" ", "")
                    .replace("-", "")
                    .strip()
                )

                # Ensure country code starts with +
                if not phone_country.startswith("+"):

                    phone_country = (
                        f"+{phone_country}"
                    )

                # Prevent accidental duplicate +
                phone_country = (
                    "+" +
                    phone_country.lstrip("+")
                )

                phone = (
                    f"{phone_country}"
                    f"{phone_number}"
                )

            else:

                phone = phone_number

        # ====================================================
        # LOCATION
        # ====================================================

        country = request.form.get(
            "country",
            ""
        ).strip()

        city = request.form.get(
            "city",
            ""
        ).strip()

        state = request.form.get(
            "state",
            ""
        ).strip()

        address = request.form.get(
            "address",
            ""
        ).strip()

        # ====================================================
        # OTHER INFORMATION
        # ====================================================

        bio = request.form.get(
            "bio",
            ""
        ).strip()

        role = request.form.get(
            "role",
            UserRole.student.value
        ).strip().lower()

        gender = request.form.get(
            "gender",
            ""
        ).strip()

        pob = request.form.get(
            "pob",
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

        raw_status = request.form.get(
            "status",
            "true"
        ).strip().lower()

        if raw_status in {
            "true",
            "1",
            "active",
            "enabled",
            "on"
        }:

            status = True

        elif raw_status in {
            "false",
            "0",
            "inactive",
            "disabled",
            "off"
        }:

            status = False

        else:

            flash(
                "Invalid account status.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # VERIFICATION
        # ====================================================

        raw_verified = request.form.get(
            "is_verified",
            "false"
        ).strip().lower()

        if raw_verified in {
            "true",
            "1",
            "verified",
            "yes",
            "on"
        }:

            is_verified = True

        elif raw_verified in {
            "false",
            "0",
            "unverified",
            "no",
            "off"
        }:

            is_verified = False

        else:

            flash(
                "Invalid verification value.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # PHOTO VISIBILITY
        # ====================================================

        photo_visibility = request.form.get(
            "photo_visibility",
            "everyone"
        ).strip().lower()

        if photo_visibility not in {
            "everyone",
            "private"
        }:

            photo_visibility = "everyone"

        # ====================================================
        # DATE OF BIRTH
        # ====================================================

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

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

        # ====================================================
        # ROLE VALIDATION
        # ====================================================

        if role not in allowed_roles:

            flash(
                "Invalid user role selected.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # HIERARCHY VALIDATION
        #
        # superadmin:
        #   institution optional
        #   branch optional
        #
        # school_admin:
        #   institution required
        #   branch optional
        #
        # branch_admin / teacher / student / parent:
        #   institution required
        #   branch required
        # ====================================================

        if role != UserRole.superadmin.value:

            if institution is None:

                flash(
                    "Institution is required for this user role.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

        branch_required_roles = {
            UserRole.branch_admin.value,
            UserRole.teacher.value,
            UserRole.student.value,
            UserRole.parent.value
        }

        if role in branch_required_roles:

            if branch is None:

                flash(
                    "Branch is required for this user role.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

        # ====================================================
        # SCHOOL ADMIN:
        # BRANCH IS OPTIONAL
        # ====================================================

        if role == UserRole.school_admin.value:

            if branch is not None:

                if (
                    institution is None
                    or branch.institution_id != institution.id
                ):

                    flash(
                        "Selected branch does not belong "
                        "to the selected institution.",
                        "danger"
                    )

                    return render_template(
                        "backend/pages/users/add_user.html",
                        roles=allowed_roles,
                        institutions=institutions,
                        branches=branches
                    )

        # ====================================================
        # SUPERADMIN:
        # DO NOT REQUIRE INSTITUTION OR BRANCH
        # ====================================================

        if role == UserRole.superadmin.value:

            # A branch cannot exist without institution
            if branch is not None and institution is None:

                flash(
                    "A branch cannot be assigned without "
                    "an institution.",
                    "danger"
                )

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

        # ====================================================
        # REQUIRED FULL NAME
        # ====================================================

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # REQUIRED USERNAME
        # ====================================================

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # REQUIRED EMAIL
        # ====================================================

        if not email:

            flash(
                "Email address is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # PASSWORD REQUIRED
        # ====================================================

        if not password:

            flash(
                "Password is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # PASSWORD LENGTH
        # ====================================================

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # PASSWORD CONFIRMATION
        # ====================================================

        if password != confirm_password:

            flash(
                "Password and confirm password do not match.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # DUPLICATE USERNAME
        # ====================================================

        existing_username = (
            User.query
            .filter(
                db.func.lower(User.username)
                == username.lower()
            )
            .first()
        )

        if existing_username:

            flash(
                "This username is already registered.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # DUPLICATE EMAIL
        # ====================================================

        existing_email = (
            User.query
            .filter(
                db.func.lower(User.email)
                == email.lower()
            )
            .first()
        )

        if existing_email:

            flash(
                "This email address is already registered.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

        # ====================================================
        # DUPLICATE PHONE
        #
        # Only check if phone exists.
        # ====================================================

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

                return render_template(
                    "backend/pages/users/add_user.html",
                    roles=allowed_roles,
                    institutions=institutions,
                    branches=branches
                )

        # ====================================================
        # PHOTO
        # ====================================================

        photo_file = request.files.get(
            "photo"
        )

        photo = None

        # ====================================================
        # CLOUDINARY PHOTO UPLOAD
        #
        # Uncomment if Cloudinary is configured.
        #
        # import cloudinary.uploader
        #
        # if photo_file and photo_file.filename:
        #
        #     upload_result = (
        #         cloudinary.uploader.upload(
        #             photo_file,
        #             folder="users/profile"
        #         )
        #     )
        #
        #     photo = upload_result.get(
        #         "secure_url"
        #     )
        # ====================================================

        # ====================================================
        # CREATE USER
        # ====================================================

        now = datetime.utcnow()

        new_user = User(

            # ------------------------------------------------
            # INSTITUTION
            # ------------------------------------------------

            institution_id=(
                institution.id
                if institution
                else None
            ),

            # ------------------------------------------------
            # BRANCH
            # ------------------------------------------------

            branch_id=(
                branch.id
                if branch
                else None
            ),

            # ------------------------------------------------
            # BASIC INFORMATION
            # ------------------------------------------------

            username=username,

            email=email,

            fullname=fullname,

            phone=phone,

            # ------------------------------------------------
            # LOCATION
            # ------------------------------------------------

            country=country or None,

            city=city or None,

            state=state or None,

            address=address or None,

            # ------------------------------------------------
            # BIO
            # ------------------------------------------------

            bio=bio or None,

            # ------------------------------------------------
            # ROLE
            # ------------------------------------------------

            role=role,

            # ------------------------------------------------
            # ACCOUNT STATUS
            # ------------------------------------------------

            status=status,

            is_verified=is_verified,

            # ------------------------------------------------
            # PHOTO
            # ------------------------------------------------

            photo=photo,

            photo_visibility=photo_visibility,

            # ------------------------------------------------
            # AUTHENTICATION
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
            # PERSONAL INFORMATION
            # ------------------------------------------------

            gender=gender or None,

            dob=dob,

            pob=pob or None,

            # ------------------------------------------------
            # TIMESTAMPS
            # ------------------------------------------------

            created_at=now,

            updated_at=now
        )

        # ====================================================
        # PASSWORD HASH
        # ====================================================

        new_user.set_password(
            password
        )

        # ====================================================
        # DATABASE SAVE
        # ====================================================

        try:

            db.session.add(
                new_user
            )

            db.session.commit()

            # =================================================
            # LOG
            # =================================================

            current_app.logger.info(
                "New user created successfully. "
                "User ID: %s, "
                "Username: %s, "
                "Role: %s, "
                "Institution ID: %s, "
                "Branch ID: %s, "
                "Created by Superadmin ID: %s",
                new_user.id,
                new_user.username,
                new_user.role,
                new_user.institution_id,
                new_user.branch_id,
                current_user.id
            )

            # =================================================
            # SUCCESS MESSAGE
            # =================================================

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

        except Exception as e:

            db.session.rollback()

            current_app.logger.exception(
                "Error creating new user: %s",
                e
            )

            flash(
                "Unable to create the user. "
                "Please check the information and try again.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles,
                institutions=institutions,
                branches=branches
            )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/users/add_user.html",
        roles=allowed_roles,
        institutions=institutions,
        branches=branches,
        user=current_user
    )





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
            "You do not have permission to edit users.",
            "danger"
        )
        return redirect(
            url_for("main.dashboard")
        )


    # ========================================================
    # FIND USER
    # ========================================================

    user = User.query.get(user_id)

    if not user:
        flash(
            "User not found.",
            "danger"
        )
        return redirect(
            url_for("main.all_users")
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
    # FORM ERROR RENDER HELPER
    #
    # This keeps institution / branch data available whenever
    # the form needs to be rendered again.
    # ========================================================

    def render_edit_form():

        selected_institution_id = (
            request.form.get(
                "institution_id",
                str(user.institution_id or "")
            ).strip()
        )

        selected_branch_id = (
            request.form.get(
                "branch_id",
                str(user.branch_id or "")
            ).strip()
        )


        # ----------------------------------------------------
        # SAFE INSTITUTION ID
        # ----------------------------------------------------

        try:
            selected_institution_id = (
                int(selected_institution_id)
                if selected_institution_id
                else None
            )

        except (TypeError, ValueError):

            selected_institution_id = None


        # ----------------------------------------------------
        # SAFE BRANCH ID
        # ----------------------------------------------------

        try:
            selected_branch_id = (
                int(selected_branch_id)
                if selected_branch_id
                else None
            )

        except (TypeError, ValueError):

            selected_branch_id = None


        # ----------------------------------------------------
        # BRANCHES
        # ----------------------------------------------------

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


        return render_template(
            "backend/pages/users/edit_user.html",

            user=user,

            current_user=current_user,

            roles=allowed_roles,

            institutions=institutions,

            branches=branches,

            selected_institution_id=(
                selected_institution_id
            ),

            selected_branch_id=(
                selected_branch_id
            )
        )


    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":


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


        fullname = request.form.get(
            "fullname",
            ""
        ).strip()


        # ====================================================
        # PHONE
        # ====================================================

        phone_country = request.form.get(
            "phone_country",
            ""
        ).strip()


        phone_number = request.form.get(
            "phone",
            ""
        ).strip()


        phone_number = (
            phone_number
            .replace(" ", "")
            .replace("-", "")
            .replace("(", "")
            .replace(")", "")
        )


        phone = None


        if phone_number:

            if phone_country:

                phone_country = (
                    phone_country
                    .replace(" ", "")
                    .replace("-", "")
                    .strip()
                )


                if not phone_country.startswith("+"):

                    phone_country = (
                        f"+{phone_country}"
                    )


                phone = (
                    f"{phone_country}"
                    f"{phone_number}"
                )

            else:

                phone = phone_number


        # ====================================================
        # LOCATION
        # ====================================================

        country = request.form.get(
            "country",
            ""
        ).strip()


        city = request.form.get(
            "city",
            ""
        ).strip()


        state = request.form.get(
            "state",
            ""
        ).strip()


        address = request.form.get(
            "address",
            ""
        ).strip()


        # ====================================================
        # PERSONAL INFORMATION
        # ====================================================

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


        # ====================================================
        # ROLE
        # ====================================================

        role = request.form.get(
            "role",
            user.role or UserRole.student.value
        ).strip().lower()


        # ====================================================
        # STATUS
        # ====================================================

        status_value = request.form.get(
            "status",
            "true"
        ).strip().lower()


        status = (
            status_value
            in [
                "true",
                "1",
                "yes",
                "active",
                "on"
            ]
        )


        # ====================================================
        # VERIFICATION
        # ====================================================

        verification_value = request.form.get(
            "is_verified",
            "false"
        ).strip().lower()


        is_verified = (
            verification_value
            in [
                "true",
                "1",
                "yes",
                "verified",
                "on"
            ]
        )


        # ====================================================
        # PHOTO VISIBILITY
        # ====================================================

        photo_visibility = request.form.get(
            "photo_visibility",
            user.photo_visibility or "everyone"
        ).strip().lower()


        if photo_visibility not in [
            "everyone",
            "private"
        ]:

            photo_visibility = "everyone"


        # ====================================================
        # DATE OF BIRTH
        # ====================================================

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

                return render_edit_form()


        # ====================================================
        # INSTITUTION
        # ====================================================

        institution_id_value = request.form.get(
            "institution_id",
            ""
        ).strip()


        institution_id = None


        if institution_id_value:

            try:

                institution_id = int(
                    institution_id_value
                )

            except (TypeError, ValueError):

                flash(
                    "Invalid institution selected.",
                    "danger"
                )

                return render_edit_form()


        # ====================================================
        # BRANCH
        # ========================================================

        branch_id_value = request.form.get(
            "branch_id",
            ""
        ).strip()


        branch_id = None


        if branch_id_value:

            try:

                branch_id = int(
                    branch_id_value
                )

            except (TypeError, ValueError):

                flash(
                    "Invalid branch selected.",
                    "danger"
                )

                return render_edit_form()


        # ====================================================
        # PASSWORD
        #
        # Password is OPTIONAL during editing.
        # Empty password means keep existing password.
        # ========================================================

        password = request.form.get(
            "password",
            ""
        )


        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ========================================================
        # VALIDATION
        # ========================================================

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return render_edit_form()


        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_edit_form()


        if not email:

            flash(
                "Email address is required.",
                "danger"
            )

            return render_edit_form()


        if role not in allowed_roles:

            flash(
                "Invalid user role selected.",
                "danger"
            )

            return render_edit_form()


        # ========================================================
        # ROLE → INSTITUTION / BRANCH RULES
        #
        # superadmin:
        #   institution = optional
        #   branch = optional
        #
        # school_admin:
        #   institution = required
        #   branch = optional
        #
        # branch_admin / teacher / student / parent:
        #   institution = required
        #   branch = required
        # ========================================================

        if role == UserRole.superadmin.value:

            institution_id = None
            branch_id = None


        else:

            if not institution_id:

                flash(
                    "Institution is required for this user role.",
                    "danger"
                )

                return render_edit_form()


            if role in [
                UserRole.branch_admin.value,
                UserRole.teacher.value,
                UserRole.student.value,
                UserRole.parent.value
            ]:

                if not branch_id:

                    flash(
                        "Branch is required for this user role.",
                        "danger"
                    )

                    return render_edit_form()


        # ========================================================
        # VALIDATE INSTITUTION
        # ========================================================

        institution = None


        if institution_id:

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
                    "Selected institution does not exist.",
                    "danger"
                )

                return render_edit_form()


            # --------------------------------------------------
            # OPTIONAL STATUS VALIDATION
            #
            # If your Institution model has status values
            # active / inactive / suspended.
            # --------------------------------------------------

            institution_status = getattr(
                institution,
                "status",
                None
            )


            if institution_status:

                institution_status_normalized = (
                    str(
                        institution_status
                    )
                    .strip()
                    .lower()
                )


                if institution_status_normalized in [
                    "inactive",
                    "suspended"
                ]:

                    flash(
                        "The selected institution is not active.",
                        "danger"
                    )

                    return render_edit_form()


        # ========================================================
        # VALIDATE BRANCH
        # ========================================================

        branch = None


        if branch_id:

            branch = (
                Branch.query
                .filter(
                    Branch.id ==
                    branch_id
                )
                .first()
            )


            if not branch:

                flash(
                    "Selected branch does not exist.",
                    "danger"
                )

                return render_edit_form()


            # --------------------------------------------------
            # CRITICAL:
            # Branch MUST belong to selected institution.
            # --------------------------------------------------

            if (
                institution_id
                and branch.institution_id
                != institution_id
            ):

                flash(
                    "The selected branch does not belong to the selected institution.",
                    "danger"
                )

                return render_edit_form()


            # --------------------------------------------------
            # OPTIONAL BRANCH STATUS VALIDATION
            # --------------------------------------------------

            branch_status = getattr(
                branch,
                "status",
                None
            )


            if branch_status:

                branch_status_normalized = (
                    str(
                        branch_status
                    )
                    .strip()
                    .lower()
                )


                if branch_status_normalized in [
                    "inactive",
                    "suspended"
                ]:

                    flash(
                        "The selected branch is not active.",
                        "danger"
                    )

                    return render_edit_form()


        # ========================================================
        # USERNAME DUPLICATE CHECK
        #
        # Exclude current user.
        # ========================================================

        existing_username = (
            User.query
            .filter(
                db.func.lower(
                    User.username
                ) == username.lower(),
                User.id != user.id
            )
            .first()
        )


        if existing_username:

            flash(
                "This username is already registered by another user.",
                "danger"
            )

            return render_edit_form()


        # ========================================================
        # EMAIL DUPLICATE CHECK
        # ========================================================

        existing_email = (
            User.query
            .filter(
                db.func.lower(
                    User.email
                ) == email.lower(),
                User.id != user.id
            )
            .first()
        )


        if existing_email:

            flash(
                "This email address is already registered by another user.",
                "danger"
            )

            return render_edit_form()


        # ========================================================
        # FULLNAME DUPLICATE CHECK
        #
        # Your User model currently has unique=True on fullname.
        # ========================================================

        existing_fullname = (
            User.query
            .filter(
                db.func.lower(
                    User.fullname
                ) == fullname.lower(),
                User.id != user.id
            )
            .first()
        )


        if existing_fullname:

            flash(
                "This full name is already registered by another user.",
                "danger"
            )

            return render_edit_form()


        # ========================================================
        # PASSWORD VALIDATION
        # ========================================================

        if password:

            if len(password) < 6:

                flash(
                    "Password must contain at least 6 characters.",
                    "danger"
                )

                return render_edit_form()


            if password != confirm_password:

                flash(
                    "Password and confirm password do not match.",
                    "danger"
                )

                return render_edit_form()


        else:

            # Password is not being changed.
            confirm_password = ""


        # ========================================================
        # PHOTO
        # ========================================================

        photo_file = request.files.get(
            "photo"
        )


        # Keep existing photo unless a new file is supplied.
        new_photo = user.photo


        if photo_file and photo_file.filename:

            # ----------------------------------------------------
            # PHOTO UPLOAD
            #
            # This block supports Cloudinary if configured.
            #
            # Required environment variables:
            #
            # CLOUDINARY_CLOUD_NAME
            # CLOUDINARY_API_KEY
            # CLOUDINARY_API_SECRET
            # ----------------------------------------------------

            try:

                import cloudinary
                import cloudinary.uploader


                cloud_name = current_app.config.get(
                    "CLOUDINARY_CLOUD_NAME"
                ) or current_app.config.get(
                    "CLOUDINARY_CLOUD"
                )


                api_key = current_app.config.get(
                    "CLOUDINARY_API_KEY"
                )


                api_secret = current_app.config.get(
                    "CLOUDINARY_API_SECRET"
                )


                # ------------------------------------------------
                # Try environment variables if config is empty.
                # ------------------------------------------------

                import os


                cloud_name = (
                    cloud_name
                    or os.getenv(
                        "CLOUDINARY_CLOUD_NAME"
                    )
                )


                api_key = (
                    api_key
                    or os.getenv(
                        "CLOUDINARY_API_KEY"
                    )
                )


                api_secret = (
                    api_secret
                    or os.getenv(
                        "CLOUDINARY_API_SECRET"
                    )
                )


                if not all([
                    cloud_name,
                    api_key,
                    api_secret
                ]):

                    flash(
                        "Cloudinary is not configured. Unable to upload your profile photo.",
                        "danger"
                    )

                    return render_edit_form()


                cloudinary.config(
                    cloud_name=cloud_name,
                    api_key=api_key,
                    api_secret=api_secret,
                    secure=True
                )


                upload_result = (
                    cloudinary.uploader.upload(
                        photo_file,
                        folder="private_grading/users",
                        resource_type="image"
                    )
                )


                new_photo = (
                    upload_result
                    .get("secure_url")
                )


                if not new_photo:

                    flash(
                        "Photo upload failed. Cloudinary did not return a secure URL.",
                        "danger"
                    )

                    return render_edit_form()


            except Exception as photo_error:

                current_app.logger.exception(
                    "User photo upload failed for user_id=%s: %s",
                    user.id,
                    photo_error
                )


                flash(
                    "Unable to upload your profile photo.",
                    "danger"
                )

                return render_edit_form()


        # ========================================================
        # UPDATE USER
        # ========================================================

        now = datetime.utcnow()


        user.username = username

        user.email = email

        user.fullname = fullname

        user.phone = phone

        user.country = (
            country
            or None
        )

        user.city = (
            city
            or None
        )

        user.state = (
            state
            or None
        )

        user.address = (
            address
            or None
        )

        user.bio = (
            bio
            or None
        )

        user.role = role

        user.status = status

        user.is_verified = is_verified

        user.photo = new_photo

        user.photo_visibility = photo_visibility

        user.gender = (
            gender
            or None
        )

        user.dob = dob

        user.pob = (
            pob
            or None
        )


        # ========================================================
        # INSTITUTION / BRANCH
        # ========================================================

        user.institution_id = (
            institution_id
        )

        user.branch_id = (
            branch_id
        )


        # ========================================================
        # PASSWORD
        # ========================================================

        if password:

            user.set_password(
                password
            )


        # ========================================================
        # UPDATED TIME
        # ========================================================

        user.updated_at = now


        # ========================================================
        # SAVE
        # ========================================================

        try:

            db.session.commit()


            current_app.logger.info(
                "User updated successfully. "
                "user_id=%s username=%s role=%s institution_id=%s branch_id=%s updated_by=%s",
                user.id,
                user.username,
                user.role,
                user.institution_id,
                user.branch_id,
                current_user.id
            )


            flash(
                f"User '{user.fullname or user.username}' updated successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "main.all_users"
                )
            )


        except Exception as e:

            db.session.rollback()


            current_app.logger.exception(
                "Error updating user. user_id=%s updated_by=%s error=%s",
                user.id,
                current_user.id,
                e
            )


            flash(
                "Unable to update the user. Please try again.",
                "danger"
            )


            return render_edit_form()


    # ========================================================
    # GET
    # ========================================================

    selected_institution_id = (
        user.institution_id
        if user.institution_id
        else None
    )


    selected_branch_id = (
        user.branch_id
        if user.branch_id
        else None
    )


    # ========================================================
    # LOAD BRANCHES FOR CURRENT USER
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
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/users/edit_user.html",

        # User being edited
        user=user,

        # Logged-in user
        current_user=current_user,

        # Roles
        roles=allowed_roles,

        # Institutions
        institutions=institutions,

        # Branches
        branches=branches,

        # Selected organization
        selected_institution_id=(
            selected_institution_id
        ),

        selected_branch_id=(
            selected_branch_id
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


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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


    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access this page.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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


    if not current_user.is_superadmin():

        return jsonify({

            "success": False,

            "message":
                "You do not have permission to delete academic years."

        }), 403


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

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access terms.",
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

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to add terms.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to view terms.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to edit terms.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        return jsonify(
            {
                "success": False,
                "message": (
                    "You do not have permission "
                    "to delete terms."
                )
            }
        ), 403


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

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to access programs.",
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

    program_types = (
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
        for row in program_types
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

        selected_program_type=
            selected_program_type,

        selected_institution_id=
            selected_institution_id,

        selected_branch_id=
            selected_branch_id,

        per_page=per_page,

        total_programs=total_programs,

        active_programs=active_programs,

        inactive_programs=inactive_programs,

        institution_wide_programs=
            institution_wide_programs,

        branch_programs=
            branch_programs,

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

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to add programs.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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

        # ----------------------------------------------------
        # VALIDATE BRANCH ID
        #
        # Branch is optional.
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

            # ------------------------------------------------
            # VERIFY BRANCH BELONGS TO INSTITUTION
            # ------------------------------------------------

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
                    "Duration must be a valid number.",
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
        #
        # Program code is unique per institution.
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
                    "main.all_programs"
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

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to view programs.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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
            Institution.id ==
            program.institution_id
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
                Branch.id ==
                program.branch_id
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
    # OTHER PROGRAMS IN SAME INSTITUTION
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
            Program.name.asc()
        )
        .limit(10)
        .all()
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

    if not current_user.is_superadmin():

        flash(
            "You do not have permission to edit programs.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
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

        status = request.form.get(
            "status",
            "active"
        ).strip().lower()

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
                "backend/pages/programs/edit_program.html",
                program=program,
                institutions=institutions,
                branches=branches,
                user=current_user
            )

        # ----------------------------------------------------
        # BRANCH ID
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

            # ------------------------------------------------
            # VERIFY BRANCH BELONGS TO INSTITUTION
            # ------------------------------------------------

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
                    "Duration must be a valid number.",
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

    # --------------------------------------------------------
    # SUPERADMIN ONLY
    # --------------------------------------------------------

    if not current_user.is_superadmin():

        return jsonify(
            {
                "success": False,
                "message": (
                    "You do not have permission "
                    "to delete programs."
                )
            }
        ), 403

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

        return jsonify(
            {
                "success": False,
                "message": "Program not found."
            }
        ), 404

    # --------------------------------------------------------
    # SAVE INFO BEFORE DELETE
    # --------------------------------------------------------

    program_name = program.name

    program_id_value = program.id

    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    try:

        db.session.delete(program)

        db.session.commit()

        return jsonify(
            {
                "success": True,
                "message": (
                    f"Program '{program_name}' "
                    f"was deleted successfully."
                ),
                "program_id": program_id_value
            }
        ), 200

    except IntegrityError:

        db.session.rollback()

        return jsonify(
            {
                "success": False,
                "message": (
                    "This program cannot be deleted because "
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
                    "while deleting the program."
                )
            }
        ), 500



# ============================================================
# ASSESSMENT PLAN ROUTES
# PostgreSQL / Neon
# ============================================================

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




