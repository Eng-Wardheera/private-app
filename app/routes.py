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
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app import ALLOWED_EXTENSIONS
from app.model import User, UserRole, db

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
            "You do not have permission to access all users.",
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
    # PAGINATION
    # --------------------------------------------------------
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


    # --------------------------------------------------------
    # BASE QUERY
    # --------------------------------------------------------
    query = User.query


    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------
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


    # --------------------------------------------------------
    # ALLOWED ROLES
    # --------------------------------------------------------
    allowed_roles = [
        UserRole.superadmin.value,
        UserRole.school_admin.value,
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value
    ]


    # --------------------------------------------------------
    # ROLE FILTER
    # --------------------------------------------------------
    if role and role in allowed_roles:

        query = query.filter(
            User.role == role
        )


    # --------------------------------------------------------
    # STATUS FILTER
    # --------------------------------------------------------
    if status == "active":

        query = query.filter(
            User.status.is_(True)
        )

    elif status == "inactive":

        query = query.filter(
            User.status.is_(False)
        )


    # --------------------------------------------------------
    # VERIFICATION FILTER
    # --------------------------------------------------------
    if verification == "verified":

        query = query.filter(
            User.is_verified.is_(True)
        )

    elif verification == "unverified":

        query = query.filter(
            User.is_verified.is_(False)
        )


    # --------------------------------------------------------
    # ORDER
    # --------------------------------------------------------
    query = query.order_by(
        User.created_at.desc(),
        User.id.desc()
    )


    # --------------------------------------------------------
    # PAGINATION
    # --------------------------------------------------------
    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )


    users = pagination.items


    # ========================================================
    # GLOBAL USER STATISTICS
    # ========================================================

    total_users = User.query.count()


    active_users = User.query.filter(
        User.status.is_(True)
    ).count()


    inactive_users = User.query.filter(
        User.status.is_(False)
    ).count()


    verified_users = User.query.filter(
        User.is_verified.is_(True)
    ).count()


    unverified_users = User.query.filter(
        User.is_verified.is_(False)
    ).count()


    # ========================================================
    # ROLE STATISTICS
    # ========================================================

    superadmin_count = User.query.filter(
        User.role == UserRole.superadmin.value
    ).count()


    school_admin_count = User.query.filter(
        User.role == UserRole.school_admin.value
    ).count()


    branch_admin_count = User.query.filter(
        User.role == UserRole.branch_admin.value
    ).count()


    teacher_count = User.query.filter(
        User.role == UserRole.teacher.value
    ).count()


    student_count = User.query.filter(
        User.role == UserRole.student.value
    ).count()


    parent_count = User.query.filter(
        User.role == UserRole.parent.value
    ).count()


    # ========================================================
    # ONLINE USER COUNT
    # ========================================================
    #
    # User is considered online if last_active is within
    # the last 30 seconds.
    #
    # This is only for the statistics displayed on the
    # All Users page.
    # ========================================================

    online_threshold = (
        datetime.utcnow() - timedelta(seconds=30)
    )


    online_users = User.query.filter(
        User.status.is_(True),
        User.last_active.isnot(None),
        User.last_active >= online_threshold
    ).count()


    offline_users = (
        total_users - online_users
    )


    # ========================================================
    # RENDER
    # ========================================================

    return render_template(
        "backend/pages/users/all_users.html",

        # Users
        users=users,
        user=current_user,

        # Pagination
        pagination=pagination,
        page=page,
        per_page=per_page,

        # Current filters
        search=search,
        selected_role=role,
        selected_status=status,
        selected_verification=verification,

        # Role list
        roles=allowed_roles,

        # Global statistics
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        verified_users=verified_users,
        unverified_users=unverified_users,

        # Online statistics
        online_users=online_users,
        offline_users=offline_users,

        # Role statistics
        superadmin_count=superadmin_count,
        school_admin_count=school_admin_count,
        branch_admin_count=branch_admin_count,
        teacher_count=teacher_count,
        student_count=student_count,
        parent_count=parent_count
    )





@bp.route("/add-user", methods=["GET", "POST"])
@login_required
def add_user():

    if not current_user.is_superadmin():
        flash(
            "You do not have permission to add users.",
            "danger"
        )
        return redirect(url_for("main.dashboard"))

    allowed_roles = [
        UserRole.superadmin.value,
        UserRole.school_admin.value,
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value
    ]

    if request.method == "POST":

        # ============================================================
        # BASIC INFORMATION
        # ============================================================

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

        # ============================================================
        # PHONE
        # ============================================================

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

        # Build complete international phone number
        phone = None

        if phone_number:

            if phone_country:

                phone_country = (
                    phone_country
                    .replace(" ", "")
                    .replace("-", "")
                    .strip()
                )

                # Country code must start with +
                if not phone_country.startswith("+"):
                    phone_country = f"+{phone_country}"

                # Prevent duplicate +
                phone = f"{phone_country}{phone_number}"

            else:
                phone = phone_number

        # ============================================================
        # LOCATION
        # ============================================================

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

        # ============================================================
        # OTHER INFORMATION
        # ============================================================

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

        # ============================================================
        # PASSWORD
        # ============================================================

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ============================================================
        # STATUS / VERIFICATION
        # ============================================================

        status = (
            request.form.get(
                "status",
                "true"
            ).strip().lower()
            == "true"
        )

        is_verified = (
            request.form.get(
                "is_verified",
                "false"
            ).strip().lower()
            == "true"
        )

        # ============================================================
        # PHOTO SETTINGS
        # ============================================================

        photo_visibility = request.form.get(
            "photo_visibility",
            "everyone"
        ).strip().lower()

        # ============================================================
        # DATE OF BIRTH
        # ============================================================

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
                    roles=allowed_roles
                )

        # ============================================================
        # REQUIRED FIELD VALIDATION
        # ============================================================

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        if not email:

            flash(
                "Email address is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        if role not in allowed_roles:

            flash(
                "Invalid user role selected.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        # ============================================================
        # PASSWORD VALIDATION
        # ============================================================

        if not password:

            flash(
                "Password is required.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        if password != confirm_password:

            flash(
                "Password and confirm password do not match.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        # ============================================================
        # DUPLICATE USERNAME
        # ============================================================

        existing_username = User.query.filter(
            db.func.lower(User.username)
            == username.lower()
        ).first()

        if existing_username:

            flash(
                "This username is already registered.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        # ============================================================
        # DUPLICATE EMAIL
        # ============================================================

        existing_email = User.query.filter(
            db.func.lower(User.email)
            == email.lower()
        ).first()

        if existing_email:

            flash(
                "This email address is already registered.",
                "danger"
            )

            return render_template(
                "backend/pages/users/add_user.html",
                roles=allowed_roles
            )

        # ============================================================
        # PHOTO
        # ============================================================

        photo_file = request.files.get("photo")

        photo = None

        # Cloudinary upload can be added here.
        #
        # Example:
        #
        # if photo_file and photo_file.filename:
        #     upload_result = cloudinary.uploader.upload(
        #         photo_file,
        #         folder="users/profile"
        #     )
        #
        #     photo = upload_result.get("secure_url")

        # ============================================================
        # CREATE USER
        # ============================================================

        now = datetime.utcnow()

        new_user = User(

            username=username,

            email=email,

            fullname=fullname,

            phone=phone,

            country=country or None,

            city=city or None,

            state=state or None,

            address=address or None,

            bio=bio or None,

            role=role,

            status=status,

            is_verified=is_verified,

            photo=photo,

            photo_visibility=(
                photo_visibility
                if photo_visibility in [
                    "everyone",
                    "private"
                ]
                else "everyone"
            ),

            auth_status="logout",

            session_token=None,

            login_time=None,

            last_active=now,

            last_seen=now,

            gender=gender or None,

            dob=dob,

            pob=pob or None,

            created_at=now,

            updated_at=now
        )

        # ============================================================
        # PASSWORD HASH
        # ============================================================

        new_user.set_password(password)

        # ============================================================
        # SAVE
        # ============================================================

        try:

            db.session.add(new_user)

            db.session.commit()

            current_app.logger.info(
                "New user created successfully. "
                "User ID: %s, Username: %s, Role: %s, "
                "Created by Superadmin ID: %s",
                new_user.id,
                new_user.username,
                new_user.role,
                current_user.id
            )

            flash(
                f"User '{new_user.fullname}' "
                f"was created successfully.",
                "success"
            )

            return redirect(
                url_for("main.all_users")
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
                roles=allowed_roles
            )

    # ================================================================
    # GET
    # ================================================================

    return render_template(
        "backend/pages/users/add_user.html",
        roles=allowed_roles,
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

    # --------------------------------------------------------
    # PERMISSION
    # --------------------------------------------------------
    if not current_user.is_superadmin():
        flash(
            "You do not have permission to edit users.",
            "danger"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # FIND USER
    # --------------------------------------------------------
    user = User.query.get(user_id)

    if user is None:

        flash(
            "User not found.",
            "danger"
        )

        return redirect(
            url_for("main.all_users")
        )

    # --------------------------------------------------------
    # ALLOWED ROLES
    # --------------------------------------------------------
    allowed_roles = [
        UserRole.superadmin.value,
        UserRole.school_admin.value,
        UserRole.branch_admin.value,
        UserRole.teacher.value,
        UserRole.student.value,
        UserRole.parent.value
    ]

    # ========================================================
    # POST
    # ========================================================

    if request.method == "POST":

        # ----------------------------------------------------
        # FORM VALUES
        # ----------------------------------------------------

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

        phone = request.form.get(
            "phone",
            ""
        ).strip()

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

        bio = request.form.get(
            "bio",
            ""
        ).strip()

        role = request.form.get(
            "role",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        ).strip()

        confirm_password = request.form.get(
            "confirm_password",
            ""
        ).strip()

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        status = request.form.get(
            "status"
        ) in {
            "1",
            "true",
            "active",
            "on"
        }

        # ----------------------------------------------------
        # VERIFICATION
        # ----------------------------------------------------

        is_verified = request.form.get(
            "is_verified"
        ) in {
            "1",
            "true",
            "verified",
            "on"
        }

        # ====================================================
        # VALIDATION
        # ====================================================

        if not fullname:

            flash(
                "Full name is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

        if not email:

            flash(
                "Email address is required.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

        # ----------------------------------------------------
        # VALIDATE ROLE
        # ----------------------------------------------------

        if role not in allowed_roles:

            flash(
                "Invalid user role.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

        # ====================================================
        # USERNAME DUPLICATE CHECK
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
                "That username is already being used by another user.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

        # ====================================================
        # EMAIL DUPLICATE CHECK
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
                "That email address is already being used by another user.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

        # ====================================================
        # PREVENT SUPERADMIN FROM DISABLING THEMSELVES
        # ====================================================

        if user.id == current_user.id:

            if not status:

                flash(
                    "You cannot deactivate your own account.",
                    "warning"
                )

                return redirect(
                    url_for(
                        "main.edit_user",
                        user_id=user.id
                    )
                )

            if role != UserRole.superadmin.value:

                flash(
                    "You cannot remove your own superadmin role.",
                    "warning"
                )

                return redirect(
                    url_for(
                        "main.edit_user",
                        user_id=user.id
                    )
                )

        # ====================================================
        # PASSWORD VALIDATION
        # ====================================================

        if password:

            if len(password) < 8:

                flash(
                    "Password must contain at least 8 characters.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "main.edit_user",
                        user_id=user.id
                    )
                )

            if password != confirm_password:

                flash(
                    "The new passwords do not match.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "main.edit_user",
                        user_id=user.id
                    )
                )

            # -----------------------------------------------
            # PREVENT SAME PASSWORD
            # -----------------------------------------------

            if user.check_password(password):

                flash(
                    "The new password must be different from the current password.",
                    "warning"
                )

                return redirect(
                    url_for(
                        "main.edit_user",
                        user_id=user.id
                    )
                )

        # ====================================================
        # UPDATE USER
        # ====================================================

        user.fullname = fullname
        user.username = username
        user.email = email
        user.phone = phone or None

        user.country = country or None
        user.city = city or None
        user.state = state or None
        user.address = address or None

        user.bio = bio or None

        user.role = role
        user.status = status
        user.is_verified = is_verified

        # ----------------------------------------------------
        # UPDATE PASSWORD ONLY IF PROVIDED
        # ----------------------------------------------------

        if password:

            user.set_password(password)

            # Force logout from existing sessions
            user.auth_status = "logout"
            user.session_token = None
            user.login_time = None

        # ----------------------------------------------------
        # IF ACCOUNT DEACTIVATED
        # ----------------------------------------------------

        if not status:

            user.auth_status = "logout"
            user.session_token = None
            user.login_time = None

        # ----------------------------------------------------
        # UPDATED TIME
        # ----------------------------------------------------

        user.updated_at = datetime.utcnow()

        # ====================================================
        # SAVE
        # ====================================================

        try:

            db.session.commit()

            flash(
                f"{user.fullname} has been updated successfully.",
                "success"
            )

            return redirect(
                url_for("main.all_users")
            )

        except Exception as e:

            db.session.rollback()

            current_app.logger.exception(
                "Error updating user ID %s: %s",
                user.id,
                e
            )

            flash(
                "Unable to update user. Please try again.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.edit_user",
                    user_id=user.id
                )
            )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        "backend/pages/users/edit_user.html",
        user=user,
        roles=allowed_roles
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




