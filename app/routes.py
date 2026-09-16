from datetime import datetime
from functools import wraps
import os
import re
import secrets
from uuid import uuid4
import uuid
import bcrypt
from flask import Blueprint, abort, current_app, flash, json, redirect, render_template, request, url_for
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












#---------------------------------------
#---- Route: Ending |  Logout Sections ----
#---------------------------------------
@bp.route("/logout")
@login_required
def logout():
  
    logout_user()

    flash("You have been logged out.", "info")
    return redirect(url_for("main.login"))
 
 




