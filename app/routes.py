from datetime import datetime
from functools import wraps
import os
import re
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

  
    return render_template("backend/pages/auth/login.html")
 
 
# ================= REGISTER =================
@bp.route("/register", methods=["GET", "POST"])
def register():

    return render_template("backend/pages/auth/register.html")


@bp.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "backend/home/index.html",

    
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
 
 




