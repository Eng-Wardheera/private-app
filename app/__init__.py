import os
from datetime import datetime

import pytz
from dotenv import load_dotenv

from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# ============================================================

# LOAD ENVIRONMENT VARIABLES

# ============================================================

load_dotenv()

# ============================================================

# EXTENSIONS

# ============================================================

db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()
migrate = Migrate()

# ============================================================

# GLOBAL CONFIGURATION

# ============================================================

ALLOWED_EXTENSIONS = {
"png",
"jpg",
"jpeg"
}

EAT = pytz.timezone("Africa/Nairobi")

# ============================================================

# CREATE APPLICATION

# ============================================================

def create_app():

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )


    # ========================================================
    # SECRET KEY
    # ========================================================

    secret_key = os.getenv("SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY is missing from your .env file."
        )

    app.config["SECRET_KEY"] = secret_key


    # ========================================================
    # NEON POSTGRESQL
    # ========================================================

    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is missing from your .env file."
        )


    # --------------------------------------------------------
    # PostgreSQL URL compatibility
    # --------------------------------------------------------

    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://",
            "postgresql://",
            1
        )


    # --------------------------------------------------------
    # SQLAlchemy database configuration
    # --------------------------------------------------------

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


    # ========================================================
    # SQLALCHEMY ENGINE OPTIONS
    # ========================================================

    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "connect_args": {
            "connect_timeout": 10
        }
    }


    # ========================================================
    # FLASK SETTINGS
    # ========================================================

    app.config["DEBUG"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False


    # ========================================================
    # PORT
    # ========================================================

    port = int(
        os.getenv(
            "PORT",
            "7000"
        )
    )


    # ========================================================
    # FRONTEND ORIGIN
    # ========================================================

    frontend_origin = os.getenv(
        "FRONTEND_ORIGIN",
        f"http://127.0.0.1:{port}"
    )


    # ========================================================
    # CORS
    # ========================================================

    CORS(
        app,
        resources={
            r"/*": {
                "origins": frontend_origin
            }
        },
        supports_credentials=True
    )


    # ========================================================
    # INITIALIZE EXTENSIONS
    # ========================================================

    db.init_app(app)

    mail.init_app(app)

    login_manager.init_app(app)

    migrate.init_app(
        app,
        db
    )


    # ========================================================
    # LOGIN MANAGER
    # ========================================================

    login_manager.login_view = "main.login"

    login_manager.login_message = (
        "Please login to access this page."
    )

    login_manager.login_message_category = "warning"


    # ========================================================
    # IMPORT MODELS
    # ========================================================

    from app.model import User


    # ========================================================
    # LOGIN USER LOADER
    # ========================================================

    @login_manager.user_loader
    def load_user(user_id):

        try:

            return db.session.get(
                User,
                int(user_id)
            )

        except (
            ValueError,
            TypeError
        ):

            return None


    # ========================================================
    # IMPORT BLUEPRINT
    # ========================================================

    from app.routes import bp


    # ========================================================
    # REGISTER BLUEPRINT
    # ========================================================

    app.register_blueprint(bp)


    # ========================================================
    # DATETIME TEMPLATE FILTER
    # ========================================================

    @app.template_filter("datetime")
    def format_datetime(value):

        if not value:
            return ""

        if isinstance(value, datetime):

            return value.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        return value


    # ========================================================
    # GLOBAL TEMPLATE VARIABLES
    # ========================================================

    @app.context_processor
    def inject_globals():

        return {
            "EAT": EAT
        }


    # ========================================================
    # DATABASE TEST ROUTE
    # ========================================================

    @app.get("/db-test")
    def database_test():

        from sqlalchemy import text

        try:

            result = db.session.execute(
                text("SELECT version();")
            )

            version = result.scalar()


            return {
                "status": "success",
                "database": "Neon PostgreSQL",
                "message": "Database connection successful.",
                "version": version
            }


        except Exception as e:

            db.session.rollback()

            return {
                "status": "error",
                "database": "Neon PostgreSQL",
                "message": str(e)
            }, 500


    # ========================================================
    # HEALTH CHECK
    # ========================================================

    @app.get("/health")
    def health():

        return {
            "status": "ok",
            "application": "private-grading"
        }


    # ========================================================
    # RETURN APP
    # ========================================================

    return app

