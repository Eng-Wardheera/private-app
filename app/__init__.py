import os
from datetime import datetime

import cloudinary
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
# CLOUDINARY CONFIGURATION
# ============================================================


cloudinary.config(
    cloud_name="dzhairplt",
    api_key="597738172555213",
    api_secret="x4UXHFVqzH4Oq_MeBV4VGYoZHns",
    secure=True
)




# ============================================================
# SOMALIA REGIONS & CITIES
# GLOBAL TEMPLATE VARIABLE
# ============================================================

SOMALIA_REGIONS = {

    "Awdal": [
        "Borama",
        "Baki",
        "Lughaya",
        "Zeila",
        "Dilla",
        "Quljeed",
        "Arabsiyo",
        "Ras Kamboni"
    ],

    "Woqooyi Galbeed": [
        "Hargeisa",
        "Berbera",
        "Gabiley",
        "Burao",
        "Sheikh",
        "Wajaale",
        "Baligubadle",
        "Allaybaday"
    ],

    "Sanaag": [
        "Erigavo",
        "Ceerigaabo",
        "Badhan",
        "Dhahar",
        "Las Qoray",
        "Hingalol",
        "Garadag",
        "Maydh"
    ],

    "Sool": [
        "Las Anod",
        "Laascaanood",
        "Taleex",
        "Xudun",
        "Caynabo",
        "Boocame",
        "Daraasalaam",
        "Widhwidh"
    ],

    "Togdheer": [
        "Burao",
        "Oodweyne",
        "Buhoodle",
        "Sheikh",
        "Duruqsi",
        "Qoryaale"
    ],

    "Bari": [
        "Bosaso",
        "Qardho",
        "Iskushuban",
        "Caluula",
        "Bandar Beyla",
        "Ufeyn",
        "Carmo",
        "Xaafuun",
        "Bargaal"
    ],

    "Nugaal": [
        "Garowe",
        "Garoowe",
        "Eyl",
        "Burtinle",
        "Dangorayo",
        "Godob Jiraan",
        "Galkayo"
    ],

    "Mudug": [
        "Galkayo",
        "Gaalkacyo",
        "Hobyo",
        "Harardhere",
        "Jariiban",
        "Goldogob",
        "Bandiiradley",
        "Saaxo"
    ],

    "Galguduud": [
        "Dhuusamareeb",
        "Dhusamareb",
        "Cadaado",
        "Guriceel",
        "Ceel Buur",
        "Ceel Dheer",
        "Balanbale",
        "Cabudwaaq",
        "Godinlabe"
    ],

    "Hiiraan": [
        "Beledweyne",
        "Bulo Burto",
        "Jalalaqsi",
        "Buq Aqable",
        "Mataban",
        "Maxaas",
        "Halgan"
    ],

    "Shabeellaha Dhexe": [
        "Jowhar",
        "Balcad",
        "Cadale",
        "Mahadaay",
        "Adan Yabal",
        "Warsheikh",
        "Runirgood"
    ],

    "Banaadir": [
        "Mogadishu",
        "Muqdisho",
        "Hodan",
        "Wadajir",
        "Warta Nabadda",
        "Yaqshid",
        "Kaaraan",
        "Dayniile",
        "Dharkenley",
        "Hamar Jajab",
        "Hamar Weyne",
        "Shibis",
        "Boondheere",
        "Cabdicasiis",
        "Shangaani",
        "Howlwadaag",
        "Xamar Jabjab"
    ],

    "Shabeellaha Hoose": [
        "Marka",
        "Afgooye",
        "Wanlaweyn",
        "Qoryooley",
        "Baraawe",
        "Awdheegle",
        "Kurtunwaarey",
        "Sablale",
        "Sablaale",
        "Lafoole"
    ],

    "Bay": [
        "Baidoa",
        "Baydhabo",
        "Burhakaba",
        "Diinsoor",
        "Qansax Dheere",
        "Buur Hakaba",
        "Bardaale"
    ],

    "Bakool": [
        "Hudur",
        "Xudur",
        "Wajid",
        "Tiyeglow",
        "Rab Dhuure",
        "Ceel Barde",
        "Yeed"
    ],

    "Gedo": [
        "Garbaharey",
        "Luuq",
        "Doolow",
        "Bardhere",
        "Beled Xaawo",
        "Ceel Waaq",
        "Doolow Ado",
        "Buurdhuubo"
    ],

    "Jubbada Dhexe": [
        "Bu'aale",
        "Buaale",
        "Jilib",
        "Saakow",
        "Salagle"
    ],

    "Jubbada Hoose": [
        "Kismayo",
        "Kismaayo",
        "Afmadow",
        "Jamaame",
        "Badhaadhe",
        "Dhobley",
        "Tabta"
    ]
}




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

    # ============================================================
    # GLOBAL CONTEXT PROCESSOR
    # ============================================================

    import pycountry


    def get_all_countries():
        """
        Return all countries from pycountry as a sorted list.
        """
        countries = []

        for country in pycountry.countries:
            countries.append({
                "code": country.alpha_2,
                "alpha3": getattr(country, "alpha_3", ""),
                "name": country.name
            })

        return sorted(
            countries,
            key=lambda x: x["name"].lower()
        )


    ALL_COUNTRIES = get_all_countries()


    @app.context_processor
    def inject_global_variables():
        return {
            "somalia_regions": SOMALIA_REGIONS,
            "all_countries": ALL_COUNTRIES
        }





    # ========================================================
    # RETURN APP
    # ========================================================

    return app

