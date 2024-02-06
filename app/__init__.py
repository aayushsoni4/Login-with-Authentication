from flask import Flask
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

import pyotp
import os
import logging

# Create the Flask app instance
app = Flask(__name__)

# Load configuration from config.py
app.config.from_object("config.Config")

# Initialize Flask-SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Mail for sending emails
mail = Mail(app)

# Initialize Flask-Bcrypt with the Flask app for password hashing
bcrypt = Bcrypt(app)

# Initialize the TOTP generator with the OTP key from the environment variables
otp = pyotp.TOTP(os.getenv("otp_key"), interval=300)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import blueprints
from app.main.routes import main_bp
from app.auth.routes import auth_bp

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp, url_prefix="/auth")

# Create tables in the database if necessary
with app.app_context():
    db.create_all()

# Import User model
from app.models import User


# User loader function
@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login user loader callback function.
    """
    return User.query.get(int(user_id))
