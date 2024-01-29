# Import necessary modules
from flask import render_template, redirect, url_for, request, session, flash
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import pyotp
import logging
import os

# Import the Flask app instance
from app import app

# Flag to track if the first request has been processed
app.first_request_processed = False

# Load environment variables from the .env file
load_dotenv()

# Initialize Flask-Bcrypt with the Flask app for password hashing
bcrypt = Bcrypt(app)

# Configure Flask app with necessary environment variables
app.config.update(
    SECRET_KEY=os.getenv("YOUR_SECRET_KEY"),
    SQLALCHEMY_DATABASE_URI=f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_DATABASE')}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
)

# Initialize Flask-SQLAlchemy
db = SQLAlchemy(app)
mail = Mail(app)
otp = pyotp.TOTP(os.getenv("otp_key"), interval=300)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Define User model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_activated = db.Column(db.Boolean, default=False)


def initialize_table():
    """
    Initialize the 'users' table.
    """
    try:
        db.create_all()
        app.first_request_processed = True
        logger.info("Initialized 'users' table.")
    except Exception as e:
        logger.error(f"Error initializing 'users' table: {str(e)}")


def add_user(username, email, password):
    """
    Add a new user to the 'users' table.
    """
    if not username or not password:
        logger.error("Invalid username or password provided.")
        return False

    try:
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        logger.info(f"User '{username}' added to 'users' table.")
        return True
    except Exception as e:
        logger.error(f"Error adding user to 'users' table: {str(e)}")
        return False


def get_user_by_credentials(email_or_name, password):
    """
    Retrieve a user by credentials from the 'users' table.
    """
    try:
        user = User.query.filter(
            (User.email == email_or_name) | (User.username == email_or_name)
        ).first()

        if user and bcrypt.checkpw(
            password.encode("utf-8"), user.password.encode("utf-8")
        ):
            logger.info(f"User '{user.username}' retrieved from 'users' table.")
            return user
        else:
            logger.warning("Invalid credentials provided.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving user from 'users' table: {str(e)}")
        return None


def activate_user(email):
    """
    Activate a user for the specified email.
    """
    try:
        user = User.query.filter_by(email=email).first()

        if user:
            user.is_activated = True
            db.session.commit()
            logger.info(f"User '{user.username}' activated in 'users' table.")
            return True
        else:
            logger.warning(f"User with email '{email}' not found.")
            return None
    except Exception as e:
        logger.error(f"Error activating user in 'users' table: {str(e)}")
        return None


def get_email(username):
    """
    Retrieve the email associated with the given username from the Database.
    """
    try:
        user = User.query.filter_by(username=username).first()

        if user:
            logger.info(f"Email for user '{username}' retrieved from 'users' table.")
            return user.email
        else:
            logger.warning(f"User '{username}' not found in 'users' table.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving email from 'users' table: {str(e)}")
        return None


def sendOTP(email):
    """
    Send a one-time password (OTP) for email verification.

    Returns:
        bool: True if OTP is sent successfully, False otherwise.
    """
    try:
        totp_value = otp.now()
        message = Message("Your OTP for Verification", recipients=[email])
        message.body = f"Your OTP is: {totp_value}"
        mail.send(message)
        logger.info(f"OTP sent successfully to {email}.")
        return True
    except Exception as e:
        logger.error(f"Error sending OTP to {email}: {str(e)}")
        return False


@app.route("/")
def home():
    """
    Define the route for the home page.

    If the user is not logged in, render the home page template.
    If the user is logged in, redirect to the profile page.

    Returns:
        render_template or redirect: Render the home page or redirect to the profile page.
    """
    user = session.get("user")

    if user is None:
        return render_template("home.html")

    return redirect(url_for("profile"))


@app.before_request
def check_first_request():
    """
    Define a function to run before each request to check and initialize the 'users' table.

    This function calls initialize_table to check and initialize the 'users' table
    before processing each request.

    Returns:
        None
    """
    initialize_table()


@app.route("/register", methods=["POST", "GET"])
def register():
    """
    Define the route for user registration.

    If the request method is POST, validate the registration form, add the user,
    generate and send OTP, and redirect to the user_validation route.
    If the request method is GET, render the registration page.

    Returns:
        render_template or redirect: Render the registration page or redirect to user_validation.
    """
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        if add_user(username, email, hashed_password):
            # Generate OTP and store it in session
            session["email"] = email
            # Send the email
            sendOTP(email)

            return redirect(url_for("user_validation"))
        else:
            flash("Registration failed.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/user_validation", methods=["POST", "GET"])
def user_validation():
    """
    Define the route for user validation.

    If the request method is POST, validate the OTP, activate the user,
    set the user in session, and redirect to the profile page.
    If the request method is GET, render the user validation page.

    Returns:
        render_template or redirect: Render the user validation page or redirect to profile.
    """
    email = session.get("email")

    if email is None:
        flash("Error! Please register again.", "error")
        return redirect(url_for("register"))

    if request.method == "POST":
        user_otp = request.form.get("otp")

        current_otp = otp.now()

        if user_otp == current_otp:
            if activate_user(email):
                flash("Registration successful.", "success")
                session["user"] = email
                session.pop("email", None)
                return redirect(url_for("profile"))
            else:
                flash("Error!", "error")
                return redirect(url_for("user_validation"))
        else:
            flash("Invalid OTP.", "error")
            return redirect(url_for("user_validation"))

    return render_template("user_validation.html")


@app.route("/resend_otp", methods=["GET"])
def resend_otp():
    """
    Add a new route to handle the resend_otp functionality.

    Resend the OTP and flash a message indicating success.
    Redirect to the user_validation route.

    Returns:
        redirect: Redirect to user_validation route.
    """
    email = session.get("email")

    if email is None:
        flash("Error! Please register again.", "error")
        return redirect(url_for("register"))

    # Attempt to resend the OTP
    if sendOTP(email):
        flash("New OTP sent successfully.", "info")
        return redirect(url_for("user_validation"))
    else:
        flash("Error resending OTP. Please try again later.", "error")
        # Delete the user from the database
        user = User.query.filter_by(email=email).first()
        if user:
            db.session.delete(user)
            db.session.commit()
        return redirect(url_for("register"))


@app.route("/login", methods=["POST", "GET"])
def login():
    """
    Define the route for user login.

    If the request method is POST, validate login credentials,
    handle account activation, and redirect to profile or user_validation.
    If the request method is GET, render the login page.

    Returns:
        render_template or redirect: Render the login page or redirect to profile or user_validation.
    """
    if request.method == "POST":
        email_or_name = request.form.get("username")
        password = request.form.get("password")

        result = get_user_by_credentials(email_or_name, password)

        if result:
            if result[0][4] == 1:
                # Setting the user_id in session during login
                session["user"] = email_or_name
                return redirect(url_for("profile"))
            else:
                session["email"] = (
                    get_email(email_or_name)
                    if "@" not in email_or_name
                    else email_or_name
                )
                sendOTP(session.get("email"))
                flash("Account not activated. Please verify your email.", "info")
                return redirect(url_for("user_validation"))

        flash("Login failed.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/profile")
def profile():
    """
    Define the route for the user profile.

    If the user is not logged in, redirect to the login page.
    If the user is logged in, retrieve all users and render the profile page.

    Returns:
        redirect or render_template: Redirect to login or render the profile page.
    """
    user = session.get("user")

    if user is None:
        return redirect(url_for("login"))

    result = User.query.all()

    if result:
        return render_template("profile.html", result=result)

    flash("Enter valid Username and Password", "error")
    return redirect(url_for("home"))
