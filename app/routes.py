# Import necessary modules
import logging
from datetime import datetime, timedelta, timezone
import os
import secrets

from flask import render_template, redirect, url_for, request, session, flash
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import pyotp

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
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
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
    """
    User model representing the 'users' table in the database.

    Attributes:
        id (int): Primary key for the User model.
        username (str): User's username, unique and not nullable.
        email (str): User's email, unique and not nullable.
        password (str): User's password, not nullable.
        is_activated (bool): Flag indicating whether the user is activated, default is False.
    """

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
    # Check if the first request has been processed to avoid repeated table creation
    if not app.first_request_processed:
        try:
            # Create the 'users' table
            db.create_all()
            app.first_request_processed = True
            logger.info("Initialized 'users' table.")
        except Exception as e:
            logger.error(f"Error initializing 'users' table: {e}")


def add_user(username, email, password):
    """
    Add a new user to the 'users' table.

    Args:
        username (str): The username of the user.
        email (str): The email of the user.
        password (str): The hashed password of the user.

    Returns:
        bool: True if the user is successfully added, False otherwise.
    """
    # Validate username and password
    if not username or not password:
        logger.error("Invalid username or password provided.")
        return False

    try:
        # Create a new user instance and add it to the 'users' table
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        logger.info(f"User '{username}' added to 'users' table.")
        return True
    except Exception as e:
        logger.error(f"Error adding user to 'users' table: {e}")
        return False


def get_user_by_credentials(email_or_name, password):
    """
    Retrieve a user by credentials from the 'users' table.

    Args:
        email_or_name (str): The email or username of the user.
        password (str): The password provided for authentication.

    Returns:
        User or None: The user object if valid credentials, None otherwise.
    """
    try:
        # Query the 'users' table based on email or username
        user = User.query.filter(
            (User.email == email_or_name) | (User.username == email_or_name)
        ).first()

        if user and bcrypt.check_password_hash(user.password, password):
            logger.info(f"User '{user.username}' retrieved from 'users' table.")
            return user
        else:
            logger.warning("Invalid credentials provided.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving user from 'users' table: {e}")
        return None


def activate_user(email):
    """
    Activate a user for the specified email.

    Args:
        email (str): The email of the user to be activated.

    Returns:
        bool or None: True if the user is activated, None if the user is not found.
    """
    try:
        # Query the 'users' table and activate the user
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
        logger.error(f"Error activating user in 'users' table: {e}")
        return None


def get_email(username):
    """
    Retrieve the email associated with the given username from the Database.

    Args:
        username (str): The username of the user.

    Returns:
        str or None: The email associated with the username, None if the user is not found.
    """
    try:
        # Query the 'users' table to get the email for the given username
        user = User.query.filter_by(username=username).first()

        if user:
            logger.info(f"Email for user '{username}' retrieved from 'users' table.")
            return user.email
        else:
            logger.warning(f"User '{username}' not found in 'users' table.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving email from 'users' table: {e}")
        return None


def send_otp(email):
    """
    Send a one-time password (OTP) for email verification.

    Args:
        email (str): The email address to which the OTP will be sent.

    Returns:
        bool: True if the OTP is sent successfully, False otherwise.
    """
    try:
        # Generate a one-time password (OTP)
        totp_value = otp.now()
        message = Message("Your OTP for Verification", recipients=[email])
        message.body = f"Your OTP is: {totp_value}"
        mail.send(message)
        logger.info(f"OTP sent successfully to {email}.")
        return True
    except Exception as e:
        logger.error(f"Error sending OTP to {email}: {e}")
        return False


# Function to generate a secure token
def generate_token():
    """
    Generate a secure token.

    Returns:
        str: A securely generated token.
    """
    return secrets.token_urlsafe(32)


# Function to send a password reset email
def send_password_reset_email(email, token):
    """
    Send a password reset email containing the reset link with the token.
    You can customize this function based on your email service and template.

    Args:
        email (str): The email address of the user.
        token (str): The unique token for password reset.

    Returns:
        bool: True if the email is sent successfully, False otherwise.
    """
    # Construct the reset link with the token
    reset_link = url_for("reset_password", token=token, _external=True)

    try:
        # Create a message with the reset link
        message = Message("Password Reset", recipients=[email])
        message.body = f"Click the following link to reset your password: {reset_link}"

        # Send the email
        mail.send(message)
        logger.info(f"Password reset email sent successfully to {email}.")
        return True
    except Exception as e:
        logger.error(f"Error sending password reset email to {email}: {e}")
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

    If the request method is POST, validate the registration form, check for an existing user,
    add the user, generate and send OTP, and redirect to the user_validation route.
    If the request method is GET, render the registration page.

    Returns:
        render_template or redirect: Render the registration page or redirect to user_validation.
    """
    # Handle POST request for user registration
    if request.method == "POST":
        # Retrieve user registration form data
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Check if a user with the provided email already exists
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("User with this email already exists. Please login.", "error")
            return redirect(url_for("login"))

        # Attempt to add the user to the database
        if add_user(username, email, hashed_password):
            # Generate OTP and store it in the session
            session["email"] = email

            # Send the email with OTP
            if send_otp(email):
                flash("OTP sent successfully.", "info")
                return redirect(url_for("user_validation"))
            else:
                flash("Error sending OTP. Please try again later.", "error")
                return redirect(url_for("register"))
        else:
            flash("Registration failed.", "error")
            return redirect(url_for("register"))

    # Render the registration page for GET requests
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
    # Retrieve the email from the session
    email = session.get("email")

    # Check if the email is not present in the session (error condition)
    if email is None:
        flash("Error! Please register again.", "error")
        return redirect(url_for("register"))

    # Handle POST request for OTP validation
    if request.method == "POST":
        # Retrieve the OTP entered by the user in the form
        user_otp = request.form.get("otp")

        # Get the current OTP using the TOTP generator
        current_otp = otp.now()

        # Check if the entered OTP matches the current OTP
        if user_otp == current_otp:
            # If OTP is valid, activate the user and set the user in session
            if activate_user(email):
                flash("Registration successful.", "success")
                session["user"] = email
                session.pop("email", None)  # Remove the email from session
                return redirect(url_for("profile"))
            else:
                flash("Error activating user.", "error")
                return redirect(url_for("user_validation"))
        else:
            flash("Invalid OTP.", "error")
            return redirect(url_for("user_validation"))

    # Render the user validation page for GET requests
    return render_template("user_validation.html")


@app.route("/resend_otp", methods=["GET"])
def resend_otp():
    """
    Define a route to handle the resend_otp functionality.

    Resend the OTP and flash a message indicating success.
    Redirect to the user_validation route.

    Returns:
        redirect: Redirect to user_validation route.
    """
    # Retrieve the user's email from the session
    email = session.get("email")

    # Check if the email is not available in the session
    if email is None:
        flash("Error! Please register again.", "error")
        return redirect(url_for("register"))

    # Attempt to resend the OTP
    if send_otp(email):
        flash("New OTP sent successfully.", "info")
        return redirect(url_for("user_validation"))
    else:
        flash("Error resending OTP. Please try again later.", "error")

        # Delete the user from the database if email sending fails
        user = User.query.filter_by(email=email).first()
        if user:
            db.session.delete(user)
            db.session.commit()

        # Redirect to the registration page in case of failure
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

    # Check if the user is already logged in
    user = session.get("user")

    if user:
        return redirect(url_for("profile"))

    # Process POST request for login
    if request.method == "POST":
        email_or_name = request.form.get("username")
        password = request.form.get("password")

        # Retrieve user by credentials
        user = get_user_by_credentials(email_or_name, password)

        if user:
            if user.is_activated:
                # Setting the user_id in session during login
                session["user"] = user.username
                return redirect(url_for("profile"))
            else:
                # If the account is not activated, send OTP for validation
                session["email"] = user.email
                send_otp(session.get("email"))
                flash("Account not activated. Please verify your email.", "info")
                return redirect(url_for("user_validation"))

        # Flash a message for a failed login attempt
        flash("Login failed. Please check your credentials.", "error")
        return redirect(url_for("login"))

    # Render the login page for GET request
    return render_template("login.html")


@app.route("/forgot_password", methods=["POST", "GET"])
def forgot_password():
    """
    Define the route for handling password reset requests.

    If the request method is POST, validate the email or username,
    generate a unique token, store the token and user information in session,
    send a password reset email, and redirect to the login page.
    If the request method is GET, render the forgot password page.

    Returns:
        render_template or redirect: Render the forgot password page or redirect to login.
    """
    # Process POST request for password reset
    if request.method == "POST":
        email_or_name = request.form.get("email")

        # Assume you have a User model with an email field
        user = User.query.filter(
            (User.email == email_or_name) | (User.username == email_or_name)
        ).first()

        if user:
            # Generate a unique token with a 15-minute expiration
            token = generate_token()

            # Store the token and user information (e.g., user ID) in a secure way
            session["reset_token"] = token
            session["reset_token_expiration"] = datetime.utcnow() + timedelta(
                minutes=15
            )
            session["user_id_to_reset"] = user.id
            session.permanent = True  # Set the session to be permanent

            # Send the password reset email
            if send_password_reset_email(user.email, token):
                flash(
                    "Password reset email sent successfully. Check your inbox.",
                    "success",
                )
                return redirect(url_for("login"))
            else:
                flash(
                    "Error sending password reset email. Please try again later.",
                    "error",
                )
                return redirect(url_for("forgot_password"))
        else:
            # Flash a message if no account found with the provided email or username
            flash("No account found with that email or username.", "warning")
            return redirect(url_for("forgot_password"))

    # Render the forgot password page for GET request
    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """
    Route to handle password reset. Validates the token and allows the user to reset their password.

    If the token is valid, retrieve the user ID associated with the token,
    update the user's password based on the form input, and redirect to the login page.
    If the token is invalid or expired, flash an error message and redirect to the forgot password page.

    Returns:
        render_template or redirect: Render the reset password page or redirect to forgot password.
    """
    # Validate the token and check its expiration
    if token == session.get("reset_token"):
        expiration_timestamp = session.get("reset_token_expiration")

        # Check if the token has expired
        if (
            expiration_timestamp
            and datetime.utcnow().replace(tzinfo=timezone.utc) > expiration_timestamp
        ):
            flash("Token has expired. Please request a new password reset.", "error")
            return redirect(url_for("forgot_password"))

        # Retrieve the user ID associated with the token
        user_id = session.get("user_id_to_reset")
        user = User.query.get(user_id)

        if user:
            # Process the POST request to update the password
            if request.method == "POST":
                # Update the user's password based on the form input
                new_password = request.form.get("new_password")
                # Update the user's password in the database
                # This step depends on your User model and database setup
                user.password = bcrypt.generate_password_hash(new_password).decode(
                    "utf-8"
                )
                db.session.commit()

                # Clear the session variables after successful password reset
                session.pop("reset_token", None)
                session.pop("reset_token_expiration", None)
                session.pop("user_id_to_reset", None)

                flash(
                    "Password reset successful. You can now log in with your new password.",
                    "success",
                )
                return redirect(url_for("login"))

            # Render the reset password page for GET request
            return render_template("reset_password.html", token=token)

    # Flash an error message for invalid or expired token and redirect to forgot password
    flash("Invalid or expired token. Please try again.", "error")
    return redirect(url_for("forgot_password"))


@app.route("/profile")
def profile():
    """
    Define the route for the user profile.

    If the user is not logged in, redirect to the login page.
    If the user is logged in, retrieve all users and render the profile page.

    Returns:
        redirect or render_template: Redirect to login or render the profile page.
    """
    # Check if the user is logged in
    user = session.get("user")

    if user is None:
        # Redirect to the login page if the user is not logged in
        return redirect(url_for("login"))

    # Retrieve all users from the database
    result = User.query.all()

    if result:
        # Render the profile page with the user information
        return render_template("profile.html", result=result)

    # Flash an error message and redirect to the home page if no users are found
    flash("Enter valid Username and Password", "error")
    return redirect(url_for("home"))
