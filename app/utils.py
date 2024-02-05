# Import necessary modules
from flask_bcrypt import Bcrypt
import pyotp
import os
from dotenv import load_dotenv
import logging
import secrets
from flask_mail import Mail, Message
from flask import url_for

# Import Flask app instance, database, and User model
from app import app, db, mail
from app.models import User

# Load environment variables from the .env file
load_dotenv()

# Initialize Flask-Bcrypt with the Flask app for password hashing
bcrypt = Bcrypt(app)

# Initialize the TOTP generator with the OTP key from the environment variables
otp = pyotp.TOTP(os.getenv("otp_key"), interval=300)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
    reset_link = url_for("auth.reset_password", token=token, _external=True)

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
