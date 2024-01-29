# Import necessary modules
from flask import render_template, redirect, url_for, request, session, flash
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
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
    DB_USER=os.getenv("DB_USER"),
    DB_PASSWORD=os.getenv("DB_PASSWORD"),
    DB_HOST=os.getenv("DB_HOST"),
    DB_PORT=os.getenv("DB_PORT"),
    DB_DATABASE=os.getenv("DB_DATABASE"),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
)

# Initialize Flask-Mail
mail = Mail(app)
otp = pyotp.TOTP(os.getenv("otp_key"), interval=300)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the SQLAlchemy engine using the configured database URI
db_uri = f"mysql+mysqlconnector://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_DATABASE']}"
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
engine = create_engine(db_uri)


def create_table_if_not_exists():
    """
    Create the 'users' table if it doesn't exist.

    This function uses the configured database connection to create the 'users' table
    with specific columns if it does not already exist.

    Returns:
        None
    """
    with engine.connect() as connection:
        try:
            # SQL query to create the 'users' table
            query = text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    is_activated TINYINT DEFAULT 0
                );
            """
            )
            # Execute the query
            connection.execute(query)
        except Exception as e:
            # Log an error message if there's an issue creating the table
            logger.error(f"Error creating table: {str(e)}")


def initialize_table():
    """
    Initialize the 'users' table.

    This function initializes the 'users' table by calling create_table_if_not_exists
    if the first request has not been processed yet.

    Returns:
        None
    """
    if not app.first_request_processed:
        create_table_if_not_exists()
        app.first_request_processed = True


def add_user(username, email, password):
    """
    Add a new user to the 'users' table.

    Args:
        username (str): The username of the new user.
        email (str): The email of the new user.
        password (str): The hashed password of the new user.

    Returns:
        bool: True if the user is successfully added, False otherwise.
    """
    if not username or not password:
        logger.error("Invalid username or password provided.")
        return False
    with engine.connect() as connection:
        try:
            # SQL query to insert a new user into the 'users' table
            query = text(
                "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)"
            )
            # Execute the query with provided parameters
            connection.execute(
                query, {"username": username, "email": email, "password": password}
            )
            # Commit the changes to the database
            connection.commit()
            return True
        except Exception as e:
            # Log an error message if there's an issue adding a user
            logger.error(f"Error adding user: {str(e)}")
            return False


def get_user_by_credentials(email_or_name, password):
    """
    Retrieve a user by credentials from the 'users' table.

    Args:
        email_or_name (str): The email or username of the user.
        password (str): The password of the user.

    Returns:
        list or None: A list of user records if credentials are valid, None otherwise.
    """
    with engine.connect() as connection:
        try:
            # SQL query to retrieve a user by email or username
            query = text(
                "SELECT * FROM users WHERE (email = :input) OR (username = :input)"
            )
            # Execute the query with provided parameters
            result = connection.execute(query, {"input": email_or_name}).fetchall()
            if result:
                # Check if the provided password matches the stored hashed password
                if bcrypt.checkpw(
                    password.encode("utf-8"), result[0][3].encode("utf-8")
                ):
                    return result
                else:
                    return None
            return result
        except Exception as e:
            # Log an error message if there's an issue retrieving a user
            logger.error(f"Error retrieving user: {str(e)}")
            return None


def get_all_users():
    """
    Retrieve all users from the 'users' table.

    Returns:
        list or None: A list of user records, each represented as a tuple.
                      Returns None if there's an issue retrieving users.
    """
    with engine.connect() as connection:
        try:
            # SQL query to retrieve all users from the 'users' table
            query = text("SELECT * FROM users")
            # Execute the query
            result = connection.execute(query).fetchall()
            return result
        except Exception as e:
            # Log an error message if there's an issue retrieving all users
            logger.error(f"Error retrieving users: {str(e)}")
            return None


def activate_user(email):
    """
    Activate a user for the specified email.

    Args:
        email (str): The email associated with the user to be activated.

    Returns:
        bool or None: True if the user is successfully activated, None otherwise.
    """
    with engine.connect() as connection:
        try:
            # SQL query to update the 'is_activated' column for a user
            query = text("UPDATE users SET is_activated = 1 WHERE email = :email")
            # Execute the query with provided parameters
            connection.execute(query, {"email": email})
            # Commit the changes to the database
            connection.commit()
            return True
        except Exception as e:
            # Log an error message if there's an issue activating a user
            logger.error(f"Error activating user: {str(e)}")
            return None


def get_email(username):
    """
    Retrieve the email associated with the given username from the Database.

    Args:
        username (str): The username of the user.

    Returns:
        str or None: The email associated with the username.
                     Returns None if the email is not found.
    """
    with engine.connect() as connection:
        try:
            # SQL query to retrieve the email associated with a username
            query = text("SELECT email FROM users WHERE username = :username")
            # Execute the query with provided parameters
            email = connection.execute(query, {"username": username}).fetchone()
            return email[0]
        except Exception as e:
            # Log an error message if there's an issue retrieving the email
            logger.error(f"Email not found!: {str(e)}")
            return None


def sendOTP(email):
    """
    Send a one-time password (OTP) for email verification.

    Args:
        email (str): The email to which the OTP will be sent.

    Returns:
        None
    """
    # Generate a new OTP
    totp_value = otp.now()
    # Create a message with the OTP and send it to the specified email
    message = Message("Your OTP for Verification", recipients=[email])
    message.body = f"Your OTP is: {totp_value}"
    mail.send(message)


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

    # Send the new OTP
    sendOTP(email)

    flash("New OTP sent successfully.", "info")
    return redirect(url_for("user_validation"))


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
    result = get_all_users()

    if result:
        return render_template("profile.html", result=result)

    flash("Enter valid Username and Password", "error")
    return redirect(url_for("home"))
