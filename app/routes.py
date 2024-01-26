# Import necessary modules
from flask import render_template, redirect, url_for, request, session, flash
from sqlalchemy import create_engine, text
from dotenv import load_dotenv
from flask_mail import Mail, Message
import bcrypt
import pyotp
import random
import logging
import os

# Import the Flask app instance
from app import app
app.first_request_processed = False

# Set the Flask app's secret key from environment variables
app.secret_key = os.getenv('YOUR_SECRET_KEY')

# Load environment variables from the .env file
load_dotenv()

# Configure Flask app with necessary environment variables
app.config.update(
    SECRET_KEY=os.getenv('YOUR_SECRET_KEY'),
    DB_USER=os.getenv('DB_USER'),
    DB_PASSWORD=os.getenv('DB_PASSWORD'),
    DB_HOST=os.getenv('DB_HOST'),
    DB_PORT=os.getenv('DB_PORT'),
    DB_DATABASE=os.getenv('DB_DATABASE'),
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT')),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER'),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
)

# Initialize Flask-Mail
mail = Mail(app)
otp = pyotp.TOTP(os.getenv('otp_key'), interval=300)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the SQLAlchemy engine using the configured database URI
db_uri = f"mysql+mysqlconnector://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_DATABASE']}"
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
engine = create_engine(db_uri)

# Function to create the 'users' table if it doesn't exist
def create_table_if_not_exists():
    with engine.connect() as connection:
        try:
            query = text("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    is_activated TINYINT DEFAULT 0
                );
            """)
            connection.execute(query)
        except Exception as e:
            # Log an error message if there's an issue creating the table
            logger.error(f"Error creating table: {str(e)}")

# Function to initialize the 'users' table
def initialize_table():
    if not app.first_request_processed:
        create_table_if_not_exists()
        app.first_request_processed = True

# Function to add a new user to the 'users' table
def add_user(username, email, password):
    if not username or not password:
        logger.error("Invalid username or password provided.")
        return False
    with engine.connect() as connection:
        try:
            query = text("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)")
            connection.execute(query, {"username": username, "email": email, "password": password})
            connection.commit()
            return True
        except Exception as e:
            # Log an error message if there's an issue adding a user
            logger.error(f"Error adding user: {str(e)}")
            return False

# Function to retrieve a user by credentials from the 'users' table
def get_user_by_credentials(email_or_name, password):
    with engine.connect() as connection:
        try:
            query = text("SELECT * FROM users WHERE (email = :input) OR (username = :input)")
            result = connection.execute(query, {"input": email_or_name}).fetchall()
            if result:
                if bcrypt.checkpw(password.encode('utf-8'), result[0][3].encode('utf-8')):
                    return result
                else:
                    return None
            return result
        except Exception as e:
            # Log an error message if there's an issue retrieving a user
            logger.error(f"Error retrieving user: {str(e)}")
            return None

# Function to retrieve all users from the 'users' table
def get_all_users():
    with engine.connect() as connection:
        try:
            query = text("SELECT * FROM users")
            result = connection.execute(query).fetchall()
            return result
        except Exception as e:
            # Log an error message if there's an issue retrieving all users
            logger.error(f"Error retrieving users: {str(e)}")
            return None

def activate_user(email):
    with engine.connect() as connection:
        try:
            query = text("UPDATE users SET is_activated = 1 WHERE email = :email")
            connection.execute(query, {"email": email})
            connection.commit()
            return True
        except Exception as e:
            # Log an error message if there's an issue activating a user
            logger.error(f"Error activating user: {str(e)}")
            return None

def get_email(username):
    with engine.connect() as connection:
        try:
            query = text("SELECT email FROM users WHERE username = :username")
            email = connection.execute(query, {"username": username}).fetchone()
            return email[0]
        except Exception as e:
            # Log an error message if there's an issue activating a user
            logger.error(f"Email not found!: {str(e)}")
            return None
        
def sendOTP(email):
    totp_value = otp.now()
    message = Message("Your OTP for Verification", recipients=[email])
    message.body = f"Your OTP is: {totp_value}"
    mail.send(message)

# Define the route for the home page
@app.route('/')
def home():
    user = session.get('user')
    
    if user is None:
        return render_template('home.html')

    return redirect(url_for('profile'))

# Define a function to run before each request to check and initialize the 'users' table
@app.before_request
def check_first_request():
    initialize_table()

# Define the route for user registration
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        if add_user(username, email, hashed_password):
            # Generate OTP and store it in session
            session['email'] = email
            # Send the email
            sendOTP(email)
            
            return redirect(url_for('user_validation'))
        else:
            flash('Registration failed.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/user_validation', methods=['POST', 'GET'])
def user_validation():

    email = session.get('email')

    if email is None:
        flash('Error! Please register again.', 'error')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')

        current_otp = otp.now()

        if user_otp == current_otp:
            if activate_user(email):
                flash('Registration successful.', 'success')
                session['user'] = email
                session.pop('email', None)
                return redirect(url_for('profile'))
            else:
                flash('Error!', 'error')
                return redirect(url_for('user_validation'))
        else:
            flash('Invalid OTP.', 'error')
            return redirect(url_for('user_validation'))

    return render_template('user_validation.html')

# Add a new route to handle the resend_otp functionality
@app.route('/resend_otp', methods=['GET'])
def resend_otp():
    email = session.get('email')

    if email is None:
        flash('Error! Please register again.', 'error')
        return redirect(url_for('register'))

    # Send the new OTP
    sendOTP(email)

    flash('New OTP sent successfully.', 'info')
    return redirect(url_for('user_validation'))

# Define the route for user login
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email_or_name = request.form.get('username')
        password = request.form.get('password')

        result = get_user_by_credentials(email_or_name, password)

        if result:
            if result[0][4] == 1:
                # Setting the user_id in session during login
                session['user'] = email_or_name 
                return redirect(url_for('profile'))
            else:
                session['email'] = get_email(email_or_name) if '@' not in email_or_name else email_or_name
                sendOTP(session.get('email'))
                flash('Account not activated. Please verify your email.', 'info')
                return redirect(url_for('user_validation'))

        flash('Login failed.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

# Define the route for the user profile
@app.route('/profile')
def profile():
    user = session.get('user')
    
    if user is None:
        return redirect(url_for('login'))
    result = get_all_users()

    if result:
        return render_template('profile.html', result=result)

    flash('Enter valid Username and Password', 'error')
    return redirect(url_for('home'))
