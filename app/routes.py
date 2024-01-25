# Import necessary modules
from flask import render_template, redirect, url_for, request, session, flash
from sqlalchemy import create_engine, text
import bcrypt
from dotenv import load_dotenv
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
app.config['SECRET_KEY'] = os.getenv('YOUR_SECRET_KEY')
app.config['DB_USER'] = os.getenv('DB_USER')
app.config['DB_PASSWORD'] = os.getenv('DB_PASSWORD')
app.config['DB_HOST'] = os.getenv('DB_HOST')
app.config['DB_PORT'] = os.getenv('DB_PORT')
app.config['DB_DATABASE'] = os.getenv('DB_DATABASE')

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

# Define the route for the home page
@app.route('/')
def home():
    return render_template('home.html')

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
            session['is_activated'] = True
            return redirect(url_for('login'))
        else:
            flash('Registration failed.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

# Define the route for user login
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email_or_name = request.form.get('username')
        password = request.form.get('password')

        result = get_user_by_credentials(email_or_name, password)

        if result:
            return redirect(url_for('profile'))

        flash('Login failed.', 'error')
        return redirect(url_for('home'))

    is_activated = session.pop('is_activated', False)
    return render_template('home.html', is_activated=is_activated)

# Define the route for the user profile
@app.route('/profile')
def profile():
    result = get_all_users()

    if result:
        return render_template('profile.html', result=result)

    flash('Enter valid Username and Password', 'error')
    return redirect(url_for('home'))
