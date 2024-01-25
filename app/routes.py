from flask import render_template, redirect, url_for, request, session, flash
from sqlalchemy import create_engine, text
import bcrypt
from dotenv import load_dotenv
import os

from app import app
app.secret_key = os.getenv('YOUR_SECRET_KEY')

load_dotenv()


engine = create_engine(
    f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_DATABASE')}"
)

def add_user(username, email, password):
    if len(username)==0 or len(password)==0:
        return False
    with engine.connect() as connection:
        try:
            query = text("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)")
            connection.execute(query, {"username": username, "email": email, "password": password})
            connection.commit()
            return True
        except Exception as e:
            print(f"Error adding user: {str(e)}")
            return False

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
            print(f"Error retrieving user: {str(e)}")
            return None

def get_all_users():
    with engine.connect() as connection:
        try:
            query = text("SELECT * FROM users")
            result = connection.execute(query).fetchall()
            return result
        except Exception as e:
            print(f"Error retrieving users: {str(e)}")
            return None

@app.route('/')
def home():
    return render_template('home.html')

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

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email_or_name = request.form.get('username')
        password = request.form.get('password')

        result = get_user_by_credentials(email_or_name, password)

        if result:
            session['username'] = result[0][1]
            session['email'] = result[0][2]
            session['password'] = result[0][3]
            return redirect(url_for('profile'))

        flash('Login failed.', 'error')
        return redirect(url_for('home'))

    is_activated = session.pop('is_activated', False)
    return render_template('home.html', is_activated=is_activated)

@app.route('/profile')
def profile():
    result = get_all_users()

    if result:
        return render_template('profile.html', result=result)

    flash('Enter valid Username and Password', 'error')
    return redirect(url_for('home'))