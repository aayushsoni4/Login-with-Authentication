from app import app
from flask import render_template, redirect, url_for, request, session, flash
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

load_dotenv()

app.secret_key = os.getenv('YOUR_SECRET_KEY')
connection = None

def get_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_DATABASE')
        )
        return connection
    except Error as e:
        print(f"Error: {e}")
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

        try:
            connection = get_connection()
            cursor = connection.cursor()

            insert_query = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (username, email, password))
            connection.commit()

        except Error as e:
            flash(f'Registration failed. Error: {str(e)}', 'error')
            return redirect(url_for('register'))

        finally:
            cursor.close()
            connection.close()
        session['is_activated'] = True
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email_or_name = request.form.get('username')
        password = request.form.get('password')

        try:
            connection = get_connection()
            cursor = connection.cursor()

            select_query = "SELECT * FROM users WHERE (email = %s AND password = %s) OR (name = %s AND password = %s)"

            cursor.execute(select_query, (email_or_name, password, email_or_name, password))
            result = cursor.fetchall()

        except Error as e:
            flash(f'Login failed. Error: {str(e)}', 'error')
            return redirect(url_for('home'))

        finally:
            cursor.close()
            connection.close()

        if result:
            session['username'] = result[0][1]
            session['email'] = result[0][2]
            session['password'] = result[0][3]
            return redirect(url_for('main'))
    is_activated = session.pop('is_activated',False)
    return render_template('home.html', is_activated=is_activated)

@app.route('/profile')
def main():
    try:
        connection = get_connection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM users"

        cursor.execute(select_query)
        result = cursor.fetchall()

    except Error as e:
        flash(f'Error retrieving profile data. Error: {str(e)}', 'error')
        return redirect(url_for('home'))

    finally:
        cursor.close()
        connection.close()

    return render_template('profile.html', result=result)
