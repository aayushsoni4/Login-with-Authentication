from app import app
from flask import render_template, redirect, url_for, request, session

app.secret_key = 'your_secret_key'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        session['is_activated'] = True
        session['email'] = email
        session['username'] = username
        session['password'] = password
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    is_activated = session.pop('is_activated', False)
    email = session.pop('email', None)
    username = session.pop('username', None)
    password = session.pop('password', None)
    return render_template('home.html', is_activated=is_activated, 
                            email=email, username=username, password=password)
