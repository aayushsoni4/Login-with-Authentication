from app import app
from flask import render_template, redirect, url_for, request, session

app.secret_key = 'your_secret_key'

@app.route('/')
def home():
    is_activated = session.pop('is_activated', False)
    return render_template('login.html', is_activated=is_activated)

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        session['is_activated'] = True
        return redirect(url_for('home'))
    return render_template('register.html')
