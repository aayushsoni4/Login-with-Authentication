# Import necessary modules
from flask import Flask, render_template, redirect, url_for, request, session, flash
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

load_dotenv()

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


# Define User model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_activated = db.Column(db.Boolean, default=False)


# Create all tables
with app.app_context():
    db.create_all()

# Query and print all users
with app.app_context():
    users = User.query.all()
    print("Users in the 'users' table:")
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}")
        print(user)
