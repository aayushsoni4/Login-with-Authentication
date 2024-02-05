from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

# Create the Flask app instance
app = Flask(__name__)

# Load configuration from config.py
app.config.from_object("config.Config")

# Initialize Flask-SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Mail for sending emails
mail = Mail(app)

# Import routes and models
from app import routes, models

# Create tables in the database if necessary
with app.app_context():
    db.create_all()
