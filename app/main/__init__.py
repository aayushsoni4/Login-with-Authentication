# Import the Blueprint class from Flask
from flask import Blueprint

# Create a Blueprint for the main module
main_bp = Blueprint("main", __name__)

# Import the routes associated with the main module
from app.main import routes
