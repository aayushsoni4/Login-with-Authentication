from flask import Blueprint

# Create a Blueprint for the authentication module
auth_bp = Blueprint("auth", __name__)

# Import the routes associated with the authentication module
from app.auth import routes
