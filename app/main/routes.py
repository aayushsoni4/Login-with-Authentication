from flask import render_template, redirect, url_for, session, flash
from flask_login import current_user, login_required
from app.models import User
from . import main_bp


# Define the route for the home page
@main_bp.route("/")
def home():
    """
    Handle the home page route.

    If the user is not logged in, render the home page template.
    If the user is logged in, redirect to the profile page.

    Returns:
        render_template or redirect: Render the home page or redirect to the profile page.
    """
    if current_user.is_authenticated:
        return redirect(url_for("main.profile"))
    return render_template("home.html")


# Define the route for the user profile
@main_bp.route("/profile")
@login_required
def profile():
    """
    Handle the user profile route.

    If the user is not logged in, Flask-Login will automatically redirect them to the login page.
    If the user is logged in, retrieve all users and render the profile page.

    Returns:
        redirect or render_template: Redirect to login or render the profile page.
    """
    # Retrieve all users from the database
    result = User.query.all()

    if result:
        # Render the profile page with the user information
        return render_template("profile.html", result=result)

    # Flash an error message and redirect to the home page if no users are found
    flash("Enter valid Username and Password", "error")
    return redirect(url_for("main.home"))
