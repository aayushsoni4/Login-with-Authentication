from flask import Blueprint, render_template, redirect, url_for, session, flash
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
    user = session.get("user")

    if user is None:
        return render_template("home.html")

    return redirect(url_for("main.profile"))


# Define the route for the user profile
@main_bp.route("/profile")
def profile():
    """
    Handle the user profile route.

    If the user is not logged in, flash a message and redirect to the login page.
    If the user is logged in, retrieve all users and render the profile page.

    Returns:
        redirect or render_template: Redirect to login or render the profile page.
    """
    # Check if the user is logged in
    user = session.get("user")

    if user is None:
        # Flash a message and redirect to the login page if the user is not logged in
        flash("Please log in to access the profile page.", "info")
        return redirect(url_for("auth.login"))

    # Retrieve all users from the database
    result = User.query.all()

    if result:
        # Render the profile page with the user information
        return render_template("profile.html", result=result)

    # Flash an error message and redirect to the home page if no users are found
    flash("Enter valid Username and Password", "error")
    return redirect(url_for("main.home"))
