from flask import Blueprint, render_template, redirect, url_for, request, session, flash
from app import db, bcrypt
from app.models import User
from app.utils import (
    add_user,
    send_otp,
    activate_user,
    get_user_by_credentials,
    otp,
    send_password_reset_email,
    generate_token,
)
from datetime import timedelta, timezone, datetime
from . import auth_bp


# Define the route for user login
@auth_bp.route("/login", methods=["POST", "GET"])
def login():
    """
    Handle user login.

    If POST, validate login credentials, handle account activation,
    and redirect to profile or validate_user.
    If GET, render the login page.

    Returns:
        render_template or redirect: Render login page or redirect to profile or validate_user.
    """
    # Check if the user is already logged in
    user = session.get("user")

    if user:
        return redirect(url_for("main.profile"))

    # Process POST request for login
    if request.method == "POST":
        email_or_name = request.form.get("username")
        password = request.form.get("password")

        # Retrieve user by credentials
        user = get_user_by_credentials(email_or_name, password)

        if user:
            if user.is_activated:
                # Set the user_id in session during login
                session["user"] = user.username
                return redirect(url_for("main.profile"))
            else:
                # If the account is not activated, send OTP for validation
                session["email"] = user.email
                send_otp(session.get("email"))
                flash("Account not activated. Please verify your email.", "info")
                return redirect(url_for("auth.validate_user"))

        # Flash a message for a failed login attempt
        flash("Login failed. Please check your credentials.", "error")
        return redirect(url_for("auth.login"))

    # Render the login page for GET request
    return render_template("login.html")


# Define the route for user registration
@auth_bp.route("/register", methods=["POST", "GET"])
def register():
    """
    Handle user registration.

    If POST, validate the registration form, check for an existing user,
    add the user, generate and send OTP, and redirect to validate_user.
    If GET, render the registration page.

    Returns:
        render_template or redirect: Render registration page or redirect to validate_user.
    """

    # Check if the user is already logged in
    user = session.get("user")

    if user:
        return redirect(url_for("main.profile"))

    # Handle POST request for user registration
    if request.method == "POST":
        # Retrieve user registration form data
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Check if a user with the provided email already exists
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("User with this email already exists. Please login.", "error")
            return redirect(url_for("auth.login"))

        # Attempt to add the user to the database
        if add_user(username, email, hashed_password):
            # Generate OTP and store it in the session
            session["email"] = email

            # Send the email with OTP
            if send_otp(email):
                flash("OTP sent successfully.", "info")
                return redirect(url_for("auth.validate_user"))
            else:
                flash("Error sending OTP. Please try again later.", "error")
                return redirect(url_for("auth.register"))
        else:
            flash("Registration failed.", "error")
            return redirect(url_for("auth.register"))

    # Render the registration page for GET requests
    return render_template("register.html")


# Define the route for user validation
@auth_bp.route("/validate_user", methods=["POST", "GET"])
def validate_user():
    """
    Handle user validation.

    If POST, validate the OTP, activate the user,
    set the user in session, and redirect to the profile page.
    If GET, render the user validation page.

    Returns:
        render_template or redirect: Render user validation page or redirect to profile.
    """

    # Check if the user is already logged in
    user = session.get("user")

    if user:
        return redirect(url_for("main.profile"))

    # Retrieve the email from the session
    email = session.get("email")

    # Check if the email is not present in the session (error condition)
    if email is None:
        flash("Error! Please register again.", "error")
        return redirect(url_for("auth.register"))

    # Handle POST request for OTP validation
    if request.method == "POST":
        # Retrieve the OTP entered by the user in the form
        otp_entered = request.form.get("otp")

        # Get the current OTP using the TOTP generator
        current_otp = otp.now()

        # Check if the entered OTP matches the current OTP
        if otp_entered == current_otp:
            # If OTP is valid, activate the user and set the user in session
            if activate_user(email):
                session["user"] = email
                session.pop("email", None)  # Remove the email from session
                return redirect(url_for("main.profile"))
            else:
                flash("Error activating user.", "error")
                return redirect(url_for("auth.validate_user"))
        else:
            flash("Invalid OTP.", "error")
            return redirect(url_for("auth.validate_user"))

    # Render the user validation page for GET requests
    return render_template("validate_user.html")


# Define a route to handle the resend_otp functionality
@auth_bp.route("/resend_otp", methods=["GET"])
def resend_otp():
    """
    Handle the resend_otp functionality.

    Resend the OTP and flash a message indicating success.
    Redirect to the validate_user route.

    Returns:
        redirect: Redirect to validate_user route.
    """

    # Check if the user is already logged in
    user = session.get("user")

    if user:
        return redirect(url_for("main.profile"))

    # Retrieve the user's email from the session
    email = session.get("email")

    # Check if the email is not available in the session
    if email is None:
        flash("Error! Please register again.", "error")
        return redirect(url_for("auth.register"))

    # Attempt to resend the OTP
    if send_otp(email):
        flash("New OTP sent successfully.", "info")
        return redirect(url_for("auth.validate_user"))
    else:
        flash("Error resending OTP. Please try again later.", "error")

        # Delete the user from the database if email sending fails
        user = User.query.filter_by(email=email).first()
        if user:
            db.session.delete(user)
            db.session.commit()

        # Redirect to the registration page in case of failure
        return redirect(url_for("auth.register"))


# Define the route for user logout
@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Handle user logout.

    If POST, clear the user session and redirect to the home page.

    Returns:
        redirect: Redirect to the home page after logout.
    """
    # Check if the user is logged in
    user = session.get("user")

    if user is None:
        # User is not logged in, no need to log out, redirect to home
        flash("You are not logged in.", "info")
        return redirect(url_for("main.home"))

    # Clear the user session
    session.pop("user", None)

    # Flash a success message and redirect to the home page
    flash("Logout successful. You have been logged out.", "success")
    return redirect(url_for("main.home"))


# Define the route for handling password reset requests
@auth_bp.route("/forgot_password", methods=["POST", "GET"])
def forgot_password():
    """
    Handle password reset requests.

    If POST, validate the email or username,
    generate a unique token, store the token and user information in session,
    send a password reset email, and redirect to the login page.
    If GET, render the forgot password page.

    Returns:
        render_template or redirect: Render the forgot password page or redirect to login.
    """
    # Check if the user is already logged in
    user = session.get("user")

    if user:
        return redirect(url_for("main.profile"))

    # Process POST request for password reset
    if request.method == "POST":
        email_or_name = request.form.get("email")

        # Assume you have a User model with an email field
        user = User.query.filter(
            (User.email == email_or_name) | (User.username == email_or_name)
        ).first()

        if user:
            # Generate a unique token with a 15-minute expiration
            token = generate_token()

            # Store the token and user information (e.g., user ID) in a secure way
            session["reset_token"] = token
            session["reset_token_expiration"] = datetime.utcnow() + timedelta(
                minutes=15
            )
            session["user_id_to_reset"] = user.id
            session.permanent = True  # Set the session to be permanent

            # Send the password reset email
            if send_password_reset_email(user.email, token):
                flash(
                    "Password reset email sent successfully. Check your inbox.",
                    "success",
                )
                return redirect(url_for("auth.login"))
            else:
                flash(
                    "Error sending password reset email. Please try again later.",
                    "error",
                )
                return redirect(url_for("auth.forgot_password"))
        else:
            # Flash a message if no account found with the provided email or username
            flash("No account found with that email or username.", "warning")
            return redirect(url_for("auth.forgot_password"))

    # Render the forgot password page for GET request
    return render_template("forgot_password.html")


# Route to handle password reset. Validates the token and allows the user to reset their password.
@auth_bp.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """
    Handle password reset.

    If the token is valid, retrieve the user ID associated with the token,
    update the user's password based on the form input, and redirect to the login page.
    If the token is invalid or expired, flash an error message and redirect to the forgot password page.

    Returns:
        render_template or redirect: Render the reset password page or redirect to forgot password.
    """
    # Validate the token and check its expiration
    if token == session.get("reset_token"):
        expiration_timestamp = session.get("reset_token_expiration")

        # Check if the token has expired
        if (
            expiration_timestamp
            and datetime.utcnow().replace(tzinfo=timezone.utc) > expiration_timestamp
        ):
            flash("Token has expired. Please request a new password reset.", "error")
            return redirect(url_for("auth.forgot_password"))

        # Retrieve the user ID associated with the token
        user_id = session.get("user_id_to_reset")
        user = User.query.get(user_id)

        if user:
            # Process the POST request to update the password
            if request.method == "POST":
                # Update the user's password based on the form input
                new_password = request.form.get("new_password")
                # Update the user's password in the database
                # This step depends on your User model and database setup
                user.password = bcrypt.generate_password_hash(new_password).decode(
                    "utf-8"
                )
                db.session.commit()

                # Clear the session variables after successful password reset
                session.pop("reset_token", None)
                session.pop("reset_token_expiration", None)
                session.pop("user_id_to_reset", None)

                flash(
                    "Password reset successful. You can now log in with your new password.",
                    "success",
                )
                return redirect(url_for("auth.login"))

            # Render the reset password page for GET request
            return render_template("reset_password.html", token=token)

    # Flash an error message for invalid or expired token and redirect to forgot password
    flash("Invalid or expired token. Please try again.", "error")
    return redirect(url_for("auth.forgot_password"))
