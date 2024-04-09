from flask import render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
from app import db
from app.models import Image
from datetime import datetime, timezone

from io import BytesIO
from flask import send_file
from . import main_bp

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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


@main_bp.route("/profile")
@login_required
def profile():
    """
    Handle the user profile route.

    If the user is not logged in, Flask-Login will automatically redirect them to the login page.
    If the user is logged in, retrieve all image data for the current user and render the profile page.

    Returns:
        render_template: Render the profile page with the user's image data.
    """
    user_images = Image.query.filter_by(user_id=current_user.id).all()
    return render_template("profile.html", user_images=user_images)


@main_bp.route("/upload_image", methods=["POST"])
@login_required
def upload_image():
    """
    Handle the route for uploading user images.

    If the request method is POST, handle the image upload process.
    """
    if "image" not in request.files:
        flash("No file part", "error")
        return redirect(request.url)

    file = request.files["image"]

    if file.filename == "":
        flash("No selected file", "error")
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        image_data = file.read()
        new_image = Image(
            filename=filename,
            data=image_data,
            user_id=current_user.id,
            uploaded_at=datetime.now(timezone.utc),
        )
        db.session.add(new_image)
        db.session.commit()
        flash("Image uploaded successfully", "success")
    else:
        flash("Invalid file format. Allowed formats are png, jpg, jpeg, gif", "error")

    return redirect(url_for("main.profile"))


@main_bp.route("/image/<int:image_id>")
@login_required
def get_image(image_id):
    """
    Serve the image corresponding to the given image ID.

    Args:
        image_id (int): The ID of the image to retrieve.

    Returns:
        send_file: Response containing the image data.
    """
    image = Image.query.get_or_404(image_id)
    return send_file(BytesIO(image.data), mimetype="image/jpeg")
