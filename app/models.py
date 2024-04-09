from app import db
from flask_login import UserMixin
from datetime import datetime, timezone


class User(UserMixin, db.Model):
    """
    User model representing the 'users' table in the database.

    Attributes:
        id (int): Primary key for the User model.
        username (str): User's username, unique and not nullable.
        email (str): User's email, unique and not nullable.
        password (str): User's password, not nullable.
        is_activated (bool): Flag indicating whether the user is activated, default is False.
    """

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_activated = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.LargeBinary)

    # Required methods for Flask-Login
    def get_id(self):
        return self.id

    def is_authenticated(self):
        return True

    def is_active(self):
        return self.is_activated

    def is_anonymous(self):
        return False

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, email={self.email})"


class Image(db.Model):
    """
    Image model representing the 'images' table in the database.

    Attributes:
        id (int): Primary key for the Image model.
        filename (str): Name of the uploaded image file.
        data (bytea): Binary data of the uploaded image.
        user_id (int): Foreign key referencing the user who uploaded the image.
        uploaded_at (DateTime): Timestamp indicating when the image was uploaded.
    """

    __tablename__ = "images"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary(length=(2**32) - 1), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
