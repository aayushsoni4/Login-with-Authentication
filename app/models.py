from app import db


class User(db.Model):
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
