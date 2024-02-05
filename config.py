from dotenv import load_dotenv
import os
from datetime import timedelta

# Load environment variables from the .env file
load_dotenv()


class Config:
    # Flask App Configuration
    SECRET_KEY = os.getenv("YOUR_SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = f"mysql+mysqlconnector://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_DATABASE')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email Configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = int(os.getenv("MAIL_PORT"))
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
