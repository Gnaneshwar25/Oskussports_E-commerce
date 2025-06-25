import os
from dotenv import load_dotenv

load_dotenv()

# Use environment variables securely for API keys and credentials
RAZORPAY_API_KEY = os.getenv("RAZORPAY_API_KEY")
RAZORPAY_API_SECRET = os.getenv("RAZORPAY_API_SECRET")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
MSG91_AUTH_KEY = os.getenv("MSG91_AUTH_KEY")
MSG91_SENDER_ID = os.getenv("MSG91_SENDER_ID")
MSG91_COUNTRY = os.getenv("MSG91_COUNTRY")


ADMIN_SECRET = os.getenv("ADMIN_SECRET")
MANAGER_SECRET= os.getenv("MANAGER_SECRET")


