import uuid,time ,razorpay,hmac,hashlib,smtplib,jwt , requests,re,yagmail,os
from datetime import datetime ,timedelta
from email.message import EmailMessage
from sqlalchemy.orm import Session
from common.logging_config import logger
from sqlalchemy import or_
from decouple import config
from security.database import Database ,SessionLocal,get_db
from fastapi.security.utils import get_authorization_scheme_param
from common.models import Payment,User,SignupModel, ActiveTokens,LoginRequest,TokenBlocklist ,RazorpayWebhookPayload ,  BannerCreate, BannerUpdate
from fastapi import HTTPException , status ,Depends, Request
from common.key_config import RAZORPAY_API_KEY, RAZORPAY_API_SECRET
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()
razorpay_client = razorpay.Client(auth=("RAZORPAY_API_KEY", "RAZORPAY_API_SECRET"))

MAX_RETRIES = 5
RAZORPAY_SECRET = config("RAZORPAY_API_SECRET", default="your_secret")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'fallback-secret-key')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 3


db = Database()
client = razorpay.Client(auth=(os.getenv("RAZORPAY_API_KEY"), os.getenv("RAZORPAY_API_SECRET")))


def process_payment(order_id: int, payment_info: dict):
    conn = db.get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM payments WHERE order_id = %s", (order_id,))
        payment = cursor.fetchone()

        if not payment:
            logger.error(f"No payment record found for order {order_id}")
            return {"status": "failed", "reason": "Payment record not found"}

        retry_count = payment.get("retry_count", 0)

        while retry_count < MAX_RETRIES:
            try:
                logger.info(f"Attempt {retry_count + 1} for order {order_id}")
                result = simulate_gateway(payment_info)

                if result["status"] == "success":
                    update_payment_status(conn, order_id, "Success", retry_count)
                    return {"status": "success"}

                raise Exception("Payment failed")

            except Exception as e:
                retry_count += 1
                update_payment_status(conn, order_id, "Failed", retry_count)
                logger.warning(f"Retry {retry_count} failed for order {order_id}: {str(e)}")

                if retry_count < MAX_RETRIES:
                    sleep_time = 2 ** retry_count  # Exponential backoff
                    logger.info(f"Sleeping for {sleep_time} seconds before retry...")
                    time.sleep(sleep_time)

        logger.error(f"Max retries exceeded for order {order_id}")
        send_failure_email(payment["user_id"], order_id)
        return {"status": "failed", "reason": "Max retries exceeded"}

    finally:
        cursor.close()
        conn.close()


def update_payment_status(conn, order_id, status, retry_count):
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE payments SET status=%s, retry_count=%s, last_attempt=%s WHERE order_id=%s
    """, (status, retry_count, datetime.utcnow(), order_id))
    conn.commit()
    cursor.close()


def simulate_gateway(payment_info):
    import random
    return {"status": "success" if random.random() > 0.5 else "failure"}


def send_failure_email(user_id, order_id):
    user_email = "example@gmail.com"  # Replace with DB query to fetch user email

    msg = EmailMessage()
    msg.set_content(f"Payment for order {order_id} failed after 3 retries.")
    msg["Subject"] = "Payment Failure Alert"
    msg["From"] = "noreply@yourapp.com"
    msg["To"] = user_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(config("EMAIL_HOST_USER"), config("EMAIL_HOST_PASSWORD"))
        server.send_message(msg)
        server.quit()
        logger.info(f"Failure email sent to {user_email}")
    except Exception as e:
        logger.error(f"Failed to send failure email: {e}")


def verify_payment_signature(order_id: str, payment_id: str, signature: str) -> bool:
    try:
        msg = f"{order_id}|{payment_id}"
        generated_signature = hmac.new(
            RAZORPAY_SECRET.encode(),
            msg.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(generated_signature, signature)
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False


async def initiate_payment(payment_data) -> dict:
    conn = db.get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s",
                       (payment_data.order_id, payment_data.user_id))
        order = cursor.fetchone()
        if not order:
            raise Exception("Invalid order ID or user ID")

        cursor.execute("""
            INSERT INTO payments (order_id, user_id, amount, payment_method, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            payment_data.order_id,
            payment_data.user_id,
            payment_data.amount,
            payment_data.payment_method,
            "pending",
            datetime.utcnow()
        ))
        conn.commit()

        return {
            "message": "Payment initiated successfully",
            "order_id": payment_data.order_id,
            "status": "pending"
        }
    finally:
        cursor.close()
        conn.close()


def create_order(amount: int):
    """Create an order on Razorpay."""
    return client.order.create({
        "amount": amount * 100,  # Convert amount to paise
        "currency": "INR",
        "receipt": "receipt#1",
        "payment_capture": 1,
    })


def fetch_payment(payment_id: str):
    """Fetch payment details from Razorpay."""
    return client.payment.fetch(payment_id)


def send_email(to_email: str, subject: str, body: str):
    """Send an email notification."""
    try:
        yag = yagmail.SMTP(config("EMAIL_HOST_USER"), config("EMAIL_HOST_PASSWORD"))
        yag.send(to=to_email, subject=subject, contents=body)
        logger.info(" Email sent successfully")
    except Exception as e:
        logger.error(f" Email failed: {e}")


def send_sms(to: str, message: str):
    """Send an SMS notification."""
    try:
        cleaned = re.sub(r"[^\d]", "", to)
        if cleaned.startswith("91") and len(cleaned) == 12:
            cleaned = cleaned[2:]
        if len(cleaned) != 10:
            logger.error(f" Invalid phone number: {to}")
            return
        url = "https://control.msg91.com/api/v2/sendsms"
        headers = {
            "authkey": config("MSG91_AUTH_KEY"),
            "Content-Type": "application/json"
        }
        payload = {
            "sender": config("MSG91_SENDER_ID"),
            "route": "4",
            "country": config("MSG91_COUNTRY"),
            "sms": [
                {"message": message, "to": [cleaned]}
            ]
        }
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        logger.info(f" SMS sent to {cleaned}")
    except Exception as e:
        logger.error(f" SMS failed for {to}: {e}")

def process_razorpay_payment(amount: float, currency: str = "INR"):
    try:
        order = razorpay_client.order.create({
            "amount": int(amount * 100),  # Razorpay expects amount in paise
            "currency": currency,
            "payment_capture": "1"
        })
        return {"status": "success", "order": order}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def handle_razorpay_webhook(webhook_data: RazorpayWebhookPayload, db: Session):
    """Handle Razorpay webhook and send notifications."""
    try:
        # Generate a unique transaction ID
        transaction_id = str(uuid.uuid4())

        # Extract payment details from webhook
        data = webhook_data.payload.entity

        payment = Payment(
            amount=data.amount,
            currency=data.currency,
            transaction_id=transaction_id,  # Use generated transaction ID
            status=data.status,
            user_email=data.email,
            user_phone=data.contact,
            payment_method=data.method
        )

        db.add(payment)
        db.commit()

        # Custom message based on payment status
        if payment.status.lower() in ['captured', 'success']:
            subject = "Payment Successful"
            msg = (
                f"Hi,\n\nYour payment of ₹{payment.amount / 100:.2f} "
                f"using {payment.payment_method.upper()} was successful.\n"
                f"Transaction ID: {payment.transaction_id}\n\nThank you!"
            )
        else:
            subject = "Payment Failed"
            msg = (
                f"Hi,\n\nYour payment of ₹{payment.amount / 100:.2f} "
                f"using {payment.payment_method.upper()} has failed.\n"
                f"Transaction ID: {payment.transaction_id}\n"
                f"Please try again or use a different method.\n\nNeed help? Contact support."
            )

        # Send email and SMS
        send_email(payment.user_email, subject, msg)
        send_sms(payment.user_phone, msg)

        return {"message": "Webhook received"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def retry_failed_payments():
    """Retry failed payments up to 3 attempts."""
    db = SessionLocal()
    try:
        failed_payments = db.query(Payment).filter(Payment.status != "captured", Payment.retry_count < 3).all()
        for payment in failed_payments:
            payment.retry_count += 1
            db.commit()
            msg = f"Retrying payment for transaction {payment.transaction_id}. Retry count: {payment.retry_count}"
            send_email(payment.user_email, "Retry Payment Attempt", msg)
            send_sms(payment.user_phone, msg)
    finally:
        db.close()


class AuditLogger:
    def __init__(self):
        self.db = db

    def log_transaction(self, transaction_id, user_id, status, gateway, request_payload, response_payload, retry_count=0, failure_reason=None):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            query = """
            INSERT INTO transaction_logs
            (transaction_id, user_id, status, gateway, request_payload, response_payload, retry_count, failure_reason, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (
                transaction_id,
                user_id,
                status,
                gateway,
                str(request_payload),
                str(response_payload),
                retry_count,
                failure_reason,
                datetime.now()
            ))

            conn.commit()
        except Exception as err:
            raise Exception(f"Database error: {err}")
        finally:
            cursor.close()
            conn.close()

audit_logger = AuditLogger()

class PaymentProcessor:
    def __init__(self):
        self.retry_count = 0
        self.razorpay_key = RAZORPAY_API_KEY
        self.razorpay_secret = RAZORPAY_API_SECRET

    def process_razorpay_payment(self, req):

        return {"gateway": "razorpay", "status": "paid", "amount": req.amount}

    def handle_payment(self, req, transaction_id: str):
        gateway = req.gateway.lower()
        try:
            if gateway == "razorpay":
                response = self.process_razorpay_payment(req)
            else:
                raise ValueError("Unsupported payment gateway")

            audit_logger.log_transaction(
                transaction_id=transaction_id,
                user_id=req.user_id,
                status="success",
                gateway=gateway,
                request_payload=req.dict(),
                response_payload=response,
                retry_count=self.retry_count
            )
            return {
                "status": "success",
                "transaction_id": transaction_id,
                "response": response
            }

        except Exception as e:
            audit_logger.log_transaction(
                transaction_id=transaction_id,
                user_id=req.user_id,
                status="failure",
                gateway=gateway,
                request_payload=req.dict(),
                response_payload={},
                retry_count=self.retry_count,
                failure_reason=str(e)
            )
            raise e

# ✅ This line is important:
payment_processor = PaymentProcessor()



#banners
def create_banner(banner: BannerCreate):
    conn = db.get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        sql = """
            INSERT INTO promotional_banners (title, image_url, link_url, status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, NOW(), NOW())
        """

        # Convert banner.status to string or value before passing to SQL
        status_value = banner.status.value if hasattr(banner.status, "value") else str(banner.status)

        cursor.execute(sql, (banner.title, banner.image_url, banner.link_url, status_value))
        conn.commit()
        banner_id = cursor.lastrowid
        return get_banner_by_id(banner_id)
    finally:
        cursor.close()
        conn.close()

def get_banners(skip: int = 0, limit: int = 100):
    conn = db.get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        sql = "SELECT * FROM promotional_banners LIMIT %s OFFSET %s"
        cursor.execute(sql, (limit, skip))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

def get_banner_by_id(banner_id: int):
    conn = db.get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM promotional_banners WHERE id = %s", (banner_id,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def update_banner(banner_id: int, banner: BannerUpdate):
    conn = db.get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        sql = """
            UPDATE promotional_banners
            SET title=%s, image_url=%s, link_url=%s, status=%s, updated_at=NOW()
            WHERE id=%s
        """
        # Convert banner.status to a primitive value if it's an Enum or custom type
        status_value = banner.status.value if hasattr(banner.status, "value") else str(banner.status)

        cursor.execute(sql, (banner.title, banner.image_url, banner.link_url, status_value, banner_id))
        conn.commit()
        return get_banner_by_id(banner_id)
    finally:
        cursor.close()
        conn.close()

def delete_banner(banner_id: int):
    conn = db.get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        banner = get_banner_by_id(banner_id)
        if not banner:
            return None
        cursor.execute("DELETE FROM promotional_banners WHERE id = %s", (banner_id,))
        conn.commit()
        return banner
    finally:
        cursor.close()
        conn.close()


#new
def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=60)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "jti": jti})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, jti, expire


def decode_access_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# Current user dependency
async def get_current_user(request: Request, db: Session = Depends(get_db)):
    authorization: str = request.headers.get("Authorization")
    scheme, token = get_authorization_scheme_param(authorization)

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token in Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing jti",
        )

    if db.query(TokenBlocklist).filter(TokenBlocklist.jti == jti).first():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revoked",
        )

    username = (payload.get("sub") or
                payload.get("user") or
                payload.get("identity") or
                payload.get("username"))

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user



def revoke_token(db: Session, jti: str):
    # Check if token already exists
    token = db.query(TokenBlocklist).filter(TokenBlocklist.jti == jti).first()
    if not token:
        token = TokenBlocklist(jti=jti, created_at=datetime.utcnow())
        db.add(token)
        db.commit()


async def get_jti_from_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        return jti
    return None


def add_token_to_blocklist(db: Session, jti: str):
    blocked_token = TokenBlocklist(jti=jti, created_at=datetime.utcnow())
    db.add(blocked_token)
    db.commit()


def handle_login(data: LoginRequest, db: Session):
    identifier = data.identifier
    password = data.password

    user = db.query(User).filter(User.username == identifier).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create JWT token
    token_data = create_access_token(data={"sub": user.username, "role": user.role})

    if isinstance(token_data, tuple):
        access_token, jti, expire_time = token_data
    else:
        raise Exception("create_access_token() must return token, jti, expire_time")

    # Store token in active_tokens table (not in token_blocklist)
    active_token_entry = ActiveTokens(
        jti=jti,
        user_id=user.id,
        role=user.role,
        expires_at=expire_time,
    )
    db.add(active_token_entry)
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role
    }

def signup(user: SignupModel, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(
        or_(
            User.username == user.username,
            User.email == user.email,
            User.mobile == user.mobile
        )
    ).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="User already exists")

    # Determine role and validate secret code if needed
    role = "user"  # default role

    if user.role in ("admin", "manager"):
        if user.role == "admin":
            if user.secret_code != config("ADMIN_SECRET"):
                raise HTTPException(status_code=403, detail="Invalid admin secret code")
        elif user.role == "manager":
            if user.secret_code != config("MANAGER_SECRET"):
                raise HTTPException(status_code=403, detail="Invalid manager secret code")
        role = user.role
    else:
        role = "user"

    # Hash the password and create the new user
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        mobile=user.mobile,
        password=hashed_password,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"msg": f"{role.capitalize()} user created successfully"}



def admin_role(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user