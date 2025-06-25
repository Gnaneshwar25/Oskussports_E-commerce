import uuid
from fastapi import FastAPI, HTTPException, Query, Depends, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Optional ,List
from jose import jwt
from common import payments_helper
from common import models
from common.logging_config import logger
from security.database import Database, SessionLocal, get_db
from common.models import (
    ProductSchema,
    CategorySchema,
    PaymentRequest,
    PaymentVerificationRequest,
    RazorpayWebhookPayload,
    SignupModel,
    LoginModel,
    UserResponseModel,
    User,Payment, LoginRequest ,UserOut
)
from common.services_helper import ProductService, CategoryService
from common.payments_helper import (
    add_token_to_blocklist,
    JWT_SECRET_KEY,
    ALGORITHM

)
from common.payments_helper import process_razorpay_payment , initiate_payment, verify_payment_signature,signup, process_payment,create_order, \
    handle_razorpay_webhook ,handle_login ,retry_failed_payments ,payment_processor  , handle_login , create_access_token, get_current_user
from security.database import engine, Base
from common import services_helper
from security.role_checker import any_authenticated,admin_or_manager, admin_role
from common.services_helper import LoggingMiddleware


app = FastAPI(title="Oskus_Sports")


Base.metadata.create_all(bind=engine)

app.add_middleware(LoggingMiddleware)

db = Database()
product_service = ProductService(db)
category_service = CategoryService(db)



@app.get("/")
def home():
    """Root endpoint returning a welcome message."""
    return {
        "message": "Welcome to Oskus Sports E-Commerce API. Explore our products and categories!"
    }


@app.post('/signup', status_code=status.HTTP_201_CREATED)
def signup_endpoint(user: SignupModel, db: Session = Depends(get_db)):
    return signup(user, db)


@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    return handle_login(data, db)

@app.get('/protected', response_model=UserResponseModel)
def protected(current_user: User = Depends(get_current_user)):
    return UserResponseModel(
        username=current_user.username,
        email=current_user.email,
        mobile=current_user.mobile,
        role=current_user.role
    )

@app.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth.split(" ")[1]
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Token missing jti")
    add_token_to_blocklist(db, jti)
    return {"msg": "Token revoked"}

@app.put("/admin/users/{user_id}/role")
def update_user_role(
        user_id: int,
        new_role: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(admin_role)
):
    valid_roles = ["admin", "manager", "user"]
    if new_role not in valid_roles:
        raise HTTPException(status_code=400, detail="Invalid role")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = new_role
    db.commit()
    return {"message": "User role updated successfully"}



@app.get("/products/list")
def list_all_products(current_user: User = Depends(any_authenticated)):
    return product_service.get_all_products()

@app.get("/products/")
def get_products(
    name: Optional[str] = Query(None),
    category_id: Optional[int] = Query(None),
    min_price: Optional[float] = Query(None),
    max_price: Optional[float] = Query(None),
    in_stock: Optional[bool] = Query(None),
    sort_by: Optional[str] = Query("price_asc"),
    limit: int = Query(10),
    offset: int = Query(0),
    current_user: User = Depends(any_authenticated)
):
    try:
        products = product_service.search_products(
            name, category_id, min_price, max_price, in_stock, sort_by, limit, offset
        )
        return {"message": "Products retrieved successfully.", "data": products}
    except Exception as e:
        logger.error(f"Error in /products/ API: {e}")
        return JSONResponse(content={"error": "Failed to retrieve products."}, status_code=500)

@app.get("/products/{product_id}")
def fetch_product_by_id(
    product_id: int,
    current_user: User = Depends(any_authenticated)
):
    return product_service.get_product_by_id(product_id)

@app.post("/products/")
def create_product(
    product: ProductSchema,
    current_user: User = Depends(admin_role)
):
    return product_service.add_product(product)

@app.put("/products/{product_id}")
def update_product(
    product_id: int,
    product: ProductSchema,
    current_user: User = Depends(admin_or_manager)
):
    return product_service.update_product(product_id, product)

@app.delete("/products/{product_id}")
def delete_product(
    product_id: int,
    current_user: User = Depends(admin_role)
):
    return product_service.delete_product(product_id)

@app.get("/categories/")
def list_categories(
    current_user: User = Depends(any_authenticated)
):
    return category_service.get_all_categories()

@app.get("/categories/{category_id}")
def retrieve_category(
    category_id: int,
    current_user: User = Depends(any_authenticated)
):
    return category_service.get_category_by_id(category_id)

@app.post("/categories/")
def create_category(
    category: CategorySchema,
    current_user: User = Depends(admin_role)
):
    return category_service.add_category(category.category_name, category.parent_category_id)

@app.put("/categories/{category_id}")
def modify_category(
    category_id: int,
    category: CategorySchema,
    current_user: User = Depends(admin_or_manager)
):
    return category_service.update_category(category_id, category.category_name, category.parent_category_id)

@app.delete("/categories/{category_id}")
def remove_category(
    category_id: int,
    current_user: User = Depends(admin_role)
):
    return category_service.delete_category(category_id)
# ======== Payment Endpoints with RBAC ========
@app.post("/payments/razorpay/")
def razorpay_payment(
    amount: float,
    currency: str = "INR",
    current_user: User = Depends(any_authenticated)
):
    return process_razorpay_payment(amount, currency)


@app.post("/payments/initiate")
async def initiate(
    payment: PaymentRequest,
    current_user: User = Depends(any_authenticated)
):
    try:
        result = await initiate_payment(payment)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/verify-payment")
async def verify_payment(
    data: PaymentVerificationRequest,
    current_user: User = Depends(any_authenticated)
):
    is_valid = verify_payment_signature(data.order_id, data.payment_id, data.signature)
    if is_valid:
        return {"status": "success", "message": "Payment verified"}
    else:
        raise HTTPException(status_code=400, detail="Payment verification failed")


@app.post("/pay/{order_id}")
def initiate_payment_process(
    order_id: int,
    payment_info: dict,
    current_user: User = Depends(any_authenticated)
):
    result = process_payment(order_id, payment_info)
    if result["status"] == "failed":
        raise HTTPException(status_code=400, detail=result["reason"])
    return {"message": "Payment successful"}


@app.post("/api/payments/create-order/")
def create_payment(
    amount: int,
    current_user: User = Depends(any_authenticated)
):
    return {"status": "success", "order": create_order(amount)}


@app.get("/admin/payments/")
def get_all_payments(
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_role)  # Only admin
):
    return db.query(Payment).all()


@app.get("/admin/payments/{status}")
def get_payments_by_status(
    status: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_role)
):
    return db.query(Payment).filter(Payment.status == status).all()


@app.post("/admin/retry-failed-payments/")
def retry_failed(
    current_user: User = Depends(admin_role)
):
    retry_failed_payments()
    return {"status": "success", "message": "Failed payments retry initiated"}


@app.post("/webhook/razorpay/")
async def razorpay_webhook(
    webhook_data: RazorpayWebhookPayload,
    db: Session = Depends(get_db),
    # No authentication for webhooks (external service)
):
    return handle_razorpay_webhook(webhook_data, db)


@app.post("/api/pay")
def pay(
    request: PaymentRequest,
    current_user: User = Depends(any_authenticated)
):
    transaction_id = str(uuid.uuid4())
    try:
        response = payment_processor.handle_payment(request, transaction_id)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ======== Banner Endpoints with RBAC ========
@app.post("/api/banners/", response_model=models.BannerInDB)
def create_banner(
    banner: models.BannerCreate,
    current_user: User = Depends(admin_role)  # Only admin
):
    return payments_helper.create_banner(banner)


@app.get("/api/banners/", response_model=List[models.BannerInDB])
def read_banners(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(any_authenticated)
):
    return payments_helper.get_banners(skip, limit)


@app.get("/api/banners/{banner_id}", response_model=models.BannerInDB)
def read_banner(
    banner_id: int,
    current_user: User = Depends(any_authenticated)
):
    banner = payments_helper.get_banner_by_id(banner_id)
    if not banner:
        raise HTTPException(status_code=404, detail="Banner not found")
    return banner


@app.put("/api/banners/{banner_id}", response_model=models.BannerInDB)
def update_banner(
    banner_id: int,
    banner: models.BannerUpdate,
    current_user: User = Depends(admin_role)
):
    updated = payments_helper.update_banner(banner_id, banner)
    if not updated:
        raise HTTPException(status_code=404, detail="Banner not found")
    return updated


@app.delete("/api/banners/{banner_id}", response_model=models.BannerInDB)
def delete_banner(
    banner_id: int,
    current_user: User = Depends(admin_role)
):
    deleted = payments_helper.delete_banner(banner_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Banner not found")
    return deleted


@app.get("/admin/users", response_model=List[UserOut])
def get_users(
    db: Session = Depends(get_db),
    current_admin: User = Depends(admin_role)
):
    users = db.query(User).all()
    return users

@app.put("/admin/users/{user_id}/disable")
def disable_user(
    user_id: int,
    current_admin: User = Depends(admin_role),
    db: Session = Depends(get_db)
):
    success = services_helper.disable_user(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User disabled successfully"}

@app.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    current_admin: User = Depends(admin_role),
    db: Session = Depends(get_db)
):
    success = services_helper.delete_user(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}


