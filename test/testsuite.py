import uuid
import pytest
from fastapi.testclient import TestClient
from api.main import app , admin_role ,any_authenticated
from security.database import get_db



client = TestClient(app)

@pytest.fixture(autouse=True)
def override_get_db(mocker):

    mock_session = mocker.MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = None
    def _dummy_get_db():
        yield mock_session
    app.dependency_overrides[get_db] = _dummy_get_db
    yield

    app.dependency_overrides.clear()


def test_signup_success(mocker):
    user = {
        "username": f"newuser_{uuid.uuid4().hex[:8]}",
        "email": f"newuser_{uuid.uuid4().hex[:8]}@example.com",
        "mobile": "1234567890",
        "password": "Password@123"
    }
    response = client.post("/signup", json=user)
    print(response.status_code, response.json())
    assert response.status_code == 201
    assert response.json()["msg"] == "User user created successfully"


def test_login_success(mocker):
    data = {"identifier": "user1", "password": "Password@123"}
    mocker.patch("api.main.handle_login", return_value={"access_token": "dummy.jwt.token", "token_type": "bearer"})
    response = client.post("/login", json=data)
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_protected_route_requires_auth(mocker):
    response = client.get("/protected")
    assert response.status_code == 401

def test_logout_success(mocker):
    token = "test.jwt.token"
    mocker.patch("jose.jwt.decode", return_value={"jti": "123"})
    mocker.patch("common.payments_helper.add_token_to_blocklist")
    headers = {"Authorization": "Bearer " + token}
    response = client.post("/logout", headers=headers)
    assert response.status_code == 200
    assert response.json()["msg"] == "Token revoked"

def fake_admin_role():
    return {"role": "admin"}

def test_update_user_role_invalid_role():
    app.dependency_overrides[admin_role] = fake_admin_role
    response = client.put(
        "/admin/users/1/role?new_role=invalidrole",
        headers={"Authorization": "Bearer dummy"}
    )
    print(response.status_code, response.json())
    assert response.status_code == 400
    app.dependency_overrides = {}


def test_list_all_products_requires_auth(mocker):
    response = client.get("/products/list")
    assert response.status_code == 401
def fake_any_authenticated():
    return {"role": "user"}

def test_list_all_products_success(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.services_helper.ProductService.get_all_products", return_value=[{"id": 1, "name": "Product1"}])
    response = client.get("/products/list", headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())
    assert response.status_code == 200
    app.dependency_overrides = {}


def test_get_products_with_filters(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.services_helper.ProductService.search_products", return_value=[{"id": 2, "name": "FilteredProduct"}])
    response = client.get("/products/?name=FilteredProduct", headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())
    assert response.status_code == 200
    app.dependency_overrides = {}

def test_create_product_requires_admin(mocker):
    product = {
        "name": "test Product",
        "description": "Desc",
        "price": 10.0,
        "stock": 99,
        "category_id": 1
    }
    response = client.post("/products/", json=product)
    assert response.status_code == 401


def test_fetch_product_by_id(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.services_helper.ProductService.get_product_by_id", return_value={"id": 1, "name": "Product1"})
    response = client.get("/products/1", headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())  # For debugging
    assert response.status_code == 200
    app.dependency_overrides = {}


def test_list_categories_requires_auth():
    response = client.get("/categories/")
    assert response.status_code == 401

def test_list_categories_success(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.services_helper.CategoryService.get_all_categories", return_value=[{"id": 1, "category_name": "Sports"}])
    response = client.get("/categories/", headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())  # for debugging
    assert response.status_code == 200
    app.dependency_overrides = {}

def test_create_category_requires_admin(mocker):
    category = {"category_name": "NewCat", "parent_category_id": None}
    response = client.post("/categories/", json=category)
    assert response.status_code == 401

def test_retrieve_category_by_id(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.services_helper.CategoryService.get_category_by_id", return_value={"id": 1, "category_name": "Sports"})
    response = client.get("/categories/1", headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())  # For debugging, remove if not needed
    assert response.status_code == 200
    app.dependency_overrides = {}



def test_razorpay_payment_success(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.payments_helper.process_razorpay_payment", return_value={"status": "success"})
    response = client.post("/payments/razorpay/?amount=100&currency=INR", headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())  # For debugging
    assert response.status_code == 200
    app.dependency_overrides = {}

def test_initiate_payment_success(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch(
        "common.payments_helper.initiate_payment",
        new_callable=mocker.AsyncMock,
        return_value={"status": "initiated"}
    )
    payment_req = {
        "order_id": 2,
        "user_id": 2,
        "gateway": "razorpay",
        "amount": 100.0,
        "payment_method": "card",
        "currency": "INR"
    }
    response = client.post("/payments/initiate", json=payment_req, headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())
    assert response.status_code == 200
    app.dependency_overrides = {}

def fake_verify(*args, **kwargs):
    print("MOCK CALLED")
    return True

def test_verify_payment_success(monkeypatch):
    monkeypatch.setattr("api.main.verify_payment_signature", fake_verify)
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    verify_req = {"order_id": "order_123", "payment_id": "pay_123", "signature": "sig"}
    response = client.post("/verify-payment", json=verify_req, headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())
    assert response.status_code == 200
    app.dependency_overrides = {}

def test_verify_payment_failure(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.payments_helper.verify_payment_signature", return_value=False)
    verify_req = {"order_id": "order_123", "payment_id": "pay_123", "signature": "sig"}
    response = client.post("/verify-payment", json=verify_req, headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())
    assert response.status_code == 400
    app.dependency_overrides = {}

def test_pay_endpoint_success(mocker):
    app.dependency_overrides[any_authenticated] = fake_any_authenticated
    mocker.patch("common.payments_helper.payment_processor.handle_payment", return_value={"status": "success"})
    pay_req = {
        "amount": 100,
        "currency": "INR",
        "order_id": 123,
        "user_id": 42,
        "gateway": "razorpay",
        "payment_method": "card"
    }
    response = client.post("/api/pay", json=pay_req, headers={"Authorization": "Bearer dummy"})
    print(response.status_code, response.json())
    assert response.status_code == 200
    app.dependency_overrides = {}

