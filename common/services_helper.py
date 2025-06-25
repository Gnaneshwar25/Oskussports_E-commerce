import logging
from security.database import Database

from sqlalchemy.orm import Session
from common.models import User

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import time
from common.logging_config import logger


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sports_ecommerce")

class ProductService:
    def __init__(self, db: Database):
        self.db = db

    def get_all_products(self):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM products WHERE is_deleted = 0")
            products = cursor.fetchall()

            if not products:
                return {"message": "No products found in the database."}

            return {"message": "All products retrieved successfully.", "data": products}
        except Exception as e:
            logger.error(f"Error fetching all products: {e}")
            return {"error": "Failed to retrieve products."}
        finally:
            cursor.close()
            conn.close()

    def search_products(self, name=None, category_id=None, min_price=None, max_price=None, in_stock=None,
                        sort_by="price_asc", limit=10, offset=0):
        """Fetch products based on search criteria"""
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)

        if limit == 0:
            limit = 10  # Default to 10 if 0 is provided

        query = "SELECT * FROM products WHERE is_deleted = 0"
        params = []

        if name:
            query += " AND name LIKE %s"
            params.append(f"%{name}%")
        if category_id:
            query += " AND category_id = %s"
            params.append(category_id)
        if min_price is not None:
            query += " AND price >= %s"
            params.append(min_price)
        if max_price is not None:
            query += " AND price <= %s"
            params.append(max_price)
        if in_stock is not None:
            query += " AND stock > 0" if in_stock else " AND stock = 0"

        # Sorting
        sort_options = {"price_asc": "price ASC", "price_desc": "price DESC"}
        query += f" ORDER BY {sort_options.get(sort_by, 'price ASC')}"

        # Pagination
        query += " LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        try:
            cursor.execute(query, tuple(params))
            products = cursor.fetchall()

            if not products:
                return {"message": "No products found matching your search criteria."}

            return {"message": "Filtered products retrieved successfully.", "data": products}
        except Exception as e:
            logger.error(f"Error fetching filtered products: {e}")
            return {"error": f"Database error: {str(e)}"}
        finally:
            cursor.close()
            conn.close()

    def get_product_by_id(self, product_id: int):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM products WHERE id = %s AND is_deleted = 0", (product_id,))
            product = cursor.fetchone()

            if not product:
                return {"message": f"Product with ID {product_id} was not found."}

            return {"message": "Product details retrieved successfully.", "data": product}
        except Exception as e:
            logger.error(f"Error fetching product {product_id}: {e}")
            return {"error": "Failed to retrieve product details."}
        finally:
            cursor.close()
            conn.close()

    def add_product(self, product):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                INSERT INTO products (name, description, price, stock, category_id, image_url, created_at, updated_at, is_deleted)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), 0)
                """,
                (product.name, product.description, product.price, product.stock, product.category_id, product.image_url)
            )
            conn.commit()
            return {"message": f"Product '{product.name}' added successfully.", "product_id": cursor.lastrowid}
        except Exception as e:
            logger.error(f"Error adding product '{product.name}': {e}")
            return {"error": "Failed to add product."}
        finally:
            cursor.close()
            conn.close()

    def update_product(self, product_id, product):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
            existing = cursor.fetchone()

            if not existing:
                return {"message": f"Product with ID {product_id} does not exist. No update was made."}

            query = """
            UPDATE products SET name = %s, description = %s, price = %s, stock = %s, category_id = %s, image_url = %s, updated_at = NOW()
            WHERE id = %s
            """
            cursor.execute(query, (product.name, product.description, product.price, product.stock, product.category_id, product.image_url, product_id))
            conn.commit()

            return {"message": f"Product '{product.name}' has been updated successfully."}
        except Exception as e:
            logger.error(f"Error updating product {product_id}: {e}")
            return {"error": "Failed to update product."}
        finally:
            cursor.close()
            conn.close()

    def delete_product(self, product_id: int):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE products SET is_deleted = 1 WHERE id = %s", (product_id,))
            conn.commit()

            return {"message": f"Product with ID {product_id} has been marked as deleted."}
        except Exception as e:
            logger.error(f"Error deleting product {product_id}: {e}")
            return {"error": "Failed to delete product."}
        finally:
            cursor.close()
            conn.close()


class CategoryService:
    def __init__(self, db: Database):
        self.db = db

    def get_all_categories(self):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM categories")
            categories = cursor.fetchall()

            if not categories:
                return {"message": "No categories found in the database."}

            return {"message": "All categories retrieved successfully.", "data": categories}
        except Exception as e:
            logger.error(f"Error fetching categories: {e}")
            return {"error": "Failed to retrieve categories."}
        finally:
            cursor.close()
            conn.close()

    def get_category_by_id(self, category_id: int):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
            category = cursor.fetchone()

            if not category:
                return {"message": f"Category with ID {category_id} was not found."}

            return {"message": "Category details retrieved successfully.", "data": category}
        except Exception as e:
            logger.error(f"Error fetching category {category_id}: {e}")
            return {"error": "Failed to retrieve category details."}
        finally:
            cursor.close()
            conn.close()

    def add_category(self, category_name, parent_category_id):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM categories WHERE category_name = %s", (category_name,))
            if cursor.fetchone():
                return {"message": f"Category '{category_name}' already exists. No new category was added."}

            cursor.execute(
                "INSERT INTO categories (category_name, parent_category_id, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                (category_name, parent_category_id))
            conn.commit()
            return {"message": f"Category '{category_name}' has been successfully added.", "category_id": cursor.lastrowid}
        except Exception as e:
            logger.error(f"Error adding category '{category_name}': {e}")
            return {"error": "Failed to add category."}
        finally:
            cursor.close()
            conn.close()

    def update_category(self, category_id, category_name, parent_category_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
            existing = cursor.fetchone()

            if not existing:
                return {"message": f"Category with ID {category_id} does not exist. No update was made."}

            query = "UPDATE categories SET category_name = %s, parent_category_id = %s, updated_at = NOW() WHERE category_id = %s"
            cursor.execute(query, (category_name, parent_category_id, category_id))
            conn.commit()

            return {"message": f"Category '{category_name}' has been updated successfully."}
        except Exception as e:
            logger.error(f"Error updating category {category_id}: {e}")
            return {"error": "Failed to update category."}
        finally:
            cursor.close()
            conn.close()

    def delete_category(self, category_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM categories WHERE category_id = %s", (category_id,))
            existing = cursor.fetchone()

            if not existing:
                return {"message": f"Category with ID {category_id} was not found. No deletion was performed."}

            cursor.execute("DELETE FROM categories WHERE category_id = %s", (category_id,))
            conn.commit()

            return {"message": f"Category with ID {category_id} has been deleted successfully."}
        except Exception as e:
            logger.error(f"Error deleting category {category_id}: {e}")
            return {"error": "Failed to delete category."}
        finally:
            cursor.close()
            conn.close()



def get_all_users(db: Session):
    return db.query(User).all()

def disable_user(db: Session, user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_active = False
        db.commit()
        return True
    return False


def delete_user(db: Session, user_id: int) -> bool:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False


    for token in user.active_tokens:
        db.delete(token)

    db.delete(user)
    db.commit()
    return True


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000

        logger.info(f"{request.method} {request.url.path} -> Status: {response.status_code} | Time: {process_time:.2f} ms")

        return response






