import configparser
import os
from service.util.sample_helper import get_db_connection  # Import the function

# Load database credentials from properties file
def load_properties(file_path):
    properties = {}
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                properties[key.strip()] = value.strip()
    return properties

config = load_properties("resources/config/oskus-sports.properties")

DB_HOST = config.get("DB_HOST")
DB_USER = config.get("DB_USER")
DB_PASSWORD = config.get("DB_PASSWORD")
DB_NAME = config.get("DB_NAME")


def create_database():
    """Creates the database if it doesn't exist."""
    conn = get_db_connection(DB_HOST, DB_USER, DB_PASSWORD)
    if conn:
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        conn.commit()
        cursor.close()
        conn.close()


def create_orders_table():
    """Creates the orders_table if it doesn't exist."""
    conn = get_db_connection(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    if conn:
        cursor = conn.cursor()
        create_table_query = """
        CREATE TABLE IF NOT EXISTS orders_table (
            order_id INT PRIMARY KEY AUTO_INCREMENT,
            product_id INT,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_amount DECIMAL(10,2),
            shipping_address VARCHAR(200) NOT NULL,
            order_status VARCHAR(100),
            payment_status VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """
        cursor.execute(create_table_query)
        conn.commit()
        cursor.close()
        conn.close()


def write_data(product_id, total_amount, shipping_address, order_status, payment_status):
    """Inserts sample data into the orders_table."""
    conn = get_db_connection(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    if conn:
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO orders_table (product_id, total_amount, shipping_address, order_status, payment_status)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (product_id, total_amount, shipping_address, order_status, payment_status))
        conn.commit()
        cursor.close()
        conn.close()


def read_data():
    """Fetches all data from the orders_table."""
    conn = get_db_connection(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    if conn:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM orders_table")
            results = cursor.fetchall()
        conn.close()
        return results
    return []
