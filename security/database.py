import os
from decouple import Config, RepositoryEnv
from mysql.connector import pooling
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
load_dotenv()

# Load config from oskus-sports.properties
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.abspath(os.path.join(BASE_DIR, "../resources/oskus-sports.properties"))
config = Config(RepositoryEnv(CONFIG_PATH))

# Database credentials from config
DB_HOST = config("DB_HOST")
DB_PORT = config("DB_PORT")
DB_USER = config("DB_USER")
DB_PASSWORD = config("DB_PASSWORD")
DB_NAME = config("DB_NAME")

# ---------- SQLAlchemy Setup ----------
DATABASE_URL= f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------- mysql.connector Pooling ----------
class Database:
    def __init__(self):
        self.pool = pooling.MySQLConnectionPool(
            pool_name="mypool",
            pool_size=5,
            host=DB_HOST,
            port=int(DB_PORT),
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

    def get_connection(self):
        return self.pool.get_connection()

# ---------- Dependency for FastAPI ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


