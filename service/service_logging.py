import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from common.logging_config import logger

def fetch_data():
    logger.debug("Fetching data from the database")
    return {"data": "Sample Data"}
