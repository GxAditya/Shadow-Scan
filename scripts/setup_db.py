import os
import sys
import logging
from dotenv import load_dotenv

# Add parent directory to path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_database():
    """Create database tables based on SQLAlchemy models"""
    try:
        # Load environment variables
        load_dotenv()
        
        # Check if DATABASE_URL is set
        if not os.environ.get("DATABASE_URL"):
            logger.error("DATABASE_URL environment variable is not set. Please set it before running this script.")
            sys.exit(1)
            
        logger.info("Creating database tables...")
        with app.app_context():
            db.create_all()
        logger.info("Database tables created successfully!")
        
    except Exception as e:
        logger.error(f"Error setting up database: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    setup_database()