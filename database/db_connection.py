import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

# Load environment variables from the project root
PROJECT_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

load_dotenv(os.path.join(PROJECT_DIR, ".env"))

# Read database credentials
DATABASE_URL = URL.create(
    drivername="postgresql+psycopg2",
    username=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT", "5432")),
    database=os.getenv("DB_NAME")
)

# Create database engine
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)


def test_connection():

    try:
        with engine.connect() as connection:

            result = connection.execute(
                text("SELECT current_database();")
            )

            database_name = result.scalar()

            print("Database connection successful!")
            print("Connected database:", database_name)

    except Exception as error:

        print("Database connection failed!")
        print("Error:", error)

        raise


if __name__ == "__main__":
    test_connection()
