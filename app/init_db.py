"""Create the tables. Run before starting the server: python -m app.init_db"""
from app.db import init_db

# sthapit27ps

if __name__ == "__main__":
    init_db()
    print("tables ready")
