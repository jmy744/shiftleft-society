"""Compatibility entry point for the unified idempotent schema."""
import asyncio
from database import init_db

if __name__ == "__main__":
    asyncio.run(init_db())
    print("Database schema is current (v5).")
