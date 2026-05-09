import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    MIMO_API_KEY: str = os.getenv("MIMO_API_KEY", "")
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", 8000))
    DEBUG: bool = bool(os.getenv("DEBUG", "false").lower() == "true")

settings = Settings()
