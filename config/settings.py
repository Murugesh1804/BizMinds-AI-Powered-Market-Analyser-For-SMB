import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API keys
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")

# Database settings
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/market_research")

# App settings
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1", "t")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Logging settings
LOG_FILE = os.path.join("app", "logs", "api_requests.log")

# Google Maps API settings
MAPS_RADIUS = 3000  # 3km radius for searches

# Supported languages
SUPPORTED_LANGUAGES = ["en", "hi", "ta"]
