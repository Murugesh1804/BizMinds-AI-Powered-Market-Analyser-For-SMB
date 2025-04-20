import json
import logging
import os
from datetime import datetime
from fastapi import Request
import aiofiles
from pymongo import MongoClient
from config.settings import LOG_FILE, MONGODB_URI, LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("market_research_api")

# Initialize MongoDB connection for logging
try:
    mongo_client = MongoClient(MONGODB_URI)
    db = mongo_client["market_research"]
    log_collection = db["api_logs"]
    use_mongo = True
    logger.info("MongoDB connected for logging")
except Exception as e:
    logger.warning(f"MongoDB connection failed, using file logs only: {e}")
    use_mongo = False

async def log_request(request: Request, process_time: float):
    timestamp = datetime.now().isoformat()
    client_host = request.client.host if request.client else "unknown"
    
    # Get query parameters
    params = dict(request.query_params)
    
    # Try to get the request body for POST requests
    body = None
    if request.method in ["POST", "PUT"]:
        try:
            body = await request.json()
        except:
            body = "Could not parse body"
    
    log_data = {
        "timestamp": timestamp,
        "method": request.method,
        "url": str(request.url),
        "path": request.url.path,
        "params": params,
        "client_ip": client_host,
        "process_time_ms": round(process_time * 1000, 2),
        "user_agent": request.headers.get("user-agent", "unknown"),
        "body": body
    }
    
    # Log to MongoDB if available
    if use_mongo:
        try:
            log_collection.insert_one(log_data)
        except Exception as e:
            logger.error(f"Failed to log to MongoDB: {e}")
    
    # Always log to file as backup
    async with aiofiles.open(LOG_FILE, "a") as f:
        await f.write(json.dumps(log_data) + "\n")
    
    logger.info(f"{request.method} {request.url.path} - {process_time:.2f}s")
