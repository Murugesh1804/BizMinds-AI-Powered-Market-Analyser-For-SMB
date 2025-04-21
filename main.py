import os
import json
import time
import logging
import sqlite3
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests
import pandas as pd
import googlemaps
from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from collections import Counter
import jwt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from io import BytesIO

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
DATABASE_PATH = os.getenv("DATABASE_PATH", "market_research.db")
MAPS_RADIUS = 3000  # 3km radius for searches
LOG_FILE = "api_requests.log"
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_EXPIRATION = 24  # hours

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("market_research_api")

# Initialize Google Maps client
try:
    gmaps = googlemaps.Client(key=GOOGLE_MAPS_API_KEY)
except Exception as e:
    logger.error(f"Failed to initialize Google Maps client: {e}")
    raise Exception(f"Failed to initialize Google Maps client: {e}")

# --- SQLite Database Setup ---
def get_db():
    """Get database connection, creating it if it doesn't exist"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row  # This enables accessing columns by name
    return db

def init_db():
    """Initialize the database with required tables"""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    business_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create business_strategies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS business_strategies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    business_type TEXT NOT NULL,
                    location_name TEXT NOT NULL,
                    location_coords TEXT NOT NULL,
                    trend_data TEXT,  -- JSON formatted string
                    competitor_data TEXT,  -- JSON formatted string
                    strategy TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create analyzed_locations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    location_coords TEXT NOT NULL,
                    location_name TEXT,
                    trend_data TEXT,  -- JSON formatted string
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    UNIQUE(user_id, location_coords)
                )
            ''')
            
            # Create heatmap_data table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS heatmap_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    location TEXT NOT NULL,
                    category TEXT NOT NULL,
                    heatmap_data TEXT,  -- JSON formatted string
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create competitor_insights table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS competitor_insights (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    location TEXT NOT NULL,
                    category TEXT NOT NULL,
                    insight_data TEXT,  -- JSON formatted string
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create landmark_data table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS landmark_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    business TEXT NOT NULL,
                    location TEXT NOT NULL,
                    landmark_data TEXT,  -- JSON formatted string
                    recommendation TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create generated_reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS generated_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    report_name TEXT NOT NULL, 
                    report_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            conn.commit()
            logger.info("Successfully initialized SQLite database")
    except Exception as e:
        logger.error(f"Failed to initialize SQLite database: {e}")
        raise

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize database when the application starts
with app.app_context():
    init_db()

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection when app context ends"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- Authentication Functions ---
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(user_id):
    """Generate JWT token for user"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    """Verify JWT token and return user_id if valid"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def auth_required(func):
    """Decorator for routes that require authentication"""
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401
        
        token = token.split(' ')[1]
        user_id = verify_token(token)
        
        if not user_id:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        # Add user_id to the request context
        request.user_id = user_id
        return func(*args, **kwargs)
    
    # Preserve the endpoint name for Flask
    wrapper.__name__ = func.__name__
    return wrapper

# --- Utility Functions ---
def log_request(req):
    """Log API request to file"""
    timestamp = datetime.now().isoformat()
    client_host = request.remote_addr or "unknown"
    
    # Get query parameters
    params = dict(request.args)
    
    log_data = {
        "timestamp": timestamp,
        "method": request.method,
        "url": request.url,
        "path": request.path,
        "params": params,
        "client_ip": client_host,
        "user_agent": request.headers.get("user-agent", "unknown")
    }
    
    # Log to file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_data) + "\n")
    
    logger.info(f"{request.method} {request.path}")

def validate_location(location: str):
    """Validate location format (city, state or latitude,longitude)"""
    if not location:
        return False, "Location parameter is required"
    
    # Check if location is lat,lng format
    if "," in location:
        try:
            lat, lng = location.split(",")
            float(lat.strip())
            float(lng.strip())
            return True, "Valid location"
        except ValueError:
            pass
    
    # Otherwise assume it's a text location (will be geocoded by services)
    return True, "Valid location"

def format_json_response(data):
    """Format data as clean JSON response"""
    return json.loads(json.dumps(data, default=str))

def dataframe_to_dict(df):
    """Convert pandas DataFrame to dictionary for JSON response"""
    if isinstance(df, pd.DataFrame):
        return df.to_dict(orient="records")
    return df

# --- Google Maps Service Functions ---
def geocode_location(location):
    """Convert location string to coordinates"""
    # Check if location is already in lat,lng format
    if "," in location:
        try:
            lat, lng = location.split(",")
            return {"lat": float(lat.strip()), "lng": float(lng.strip())}
        except ValueError:
            pass

    # Geocode the location string
    try:
        geocode_result = gmaps.geocode(location)
        if not geocode_result:
            return None, "Location not found"
        
        # Get the coordinates
        location_coords = geocode_result[0]['geometry']['location']
        return location_coords, None
    except Exception as e:
        return None, f"Geocoding error: {str(e)}"

def get_nearby_places(location, place_type=None, keyword=None, radius=MAPS_RADIUS):
    """Get nearby places based on type or keyword"""
    coords, error = geocode_location(location)
    if error:
        return None, error
    
    try:
        places_result = gmaps.places_nearby(
            location=(coords['lat'], coords['lng']),
            radius=radius,
            type=place_type,
            keyword=keyword
        )
        
        # Transform to pandas DataFrame for easier manipulation
        places = []
        for place in places_result.get('results', []):
            places.append({
                'name': place.get('name'),
                'place_id': place.get('place_id'),
                'lat': place['geometry']['location']['lat'],
                'lng': place['geometry']['location']['lng'],
                'rating': place.get('rating', 0),
                'user_ratings_total': place.get('user_ratings_total', 0),
                'vicinity': place.get('vicinity'),
                'types': place.get('types', [])
            })
        
        return pd.DataFrame(places) if places else pd.DataFrame(), None
    
    except Exception as e:
        return None, f"Google Places API error: {str(e)}"

# --- Request logging middleware ---
@app.before_request
def before_request():
    log_request(request)

# --- API Endpoints ---
@app.route("/")
def root():
    return jsonify({"message": "Market Research API for competitor analysis and heatmap generation"})

@app.route("/health")
def health_check():
    return jsonify({"status": "healthy"})

# --- Authentication Endpoints ---
@app.route("/register", methods=["POST"])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        business_name = data.get("business_name", "")
        
        # Validate inputs
        if not username or not password or not email:
            return jsonify({"error": "Username, password, and email are required"}), 400
        
        # Check if username or email already exists
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            return jsonify({"error": "Username or email already exists"}), 409
        
        # Hash password and create user
        password_hash = hash_password(password)
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, business_name) VALUES (?, ?, ?, ?)",
            (username, password_hash, email, business_name)
        )
        db.commit()
        
        # Get the new user's ID
        user_id = cursor.lastrowid
        
        # Generate token
        token = generate_token(user_id)
        
        return jsonify({
            "message": "User registered successfully",
            "user_id": user_id,
            "token": token
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    """Log in a user"""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        
        # Validate inputs
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        # Check credentials
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user or user['password_hash'] != hash_password(password):
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Generate token
        token = generate_token(user['id'])
        
        return jsonify({
            "message": "Login successful",
            "user_id": user['id'],
            "username": user['username'],
            "business_name": user['business_name'],
            "token": token
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/user-profile", methods=["GET"])
@auth_required
def get_user_profile():
    """Get user profile information"""
    try:
        user_id = request.user_id
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT id, username, email, business_name, created_at FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "business_name": user['business_name'],
            "created_at": user['created_at']
        })
        
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/competitor-insights")
@auth_required
def get_competitor_insights():
    """Get insights about competitors in the area"""
    # Get parameters
    location = request.args.get("location", "")
    category = request.args.get("category", "")
    user_id = request.user_id
    
    # Validate parameters
    is_valid, error_msg = validate_location(location)
    if not is_valid:
        return jsonify({"error": error_msg}), 400
    
    if not category:
        return jsonify({"error": "Category parameter is required"}), 400
    
    try:
        # Get nearby competitors
        competitors_df, error = get_nearby_places(location, keyword=category)
        if error:
            return jsonify({"error": error}), 500
        
        response = {}
        
        if competitors_df.empty:
            response = {
                "total": 0,
                "avg_rating": 0,
                "avg_reviews": 0,
                "details": []
            }
        else:
            # Calculate insights
            total = len(competitors_df)
            avg_rating = competitors_df['rating'].mean() if 'rating' in competitors_df.columns else 0
            avg_reviews = competitors_df['user_ratings_total'].mean() if 'user_ratings_total' in competitors_df.columns else 0
            
            # Format response
            response = {
                "total": total,
                "avg_rating": round(float(avg_rating), 2),
                "avg_reviews": round(float(avg_reviews), 2),
                "details": dataframe_to_dict(competitors_df)
            }
        
        # Store insights in database
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO competitor_insights (user_id, location, category, insight_data) VALUES (?, ?, ?, ?)",
            (user_id, location, category, json.dumps(response))
        )
        db.commit()
        
        return jsonify(format_json_response(response))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/heatmap")
@auth_required
def get_heatmap_data():
    """Get coordinates of nearby businesses of the same category for heatmap generation"""
    # Get parameters
    location = request.args.get("location", "")
    category = request.args.get("category", "")
    user_id = request.user_id
    
    # Validate parameters
    is_valid, error_msg = validate_location(location)
    if not is_valid:
        return jsonify({"error": error_msg}), 400
    
    if not category:
        return jsonify({"error": "Category parameter is required"}), 400
    
    try:
        # Get nearby places of the specified category
        places_df, error = get_nearby_places(location, keyword=category)
        if error:
            return jsonify({"error": error}), 500
        
        coords, geocode_error = geocode_location(location)
        if geocode_error:
            return jsonify({"error": geocode_error}), 500
        
        response = {}
            
        if places_df.empty:
            response = {
                "coordinates": [],
                "center": coords,
                "count": 0
            }
        else:
            # Extract relevant coordinates for heatmap
            coordinates = places_df[['lat', 'lng']].to_dict('records')
            
            response = {
                "coordinates": coordinates,
                "center": coords,
                "count": len(coordinates)
            }
        
        # Store heatmap data in database
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO heatmap_data (user_id, location, category, heatmap_data) VALUES (?, ?, ?, ?)",
            (user_id, location, category, json.dumps(response))
        )
        db.commit()
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def call_groq_ai(business, landmark_data, user_id=None):
    user_context = ""
    if user_id:
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT business_name FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if user and user['business_name']:
                user_context = f"For the business '{user['business_name']}', "
        except Exception as e:
            logger.error(f"Error getting user context: {e}")
    
    prompt = f"""
    {user_context}I am opening a new business: '{business}'.
    Based on the nearby landmarks data: {landmark_data},
    suggest the best location (lat/lng) where customer footfall is likely to be highest.
    Return only the coordinates and a short explanation.
    """

    headers = {
        "Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "llama3-70b-8192",
        "messages": [
            {"role": "system", "content": "You are a helpful business advisor with geospatial reasoning."},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data)
        response.raise_for_status()

        result = response.json()
        if 'choices' in result and result['choices']:
            return result['choices'][0]['message']['content']
        else:
            return f"Groq API Error: Unexpected response format\n{result}"

    except requests.exceptions.RequestException as e:
        return f"HTTP error from Groq API: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"


def search_nearby(location, place_type):
    endpoint = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
    params = {
        "location": location,
        "radius": 3000,  # in meters
        "type": place_type,
        "key": GOOGLE_MAPS_API_KEY
    }
    response = requests.get(endpoint, params=params)
    return response.json().get("results", [])

@app.route("/landmark-mapper", methods=["POST"])
@auth_required
def landmark_mapper():
    data = request.get_json()
    business = data.get("business")
    base_location = data.get("location")
    user_id = request.user_id

    if not business:
        return jsonify({"error": "Please provide a business type or name"}), 400

    # Collect landmark data
    hostels = search_nearby(base_location, "lodging")
    schools = search_nearby(base_location, "school")
    apartments = search_nearby(base_location, "apartment")

    landmark_data = {
        "hostels": [h["name"] for h in hostels[:5]],
        "schools": [s["name"] for s in schools[:5]],
        "apartments": [a["name"] for a in apartments[:5]]
    }

    # Use Groq to decide the best location
    ai_response = call_groq_ai(business, landmark_data, user_id)

    # Save to database
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO landmark_data (user_id, business, location, landmark_data, recommendation) VALUES (?, ?, ?, ?, ?)",
        (user_id, business, base_location, json.dumps(landmark_data), ai_response)
    )
    db.commit()

    return jsonify({
        "business": business,
        "base_location": base_location,
        "landmarks_analyzed": landmark_data,
        "recommended_location": ai_response
    })

def get_business_trends(location, radius=3000, user_id=None):
    """
    Analyze business types in the given area using Google Places API.
    """
    endpoint = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
    all_types = []

    params = {
        "location": location,
        "radius": radius,
        "type": "establishment",
        "key": GOOGLE_MAPS_API_KEY
    }

    while True:
        response = requests.get(endpoint, params=params)
        data = response.json()

        for result in data.get("results", []):
            all_types.extend(result.get("types", []))

        # Paginate if more results are available
        next_page_token = data.get("next_page_token")
        if next_page_token:
            time.sleep(2)  # wait for token to activate
            params["pagetoken"] = next_page_token
        else:
            break

    # Analyze type frequency
    type_counts = Counter(all_types)

    if not type_counts:
        return {"error": "No business data found in this location."}

    most_common = type_counts.most_common(5)
    least_common = sorted(type_counts.items(), key=lambda x: x[1])[:5]

    result = {
        "location": location,
        "top_categories": most_common,
        "untapped_categories": least_common
    }
    
    # If user_id is provided, store this data
    if user_id:
        try:
            db = get_db()
            cursor = db.cursor()
            
            # Get location name
            try:
                coords, error = geocode_location(location)
                if not error:
                    reverse_geocode = gmaps.reverse_geocode((coords['lat'], coords['lng']))
                    location_name = reverse_geocode[0]['formatted_address'] if reverse_geocode else location
                else:
                    location_name = location
            except Exception:
                location_name = location
                
            cursor.execute(
                "INSERT OR REPLACE INTO analyzed_locations (user_id, location_coords, location_name, trend_data) VALUES (?, ?, ?, ?)",
                (user_id, location, location_name, json.dumps(result))
            )
            db.commit()
        except Exception as e:
            logger.error(f"Failed to store business trends: {e}")
    
    return result

@app.route('/business-trends', methods=['POST'])
@auth_required
def business_category_trends():
    data = request.get_json()
    location = data.get("location")  # Should be in "lat,lng" format
    radius = data.get("radius", 3000)
    user_id = request.user_id

    if not location:
        return jsonify({"error": "Missing 'location' in request body"}), 400

    trends = get_business_trends(location, radius, user_id)
    return jsonify(trends)

# --- Strategy Generator with User Context ---

def call_groq_for_strategy(business_type, location_name, location_coords, trend_data, competitor_data, user_id=None):
    """Generate business strategy using Groq API"""
    # Get user context if available
    user_context = ""
    if user_id:
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT business_name FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if user and user['business_name']:
                user_context = f"For the business '{user['business_name']}', "
        except Exception as e:
            logger.error(f"Error getting user context: {e}")
    
    # Format the data for the prompt
    trend_summary = "No trend data available."
    if trend_data:
        top_categories = ", ".join([f"{cat} ({count} instances)" for cat, count in trend_data.get("top_categories", [])])
        untapped = ", ".join([f"{cat} ({count} instances)" for cat, count in trend_data.get("untapped_categories", [])])
        trend_summary = f"Top business categories in the area: {top_categories}. Untapped opportunities: {untapped}."
    
    competitor_summary = "No competitor data available."
    if competitor_data:
        total = competitor_data.get("total", 0)
        avg_rating = competitor_data.get("avg_rating", 0)
        avg_reviews = competitor_data.get("avg_reviews", 0)
        competitor_summary = f"There are {total} similar businesses with average rating of {avg_rating}/5 and {avg_reviews} reviews on average."
    
    # Build the prompt
    prompt = f"""
    {user_context}I'm planning to open a {business_type} business in {location_name} (coordinates: {location_coords}).
    
    Local market data:
    {trend_summary}
    
    Competitor analysis:
    {competitor_summary}
    
    Please provide:
    1. A business strategy recommendation (3 key points)
    2. Suggested unique selling proposition
    3. Target customer demographic
    4. One innovative location-specific marketing idea
    """
    
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "llama3-70b-8192",
        "messages": [
            {"role": "system", "content": "You are a business strategy expert who provides concise, actionable advice."},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data)
        response.raise_for_status()

        result = response.json()
        if 'choices' in result and result['choices']:
            return result['choices'][0]['message']['content']
        else:
            return f"Groq API Error: Unexpected response format\n{result}"
    
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP error from Groq API: {e}")
        return f"HTTP error from Groq API: {e}"
    except Exception as e:
        logger.error(f"Error generating strategy: {e}")
        return f"Error generating strategy: {e}"

def generate_business_strategy(location_name, location_coords, business_type, user_id, trend_data=None, competitor_data=None):
    """Generate a business strategy using Groq based on trend and competitor data"""
    # Call Groq API
    strategy = call_groq_for_strategy(
        business_type, 
        location_name, 
        location_coords, 
        trend_data, 
        competitor_data,
        user_id
    )
    
    # Store in SQLite
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Convert dict data to JSON strings for storage
        trend_data_json = json.dumps(trend_data) if trend_data else None
        competitor_data_json = json.dumps(competitor_data) if competitor_data else None
        
        cursor.execute('''
            INSERT INTO business_strategies 
            (user_id, business_type, location_name, location_coords, trend_data, competitor_data, strategy)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, business_type, location_name, location_coords, trend_data_json, competitor_data_json, strategy))
        
        db.commit()
        strategy_id = cursor.lastrowid
    except Exception as e:
        logger.error(f"SQLite error: {str(e)}")
        strategy_id = None
    
    return {
        "strategy_id": strategy_id,
        "business_type": business_type,
        "location": location_name,
        "strategy": strategy
    }
@app.route("/generate-strategy", methods=["POST"])
@auth_required
def strategy_generator_endpoint():
    """Endpoint to generate a business strategy"""
    data = request.get_json()
    user_id = request.user_id
    
    # Required parameters
    location = data.get("location")  # Can be text or "lat,lng"
    business_type = data.get("business_type")
    
    # Validate parameters
    if not location:
        return jsonify({"error": "Location parameter is required"}), 400
    if not business_type:
        return jsonify({"error": "Business type parameter is required"}), 400
    
    try:
        # Convert location to coordinates if not already
        coords, error = geocode_location(location)
        if error:
            return jsonify({"error": error}), 400
        
        location_coords = f"{coords['lat']},{coords['lng']}"
        
        # Get location name
        try:
            reverse_geocode = gmaps.reverse_geocode((coords['lat'], coords['lng']))
            location_name = reverse_geocode[0]['formatted_address'] if reverse_geocode else location
        except Exception:
            location_name = location
        
        # Check if we have analyzed this location before
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM analyzed_locations WHERE user_id = ? AND location_coords = ?", 
                     (user_id, location_coords))
        existing_location = cursor.fetchone()
        
        # Get trend data if not already cached
        if existing_location and existing_location['trend_data']:
            trend_data = json.loads(existing_location['trend_data'])
        else:
            trend_data = get_business_trends(location_coords, user_id=user_id)
        
        # Get competitor data
        competitors_df, error = get_nearby_places(location, keyword=business_type)
        if error:
            competitor_data = {"error": error}
        else:
            total = len(competitors_df) if not competitors_df.empty else 0
            avg_rating = competitors_df['rating'].mean() if not competitors_df.empty and 'rating' in competitors_df.columns else 0
            avg_reviews = competitors_df['user_ratings_total'].mean() if not competitors_df.empty and 'user_ratings_total' in competitors_df.columns else 0
            
            competitor_data = {
                "total": total,
                "avg_rating": round(float(avg_rating), 2) if avg_rating else 0,
                "avg_reviews": round(float(avg_reviews), 2) if avg_reviews else 0,
                "details": dataframe_to_dict(competitors_df) if not competitors_df.empty else []
            }
            
            # Store competitor insights
            cursor.execute(
                "INSERT INTO competitor_insights (user_id, location, category, insight_data) VALUES (?, ?, ?, ?)",
                (user_id, location, business_type, json.dumps(competitor_data))
            )
            db.commit()
        
        # Generate strategy
        strategy_result = generate_business_strategy(
            location_name,
            location_coords,
            business_type,
            user_id,
            trend_data,
            competitor_data
        )
        
        # Return combined results
        response = {
            "location": {
                "name": location_name,
                "coordinates": coords
            },
            "business_type": business_type,
            "trends": trend_data,
            "competitors": competitor_data,
            "strategy": strategy_result
        }
        
        return jsonify(format_json_response(response))
        
    except Exception as e:
        logger.error(f"Strategy generation error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/strategies", methods=["GET"])
@auth_required
def list_strategies():
    """List all stored strategies for the authenticated user"""
    try:
        user_id = request.user_id
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM business_strategies WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        
        # Convert SQLite rows to dictionaries
        strategies = []
        for row in cursor.fetchall():
            strategy_dict = dict(row)
            # Parse JSON-formatted fields
            if strategy_dict.get('trend_data'):
                strategy_dict['trend_data'] = json.loads(strategy_dict['trend_data'])
            if strategy_dict.get('competitor_data'):
                strategy_dict['competitor_data'] = json.loads(strategy_dict['competitor_data'])
            strategies.append(strategy_dict)
        
        return jsonify({
            "total": len(strategies),
            "strategies": strategies
        })
    except Exception as e:
        logger.error(f"Error listing strategies: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/strategies/<int:strategy_id>", methods=["GET"])
@auth_required
def get_strategy(strategy_id):
    """Get a specific strategy by ID"""
    try:
        user_id = request.user_id
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM business_strategies WHERE id = ? AND user_id = ?", (strategy_id, user_id))
        
        strategy = cursor.fetchone()
        if not strategy:
            return jsonify({"error": "Strategy not found or unauthorized"}), 404
        
        # Convert SQLite row to dictionary
        strategy_dict = dict(strategy)
        
        # Parse JSON-formatted fields
        if strategy_dict.get('trend_data'):
            strategy_dict['trend_data'] = json.loads(strategy_dict['trend_data'])
        if strategy_dict.get('competitor_data'):
            strategy_dict['competitor_data'] = json.loads(strategy_dict['competitor_data'])
        
        return jsonify(strategy_dict)
    except Exception as e:
        logger.error(f"Error retrieving strategy: {e}")
        return jsonify({"error": str(e)}), 500

# --- Report Generation ---
def generate_pdf_report(user_id):
    """Generate PDF report with all user data"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Get user info
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise Exception("User not found")
        
        # Create a PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Add title
        title_style = styles['Title']
        elements.append(Paragraph(f"Market Research Report for {user['business_name'] or user['username']}", title_style))
        elements.append(Spacer(1, 12))
        
        # Add date
        date_style = styles['Normal']
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", date_style))
        elements.append(Spacer(1, 24))
        
        # Section style
        section_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontSize=14,
            leading=16,
            spaceAfter=10
        )
        
        # Add business strategies
        cursor.execute("SELECT * FROM business_strategies WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        strategies = cursor.fetchall()
        
        if strategies:
            elements.append(Paragraph("Business Strategies", section_style))
            elements.append(Spacer(1, 12))
            
            for strategy in strategies:
                # Strategy header
                elements.append(Paragraph(f"Strategy for {strategy['business_type']} in {strategy['location_name']}", styles['Heading3']))
                
                # Strategy content
                elements.append(Paragraph(strategy['strategy'], styles['Normal']))
                elements.append(Spacer(1, 12))
                
                # Add trend data
                if strategy['trend_data']:
                    trend_data = json.loads(strategy['trend_data'])
                    elements.append(Paragraph("Market Trends:", styles['Heading4']))
                    
                    if 'top_categories' in trend_data:
                        elements.append(Paragraph("Top Business Categories:", styles['Heading4']))
                        top_categories = trend_data['top_categories']
                        data = [[cat, count] for cat, count in top_categories]
                        if data:
                            table = Table([['Category', 'Count']] + data, colWidths=[300, 100])
                            table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (1, 0), colors.grey),
                                ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
                                ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                                ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                                ('BOTTOMPADDING', (0, 0), (1, 0), 12),
                                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                ('BOX', (0, 0), (-1, -1), 1, colors.black),
                                ('GRID', (0, 0), (-1, -1), 1, colors.black)
                            ]))
                            elements.append(table)
                            elements.append(Spacer(1, 12))
                
                # Add competitor data
                if strategy['competitor_data']:
                    competitor_data = json.loads(strategy['competitor_data'])
                    elements.append(Paragraph("Competitor Analysis:", styles['Heading4']))
                    elements.append(Paragraph(f"Total Competitors: {competitor_data.get('total', 0)}", styles['Normal']))
                    elements.append(Paragraph(f"Average Rating: {competitor_data.get('avg_rating', 0)}", styles['Normal']))
                    elements.append(Paragraph(f"Average Reviews: {competitor_data.get('avg_reviews', 0)}", styles['Normal']))
                    elements.append(Spacer(1, 12))
                
                elements.append(Spacer(1, 24))
        
        # Add heatmap data
        cursor.execute("SELECT * FROM heatmap_data WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        heatmaps = cursor.fetchall()
        
        if heatmaps:
            elements.append(Paragraph("Heatmap Analysis", section_style))
            elements.append(Spacer(1, 12))
            
            for heatmap in heatmaps:
                elements.append(Paragraph(f"Heatmap for {heatmap['category']} in {heatmap['location']}", styles['Heading3']))
                
                heatmap_data = json.loads(heatmap['heatmap_data'])
                elements.append(Paragraph(f"Number of Locations: {heatmap_data.get('count', 0)}", styles['Normal']))
                elements.append(Paragraph(f"Center Coordinates: {heatmap_data.get('center', {})}", styles['Normal']))
                elements.append(Spacer(1, 12))
        
        # Add landmark data
        cursor.execute("SELECT * FROM landmark_data WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        landmarks = cursor.fetchall()
        
        if landmarks:
            elements.append(Paragraph("Landmark Analysis", section_style))
            elements.append(Spacer(1, 12))
            
            for landmark in landmarks:
                elements.append(Paragraph(f"Landmark Analysis for {landmark['business']} in {landmark['location']}", styles['Heading3']))
                
                if landmark['landmark_data']:
                    landmark_data = json.loads(landmark['landmark_data'])
                    
                    if 'hostels' in landmark_data:
                        elements.append(Paragraph("Nearby Hostels:", styles['Heading4']))
                        for hostel in landmark_data['hostels']:
                            elements.append(Paragraph(f"• {hostel}", styles['Normal']))
                        elements.append(Spacer(1, 6))
                    
                    if 'schools' in landmark_data:
                        elements.append(Paragraph("Nearby Schools:", styles['Heading4']))
                        for school in landmark_data['schools']:
                            elements.append(Paragraph(f"• {school}", styles['Normal']))
                        elements.append(Spacer(1, 6))
                    
                    if 'apartments' in landmark_data:
                        elements.append(Paragraph("Nearby Apartments:", styles['Heading4']))
                        for apartment in landmark_data['apartments']:
                            elements.append(Paragraph(f"• {apartment}", styles['Normal']))
                        elements.append(Spacer(1, 6))
                
                elements.append(Paragraph("Recommendation:", styles['Heading4']))
                elements.append(Paragraph(landmark['recommendation'], styles['Normal']))
                elements.append(Spacer(1, 12))
        
        # Add conclusion
        elements.append(Paragraph("Conclusion", section_style))
        elements.append(Spacer(1, 12))
        
        # Use Groq to generate a conclusion
        conclusion_text = call_groq_for_conclusion(user_id)
        elements.append(Paragraph(conclusion_text, styles['Normal']))
        
        # Build the PDF
        doc.build(elements)
        
        # Get the PDF content
        pdf_content = buffer.getvalue()
        buffer.close()
        
        # Save the PDF file
        filename = f"market_research_report_{user_id}_{int(time.time())}.pdf"
        file_path = os.path.join("reports", filename)
        
        # Ensure directory exists
        os.makedirs("reports", exist_ok=True)
        
        with open(file_path, "wb") as f:
            f.write(pdf_content)
        
        # Save report in database
        cursor.execute(
            "INSERT INTO generated_reports (user_id, report_name, report_path) VALUES (?, ?, ?)",
            (user_id, f"Market Research Report {datetime.now().strftime('%Y-%m-%d')}", file_path)
        )
        db.commit()
        
        return file_path
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise

def call_groq_for_conclusion(user_id):
    """Generate conclusion using Groq API"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Get user info
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        # Get strategies
        cursor.execute("SELECT * FROM business_strategies WHERE user_id = ? ORDER BY created_at DESC LIMIT 3", (user_id,))
        strategies = cursor.fetchall()
        
        strategy_summary = ""
        for strategy in strategies:
            strategy_summary += f"Strategy for {strategy['business_type']} in {strategy['location_name']}: {strategy['strategy'][:200]}...\n"
        
        # Build prompt
        prompt = f"""
        Create a conclusion for a market research report for {user['business_name'] or user['username']}.
        
        Recent strategies analyzed:
        {strategy_summary}
        
        The conclusion should:
        1. Summarize key insights from the data
        2. Provide 2-3 actionable recommendations for next steps
        3. Highlight potential risks and opportunities
        4. Be professional but conversational in tone
        5. Be around 250-300 words
        """
        
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }

        data = {
            "model": "llama3-70b-8192",
            "messages": [
                {"role": "system", "content": "You are a market research expert who creates insightful report conclusions."},
                {"role": "user", "content": prompt}
            ]
        }

        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data)
        response.raise_for_status()

        result = response.json()
        if 'choices' in result and result['choices']:
            return result['choices'][0]['message']['content']
        else:
            return "Unable to generate conclusion. Please review the data and insights in this report to inform your business decisions."
            
    except Exception as e:
        logger.error(f"Error generating conclusion: {e}")
        return "Unable to generate conclusion. Please review the data and insights in this report to inform your business decisions."

@app.route("/generate-report", methods=["POST"])
@auth_required
def generate_report():
    """Generate a comprehensive report for the user"""
    try:
        user_id = request.user_id
        
        # Generate PDF report
        file_path = generate_pdf_report(user_id)
        
        # Return the path to the report
        return jsonify({
            "message": "Report generated successfully",
            "report_path": file_path
        })
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/download-report/<int:report_id>", methods=["GET"])
@auth_required
def download_report(report_id):
    """Download a generated report"""
    try:
        user_id = request.user_id
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM generated_reports WHERE id = ? AND user_id = ?", (report_id, user_id))
        
        report = cursor.fetchone()
        if not report:
            return jsonify({"error": "Report not found or unauthorized"}), 404
        
        # Send the file
        return send_file(report['report_path'], as_attachment=True, download_name=f"{report['report_name']}.pdf")
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports", methods=["GET"])
@auth_required
def list_reports():
    """List all reports for the user"""
    try:
        user_id = request.user_id
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM generated_reports WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        
        reports = []
        for row in cursor.fetchall():
            reports.append({
                "id": row['id'],
                "report_name": row['report_name'],
                "created_at": row['created_at']
            })
        
        return jsonify({
            "total": len(reports),
            "reports": reports
        })
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    if not GOOGLE_MAPS_API_KEY:
        logger.warning("GOOGLE_MAPS_API_KEY not set. API will not function correctly.")
        print("WARNING: GOOGLE_MAPS_API_KEY not set. Please add it to .env file.")
    
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set. Strategy generator will not function correctly.")
        print("WARNING: GROQ_API_KEY not set. Please add it to .env file.")
    
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)
    
    # Initialize the database
    with app.app_context():
        init_db()
        
    # Start the Flask server
    app.run(host="0.0.0.0", port=5000, debug=True)