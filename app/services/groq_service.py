import requests
import json
from fastapi import HTTPException
from config.settings import GROQ_API_KEY

def generate_business_strategy(data):
    
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured")
    
    # Extract data
    location = data.get("location", "")
    category = data.get("category", "")
    competitors = data.get("competitors", {})
    landmarks = data.get("landmarks", [])
    
    # Create prompt for the LLM
    prompt = """
    Generate a detailed business strategy for a {category} business in {location}.
    
    Market Information:
    - Number of competitors: {competitors.get('total', 0)}
    - Average competitor rating: {competitors.get('avg_rating', 0)}
    - Average review count: {competitors.get('avg_reviews', 0)}
    
    Nearby landmarks:
    {json.dumps(landmarks, indent=2)}
    
    Provide a comprehensive strategy including:
    1. Target audience analysis
    2. Unique selling proposition recommendations
    3. Marketing strategies specific to this location
    4. Pricing strategy considering the competition
    5. Business hours optimization
    
    Format the response as structured JSON with these sections."""
    
    # Prepare request to Groq API
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "mixtral-8x7b-32768",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions", 
            headers=headers, 
            json=data,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        # Extract and parse the completion
        strategy_text = result["choices"][0]["message"]["content"]
        
        # Try to parse as JSON or return as text if not valid JSON
        try:
            strategy_json = json.loads(strategy_text)
            return strategy_json
        except json.JSONDecodeError:
            # Return as structured text if not valid JSON
            return {"strategy": strategy_text}
            
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Groq API error: {str(e)}")
