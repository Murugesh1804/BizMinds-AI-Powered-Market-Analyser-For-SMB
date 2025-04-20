from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List

from app.services.google_maps_service import get_nearby_places
from app.utils.helpers import validate_location, format_json_response, dataframe_to_dict

router = APIRouter()

@router.get("")
async def get_nearby_landmarks(
    location: str = Query(..., description="Location (city name or lat,lng)"),
    types: Optional[str] = Query("school,hospital,shopping_mall,bus_station,train_station", 
                               description="Comma-separated list of landmark types")
):
    # Validate location
    validate_location(location)
    
    landmark_types = types.split(",")
    results = []
    
    try:
        for landmark_type in landmark_types:
            landmark_df = get_nearby_places(location, place_type=landmark_type.strip())
            
            if not landmark_df.empty:
                # Add type column
                landmark_df['type'] = landmark_type.strip()
                
                # Convert to list of dicts and add to results
                landmarks = dataframe_to_dict(landmark_df)
                results.extend(landmarks)
        
        return format_json_response(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
