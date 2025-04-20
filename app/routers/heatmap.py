from fastapi import APIRouter, Query, HTTPException
from typing import Optional
import pandas as pd

from app.services.google_maps_service import get_nearby_places, geocode_location
from app.utils.helpers import validate_location, format_json_response, dataframe_to_dict

router = APIRouter()

@router.get("")
async def get_heatmap_data(
    location: str = Query(..., description="Location (city name or lat,lng)"),
    category: str = Query(..., description="Business category to analyze")
):
    # Validate location
    validate_location(location)
    
    try:
        # Get nearby places of the specified category
        places_df = get_nearby_places(location, keyword=category)
        
        if places_df.empty:
            return {"coordinates": [], "center": geocode_location(location)}
        
        # Extract relevant coordinates for heatmap
        coordinates = places_df[['lat', 'lng']].to_dict('records')
        
        return {
            "coordinates": coordinates,
            "center": geocode_location(location),
            "count": len(coordinates)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
