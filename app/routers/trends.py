from fastapi import APIRouter, Query, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel

from app.services.google_maps_service import get_category_trends
from app.utils.helpers import validate_location, format_json_response

router = APIRouter()

@router.get("/categories")
async def get_business_trends(
    location: str = Query(..., description="Location (city name or lat,lng)")
):
    # Validate location
    validate_location(location)
    
    # Get category trends
    try:
        trends = get_category_trends(location)
        return format_json_response(trends)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))