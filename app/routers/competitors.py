from fastapi import APIRouter, Query, HTTPException
from app.services.google_maps_service import get_nearby_places
from app.utils.helpers import validate_location, format_json_response, dataframe_to_dict

router = APIRouter()

@router.get("")
async def get_competitor_insights(
    location: str = Query(..., description="Location (city name or lat,lng)"),
    category: str = Query(..., description="Business category to analyze")
):
    # Validate location
    validate_location(location)
    
    try:
        # Get nearby competitors
        competitors_df = get_nearby_places(location, keyword=category)
        
        if competitors_df.empty:
            return {
                "total": 0,
                "avg_rating": 0,
                "avg_reviews": 0,
                "details": []
            }
        
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
        
        return format_json_response(response)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))