from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional

from app.services.groq_service import generate_business_strategy
from app.utils.helpers import format_json_response

router = APIRouter()

class StrategyRequest(BaseModel):
    location: str
    category: str
    competitors: Optional[Dict[str, Any]] = None
    landmarks: Optional[List[Dict[str, Any]]] = None

@router.post("")
async def create_business_strategy(request: StrategyRequest):
    try:
        # Generate strategy
        strategy = generate_business_strategy(request.dict())
        
        return format_json_response({
            "location": request.location,
            "category": request.category,
            "strategy": strategy
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    