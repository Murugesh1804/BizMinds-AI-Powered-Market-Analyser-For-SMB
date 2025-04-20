from fastapi import APIRouter, Query, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
import os
from typing import Optional
from pydantic import BaseModel
import json

from app.services.pdf_service import generate_market_report
from app.utils.helpers import validate_location
from config.settings import SUPPORTED_LANGUAGES

router = APIRouter()

class ReportData(BaseModel):
    location: str
    category: Optional[str] = None
    competitors: Optional[dict] = None
    landmarks: Optional[list] = None
    strategy: Optional[dict] = None

def cleanup_temp_file(path: str):
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception as e:
        pass

@router.post("")
async def generate_report(
    data: ReportData,
    background_tasks: BackgroundTasks,
    lang: str = Query("en", description=f"Report language ({', '.join(SUPPORTED_LANGUAGES)})")
):
    # Validate language
    if lang not in SUPPORTED_LANGUAGES:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported language. Supported languages: {', '.join(SUPPORTED_LANGUAGES)}"
        )
    
    try:
        # Generate PDF report
        pdf_path = generate_market_report(data.dict(), lang)
        
        # Add cleanup task
        background_tasks.add_task(cleanup_temp_file, pdf_path)
        
        # Create filename
        location_slug = data.location.replace(" ", "_").replace(",", "-")
        filename = f"market_research_{location_slug}_{lang}.pdf"
        
        # Return file
        return FileResponse(
            path=pdf_path,
            filename=filename,
            media_type="application/pdf",
            background=background_tasks
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("")
async def generate_report_get(
    background_tasks: BackgroundTasks,
    location: str = Query(..., description="Location (city name or lat,lng)"),
    category: Optional[str] = Query(None, description="Business category"),
    lang: str = Query("en", description=f"Report language ({', '.join(SUPPORTED_LANGUAGES)})"),
    data_file: Optional[str] = Query(None, description="Path to JSON data file (optional)")
):
    # Create report data
    report_data = {
        "location": location,
        "category": category
    }
    
    # Load data from file if provided
    if data_file and os.path.exists(data_file):
        try:
            with open(data_file, 'r') as f:
                file_data = json.load(f)
                report_data.update(file_data)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error loading data file: {str(e)}")
    
    # Create ReportData object
    data = ReportData(**report_data)
    
    # Generate report
    return await generate_report(data, background_tasks, lang)
    