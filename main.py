import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import os

from app.routers import trends, heatmap, landmarks, competitors, strategy, reports
from app.utils.logger import log_request

# Create FastAPI app
app = FastAPI(
    title="Market Research API",
    description="AI-powered market research tool for Indian SMBs",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Modify for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(trends.router, prefix="/trends", tags=["Trends"])
app.include_router(heatmap.router, prefix="/heatmap", tags=["Heatmap"])
app.include_router(landmarks.router, prefix="/landmarks", tags=["Landmarks"])
app.include_router(competitors.router, prefix="/competitor-insights", tags=["Competitors"])
app.include_router(strategy.router, prefix="/strategy", tags=["Strategy"])
app.include_router(reports.router, prefix="/report", tags=["Reports"])

@app.middleware("http")
async def log_requests_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    await log_request(request, process_time)
    return response

@app.get("/")
async def root():
    return {"message": "Welcome to the Market Research API for Indian SMBs"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
