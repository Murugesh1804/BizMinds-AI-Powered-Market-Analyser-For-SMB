import json
import pandas as pd
from fastapi import HTTPException

def validate_location(location: str):
    if not location:
        raise HTTPException(status_code=400, detail="Location parameter is required")
    
    # Check if location is lat,lng format
    if "," in location:
        try:
            lat, lng = location.split(",")
            float(lat.strip())
            float(lng.strip())
            return True
        except ValueError:
            pass
    
    # Otherwise assume it's a text location (will be geocoded by services)
    return True

def format_json_response(data):
    
    return json.loads(json.dumps(data, default=str))

def dataframe_to_dict(df):
    
    if isinstance(df, pd.DataFrame):
        return df.to_dict(orient="records")
    return df
