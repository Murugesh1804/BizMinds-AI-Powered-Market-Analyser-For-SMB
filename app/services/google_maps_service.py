import googlemaps
from config.settings import GOOGLE_MAPS_API_KEY, MAPS_RADIUS
from fastapi import HTTPException
import pandas as pd

# Initialize Google Maps client
try:
    gmaps = googlemaps.Client(key=GOOGLE_MAPS_API_KEY)
except Exception as e:
    raise Exception(f"Failed to initialize Google Maps client: {e}")

def geocode_location(location):
    
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
            raise HTTPException(status_code=404, detail=f"Location not found: {location}")
        
        # Get the coordinates
        location_coords = geocode_result[0]['geometry']['location']
        return location_coords
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Geocoding error: {str(e)}")

def get_nearby_places(location, place_type=None, keyword=None, radius=MAPS_RADIUS):
    
    coords = geocode_location(location)
    
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
        
        return pd.DataFrame(places) if places else pd.DataFrame()
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Google Places API error: {str(e)}")

def get_place_details(place_id):
    
    try:
        place_details = gmaps.place(place_id=place_id)
        return place_details.get('result', {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching place details: {str(e)}")

def get_category_trends(location, radius=MAPS_RADIUS):

    coords = geocode_location(location)
    
    # Place types to search for
    business_types = [
        'restaurant', 'cafe', 'store', 'grocery_or_supermarket', 
        'clothing_store', 'electronics_store', 'pharmacy', 'bakery',
        'book_store', 'convenience_store', 'department_store', 'food'
    ]
    
    trends = {}
    
    for b_type in business_types:
        try:
            places = gmaps.places_nearby(
                location=(coords['lat'], coords['lng']),
                radius=radius,
                type=b_type
            )
            trends[b_type] = len(places.get('results', []))
        except Exception as e:
            trends[b_type] = 0
    
    # Sort by count (descending)
    sorted_trends = {k: v for k, v in sorted(trends.items(), key=lambda x: x[1], reverse=True)}
    
    return {
        "most_common": list(sorted_trends.keys())[:3],
        "least_common": list(sorted_trends.keys())[-3:],
        "all_categories": sorted_trends
    }
