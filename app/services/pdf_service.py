import os
import pandas as pd
import tempfile
from fpdf import FPDF
from fastapi import HTTPException
from datetime import datetime

from app.services.translation_service import translate_text
from config.settings import SUPPORTED_LANGUAGES

class MarketResearchPDF:
    def __init__(self, data, language="en"):
        self.data = data
        self.language = language
        self.pdf = FPDF()
        self.pdf.add_page()
        
        # Set default font
        self.pdf.add_font('DejaVu', '', os.path.join(os.path.dirname(__file__), 'DejaVuSansCondensed.ttf'), uni=True)
        self.pdf.set_font('DejaVu', '', 10)
    
    def translate(self, text):
        """Translate text based on target language"""
        if self.language != "en":
            return translate_text(text, source_lang="en", target_lang=self.language)
        return text
    
    def add_title(self, title):
        translated_title = self.translate(title)
        self.pdf.set_font('DejaVu', '', 16)
        self.pdf.cell(0, 10, translated_title, 0, 1, 'C')
        self.pdf.ln(5)
        self.pdf.set_font('DejaVu', '', 10)
    
    def add_heading(self, heading):
        translated_heading = self.translate(heading)
        self.pdf.set_font('DejaVu', '', 14)
        self.pdf.cell(0, 10, translated_heading, 0, 1, 'L')
        self.pdf.ln(2)
        self.pdf.set_font('DejaVu', '', 10)
    
    def add_text(self, text):
        translated_text = self.translate(text)
        self.pdf.multi_cell(0, 5, translated_text)
        self.pdf.ln(5)
    
    def add_table(self, headers, data):
        # Translate headers
        translated_headers = [self.translate(h) for h in headers]
        
        # Calculate column width
        col_width = self.pdf.w / len(headers)
        
        # Add headers
        self.pdf.set_font('DejaVu', '', 11)
        self.pdf.set_fill_color(200, 220, 255)
        
        for header in translated_headers:
            self.pdf.cell(col_width, 7, header, 1, 0, 'C', 1)
        self.pdf.ln()
        
        # Add data rows
        self.pdf.set_font('DejaVu', '', 10)
        self.pdf.set_fill_color(255, 255, 255)
        
        for row in data:
            for item in row:
                # Convert to string and translate if needed
                cell_text = str(item)
                if isinstance(item, str) and len(cell_text) > 2:  # Only translate longer strings
                    cell_text = self.translate(cell_text)
                self.pdf.cell(col_width, 6, cell_text, 1, 0, 'L')
            self.pdf.ln()
        
        self.pdf.ln(5)
    
    def generate_report(self):
        # Add report title and date
        self.add_title("Market Research Report")
        report_date = datetime.now().strftime("%Y-%m-%d")
        self.add_text(f"{self.translate('Date')}: {report_date}")
        self.add_text(f"{self.translate('Location')}: {self.data.get('location', '')}")
        
        # Add category information
        if 'category' in self.data:
            self.add_text(f"{self.translate('Business Category')}: {self.data.get('category', '')}")
        
        # Add competitor insights
        if 'competitors' in self.data:
            self.add_heading(self.translate("Competitor Analysis"))
            
            competitors = self.data['competitors']
            self.add_text(f"{self.translate('Total Competitors')}: {competitors.get('total', 0)}")
            self.add_text(f"{self.translate('Average Rating')}: {competitors.get('avg_rating', 0)}")
            self.add_text(f"{self.translate('Average Reviews')}: {competitors.get('avg_reviews', 0)}")
            
            # Add competitor table if available
            if 'details' in competitors and competitors['details']:
                headers = ['Name', 'Rating', 'Reviews', 'Address']
                data = [
                    [c.get('name', ''), c.get('rating', ''), c.get('user_ratings_total', ''), c.get('vicinity', '')]
                    for c in competitors['details'][:10]  # Limit to 10 competitors
                ]
                self.add_table(headers, data)
        
        # Add landmarks information
        if 'landmarks' in self.data and self.data['landmarks']:
            self.add_heading(self.translate("Nearby Landmarks"))
            
            landmarks = self.data['landmarks']
            landmarks_data = []
            
            if isinstance(landmarks, list):
                for lm in landmarks[:10]:  # Limit to 10 landmarks
                    if isinstance(lm, dict):
                        landmarks_data.append([
                            lm.get('name', ''), 
                            lm.get('type', ''), 
                            lm.get('vicinity', '')
                        ])
            
            if landmarks_data:
                headers = ['Name', 'Type', 'Address']
                self.add_table(headers, landmarks_data)
        
        # Add strategy insights if available
        if 'strategy' in self.data:
            self.add_heading(self.translate("Business Strategy"))
            
            strategy = self.data['strategy']
            if isinstance(strategy, dict):
                for key, value in strategy.items():
                    if isinstance(value, str):
                        self.add_text(f"{self.translate(key.replace('_', ' ').title())}: {value}")
                    elif isinstance(value, dict):
                        self.add_text(f"{self.translate(key.replace('_', ' ').title())}:")
                        for sub_key, sub_value in value.items():
                            self.add_text(f"� {self.translate(sub_key.replace('_', ' ').title())}: {sub_value}")
                    elif isinstance(value, list):
                        self.add_text(f"{self.translate(key.replace('_', ' ').title())}:")
                        for item in value:
                            self.add_text(f"� {item}")
            elif isinstance(strategy, str):
                self.add_text(strategy)
        
        # Add footer
        self.pdf.set_y(-15)
        self.pdf.set_font('DejaVu', '', 8)
        footer_text = self.translate("Generated by AI-powered Market Research Tool")
        self.pdf.cell(0, 10, footer_text, 0, 0, 'C')
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
            tmp_path = tmp.name
        
        # Save PDF to temp file
        self.pdf.output(tmp_path)
        return tmp_path

def generate_market_report(data, language="en"):
    if language not in SUPPORTED_LANGUAGES:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported language. Supported languages: {', '.join(SUPPORTED_LANGUAGES)}"
        )
    
    try:
        # Create PDF generator
        pdf_generator = MarketResearchPDF(data, language)
        
        # Generate report
        pdf_path = pdf_generator.generate_report()
        
        return pdf_path
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")
