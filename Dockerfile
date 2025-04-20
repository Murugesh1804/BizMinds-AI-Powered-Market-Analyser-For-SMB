FROM python:3.9-slim

    WORKDIR /app

    # Install system dependencies
    RUN apt-get update && apt-get install -y --no-install-recommends         build-essential         && rm -rf /var/lib/apt/lists/*

    # Copy requirements and install dependencies
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # Copy application code
    COPY . .

    # Download DejaVu font for PDF generation
    RUN mkdir -p app/services &&         wget -O app/services/DejaVuSansCondensed.ttf https://github.com/dejavu-fonts/dejavu-fonts/raw/master/ttf/DejaVuSansCondensed.ttf

    # Run the application
    CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
    