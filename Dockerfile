# Use official Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install minimal dependencies needed for parsing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libz-dev \
    libarrow-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Run the script
CMD ["python", "main.py"]

