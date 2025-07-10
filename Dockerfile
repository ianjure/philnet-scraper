# Use official Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install minimal dependencies needed for Playwright + Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg unzip wget \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2 \
    libpangocairo-1.0-0 libxss1 libgtk-3-0 libx11-xcb1 \
    libxshmfence1 libglu1-mesa xvfb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (chromium)
RUN playwright install chromium
COPY . .

# Run the script
CMD ["python", "main.py"]
