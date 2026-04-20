# Use Python 3.11 - The most stable version for your app
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application code
COPY . .

# Create uploads folder
RUN mkdir -p uploads

# Expose the port Render expects
EXPOSE 10000

# Run the app with gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]
