# Dockerfile

# Use the official Python image
FROM python:3.12-slim

# Install system dependencies for TShark and other packages
RUN apt-get update && apt-get install -y \
    tshark \
    && rm -rf /var/lib/apt/lists/*  # Clean up unnecessary files to reduce image size

# Set the working directory
WORKDIR /kflow

# Copy the requirements.txt and install dependencies
COPY requirements.txt /kflow/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY . /kflow/

# Set environment variables (Optional)
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Expose the port Flask will run on
EXPOSE 5000

# Command to run the app
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]

# docker run -dt -p 5000:5000 --name kflow-1.1 kflow:1.1
