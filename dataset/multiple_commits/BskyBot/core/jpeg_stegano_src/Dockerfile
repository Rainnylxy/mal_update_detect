# Use the official Python 2.7 image
FROM python:2.7

# Set the working directory
WORKDIR /app

# Install system dependencies required for PIL (used by steganography)
RUN apt-get update && apt-get install -y \
    libjpeg-dev \
    zlib1g-dev \
    && apt-get clean

# Install the steganography library
RUN pip install steganography

# Copy the encode/decode script into the container
COPY docker_main.py .

# Install any additional dependencies if needed
RUN pip install argparse

# Define the entrypoint for the container
ENTRYPOINT ["python", "docker_main.py"]
