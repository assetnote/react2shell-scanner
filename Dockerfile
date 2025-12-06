FROM python:3.11-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner.py script
COPY scanner.py .

# Set the entrypoint to execute the script with the URL argument
ENTRYPOINT ["python3", "scanner.py"]
