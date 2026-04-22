# Step 1: Base image
FROM python:3.11-slim

# Step 2: Set working directory
WORKDIR /app

# Step 3: Copy requirements (agar tumhari requirements.txt hai)
COPY requirements.txt .

# Step 4: Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy project files
COPY . .
#expose port
EXPOSE 5000
# Step 6: Run server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "5000"]
