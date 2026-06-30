FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3001
# analyse a mounted capture, then serve the map:
#   docker run -p 3001:3001 -v $PWD/capture.pcap:/data/capture.pcap strata \
#     sh -c "python run.py analyze /data/capture.pcap && python run.py dashboard"
CMD ["python", "run.py", "dashboard"]
