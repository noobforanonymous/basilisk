FROM python:3.12-slim
WORKDIR /lab
RUN pip install --no-cache-dir fastapi==0.135.1 uvicorn==0.41.0 websockets==16.0
COPY app.py /lab/app.py
USER 65532:65532
EXPOSE 8765
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8765", "--no-access-log"]
