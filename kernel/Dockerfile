FROM python:3.11-slim
WORKDIR /scanner
COPY scanner.py /scanner/scanner.py
ENTRYPOINT ["python", "/scanner/scanner.py"]
CMD ["--post", "http://backend:8000", "--loop", "120"]
