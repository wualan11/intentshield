FROM python:3.12-slim

WORKDIR /app

# 智链盾为纯 Python 标准库实现（http.server + sqlite3），无第三方运行依赖
COPY . /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8800

CMD ["python", "app.py"]
