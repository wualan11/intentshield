FROM python:3.12-slim

WORKDIR /app

# 智链盾为纯 Python 标准库实现（http.server + sqlite3），无第三方运行依赖
COPY . /app

# 云平台（Render / Koyeb 等）通过 PORT 环境变量注入监听端口；
# 这里给出默认值 10000 与 Render 的默认期望端口对齐，运行时平台注入值优先
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=10000

EXPOSE 10000

CMD ["python", "app.py"]
