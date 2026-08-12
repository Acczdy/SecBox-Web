# SecBox-Web 公网部署镜像
FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai

# 安装 tzdata，使容器日志使用北京时间。
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 依赖层单独缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 运行时卷只保存签名密钥与 OOB 密码哈希，不保存明文密码。
RUN mkdir -p /app/runtime

# 安全加固：非 root 用户运行（所有监听端口 >1024，无需特权）
RUN useradd --system --no-create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

# OOB 回调端口由部署者在项目根目录 .env 中设置，并由 Compose 发布。
EXPOSE 5001

# 首次启动生成运行时密钥，随后自动探测服务器出口公网 IP。
ENTRYPOINT ["python", "docker_entrypoint.py"]

# 单进程（-w 1）：带外凭证与回调结果存于内存；多线程并发由 --threads 提供
# app:app = 模块 app.py 内的 Flask 应用对象 app（缺失则 gunicorn 无可加载应用，容器重启循环）
CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "1", "--threads", "8", \
     "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
