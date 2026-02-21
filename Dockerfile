# 轻量级方案：无桌面环境，仅 Xvfb 虚拟显示 + Edge
# 使用 debian:bookworm-slim 保证标准 Debian 源可用；Edge 官方仅提供 amd64 包，构建时可传 --build-arg TARGETPLATFORM=linux/arm64 覆盖
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV BROWSER_TYPE=edge

# 单层内完成：仅保留 Edge 直接依赖 + Xvfb/字体，其余由 apt 自动拉取
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gnupg ca-certificates apt-transport-https \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/edge stable main" > /etc/apt/sources.list.d/microsoft-edge.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        xvfb \
        fonts-liberation \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libatspi2.0-0 \
        libcairo2 \
        libcups2 \
        libcurl4 \
        libdbus-1-3 \
        libgbm1 \
        libglib2.0-0 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libudev1 \
        libuuid1 \
        libvulkan1 \
        libx11-6 \
        libxcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxkbcommon0 \
        libxrandr2 \
        libxss1 \
        libxtst6 \
        microsoft-edge-stable \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 3 与 venv（Bookworm 默认 3.11）；用 venv 安装依赖以符合 PEP 668
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv \
    && ln -sf /opt/venv/bin/python3 /usr/local/bin/python

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY server_requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r server_requirements.txt

COPY . .

EXPOSE 8889

COPY docker_startup.sh /
RUN chmod +x /docker_startup.sh

ENTRYPOINT ["/docker_startup.sh"]


# Docker 默认只给容器分配 64MB 的共享内存
# 在当前目录下构建镜像（确保在Dockerfile所在目录）
# docker build -t yf_chrome .
# 运行容器（增加共享内存、指定端口）,无代理
# docker run -d --name yf_chrome --shm-size=6g -p 8889:8889  yf_chrome


# 使用宿主机代理
# docker run -d --name yf_chrome --shm-size=4g -p 8889:8889 --add-host=host.docker.internal:host-gateway -e CHROME_PROXYS=http://host.docker.internal:7890 yf_chrome