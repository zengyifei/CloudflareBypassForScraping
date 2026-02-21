#!/bin/bash
# 启动虚拟显示供无头 Edge 使用；服务由 server.py 在运行满 8h 后主动退出，由 compose restart 重启整个容器
Xvfb :99 -screen 0 1024x768x24 &
export DISPLAY=:99

cd /app
exec python server.py -r
