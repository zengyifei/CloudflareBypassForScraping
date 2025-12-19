服务器上yf_chrome 配置文件的位置: `sudo vim /etc/systemd/system/yf_chrome.service`  
停止服务: `sudo systemctl stop yf_chromesudo systemctl stop yf_chrome`  
启动服务: `sudo systemctl start yf_chrome`  
修改了配置的话，需要先执行 `sudo systemctl daemon-reload` 再重启服务  
重启服务: `sudo systemctl restart yf_chrome`  
查看服务状态: `sudo systemctl status yf_chrome`  

配置文件路径: `/etc/systemd/system/yf_chrome.service`
配置文件内容:
```
[Unit]
Description=Uvicorn Service with Auto-Restart
After=network.target

[Service]
ExecStart=/usr/bin/env python3 server.py
# 每24h自动重启
# 强制运行24小时后退出
RuntimeMaxSec=86400
Restart=always
RestartSec=5 
TimeoutStopSec=10
KillMode=mixed
User=ubuntu
WorkingDirectory=/home/ubuntu/CloudflareBypassForScraping

# 内存超限自动重启
MemoryMax=1500M    

[Install]
WantedBy=multi-user.target
```
