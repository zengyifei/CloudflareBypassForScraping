服务器上启动的话，记得先在项目下执行`pip install -r server_requirements.txt`.然后下面配置文件的用户名和项目路径，以及重启时间和内存限额配下  
还有就是服务器上得保证安装了xvfb, `apt update && apt install -y xvfb`
还有就是服务器上得保证安装了浏览器，比如Edge
```
//导入微软 GPG 密钥
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/
sudo rm microsoft.gpg

//添加 Edge 软件源
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/edge stable main" > /etc/apt/sources.list.d/microsoft-edge-dev.list'

// 更新并安装
sudo apt update
sudo apt install microsoft-edge-stable
```

服务器上yf_chrome 配置文件的位置: `sudo vim /etc/systemd/system/yf_chrome.service`  
停止服务: `sudo systemctl stop yf_chrome`  
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
# 配置环境变量
Environment="BROWSER_TYPE=edge"
Environment="CHROME_PROXYS=http://localhost:7890"

# 内存超限自动重启
MemoryMax=1500M    

[Install]
WantedBy=multi-user.target
```
