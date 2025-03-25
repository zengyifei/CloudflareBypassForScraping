服务器上yf_chrome 配置文件的位置: `/etc/systemd/system/yf_chrome.service`
停止服务: `sudo systemctl stop yf_chrome`
启动服务: `sudo systemctl start yf_chrome`
修改了配置的话，需要先执行 `sudo systemctl daemon-reload` 再重启服务
重启服务: `sudo systemctl restart yf_chrome`
查看服务状态: `sudo systemctl status yf_chrome`


