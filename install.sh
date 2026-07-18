#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo sh install.sh"; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install_packages() {
    command -v python3 >/dev/null && command -v rsync >/dev/null && command -v ssh >/dev/null && return
    echo "正在安装 Python 3、rsync 和 SSH 客户端……"
    if command -v apt-get >/dev/null; then apt-get update && apt-get install -y python3 rsync openssh-client
    elif command -v dnf >/dev/null; then dnf install -y python3 rsync openssh-clients
    elif command -v yum >/dev/null; then yum install -y python3 rsync openssh-clients
    elif command -v zypper >/dev/null; then zypper --non-interactive install python3 rsync openssh
    elif command -v pacman >/dev/null; then pacman -Sy --noconfirm python rsync openssh
    elif command -v apk >/dev/null; then apk add python3 rsync openssh-client
    else echo "无法识别包管理器，请先安装 python3、rsync、ssh 后重试。"; exit 1
    fi
}

install_packages
install -d -m 755 /opt/simple-backup
install -d -m 700 /var/lib/simple-backup
install -m 755 "$SCRIPT_DIR/backup_manager.py" /opt/simple-backup/backup_manager.py
python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup --init

if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    cat >/etc/systemd/system/simple-backup.service <<'EOF'
[Unit]
Description=Simple Backup service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable simple-backup
    systemctl restart simple-backup
elif command -v rc-service >/dev/null; then
    cat >/etc/init.d/simple-backup <<'EOF'
#!/sbin/openrc-run
name="Simple Backup"
command="/usr/bin/python3"
command_args="/opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup"
command_background=true
pidfile="/run/simple-backup.pid"
output_log="/var/log/simple-backup.log"
error_log="/var/log/simple-backup.log"
depend() { need net; }
EOF
    chmod 755 /etc/init.d/simple-backup
    rc-update add simple-backup default
    rc-service simple-backup restart || rc-service simple-backup start
elif [ -d /etc/init.d ]; then
    cat >/etc/init.d/simple-backup <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides: simple-backup
# Required-Start: $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
### END INIT INFO
case "$1" in
start) [ -f /run/simple-backup.pid ] && kill -0 "$(cat /run/simple-backup.pid)" 2>/dev/null && exit 0; nohup /usr/bin/python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup >>/var/log/simple-backup.log 2>&1 & echo $! >/run/simple-backup.pid ;;
stop) [ ! -f /run/simple-backup.pid ] || { kill "$(cat /run/simple-backup.pid)" 2>/dev/null || true; rm -f /run/simple-backup.pid; } ;;
restart) "$0" stop; "$0" start ;;
*) echo "用法：$0 {start|stop|restart}"; exit 1 ;;
esac
EOF
    chmod 755 /etc/init.d/simple-backup
    if command -v update-rc.d >/dev/null; then update-rc.d simple-backup defaults; fi
    /etc/init.d/simple-backup restart
else
    echo "未识别系统服务管理器。可手动运行：python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup"
    exit 0
fi

echo "安装完成。网页默认仅监听服务器本机。"
echo "在你的电脑执行：ssh -L 8088:127.0.0.1:8088 root@你的服务器IP"
echo "然后浏览器打开：http://127.0.0.1:8088"
