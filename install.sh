#!/bin/sh
set -eu
umask 077

REPO_RAW="https://raw.githubusercontent.com/JohnMuyuan/Server-File-backuper/main"
APP_DIR="/opt/simple-backup"
DATA_DIR="/var/lib/simple-backup"
APP="$APP_DIR/backup_manager.py"
COMMAND="/usr/local/bin/simple-backup"
CERT="$DATA_DIR/server.crt"
KEY="$DATA_DIR/server.key"

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo simple-backup"; exit 1; }
}

installed() { [ -f "$APP" ] && [ -f "$DATA_DIR/config.json" ]; }

download() {
    curl -fLsS --retry 3 --connect-timeout 15 "$1" -o "$2"
}

install_packages() {
    missing=""
    for command in python3 rsync ssh lftp curl openssl; do
        command -v "$command" >/dev/null 2>&1 || missing=1
    done
    [ -z "$missing" ] && return
    echo "正在安装 Python 3、rsync、lftp、SSH、curl 和 OpenSSL……"
    if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y python3 rsync lftp openssh-client curl openssl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then dnf install -y python3 rsync lftp openssh-clients curl openssl ca-certificates
    elif command -v yum >/dev/null 2>&1; then yum install -y python3 rsync lftp openssh-clients curl openssl ca-certificates
    elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install python3 rsync lftp openssh curl openssl ca-certificates
    elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm python rsync lftp openssh curl openssl ca-certificates
    elif command -v apk >/dev/null 2>&1; then apk add python3 rsync lftp openssh-client curl openssl ca-certificates
    else echo "无法识别包管理器，请先安装 python3、rsync、lftp、ssh、curl、openssl。"; exit 1
    fi
}

prompt() {
    label=$1 default=$2
    printf "%s [%s]: " "$label" "$default" >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    [ -n "$answer" ] && printf '%s' "$answer" || printf '%s' "$default"
}

secret_prompt() {
    printf "%s（留空自动生成）: " "$1" >/dev/tty
    stty -echo </dev/tty
    IFS= read -r answer </dev/tty || answer=""
    stty echo </dev/tty
    printf '\n' >/dev/tty
    printf '%s' "$answer"
}

random_password() { openssl rand -base64 18 | tr -d '/+=' | cut -c1-18; }

public_ip() { curl -4 -LsS --max-time 5 https://api.ipify.org 2>/dev/null || printf '你的服务器IP'; }

generate_cert() {
    install -d -m 700 "$DATA_DIR"
    rm -f "$CERT" "$KEY"
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -subj "/CN=Simple Backup" -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
    chmod 600 "$CERT" "$KEY"
}

open_firewall() {
    port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "$port/tcp" >/dev/null
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$port/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
    fi
}

setup_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        cat >/etc/systemd/system/simple-backup.service <<'EOF'
[Unit]
Description=Simple Backup service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
UMask=0077
ExecStart=/usr/bin/python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable simple-backup >/dev/null
        systemctl restart simple-backup
    elif command -v rc-service >/dev/null 2>&1; then
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
        rc-update add simple-backup default >/dev/null
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
status) [ -f /run/simple-backup.pid ] && kill -0 "$(cat /run/simple-backup.pid)" 2>/dev/null ;;
*) echo "用法：$0 {start|stop|restart|status}"; exit 1 ;;
esac
EOF
        chmod 755 /etc/init.d/simple-backup
        command -v update-rc.d >/dev/null 2>&1 && update-rc.d simple-backup defaults >/dev/null || true
        /etc/init.d/simple-backup restart
    else
        nohup python3 "$APP" --data-dir "$DATA_DIR" >>/var/log/simple-backup.log 2>&1 &
        echo $! >/run/simple-backup.pid
        echo "提示：未识别开机服务管理器，本次已后台启动，但需自行配置开机启动。"
    fi
}

service_action() {
    action=$1
    if [ -f /etc/systemd/system/simple-backup.service ]; then systemctl "$action" simple-backup
    elif command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/simple-backup ]; then rc-service simple-backup "$action"
    elif [ -x /etc/init.d/simple-backup ]; then /etc/init.d/simple-backup "$action"
    else echo "未找到服务"; return 1
    fi
}

install_app() {
    require_root
    installed && { echo "已经安装，请运行 simple-backup update 更新。"; return; }
    install_packages
    interactive=0
    [ "${SB_NONINTERACTIVE:-0}" != 1 ] && [ -t 0 ] && [ -r /dev/tty ] && interactive=1
    username=${SB_PANEL_USER:-admin}
    port=${SB_PANEL_PORT:-8088}
    password=${SB_PANEL_PASSWORD:-}
    if [ "$interactive" -eq 1 ]; then
        username=$(prompt "管理用户名" "$username")
        port=$(prompt "公网 HTTPS 端口" "$port")
        password=$(secret_prompt "管理密码")
    fi
    printf '%s' "$username" | grep -Eq '^[A-Za-z0-9_.-]{3,32}$' || { echo "用户名格式不正确"; exit 1; }
    printf '%s' "$port" | grep -Eq '^[0-9]+$' || { echo "端口格式不正确"; exit 1; }
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "端口必须在 1-65535 之间"; exit 1; }
    [ -n "$password" ] || password=$(random_password)
    [ "${#password}" -ge 10 ] || { echo "密码至少需要 10 位"; exit 1; }

    temp=$(mktemp -d)
    trap 'rm -rf "$temp"' EXIT INT TERM
    download "$REPO_RAW/backup_manager.py" "$temp/backup_manager.py"
    download "$REPO_RAW/install.sh" "$temp/install.sh"
    python3 -m py_compile "$temp/backup_manager.py"
    sh -n "$temp/install.sh"
    install -d -m 755 "$APP_DIR"
    install -d -m 700 "$DATA_DIR"
    install -m 755 "$temp/backup_manager.py" "$APP"
    install -m 755 "$temp/install.sh" "$COMMAND"
    generate_cert
    SIMPLE_BACKUP_PANEL_USER="$username" SIMPLE_BACKUP_PANEL_PASSWORD="$password" \
    SIMPLE_BACKUP_PANEL_HOST="0.0.0.0" SIMPLE_BACKUP_PANEL_PORT="$port" \
    SIMPLE_BACKUP_TLS_CERT="$CERT" SIMPLE_BACKUP_TLS_KEY="$KEY" \
        python3 "$APP" --data-dir "$DATA_DIR" --init
    open_firewall "$port"
    setup_service
    address=$(public_ip)
    echo
    echo "安装完成：https://$address:$port"
    echo "管理用户名：$username"
    echo "管理密码：$password"
    echo "首次打开会出现自签名证书警告，确认继续访问即可。"
    echo "以后运行 simple-backup 打开管理菜单。"
}

update_app() {
    require_root
    installed || { echo "尚未安装"; exit 1; }
    install_packages
    temp=$(mktemp -d)
    trap 'rm -rf "$temp"' EXIT INT TERM
    download "$REPO_RAW/backup_manager.py" "$temp/backup_manager.py"
    download "$REPO_RAW/install.sh" "$temp/install.sh"
    python3 -m py_compile "$temp/backup_manager.py"
    sh -n "$temp/install.sh"
    install -m 755 "$temp/backup_manager.py" "$APP"
    install -m 755 "$temp/install.sh" "$COMMAND"
    [ -f "$CERT" ] && [ -f "$KEY" ] || generate_cert
    SIMPLE_BACKUP_PANEL_HOST="0.0.0.0" SIMPLE_BACKUP_TLS_CERT="$CERT" SIMPLE_BACKUP_TLS_KEY="$KEY" \
        python3 "$APP" --data-dir "$DATA_DIR" --configure-panel
    port=$(python3 -c 'import json; print(json.load(open("/var/lib/simple-backup/config.json")).get("listen_port",8088))')
    open_firewall "$port"
    service_action restart
    echo "更新完成。"
}

panel_info() {
    installed || { echo "尚未安装"; return; }
    values=$(python3 -c 'import json; c=json.load(open("/var/lib/simple-backup/config.json")); print(c.get("admin_username","admin")); print(c.get("listen_port",8088))')
    username=$(printf '%s\n' "$values" | sed -n '1p')
    port=$(printf '%s\n' "$values" | sed -n '2p')
    echo "面板地址：https://$(public_ip):$port"
    echo "管理用户名：$username"
}

change_panel() {
    require_root
    values=$(python3 -c 'import json; c=json.load(open("/var/lib/simple-backup/config.json")); print(c.get("admin_username","admin")); print(c.get("listen_port",8088))')
    old_user=$(printf '%s\n' "$values" | sed -n '1p')
    old_port=$(printf '%s\n' "$values" | sed -n '2p')
    username=$(prompt "新管理用户名" "$old_user")
    port=$(prompt "新公网 HTTPS 端口" "$old_port")
    password=$(secret_prompt "新管理密码")
    printf '%s' "$username" | grep -Eq '^[A-Za-z0-9_.-]{3,32}$' || { echo "用户名格式不正确"; return 1; }
    printf '%s' "$port" | grep -Eq '^[0-9]+$' || { echo "端口格式不正确"; return 1; }
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "端口必须在 1-65535 之间"; return 1; }
    [ -z "$password" ] || [ "${#password}" -ge 10 ] || { echo "密码至少需要 10 位"; return 1; }
    SIMPLE_BACKUP_PANEL_USER="$username" SIMPLE_BACKUP_PANEL_PASSWORD="$password" \
    SIMPLE_BACKUP_PANEL_HOST="0.0.0.0" SIMPLE_BACKUP_PANEL_PORT="$port" \
        python3 "$APP" --data-dir "$DATA_DIR" --configure-panel
    open_firewall "$port"
    service_action restart
    panel_info
}

uninstall_app() {
    require_root
    printf "确认卸载程序？备份文件不会删除 [y/N]: " >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    [ "$answer" = y ] || [ "$answer" = Y ] || { echo "已取消"; return; }
    service_action stop 2>/dev/null || true
    if [ -f /etc/systemd/system/simple-backup.service ]; then
        systemctl disable simple-backup >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/simple-backup.service
        systemctl daemon-reload
    fi
    command -v rc-update >/dev/null 2>&1 && rc-update del simple-backup default >/dev/null 2>&1 || true
    rm -f /etc/init.d/simple-backup
    rm -rf "$APP_DIR"
    rm -f "$COMMAND"
    printf "同时删除面板设置和证书？备份文件仍会保留 [y/N]: " >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    if [ "$answer" = y ] || [ "$answer" = Y ]; then rm -rf "$DATA_DIR"; fi
    echo "卸载完成，备份目录未删除。"
}

show_logs() {
    if [ -f /etc/systemd/system/simple-backup.service ]; then journalctl -u simple-backup -n 100 --no-pager
    else tail -n 100 /var/log/simple-backup.log 2>/dev/null || true
    fi
}

menu() {
    require_root
    while true; do
        echo
        echo "====== Simple Backup 管理菜单 ======"
        echo "1. 查看面板信息    2. 查看服务状态"
        echo "3. 启动服务        4. 停止服务"
        echo "5. 重启服务        6. 修改账号/密码/端口"
        echo "7. 更新程序        8. 查看日志"
        echo "9. 重建 HTTPS 证书 10. 卸载"
        echo "0. 退出"
        printf "请选择: " >/dev/tty
        IFS= read -r choice </dev/tty || return
        case "$choice" in
            1) panel_info ;;
            2) service_action status || true ;;
            3) service_action start ;;
            4) service_action stop ;;
            5) service_action restart ;;
            6) change_panel ;;
            7) update_app ;;
            8) show_logs ;;
            9) generate_cert; service_action restart; echo "证书已重建。" ;;
            10) uninstall_app; return ;;
            0) return ;;
            *) echo "请输入菜单中的数字。" ;;
        esac
    done
}

case "${1:-}" in
    install) install_app ;;
    update) update_app ;;
    uninstall) uninstall_app ;;
    status|start|stop|restart) require_root; service_action "$1" ;;
    logs) require_root; show_logs ;;
    info) require_root; panel_info ;;
    "") if installed; then menu; else install_app; fi ;;
    *) echo "用法：simple-backup [install|update|uninstall|status|start|stop|restart|logs|info]"; exit 1 ;;
esac
