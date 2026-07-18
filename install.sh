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
IP_FILE="$DATA_DIR/public_ip"
ACME="/root/.acme.sh/acme.sh"

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "请使用 root 运行：sudo simple-backup"; exit 1; }
}

installed() { [ -f "$APP" ] && [ -f "$DATA_DIR/config.json" ]; }
download() { curl -fLsS --retry 3 --connect-timeout 15 "$1" -o "$2"; }

install_packages() {
    missing=""
    for command in python3 rsync ssh sshpass lftp curl openssl socat crontab; do
        command -v "$command" >/dev/null 2>&1 || missing=1
    done
    [ -x "$ACME" ] || missing=1
    [ -z "$missing" ] && return
    echo "正在安装 Python 3、rsync、lftp、SSH、sshpass、curl、OpenSSL、socat 和定时任务服务……"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3 rsync lftp openssh-client sshpass curl openssl ca-certificates socat cron
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 rsync lftp openssh-clients sshpass curl openssl ca-certificates socat cronie
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 rsync lftp openssh-clients sshpass curl openssl ca-certificates socat cronie
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install python3 rsync lftp openssh sshpass curl openssl ca-certificates socat cron
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm python rsync lftp openssh sshpass curl openssl ca-certificates socat cronie
    elif command -v apk >/dev/null 2>&1; then
        apk add python3 rsync lftp openssh-client sshpass curl openssl ca-certificates socat
    else
        echo "无法识别包管理器，请手动安装 python3、rsync、lftp、ssh、curl、openssl、socat 和 cron。"
        exit 1
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
detect_ip() { curl -4 -fLsS --max-time 8 https://api.ipify.org 2>/dev/null || true; }

valid_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    value = ipaddress.ip_address(sys.argv[1])
    raise SystemExit(0 if value.version == 4 and value.is_global else 1)
except ValueError:
    raise SystemExit(1)
PY
}

open_firewall() {
    firewall_port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "$firewall_port/tcp" >/dev/null
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$firewall_port/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
    fi
}

port_free() {
    python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
}

ensure_cron() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-update add crond default >/dev/null 2>&1 || true
        rc-service crond start >/dev/null 2>&1 || true
    fi
}

issue_ip_certificate() {
    ip=${1:-${SB_PUBLIC_IP:-}}
    [ -n "$ip" ] || ip=$(detect_ip)
    if [ "${SB_NONINTERACTIVE:-0}" != 1 ] && [ -t 0 ] && [ -r /dev/tty ]; then
        ip=$(prompt "公网 IPv4（证书绑定这个 IP）" "$ip")
    fi
    valid_ipv4 "$ip" || { echo "无法确认有效的公网 IPv4：$ip"; exit 1; }
    port_free 80 || {
        echo "TCP 80 已被其他程序占用，Let’s Encrypt 无法校验证书。请释放 80 端口后重试。"
        exit 1
    }
    open_firewall 80
    echo "正在申请 Let’s Encrypt 短期 IP 证书；请确保云防火墙/安全组已放行 TCP 80……"
    if [ ! -x "$ACME" ]; then
        curl -fsSL https://get.acme.sh | sh
    fi
    ensure_cron
    "$ACME" --set-default-ca --server letsencrypt --force
    [ -z "${SB_ACME_EMAIL:-}" ] || "$ACME" --register-account -m "$SB_ACME_EMAIL" --server letsencrypt || true
    "$ACME" --issue -d "$ip" --standalone --server letsencrypt \
        --certificate-profile shortlived --days 6 --httpport 80 --force || {
        echo "证书申请失败。请确认该公网 IP 指向本机，且互联网可访问本机 TCP 80。"
        exit 1
    }
    install -d -m 700 "$DATA_DIR"
    "$ACME" --install-cert -d "$ip" --force --key-file "$KEY" --fullchain-file "$CERT" \
        --reloadcmd "simple-backup restart >/dev/null 2>&1 || true"
    chmod 600 "$KEY"
    chmod 644 "$CERT"
    printf '%s\n' "$ip" >"$IP_FILE"
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
ExecStart=/usr/bin/python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup serve
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
command_args="/opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup serve"
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
start) [ -f /run/simple-backup.pid ] && kill -0 "$(cat /run/simple-backup.pid)" 2>/dev/null && exit 0
       nohup /usr/bin/python3 /opt/simple-backup/backup_manager.py --data-dir /var/lib/simple-backup serve >>/var/log/simple-backup.log 2>&1 & echo $! >/run/simple-backup.pid ;;
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
        nohup python3 "$APP" --data-dir "$DATA_DIR" serve >>/var/log/simple-backup.log 2>&1 &
        echo $! >/run/simple-backup.pid
        echo "提示：未识别开机服务管理器，本次已后台启动，请自行配置开机启动。"
    fi
}

service_action() {
    action=$1
    if [ -f /etc/systemd/system/simple-backup.service ]; then
        systemctl "$action" simple-backup
    elif command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/simple-backup ]; then
        rc-service simple-backup "$action"
    elif [ -x /etc/init.d/simple-backup ]; then
        /etc/init.d/simple-backup "$action"
    else
        echo "未找到服务"
        return 1
    fi
}

download_release() {
    temp=$(mktemp -d)
    download "$REPO_RAW/backup_manager.py" "$temp/backup_manager.py"
    download "$REPO_RAW/install.sh" "$temp/install.sh"
    python3 -m py_compile "$temp/backup_manager.py"
    install -d -m 755 "$APP_DIR"
    install -m 755 "$temp/backup_manager.py" "$APP"
    install -m 755 "$temp/install.sh" "$COMMAND"
    rm -rf "$temp"
}

install_app() {
    require_root
    installed && { echo "已经安装，请运行 simple-backup update 更新。"; return; }
    install_packages
    interactive=0
    [ "${SB_NONINTERACTIVE:-0}" != 1 ] && [ -t 0 ] && [ -r /dev/tty ] && interactive=1
    username=${SB_PANEL_USER:-admin}
    password=${SB_PANEL_PASSWORD:-}
    port=${SB_PANEL_PORT:-8088}
    if [ "$interactive" = 1 ]; then
        echo "Simple Backup 一键安装"
        username=$(prompt "面板用户名" "$username")
        password=$(secret_prompt "面板密码")
        port=$(prompt "公网面板端口（不能填 80）" "$port")
    fi
    [ -n "$password" ] || password=$(random_password)
    case "$port" in *[!0-9]*|"") echo "端口必须是数字"; exit 1 ;; esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$port" -ne 80 ] || {
        echo "面板端口必须在 1-65535 之间且不能是 80"; exit 1;
    }
    port_free "$port" || { echo "面板端口 $port 已被占用，请更换端口。"; exit 1; }
    download_release
    issue_ip_certificate
    python3 "$APP" --data-dir "$DATA_DIR" init --username "$username" --password "$password" \
        --port "$port" --host "0.0.0.0" --cert "$CERT" --key "$KEY"
    open_firewall "$port"
    setup_service
    ip=$(cat "$IP_FILE")
    echo
    echo "安装完成：https://$ip:$port"
    echo "管理用户名：$username"
    echo "管理密码：$password"
    echo "请妥善保存密码。以后运行 simple-backup 打开管理菜单。"
}

update_app() {
    require_root
    installed || { install_app; return; }
    install_packages
    download_release
    if [ ! -s "$CERT" ] || [ ! -s "$KEY" ] || ! openssl x509 -in "$CERT" -issuer -noout 2>/dev/null | grep -qi "Let's Encrypt"; then
        issue_ip_certificate
    fi
    current_port=$(python3 -c 'import json; print(json.load(open("/var/lib/simple-backup/config.json")).get("listen_port",8088))')
    if [ "$current_port" = 80 ]; then
        port_free 8088 || { echo "检测到旧安装端口错误为 80，但 8088 已被占用；请先运行菜单第 6 项修改端口。"; exit 1; }
        python3 - "$DATA_DIR/config.json" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    config = json.load(source)
config["listen_port"] = 8088
temp = path + ".tmp"
with open(temp, "w", encoding="utf-8") as target:
    json.dump(config, target, ensure_ascii=False, indent=2)
os.chmod(temp, 0o600)
os.replace(temp, path)
PY
        open_firewall 8088
        echo "已修复旧安装器造成的端口错误：面板从 80 迁移到 8088。"
    fi
    setup_service
    echo "更新完成。"
}

panel_info() {
    installed || { echo "尚未安装"; return; }
    values=$(python3 -c 'import json; c=json.load(open("/var/lib/simple-backup/config.json")); print(c.get("admin_username","admin")); print(c.get("listen_port",8088))')
    username=$(printf '%s\n' "$values" | sed -n '1p')
    port=$(printf '%s\n' "$values" | sed -n '2p')
    ip=$(cat "$IP_FILE" 2>/dev/null || detect_ip)
    echo "面板地址：https://$ip:$port"
    echo "管理用户名：$username"
    echo "HTTPS：Let’s Encrypt 短期 IP 证书（acme.sh 自动续期）"
}

change_panel() {
    require_root
    installed || { echo "尚未安装"; return; }
    values=$(python3 -c 'import json; c=json.load(open("/var/lib/simple-backup/config.json")); print(c.get("admin_username","admin")); print(c.get("listen_port",8088))')
    old_user=$(printf '%s\n' "$values" | sed -n '1p')
    old_port=$(printf '%s\n' "$values" | sed -n '2p')
    username=$(prompt "新管理用户名" "$old_user")
    password=$(secret_prompt "新管理密码")
    port=$(prompt "新公网面板端口（不能填 80）" "$old_port")
    [ -n "$password" ] || password=$(random_password)
    case "$port" in *[!0-9]*|"") echo "端口必须是数字"; return 1 ;; esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$port" -ne 80 ] || {
        echo "面板端口必须在 1-65535 之间且不能是 80"; return 1;
    }
    python3 "$APP" --data-dir "$DATA_DIR" init --username "$username" --password "$password" \
        --port "$port" --host "0.0.0.0" --cert "$CERT" --key "$KEY"
    open_firewall "$port"
    service_action restart
    panel_info
    echo "新管理密码：$password"
}

uninstall_app() {
    require_root
    printf "确定卸载程序？已有备份文件不会被删除 [y/N]: " >/dev/tty
    IFS= read -r answer </dev/tty || answer=n
    [ "$answer" = y ] || [ "$answer" = Y ] || { echo "已取消"; return; }
    service_action stop 2>/dev/null || true
    if [ -f /etc/systemd/system/simple-backup.service ]; then
        systemctl disable simple-backup >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/simple-backup.service
        systemctl daemon-reload
    fi
    command -v rc-update >/dev/null 2>&1 && rc-update del simple-backup default >/dev/null 2>&1 || true
    rm -f /etc/init.d/simple-backup "$COMMAND"
    rm -rf "$APP_DIR"
    printf "同时删除面板设置、任务配置和证书？备份目录仍会保留 [y/N]: " >/dev/tty
    IFS= read -r remove_data </dev/tty || remove_data=n
    if [ "$remove_data" = y ] || [ "$remove_data" = Y ]; then
        ip=$(cat "$IP_FILE" 2>/dev/null || true)
        [ -z "$ip" ] || [ ! -x "$ACME" ] || "$ACME" --remove -d "$ip" >/dev/null 2>&1 || true
        rm -rf "$DATA_DIR"
    fi
    echo "卸载完成；备份文件未删除。"
}

show_logs() {
    if [ -f /etc/systemd/system/simple-backup.service ]; then
        journalctl -u simple-backup -n 100 --no-pager
    else
        tail -n 100 /var/log/simple-backup.log 2>/dev/null || true
    fi
}

menu() {
    require_root
    while :; do
        echo
        echo "Simple Backup 管理菜单"
        echo "1. 查看面板信息"
        echo "2. 查看服务状态"
        echo "3. 启动服务"
        echo "4. 停止服务"
        echo "5. 重启服务"
        echo "6. 修改面板用户名/密码/端口"
        echo "7. 更新程序"
        echo "8. 查看日志"
        echo "9. 重新申请 IP 证书"
        echo "10. 卸载"
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
            9) issue_ip_certificate; service_action restart; echo "IP 证书已更新。" ;;
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
