#!/usr/bin/env python3
"""Simple Backup: multi-task Linux backup daemon and Chinese web panel."""

import argparse
import concurrent.futures
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import selectors
import shlex
import shutil
import signal
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

GIB = 1024 ** 3
MIN_FREE = 3 * GIB
ERROR_LINE = re.compile(
    r"(?i)(?:^(?:error|fatal)\b|:\s*(?:error|fatal)\b|"
    r"\b(?:failed|failure|denied|refused|unreachable|vanished)\b|errors? detected|"
    r"no such file|not found|timed out|connection (?:reset|closed)|host key|error is not recoverable)"
)
VOLATILE_LINE = re.compile(r"(?i)(?:no such file|not found|vanished)")
RSYNC_SUMMARY_LINE = re.compile(r"(?i)^rsync (?:warning|error): .*\(code (?:23|24)\)")
DEFAULTS = {
    "tasks": [],
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "admin_username": "admin",
    "listen_host": "0.0.0.0",
    "listen_port": 8088,
    "tls_enabled": True,
    "tls_cert": "/var/lib/simple-backup/server.crt",
    "tls_key": "/var/lib/simple-backup/server.key",
    "session_secret": "",
    "offsite_enabled": False,
    "offsite_host": "",
    "offsite_port": 22,
    "offsite_user": "root",
    "offsite_auth_method": "key",
    "offsite_ssh_key": "/root/.ssh/id_ed25519",
    "offsite_remote_path": "/var/backups/simple-backup-offsite",
}
TASK_DEFAULTS = {
    "id": "", "name": "新备份任务", "remote_host": "", "remote_port": 22,
    "remote_user": "root", "remote_path": "/", "ssh_key": "/root/.ssh/id_ed25519",
    "source_type": "files", "file_mode": "snapshot",
    "database_host": "127.0.0.1", "database_port": 0,
    "database_user": "", "database_name": "",
    "backup_dir": "/var/backups/simple-backup", "interval_days": 3,
    "schedule_times": ["02:00"],
    "retention_limit": 0, "transfer_threads": 4, "enabled": True,
    "auto_install_dependencies": True, "auth_method": "key",
}

# Lucide "database-backup", "archive", "monitor", "sun" and "moon" icons
# (ISC license). Keeping the SVGs local avoids a public CDN dependency.
BRAND_ICON = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 9 3"/><path d="M3 12a9 3 0 0 0 5 2.69"/><path d="M21 5v7"/><path d="m16 19 3 3 3-3"/><path d="M19 22v-6"/></svg>"""
ARCHIVE_ICON = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>"""
THEME_ICONS = {
    "auto": """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>""",
    "light": """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>""",
    "dark": """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>""",
}
BRAND_FAVICON = "data:image/svg+xml," + urllib.parse.quote(
    BRAND_ICON.replace('currentColor', '#356df3'), safe=""
)


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def password_fields(password):
    if not 10 <= len(password) <= 256 or any(ord(char) < 32 for char in password):
        raise ValueError("管理密码需要 10-256 位，且不能包含控制字符")
    salt = secrets.token_bytes(16)
    iterations = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return {
        "password_salt": salt.hex(), "password_hash": digest.hex(),
        "password_iterations": iterations,
    }


def verify_password(config, password):
    try:
        if len(password) > 256:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(config["password_salt"]),
            int(config.get("password_iterations", 200_000)),
        ).hex()
        return hmac.compare_digest(digest, config["password_hash"])
    except (KeyError, ValueError):
        return False


def human_size(size):
    size = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024


def command_error(output, code):
    errors = [line.strip() for line in output.splitlines() if ERROR_LINE.search(line)]
    if errors:
        return " | ".join(errors[-6:])[-1600:]
    return f"命令退出码 {code}；没有返回明确错误，请查看任务完整日志"


def source_changed_only(output):
    errors = [line for line in output.splitlines() if ERROR_LINE.search(line)]
    details = [
        line for line in errors
        if not re.search(r"(?i)\b\d+\s+errors?\b", line) and not RSYNC_SUMMARY_LINE.search(line)
    ]
    return bool(details) and all(VOLATILE_LINE.search(line) for line in details)


def directory_size(path):
    path = Path(path)
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.stat(os.path.join(root, name), follow_symlinks=False).st_size
            except (FileNotFoundError, PermissionError):
                pass
    return total


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:60] or "server"


def backup_prefix(task):
    return f"{task['id']}_{safe_name(task['remote_host'])}"


def incremental_path(task):
    return Path(task["backup_dir"]) / f"incremental_{backup_prefix(task)}"


def incremental_ledger(task):
    return Path(task["backup_dir"]) / f".incremental-{task['id']}.files"


def mirror_path(task):
    return Path(task["backup_dir"]) / f"mirror_{backup_prefix(task)}"


def validate_task(raw, existing_id=""):
    task = dict(TASK_DEFAULTS)
    task.update(raw)
    task["id"] = str(existing_id or task.get("id") or secrets.token_hex(4)).lower()
    for key in (
        "name", "remote_host", "remote_user", "remote_path", "ssh_key", "backup_dir",
        "source_type", "file_mode", "database_host", "database_user", "database_name",
    ):
        task[key] = str(task.get(key, "")).strip()
    try:
        task["remote_port"] = int(task["remote_port"])
        old_days = float(task["interval_days"])
        task["interval_days"] = max(1, round(old_days))
        task["retention_limit"] = int(task["retention_limit"])
        task["transfer_threads"] = int(task["transfer_threads"])
        task["database_port"] = int(task["database_port"] or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("端口、周期、保留份数和线程数必须是数字") from exc
    task["enabled"] = bool(task.get("enabled"))
    task["auto_install_dependencies"] = bool(task.get("auto_install_dependencies"))
    task["auth_method"] = str(task.get("auth_method", "key"))
    raw_times = task.get("schedule_times") if "schedule_times" in raw else None
    if not raw_times:
        if old_days < 1:
            count = min(24, max(1, round(1 / old_days)))
            raw_times = [f"{hour:02d}:00" for hour in range(0, 24, max(1, 24 // count))][:count]
        else:
            raw_times = ["02:00"]
    elif isinstance(raw_times, str):
        raw_times = raw_times.split(",")
    task["schedule_times"] = sorted(set(str(value).strip() for value in raw_times if str(value).strip()))
    if not re.fullmatch(r"[a-f0-9]{8}", task["id"]):
        raise ValueError("任务 ID 无效")
    if not 1 <= len(task["name"]) <= 50 or any(ord(c) < 32 for c in task["name"]):
        raise ValueError("任务名称需要 1-50 个可见字符")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", task["remote_host"]):
        raise ValueError("服务器地址只能使用域名、IP 或 IPv6 地址字符")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", task["remote_user"]):
        raise ValueError("SSH 用户名格式无效")
    if task["source_type"] not in ("files", "mysql", "postgresql", "redis"):
        raise ValueError("备份类型无效")
    if task["file_mode"] not in ("snapshot", "incremental", "mirror"):
        raise ValueError("文件保存方式无效")
    if task["source_type"] != "files":
        task["file_mode"] = "snapshot"
    if task["source_type"] == "files" and (not task["remote_path"].startswith("/") or any(ord(c) < 32 for c in task["remote_path"])):
        raise ValueError("远程路径必须是绝对路径")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", task["database_host"]):
        raise ValueError("数据库地址格式无效")
    if task["database_user"] and not re.fullmatch(r"[^\x00-\x1f]{1,128}", task["database_user"]):
        raise ValueError("数据库用户名格式无效")
    if task["database_name"] and not re.fullmatch(r"[^\x00-\x1f]{1,128}", task["database_name"]):
        raise ValueError("数据库名称格式无效")
    if task["source_type"] in ("mysql", "postgresql") and (not task["database_user"] or not task["database_name"]):
        raise ValueError("MySQL / PostgreSQL 必须填写数据库用户名和数据库名称")
    if not Path(task["backup_dir"]).is_absolute() or Path(task["backup_dir"]) == Path("/"):
        raise ValueError("本地备份目录必须是绝对路径，且不能是根目录")
    if task["ssh_key"] and not Path(task["ssh_key"]).is_absolute():
        raise ValueError("SSH 密钥路径必须是绝对路径")
    if task["auth_method"] not in ("key", "password"):
        raise ValueError("SSH 认证方式无效")
    if not 1 <= task["remote_port"] <= 65535:
        raise ValueError("SSH 端口必须在 1-65535 之间")
    if not 0 <= task["database_port"] <= 65535:
        raise ValueError("数据库端口必须在 0-65535 之间；0 表示使用默认端口")
    if not 1 <= task["interval_days"] <= 3650:
        raise ValueError("间隔天数必须在 1-3650 天之间")
    if not task["schedule_times"] or len(task["schedule_times"]) > 24:
        raise ValueError("每天需要设置 1-24 个备份时间")
    if any(not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value) for value in task["schedule_times"]):
        raise ValueError("备份时间格式无效")
    if task["retention_limit"] < 0:
        raise ValueError("保留份数不能小于 0；0 表示全部保留")
    if not 1 <= task["transfer_threads"] <= 16:
        raise ValueError("并行线程数必须在 1-16 之间")
    return task


def migrate_config(config):
    merged = dict(DEFAULTS)
    merged.update(config)
    if "tasks" not in config and config.get("remote_host"):
        old = {key: config.get(key, value) for key, value in TASK_DEFAULTS.items() if key != "id"}
        if "schedule_times" not in config:
            old.pop("schedule_times", None)
        old.update(id=secrets.token_hex(4), name=config.get("task_name") or f"{config['remote_host']} 备份")
        merged["tasks"] = [validate_task(old)]
    else:
        merged["tasks"] = [validate_task(item, item.get("id", "")) for item in config.get("tasks", [])]
    merged["session_secret"] = merged.get("session_secret") or secrets.token_hex(32)
    return merged


REMOTE_SETUP = r'''set -eu
kind=${1:-files}
if [ "$kind" = files ]; then
  command -v rsync >/dev/null 2>&1 && exit 0
elif [ "$kind" = mysql ]; then
  if command -v mysqldump >/dev/null 2>&1 || command -v mariadb-dump >/dev/null 2>&1; then exit 0; fi
elif [ "$kind" = postgresql ]; then
  if command -v pg_dump >/dev/null 2>&1; then exit 0; fi
elif [ "$kind" = redis ]; then
  if command -v redis-cli >/dev/null 2>&1; then exit 0; fi
fi
if [ "$(id -u)" -eq 0 ]; then run() { "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then run() { sudo -n "$@"; }
else echo "缺少备份客户端，且当前 SSH 用户没有 root 或免密 sudo 权限" >&2; exit 42; fi
case "$kind" in
  files) apt_pkg='rsync'; rpm_pkg='rsync'; zypp_pkg='rsync'; arch_pkg='rsync'; apk_pkg='rsync' ;;
  mysql) apt_pkg='default-mysql-client'; rpm_pkg='mariadb'; zypp_pkg='mariadb-client'; arch_pkg='mariadb-clients'; apk_pkg='mysql-client' ;;
  postgresql) apt_pkg='postgresql-client'; rpm_pkg='postgresql'; zypp_pkg='postgresql'; arch_pkg='postgresql'; apk_pkg='postgresql-client' ;;
  redis) apt_pkg='redis-tools'; rpm_pkg='redis'; zypp_pkg='redis'; arch_pkg='redis'; apk_pkg='redis' ;;
esac
if command -v apt-get >/dev/null 2>&1; then run apt-get update; run apt-get install -y $apt_pkg
elif command -v dnf >/dev/null 2>&1; then run dnf install -y $rpm_pkg
elif command -v yum >/dev/null 2>&1; then run yum install -y $rpm_pkg
elif command -v zypper >/dev/null 2>&1; then run zypper --non-interactive install $zypp_pkg
elif command -v pacman >/dev/null 2>&1; then run pacman -Sy --noconfirm $arch_pkg
elif command -v apk >/dev/null 2>&1; then run apk add $apk_pkg
else echo "不支持的远程包管理器，请手动安装对应数据库客户端" >&2; exit 43; fi
'''

DATABASE_DUMP = r'''set -eu
kind=$1 host=$2 port=$3 user=$4 name=$5
IFS= read -r password || password=''
case "$kind" in
  mysql)
    export MYSQL_PWD=$password
    dump=$(command -v mysqldump || command -v mariadb-dump || true)
    [ -n "$dump" ] || { echo '缺少 mysqldump / mariadb-dump' >&2; exit 127; }
    exec "$dump" --host="$host" --port="$port" --user="$user" --single-transaction --quick --routines --events --triggers --hex-blob --databases "$name"
    ;;
  postgresql)
    export PGPASSWORD=$password
    exec pg_dump --host="$host" --port="$port" --username="$user" --no-password --format=plain "$name"
    ;;
  redis)
    export REDISCLI_AUTH=$password
    set -- redis-cli -h "$host" -p "$port"
    [ -n "$user" ] && set -- "$@" --user "$user"
    exec "$@" --rdb -
    ;;
esac
'''


class BackupApp:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.config_path = self.data_dir / "config.json"
        self.state_path = self.data_dir / "state.json"
        self.secrets_dir = self.data_dir / "secrets"
        self.log_path = self.data_dir / "app.log"
        self.lock = threading.RLock()
        self.config = migrate_config(self._read_json(self.config_path, {}))
        self.state = self._read_json(self.state_path, {"tasks": {}, "telegram_offset": 0, "low_disks": {}})
        self.state.setdefault("tasks", {})
        self.state.setdefault("low_disks", {})
        self.state.setdefault("offsite", {})
        self.jobs = {}
        self.login_failures = {}
        self.account_failures = []
        self.login_lock = threading.Lock()
        self.stop_daemon = threading.Event()
        self._save_config()
        self._save_state()

    @staticmethod
    def _read_json(path, fallback):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            return fallback

    def _save_config(self):
        with self.lock:
            atomic_json(self.config_path, self.config)

    def _save_state(self):
        with self.lock:
            atomic_json(self.state_path, self.state)

    def task(self, task_id):
        return next((item for item in self.config["tasks"] if item["id"] == task_id), None)

    def task_state(self, task_id):
        return self.state["tasks"].setdefault(task_id, {
            "next_run": 0, "last_result": "尚未运行", "last_backup": "",
            "last_error": "", "dependencies_ready": False, "schedule_anchor": "",
        })

    def next_scheduled(self, task, state, after=None):
        after_dt = datetime.fromtimestamp(after or time.time())
        try:
            anchor = datetime.strptime(state.get("schedule_anchor", ""), "%Y-%m-%d").date()
        except (ValueError, TypeError):
            anchor = after_dt.date()
            state["schedule_anchor"] = anchor.isoformat()
        days = task["interval_days"]
        elapsed = max(0, (after_dt.date() - anchor).days)
        cycle = elapsed // days * days
        for offset in (cycle, cycle + days, cycle + days * 2):
            day = anchor + timedelta(days=offset)
            for clock in task["schedule_times"]:
                hour, minute = map(int, clock.split(":"))
                candidate = datetime.combine(day, datetime.min.time()).replace(hour=hour, minute=minute)
                if candidate > after_dt:
                    return candidate.timestamp()
        return (after_dt + timedelta(days=days)).timestamp()

    def secret_path(self, task_id):
        return self.secrets_dir / f"{task_id}.json"

    def task_password(self, task_id):
        return self._read_json(self.secret_path(task_id), {}).get("ssh_password", "")

    def set_task_password(self, task_id, password):
        self.set_task_secret(task_id, "ssh_password", password)

    def task_database_password(self, task_id):
        return self._read_json(self.secret_path(task_id), {}).get("database_password", "")

    def offsite_password(self):
        return self._read_json(self.secret_path("offsite"), {}).get("ssh_password", "")

    def set_offsite_password(self, password):
        self.set_task_secret("offsite", "ssh_password", password)

    def set_task_secret(self, task_id, key, value):
        path = self.secret_path(task_id)
        values = self._read_json(path, {})
        if value:
            values[key] = value
        else:
            values.pop(key, None)
        if values:
            self.secrets_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.secrets_dir, 0o700)
            atomic_json(path, values)
        elif path.exists():
            path.unlink()

    def resolve_task(self, value, allow_single=True):
        value = (value or "").strip()
        if not value and allow_single and len(self.config["tasks"]) == 1:
            return self.config["tasks"][0]
        matches = [t for t in self.config["tasks"] if t["id"] == value or t["name"] == value]
        return matches[0] if len(matches) == 1 else None

    def sign_session(self, username, lifetime=43200):
        expires = int(time.time()) + lifetime
        payload = f"{username}|{expires}"
        signature = hmac.new(
            self.config["session_secret"].encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return f"{payload}|{signature}"

    def verify_session(self, token):
        try:
            username, expires, signature = token.rsplit("|", 2)
            payload = f"{username}|{expires}"
            expected = hmac.new(
                self.config["session_secret"].encode(), payload.encode(), hashlib.sha256
            ).hexdigest()
            return (
                int(expires) >= time.time()
                and username == self.config["admin_username"]
                and hmac.compare_digest(signature, expected)
            )
        except (ValueError, TypeError):
            return False

    def login_allowed(self, address):
        now = time.time()
        attempts = [stamp for stamp in self.login_failures.get(address, []) if now - stamp < 900]
        self.account_failures = [stamp for stamp in self.account_failures if now - stamp < 900]
        self.login_failures[address] = attempts
        return len(attempts) < 5 and len(self.account_failures) < 20

    def login_failed(self, address):
        now = time.time()
        self.login_failures.setdefault(address, []).append(now)
        self.account_failures.append(now)
        self.log(f"登录失败：来源 {address}", "WARN")

    def log(self, message, level="INFO", task_id=""):
        task_tag = f" [task:{task_id}]" if task_id else ""
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}]{task_tag} {str(message).replace(chr(13), ' ').replace(chr(10), ' | ')}\n"
        with self.lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if self.log_path.exists() and self.log_path.stat().st_size > 5 * 1024 * 1024:
                os.replace(self.log_path, self.log_path.with_suffix(".log.1"))
            with self.log_path.open("a", encoding="utf-8") as target:
                target.write(line)
            os.chmod(self.log_path, 0o600)

    def read_log(self, limit=500_000):
        try:
            data = b"".join(
                path.read_bytes()
                for path in (self.log_path.with_suffix(".log.1"), self.log_path)
                if path.exists()
            )
            return data[-limit:].decode("utf-8", "replace") if limit else data.decode("utf-8", "replace")
        except OSError:
            return "暂无日志"

    def read_task_log(self, task_id):
        marker = f"[task:{task_id}]"
        return "".join(line for line in self.read_log(None).splitlines(True) if marker in line) or "该任务暂无日志"

    @staticmethod
    def send_telegram(token, chat_id, message):
        try:
            data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode()
            urllib.request.urlopen(
                f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=15
            ).read()
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def notify(self, message, task_id=""):
        self.log(message, task_id=task_id)
        token = self.config.get("telegram_bot_token")
        chat_id = self.config.get("telegram_chat_id")
        if not token or not chat_id:
            return
        ok, error = self.send_telegram(token, chat_id, message)
        if not ok:
            self.log(f"Telegram 发送失败：{error}", "ERROR")

    def ssh_options(self, task):
        password_auth = task["auth_method"] == "password"
        options = [
            "-p", str(task["remote_port"]), "-o", f"BatchMode={'no' if password_auth else 'yes'}",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4", "-o", "StrictHostKeyChecking=accept-new",
        ]
        if password_auth:
            options += ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no"]
        elif task["ssh_key"]:
            options += ["-i", task["ssh_key"]]
        return options

    def ssh_program(self, task):
        prefix = ["sshpass", "-e", "ssh"] if task["auth_method"] == "password" else ["ssh"]
        return prefix, " ".join(shlex.quote(item) for item in [*prefix, *self.ssh_options(task)])

    def offsite_task(self, task):
        return {
            "id": task["id"], "backup_dir": task["backup_dir"],
            "auth_method": self.config["offsite_auth_method"],
            "remote_port": self.config["offsite_port"],
            "ssh_key": self.config["offsite_ssh_key"],
        }

    def remote_setup(self, task, job):
        state = self.task_state(task["id"])
        if state.get("dependencies_ready") or not task["auto_install_dependencies"]:
            return
        prefix, _ = self.ssh_program(task)
        command = [*prefix, *self.ssh_options(task), f"{task['remote_user']}@{task['remote_host']}", "sh", "-s", "--", task["source_type"]]
        code, output = self.execute(command, task, job, stdin=REMOTE_SETUP)
        if code:
            raise RuntimeError("远程依赖自动安装失败：" + command_error(output, code))
        state["dependencies_ready"] = True
        self._save_state()

    def transfer_command(self, task, staging, files_from=None):
        destination = str(staging) + "/"
        _, ssh = self.ssh_program(task)
        command = [
            "rsync", "-a", "--numeric-ids", "--partial", "--partial-dir=.rsync-partial",
            "--info=progress2", "--protect-args",
        ]
        if task.get("file_mode") == "incremental":
            command.append("--ignore-existing")
        elif task.get("file_mode") == "mirror" and mirror_path(task).is_dir():
            command.append(f"--link-dest={mirror_path(task)}")
        if files_from is not None:
            command += ["--from0", f"--files-from={files_from}", "--relative"]
        else:
            command += ["--delete-after"]
        return [
            *command, "-e", ssh,
            f"{task['remote_user']}@{task['remote_host']}:{task['remote_path'].rstrip('/')}/",
            destination,
        ]

    def scan_remote_manifest(self, task, state_dir, job, existing_root=None, ledger=None):
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for old in state_dir.glob("files.chunk.*"):
            old.unlink(missing_ok=True)
        chunk_paths = [state_dir / f"files.chunk.{index}" for index in range(task["transfer_threads"])]
        writers = [path.open("wb") for path in chunk_paths]
        for path in chunk_paths:
            os.chmod(path, 0o600)
        error_path = state_dir / "scan.error"
        prefix, _ = self.ssh_program(task)
        remote = (
            f"cd -- {shlex.quote(task['remote_path'])} && "
            "find . -mindepth 1 \\( -type d -o -type f -o -type l \\) -print0"
        )
        command = [
            *prefix, *self.ssh_options(task),
            f"{task['remote_user']}@{task['remote_host']}", remote,
        ]
        environment = os.environ.copy() if task["auth_method"] == "password" else None
        if environment is not None:
            environment["SSHPASS"] = self.task_password(task["id"])
        process = None
        buffer = b""
        count = 0
        existing_root = os.fsencode(existing_root) if existing_root else None
        ledger_writer = ledger.open("ab") if ledger else None
        if ledger:
            os.chmod(ledger, 0o600)

        def consume(data):
            nonlocal buffer, count
            buffer += data
            entries = buffer.split(b"\0")
            buffer = entries.pop()
            for entry in entries:
                if not entry:
                    continue
                relative = entry[2:] if entry.startswith(b"./") else entry
                if existing_root and os.path.lexists(os.path.join(existing_root, relative.replace(b"/", os.sep.encode()))):
                    continue
                writers[count % len(writers)].write(entry + b"\0")
                if ledger_writer:
                    ledger_writer.write(entry + b"\0")
                count += 1

        job.update(phase="正在扫描并固定本轮远端文件清单", remote_scanned=False)
        try:
            with error_path.open("wb") as errors:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors,
                    start_new_session=True, env=environment,
                )
                job["process"] = process
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                while process.poll() is None:
                    if job["stop"].is_set():
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except (AttributeError, ProcessLookupError, PermissionError):
                            process.terminate()
                    for key, _ in selector.select(1):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if data:
                            consume(data)
                    self.disk_guard(task)
                consume(process.stdout.read())
            error = error_path.read_text(encoding="utf-8", errors="replace")[-12000:]
            for line in error.splitlines():
                self.log(f"ssh-scan: {line}", "PROCESS", task["id"])
            if process.returncode:
                raise RuntimeError(command_error(error, process.returncode))
            if buffer:
                raise RuntimeError("远端文件清单格式不完整，请检查 SSH 连接是否中断")
            for writer in writers:
                writer.flush()
            job.update(remote_files=count, remote_scanned=True)
            return [path for path in chunk_paths if path.stat().st_size]
        except FileNotFoundError as exc:
            raise RuntimeError(f"本机缺少命令：{command[0]}（{exc}）") from exc
        finally:
            for writer in writers:
                writer.close()
            if ledger_writer:
                ledger_writer.close()
            job["process"] = None
            error_path.unlink(missing_ok=True)

    @staticmethod
    def clean_staging_from_manifest(staging, chunks):
        allowed = set()
        separator = os.sep.encode()
        for chunk in chunks:
            for entry in chunk.read_bytes().split(b"\0"):
                if entry:
                    relative = entry[2:] if entry.startswith(b"./") else entry
                    allowed.add(relative.replace(b"/", separator))
        root = os.fsencode(staging)
        partial_dir = b".rsync-partial"
        for current, directories, files in os.walk(root, topdown=False):
            for name in files:
                path = os.path.join(current, name)
                relative = os.path.relpath(path, root)
                if relative != partial_dir and not relative.startswith(partial_dir + separator) and relative not in allowed:
                    os.unlink(path)
            for name in directories:
                path = os.path.join(current, name)
                relative = os.path.relpath(path, root)
                if os.path.islink(path):
                    if relative not in allowed:
                        os.unlink(path)
                elif relative != partial_dir and relative not in allowed:
                    try:
                        os.rmdir(path)
                    except OSError:
                        pass
        shutil.rmtree(Path(staging) / ".rsync-partial", ignore_errors=True)

    def transfer_manifest(self, task, staging, state_dir, job):
        incremental = task.get("file_mode") == "incremental"
        chunks = self.scan_remote_manifest(
            task, state_dir, job,
            staging if incremental else None,
            incremental_ledger(task) if incremental else None,
        )
        if not chunks:
            if not incremental:
                self.clean_staging_from_manifest(staging, chunks)
            job.update(progress=100, parallel_files=0, segments_per_file=1)
            return
        job.update(
            phase="正在按固定清单并行下载", parallel_files=len(chunks), segments_per_file=1,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(chunks)) as pool:
            futures = [
                pool.submit(
                    self.execute, self.transfer_command(task, staging, chunk), task, job,
                    monitor_path=staging, complete_progress=False,
                )
                for chunk in chunks
            ]
            results = [future.result() for future in futures]
        failures = [(code, output) for code, output in results if code and not source_changed_only(output)]
        vanished = [(code, output) for code, output in results if code and source_changed_only(output)]
        if failures:
            raise RuntimeError(command_error(failures[0][1], failures[0][0]))
        if vanished:
            self.log("扫描后有实时文件已消失，本轮已跳过；不会追踪扫描后新增的文件", "WARN", task["id"])
        if incremental:
            shutil.rmtree(Path(staging) / ".rsync-partial", ignore_errors=True)
        else:
            self.clean_staging_from_manifest(staging, chunks)
        job["progress"] = 100

    def database_command(self, task):
        ports = {"mysql": 3306, "postgresql": 5432, "redis": 6379}
        arguments = (
            task["source_type"], task["database_host"],
            str(task["database_port"] or ports[task["source_type"]]),
            task["database_user"], task["database_name"],
        )
        remote = "sh -c " + shlex.quote(DATABASE_DUMP) + " simple-backup " + " ".join(map(shlex.quote, arguments))
        prefix, _ = self.ssh_program(task)
        return [*prefix, *self.ssh_options(task), f"{task['remote_user']}@{task['remote_host']}", remote]

    def dump_database(self, task, staging, job):
        suffix = "rdb" if task["source_type"] == "redis" else "sql"
        dump = staging / f"{task['source_type']}-{safe_name(task['database_name'] or 'all')}.{suffix}"
        error_path = staging / ".database-dump-error"
        environment = os.environ.copy()
        if task["auth_method"] == "password":
            environment["SSHPASS"] = self.task_password(task["id"])
        command = self.database_command(task)
        job.update(phase="正在导出数据库", progress=0, total_bytes=0)
        try:
            with dump.open("wb") as output, error_path.open("wb") as errors:
                os.chmod(dump, 0o600)
                os.chmod(error_path, 0o600)
                process = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=output, stderr=errors,
                    start_new_session=True, env=environment,
                )
                job["process"] = process
                process.stdin.write((self.task_database_password(task["id"]) + "\n").encode())
                process.stdin.close()
                last_check = last_sample = 0
                while process.poll() is None:
                    if job["stop"].is_set():
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except (AttributeError, ProcessLookupError, PermissionError):
                            process.terminate()
                    now = time.time()
                    if now - last_check >= 5:
                        last_check = now
                        self.disk_guard(task)
                    if now - last_sample >= 2:
                        last_sample = now
                        self.sample_transfer(staging, task, job)
                    time.sleep(0.2)
            self.sample_transfer(staging, task, job)
            error = error_path.read_text(encoding="utf-8", errors="replace")[-6000:]
            for line in error.splitlines():
                self.log(f"database: {line}", "PROCESS", task["id"])
            return process.returncode, error
        except FileNotFoundError as exc:
            return 127, f"本机缺少命令：{command[0]}（{exc}）"
        finally:
            job["process"] = None
            error_path.unlink(missing_ok=True)

    def free_space(self, task):
        path = Path(task["backup_dir"])
        path.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(path).free

    def stop_all(self, reason="用户要求停止", discard=False):
        with self.lock:
            jobs = list(self.jobs.values())
        for job in jobs:
            job["reason"] = reason
            job["discard_partial"] = discard
            job["stop"].set()

    def stop_backup(self, task_id, discard=False, source="网页"):
        job = self.jobs.get(task_id)
        if not job:
            return False, "任务当前未运行"
        job["discard_partial"] = discard
        job["reason"] = f"{source}{'停止并清除断点' if discard else '临时暂停'}"
        job["stop"].set()
        return True, "已发送停止指令" if discard else "已发送暂停指令"

    @staticmethod
    def clear_partial(task):
        root = Path(task["backup_dir"])
        if task.get("file_mode") == "incremental":
            target, ledger = incremental_path(task), incremental_ledger(task)
            try:
                entries = ledger.read_bytes().split(b"\0")
            except FileNotFoundError:
                entries = []
            for entry in reversed(entries):
                relative = entry[2:] if entry.startswith(b"./") else entry
                relative_path = PurePosixPath(os.fsdecode(relative))
                parts = relative_path.parts
                if not relative or relative_path.is_absolute() or ".." in parts:
                    continue
                path = target.joinpath(*parts)
                try:
                    path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
                except (FileNotFoundError, OSError):
                    pass
            ledger.unlink(missing_ok=True)
            shutil.rmtree(target / ".rsync-partial", ignore_errors=True)
        shutil.rmtree(root / f".partial-{task['id']}", ignore_errors=True)
        shutil.rmtree(root / f".transfer-{task['id']}", ignore_errors=True)
        (root / f".archive-{task['id']}.tar.zst").unlink(missing_ok=True)

    def disk_guard(self, task):
        free = self.free_space(task)
        key = str(Path(task["backup_dir"]).resolve())
        if free < MIN_FREE:
            self.stop_all("剩余硬盘容量低于 3 GB")
            if not self.state["low_disks"].get(key):
                self.state["low_disks"][key] = True
                self._save_state()
                self.notify(f"容量不足：{task['name']} 的备份盘仅剩 {human_size(free)}，已停止所有备份和自动备份。", task["id"])
            return False
        if self.state["low_disks"].pop(key, None):
            self._save_state()
        return True

    def remote_size(self, task, job):
        prefix, _ = self.ssh_program(task)
        path = shlex.quote(task["remote_path"])
        remote = (
            f"if v=$(du -sb -- {path} 2>/dev/null); then set -- $v; size=$1; "
            f"elif v=$(du -sk -- {path} 2>/dev/null); then set -- $v; size=$(($1 * 1024)); "
            f"else exit 1; fi; count=$(find {path} -type f -print 2>/dev/null | head -n {task['transfer_threads']} | wc -l); "
            "printf '%s %s\\n' \"$size\" \"$count\""
        )
        job["phase"] = "正在统计远端文件"
        job["remote_scanned"] = False
        code, output = self.execute(
            [*prefix, *self.ssh_options(task), f"{task['remote_user']}@{task['remote_host']}", remote],
            task, job,
        )
        values = re.findall(r"(?m)^\s*(\d+)\s+(\d+)\s*$", output)
        if code or not values:
            self.log("无法取得远端总大小，将继续下载并显示已传输量", "WARN", task["id"])
            return 0
        size, file_count = map(int, values[-1])
        job.update(remote_files=file_count, remote_scanned=True)
        return size

    def sample_transfer(self, staging, task, job):
        now = time.time()
        total, files = 0, []
        try:
            for root, _, names in os.walk(staging):
                for name in names:
                    path = os.path.join(root, name)
                    try:
                        stat = os.stat(path, follow_symlinks=False)
                        total += stat.st_size
                        files.append((os.path.relpath(path, staging), stat.st_size, stat.st_mtime))
                    except (FileNotFoundError, PermissionError):
                        pass
        except OSError:
            return

        previous_time = job.get("_sample_time", now)
        elapsed = max(0.001, now - previous_time)
        previous_total = job.get("_sample_total", total)
        job["speed_bps"] = max(0, total - previous_total) / elapsed
        transferred = max(0, total - job.get("_transfer_base", 0))
        job["transferred_bytes"] = transferred
        total_bytes = job.get("total_bytes", 0)
        if total_bytes:
            job["progress"] = max(job.get("progress", 0), min(99, int(transferred * 100 / total_bytes)))

        previous_files = job.get("_file_samples", {})
        candidates, current_files = [], {}
        for name, size, modified in files:
            old_size = previous_files.get(name, (0, now))[0]
            speed = max(0, size - old_size) / elapsed
            current_files[name] = (size, now)
            if speed > 0 or now - modified < 5:
                candidates.append((speed, modified, name, size))
        candidates.sort(reverse=True)
        job["slots"] = [
            {
                "slot": index + 1, "name": name, "bytes": size,
                "speed_bps": speed, "progress": job.get("progress", 0),
            }
            for index, (speed, _, name, size) in enumerate(candidates[:task["transfer_threads"]])
        ]
        job["_sample_time"] = now
        job["_sample_total"] = total
        job["_file_samples"] = current_files

        progress = job.get("progress", 0)
        if total_bytes and progress >= job.get("next_progress_notice", 25) and progress < 100:
            milestone = progress // 25 * 25
            job["next_progress_notice"] = milestone + 25
            threading.Thread(
                target=self.notify,
                args=(f"备份进度：{task['name']} 已完成约 {milestone}%", task["id"]),
                daemon=True,
            ).start()

    def execute(self, command, task, job, stdin=None, monitor_path=None, complete_progress=True, password=None):
        environment = None
        if task["auth_method"] == "password":
            environment = os.environ.copy()
            environment["SSHPASS"] = password if password is not None else self.task_password(task["id"])
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", bufsize=1, start_new_session=True,
                env=environment,
            )
        except FileNotFoundError as exc:
            return 127, f"本机缺少命令：{command[0]}（{exc}）"
        job["process"] = process
        if stdin is not None:
            process.stdin.write(stdin)
            process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output, errors, last_check, last_sample = [], [], 0, 0
        while process.poll() is None:
            if job["stop"].is_set():
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (AttributeError, ProcessLookupError, PermissionError):
                    process.terminate()
            now = time.time()
            if now - last_check >= 5:
                last_check = now
                self.disk_guard(task)
            if monitor_path is not None and now - last_sample >= 2:
                last_sample = now
                self.sample_transfer(monitor_path, task, job)
            for key, _ in selector.select(1):
                line = key.fileobj.readline()
                if not line:
                    continue
                output.append(line)
                if ERROR_LINE.search(line):
                    errors.append(line.rstrip() + "\n")
                if len(output) > 120:
                    del output[:40]
                self.log(f"{command[0]}: {line.rstrip()}", "PROCESS", task["id"])
        rest = process.stdout.read()
        if rest:
            output.append(rest)
            for line in rest.splitlines():
                if ERROR_LINE.search(line):
                    errors.append(line.rstrip() + "\n")
                self.log(f"{command[0]}: {line}", "PROCESS", task["id"])
        if monitor_path is not None:
            self.sample_transfer(monitor_path, task, job)
            if process.returncode == 0 and complete_progress:
                job["progress"] = 100
        job["process"] = None
        detail = "".join(output)[-6000:]
        if errors:
            detail += "\n" + "".join(errors[-20:])
        return process.returncode, detail[-12000:]

    def upload_offsite(self, task, backup_path, job):
        if not self.config.get("offsite_enabled"):
            return
        remote_path = self.config["offsite_remote_path"].rstrip("/") or "/"
        upload_task = self.offsite_task(task)
        password = self.offsite_password() if upload_task["auth_method"] == "password" else None
        if upload_task["auth_method"] == "key" and upload_task["ssh_key"] and not Path(upload_task["ssh_key"]).is_file():
            raise RuntimeError(f"容灾 SSH 密钥不存在：{upload_task['ssh_key']}")
        if upload_task["auth_method"] == "password" and not password:
            raise RuntimeError("容灾服务器尚未保存 SSH 密码")
        job.update(phase="正在上传容灾副本")
        prefix, _ = self.ssh_program(upload_task)
        remote = f"{self.config['offsite_user']}@{self.config['offsite_host']}"
        code, output = self.execute(
            [*prefix, *self.ssh_options(upload_task), remote, f"mkdir -p -- {shlex.quote(remote_path)}"],
            upload_task, job, password=password,
        )
        if code:
            raise RuntimeError(command_error(output, code))
        _, ssh = self.ssh_program(upload_task)
        source = str(backup_path) + ("/" if backup_path.is_dir() else "")
        destination = f"{remote}:{remote_path}/{backup_path.name + '/' if backup_path.is_dir() else ''}"
        code, output = self.execute(
            ["rsync", "-a", "--partial", "--protect-args", "-e", ssh, source, destination],
            upload_task, job, password=password,
        )
        if code:
            raise RuntimeError(command_error(output, code))
        self.state["offsite"] = {
            "last_result": "成功", "last_backup": backup_path.name,
            "last_time": f"{datetime.now():%Y-%m-%d %H:%M:%S}", "last_error": "",
        }
        self._save_state()
        self.notify(f"容灾上传成功：{task['name']}\n文件名：{backup_path.name}\n目标：{remote_path}", task["id"])

    def backups(self, task):
        root = Path(task["backup_dir"])
        suffix = "_" + backup_prefix(task)
        try:
            return sorted(
                [
                    p for p in root.iterdir()
                    if (p.is_dir() and p.name.endswith(suffix))
                    or (p.is_file() and p.name.endswith(suffix + ".tar.zst"))
                ],
                key=lambda p: p.stat().st_mtime,
            )
        except FileNotFoundError:
            return []

    def apply_retention(self, task):
        limit = task["retention_limit"]
        if not limit:
            return
        items = [item for item in self.backups(task) if item not in (incremental_path(task), mirror_path(task))]
        while len(items) >= limit:
            oldest = items.pop(0)
            self.delete_backup(oldest)
            message = f"已删除旧备份：{task['name']} / {oldest.name}"
            self.log(message, task_id=task["id"])
            self.notify(message)

    @staticmethod
    def delete_backup(path):
        path.unlink() if path.is_file() else shutil.rmtree(path)

    def backup_once(self, task, job):
        if not self.disk_guard(task):
            raise RuntimeError("剩余硬盘容量低于 3 GB")
        if task["auth_method"] == "key" and task["ssh_key"] and not Path(task["ssh_key"]).is_file():
            raise RuntimeError(f"SSH 密钥不存在：{task['ssh_key']}")
        if task["auth_method"] == "password" and not self.task_password(task["id"]):
            raise RuntimeError("尚未保存 SSH 密码，请编辑任务后重新填写")
        self.remote_setup(task, job)
        root = Path(task["backup_dir"])
        root.mkdir(parents=True, exist_ok=True)
        incremental = task["source_type"] == "files" and task.get("file_mode") == "incremental"
        mirror = task["source_type"] == "files" and task.get("file_mode") == "mirror"
        old_mirror = root / f".mirror-old-{task['id']}"
        if mirror and not mirror_path(task).exists() and old_mirror.exists():
            os.replace(old_mirror, mirror_path(task))
        staging = incremental_path(task) if incremental else root / f".partial-{task['id']}"
        if task["source_type"] == "files":
            staging.mkdir(exist_ok=True)
            os.chmod(staging, 0o700)
            resume = (staging / ".rsync-partial").exists() if incremental else any(staging.iterdir())
            job["total_bytes"] = 0 if incremental else self.remote_size(task, job)
            job.update(parallel_files=task["transfer_threads"], segments_per_file=1)
            job["phase"] = "正在重新扫描并校验断点" if resume else "正在扫描远端清单"
            job["progress"] = 0
            job["_sample_time"] = time.time()
            job["_transfer_base"] = directory_size(staging) if incremental else 0
            job["_sample_total"] = job["_transfer_base"]
            self.sample_transfer(staging, task, job)
            job.update(speed_bps=0, slots=[])
            state_dir = root / f".transfer-{task['id']}"
            try:
                self.transfer_manifest(task, staging, state_dir, job)
                code, output = 0, ""
            finally:
                shutil.rmtree(state_dir, ignore_errors=True)
        else:
            # ponytail: logical dumps restart on retry; add engine-specific incremental backup only when requested.
            shutil.rmtree(staging, ignore_errors=True)
            staging.mkdir(mode=0o700)
            job["_sample_time"] = time.time()
            job["_sample_total"] = 0
            code, output = self.dump_database(task, staging, job)
        if job["stop"].is_set():
            raise RuntimeError(job.get("reason") or "备份已停止")
        if code:
            raise RuntimeError(command_error(output, code))
        if incremental:
            job.update(phase="增量归档完成", progress=100)
            incremental_ledger(task).unlink(missing_ok=True)
            os.utime(staging)
            return staging, directory_size(staging), self.free_space(task)
        if mirror:
            job.update(phase="正在替换完整镜像", progress=100)
            shutil.rmtree(old_mirror, ignore_errors=True)
            current = mirror_path(task)
            if current.exists():
                os.replace(current, old_mirror)
            try:
                os.replace(staging, current)
            except Exception:
                if old_mirror.exists() and not current.exists():
                    os.replace(old_mirror, current)
                raise
            shutil.rmtree(old_mirror, ignore_errors=True)
            return current, directory_size(current), self.free_space(task)
        job["phase"] = "正在本机压缩"
        job["progress"] = 0
        archive = root / f".archive-{task['id']}.tar.zst"
        if archive.exists():
            archive.unlink()
        code, output = self.execute(["tar", "--zstd", "-cf", str(archive), "-C", str(staging), "."], task, job)
        if job["stop"].is_set():
            archive.unlink(missing_ok=True)
            raise RuntimeError(job.get("reason") or "压缩已停止")
        if code:
            archive.unlink(missing_ok=True)
            raise RuntimeError(command_error(output, code))
        self.apply_retention(task)
        final = root / f"{datetime.now():%Y%m%d-%H%M%S}_{backup_prefix(task)}.tar.zst"
        os.replace(archive, final)
        os.chmod(final, 0o600)
        shutil.rmtree(staging)
        return final, directory_size(final), self.free_space(task)

    def start_backup(self, task_id, source="手动"):
        task = self.task(task_id)
        if not task:
            return False, "任务不存在"
        with self.lock:
            if task_id in self.jobs:
                return False, "任务正在运行"
            job = {
                "stop": threading.Event(), "process": None, "progress": 0,
                "reason": "", "next_progress_notice": 25, "phase": "正在下载",
                "speed_bps": 0, "transferred_bytes": 0, "total_bytes": 0, "slots": [],
                "remote_files": 0, "parallel_files": 1, "segments_per_file": 1,
                "remote_scanned": False, "discard_partial": False,
            }
            self.jobs[task_id] = job
        threading.Thread(target=self._backup_worker, args=(dict(task), job, source), daemon=True).start()
        return True, "备份已在后台启动"

    def _backup_worker(self, task, job, source):
        state = self.task_state(task["id"])
        state.update(last_result="运行中", last_error="")
        self._save_state()
        self.notify(f"备份任务开始：{task['name']}（{source}）", task["id"])
        error = ""
        try:
            for attempt in range(1, 7):
                try:
                    final, size, free = self.backup_once(task, job)
                    state.update(last_result="成功", last_backup=final.name, last_error="")
                    if source == "定时":
                        state["next_run"] = self.next_scheduled(task, state, time.time() + 1)
                    self._save_state()
                    self.notify(
                        f"备份成功：{task['name']}\n文件名：{final.name}\n大小：{human_size(size)}\n"
                        f"时间：{datetime.now():%Y-%m-%d %H:%M:%S}\n剩余容量：{human_size(free)}",
                        task["id"],
                    )
                    try:
                        self.upload_offsite(task, final, job)
                    except Exception as exc:
                        error = str(exc)
                        self.state["offsite"] = {
                            "last_result": "失败", "last_backup": final.name,
                            "last_time": f"{datetime.now():%Y-%m-%d %H:%M:%S}", "last_error": error,
                        }
                        self._save_state()
                        self.notify(f"容灾上传失败：{task['name']}\n文件名：{final.name}\n原因：{error}", task["id"])
                    return
                except Exception as exc:
                    error = str(exc)
                    self.log(f"第 {attempt} 次备份尝试失败：{error}", "ERROR", task["id"])
                    if job["stop"].is_set() or attempt == 6:
                        break
                    time.sleep(min(30, attempt * 5))
            if job["stop"].is_set():
                discarded = job.get("discard_partial", False)
                if discarded:
                    self.clear_partial(task)
                state.update(last_result="已停止" if discarded else "已暂停", last_error=error)
                self._save_state()
                self.notify(
                    f"备份{'已停止并清除断点' if discarded else '已暂停，断点已保留'}：{task['name']}\n原因：{error}",
                    task["id"],
                )
                return
            state.update(last_result="失败", last_error=error)
            if source == "定时":
                state["next_run"] = self.next_scheduled(task, state, time.time() + 1)
            self._save_state()
            self.notify(f"备份失败：{task['name']}\n已连续失败 6 次并停止。\n原因：{error}", task["id"])
        finally:
            with self.lock:
                self.jobs.pop(task["id"], None)

    def resume_interrupted(self):
        resumed = 0
        for task in self.config["tasks"]:
            if self.task_state(task["id"]).get("last_result") != "运行中":
                continue
            ok, _ = self.start_backup(task["id"], "服务重启后自动续传")
            resumed += int(ok)
        return resumed

    def scheduler_loop(self):
        last_telegram = 0
        while not self.stop_daemon.wait(2):
            now = time.time()
            for task in list(self.config["tasks"]):
                try:
                    if not task["enabled"] or task["id"] in self.jobs:
                        continue
                    state = self.task_state(task["id"])
                    if not state.get("next_run"):
                        state["next_run"] = self.next_scheduled(task, state, now)
                        self._save_state()
                    elif state["next_run"] <= now and self.disk_guard(task):
                        self.start_backup(task["id"], "定时")
                except Exception as exc:
                    self.log(f"调度任务 {task.get('name', task.get('id'))} 出错：{exc}", "ERROR", task.get("id", ""))
            if now - last_telegram >= 3:
                last_telegram = now
                self.poll_telegram()

    def poll_telegram(self):
        token = self.config.get("telegram_bot_token")
        chat = str(self.config.get("telegram_chat_id", ""))
        if not token or not chat:
            return
        offset = int(self.state.get("telegram_offset", 0))
        try:
            url = f"https://api.telegram.org/bot{token}/getUpdates?" + urllib.parse.urlencode({
                "offset": offset, "timeout": 1, "allowed_updates": '["message"]'
            })
            result = json.loads(urllib.request.urlopen(url, timeout=5).read())
            for update in result.get("result", []):
                self.state["telegram_offset"] = update["update_id"] + 1
                message = update.get("message", {})
                if str(message.get("chat", {}).get("id", "")) == chat:
                    self.telegram_command(message.get("text", ""))
            self._save_state()
        except Exception:
            pass

    def telegram_command(self, text):
        command, _, argument = text.strip().partition(" ")
        command = command.split("@", 1)[0].lower()
        if command in ("/start", "/help"):
            self.notify(
                "备份管理命令：\n/tasks 查看任务\n/backup 任务ID 开始\n"
                "/stop 任务ID（或 all）暂停并保留断点\n"
                "/discard 任务ID（或 all）停止并清除断点\n/status [任务ID]\n/list 任务ID\n"
                "/delete 任务ID 备份文件名"
            )
        elif command == "/tasks":
            rows = [
                f"{t['id']}  {t['name']}  {'启用' if t['enabled'] else '停用'}"
                for t in self.config["tasks"]
            ]
            self.notify("备份任务：\n" + ("\n".join(rows) if rows else "暂无任务"))
        elif command == "/backup":
            task = self.resolve_task(argument)
            ok, message = self.start_backup(task["id"], "Telegram") if task else (False, "任务不存在或名称不唯一")
            self.notify(message)
        elif command == "/stop":
            if argument.strip().lower() == "all":
                self.stop_all("Telegram 临时暂停")
                self.notify("已要求暂停所有正在运行的备份，断点将保留")
            else:
                task = self.resolve_task(argument)
                ok, message = self.stop_backup(task["id"], False, "Telegram") if task else (False, "任务不存在或名称不唯一")
                self.notify(message)
        elif command == "/discard":
            if argument.strip().lower() == "all":
                self.stop_all("Telegram 停止并清除断点", True)
                self.notify("已要求停止所有正在运行的备份并清除断点")
            else:
                task = self.resolve_task(argument)
                ok, message = self.stop_backup(task["id"], True, "Telegram") if task else (False, "任务不存在或名称不唯一")
                self.notify(message)
        elif command == "/status":
            task = self.resolve_task(argument)
            if task:
                state = self.task_state(task["id"])
                job = self.jobs.get(task["id"])
                self.notify(
                    f"{task['name']}（{task['id']}）\n状态："
                    f"{'运行中 ' + str(job['progress']) + '%' if job else state['last_result']}\n"
                    f"最近备份：{state.get('last_backup') or '无'}\n"
                    f"错误：{state.get('last_error') or '无'}"
                )
            else:
                self.notify("任务不存在；多个任务时请提供任务 ID")
        elif command == "/list":
            task = self.resolve_task(argument)
            self.notify(
                f"{task['name']} 的备份：\n" + "\n".join(p.name for p in self.backups(task)[-20:])
                if task else "任务不存在"
            )
        elif command == "/delete":
            task_ref, _, name = argument.strip().partition(" ")
            task = self.resolve_task(task_ref, allow_single=False)
            allowed = {p.name: p for p in self.backups(task)} if task else {}
            if name in allowed:
                self.delete_backup(allowed[name])
                self.notify(f"已删除备份：{task['name']} / {name}")
            else:
                self.notify("任务或备份文件名不存在")

    @staticmethod
    def esc(value):
        return html.escape(str(value), quote=True)

    def page(self, title, body, token=""):
        csrf = hmac.new(
            self.config["session_secret"].encode(), token.encode(), hashlib.sha256
        ).hexdigest() if token else ""
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{self.esc(title)} - Simple Backup</title>
<link rel="icon" href="{BRAND_FAVICON}">
<script>document.documentElement.dataset.theme=localStorage.getItem('sb_theme')||'auto'</script><style>
:root{{--bg:#f5f7fb;--bg-soft:#eef3ff;--fg:#152033;--muted:#697386;--card:#ffffffed;--card-solid:#fff;--border:#dfe5ef;--input:#fff;--primary:#356df3;--primary-hover:#285dd8;--primary-soft:#eaf0ff;--success:#15805d;--success-soft:#e6f7f1;--danger:#cf3f4f;--danger-soft:#fff0f2;--warning:#b76b16;--warning-soft:#fff5e7;--shadow:0 16px 45px #263b6b12;--shadow-hover:0 22px 55px #263b6b1f;--ring:#356df333;--header:#ffffffdc;--header-fg:#172238;--header-muted:#65738a;--header-border:#d8e0edcc;--header-hover:#eaf0fb;--header-active:#e2eafe;--brand-tile:#edf2ff}}
html[data-theme=dark]{{--bg:#0c1320;--bg-soft:#111c30;--fg:#edf3ff;--muted:#9cabc0;--card:#131e30eb;--card-solid:#131e30;--border:#293750;--input:#0e1828;--primary:#6790ff;--primary-hover:#83a5ff;--primary-soft:#1c315d;--success:#47c79b;--success-soft:#153a35;--danger:#ff7281;--danger-soft:#401f29;--warning:#f0b45b;--warning-soft:#3d3020;--shadow:0 18px 55px #0006;--shadow-hover:0 24px 65px #0008;--ring:#7fa1ff44;--header:#09111ef2;--header-fg:#f5f8ff;--header-muted:#b9c5d8;--header-border:#ffffff12;--header-hover:#ffffff12;--header-active:#ffffff18;--brand-tile:#18294a}}
@media(prefers-color-scheme:dark){{html[data-theme=auto]{{--bg:#0c1320;--bg-soft:#111c30;--fg:#edf3ff;--muted:#9cabc0;--card:#131e30eb;--card-solid:#131e30;--border:#293750;--input:#0e1828;--primary:#6790ff;--primary-hover:#83a5ff;--primary-soft:#1c315d;--success:#47c79b;--success-soft:#153a35;--danger:#ff7281;--danger-soft:#401f29;--warning:#f0b45b;--warning-soft:#3d3020;--shadow:0 18px 55px #0006;--shadow-hover:0 24px 65px #0008;--ring:#7fa1ff44;--header:#09111ef2;--header-fg:#f5f8ff;--header-muted:#b9c5d8;--header-border:#ffffff12;--header-hover:#ffffff12;--header-active:#ffffff18;--brand-tile:#18294a}}}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;min-height:100vh;background:radial-gradient(circle at 8% 0,var(--bg-soft),transparent 32rem),var(--bg);color:var(--fg);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;-webkit-font-smoothing:antialiased}}
header{{background:var(--header);color:var(--header-fg);padding:16px}}nav{{max-width:1100px;margin:auto;display:flex;gap:18px;align-items:center;flex-wrap:wrap}}
nav b{{font-size:20px;margin-right:auto}}a{{color:#1769aa;text-decoration:none}}nav a{{color:var(--header-fg)}}
main{{max-width:1100px;margin:28px auto;padding:0 14px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:24px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;box-shadow:0 3px 12px #2030400d}}main>.card{{margin-top:24px}}
.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}.muted{{color:var(--muted)}}.ok{{color:#08783f}}.bad{{color:#e04444}}
label{{display:block;margin:12px 0 4px;font-weight:600}}input,select{{width:100%;padding:10px;border:1px solid var(--border);border-radius:7px;background:var(--input);color:var(--fg)}}
input[type=checkbox]{{width:auto}}button,.btn{{border:0;border-radius:7px;padding:9px 14px;background:#1769aa;color:white;cursor:pointer}}
.danger{{background:#b42318}}.secondary{{background:#667085}}form.inline{{display:inline}}small{{line-height:1.5}}
.time-row{{display:flex;gap:8px;margin:6px 0}}.time-row input{{margin:0}}.time-row button{{padding:6px 11px}}
.donut{{width:150px;height:150px;border-radius:50%;display:grid;place-items:center;margin:auto}}.donut:after{{content:'';width:105px;height:105px;border-radius:50%;background:var(--card)}}
.disk-wrap{{position:relative;text-align:center}}.disk-tip{{display:none;position:absolute;z-index:2;left:50%;transform:translateX(-50%);background:#111827;color:white;padding:10px;border-radius:7px;min-width:240px;white-space:pre-line}}.disk-wrap:hover .disk-tip{{display:block}}
pre{{white-space:pre-wrap;word-break:break-word;background:var(--input);border:1px solid var(--border);padding:12px;border-radius:8px;max-height:430px;overflow:auto}}
.progress{{height:12px;background:var(--border);border-radius:999px;overflow:hidden}}.progress>span{{display:block;height:100%;background:#1769aa;transition:width .3s}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;text-align:left;border-bottom:1px solid var(--border)}}.metric{{font-size:26px;margin:8px 0}}
.queue-list{{display:grid;gap:0}}.queue-item{{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid var(--border)}}.queue-item time{{color:var(--muted);white-space:nowrap}}details summary{{cursor:pointer;padding-top:10px;color:#1769aa}}
@media(max-width:640px){{header{{padding:12px 10px}}nav{{gap:12px}}nav b{{width:100%;margin:0}}main{{margin:16px auto;padding:0 10px}}.grid{{grid-template-columns:minmax(0,1fr);gap:16px}}.card{{padding:15px}}main>.card{{margin-top:16px}}input,select{{font-size:16px}}button,.btn{{min-height:42px}}.metric{{font-size:21px}}table{{min-width:620px}}.queue-item{{align-items:flex-start}}.queue-item time{{font-size:13px}}}}
@media(hover:none){{.disk-tip{{display:block;position:static;transform:none;margin-top:10px;min-width:0}}}}
html{{scroll-behavior:smooth}}body{{min-height:100vh;background:radial-gradient(circle at 8% 0,var(--bg-soft),transparent 32rem),var(--bg);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;-webkit-font-smoothing:antialiased}}
header{{position:sticky;top:0;z-index:20;padding:0;background:var(--header);color:var(--header-fg);border-bottom:1px solid var(--header-border);backdrop-filter:blur(18px);box-shadow:0 8px 30px #0001;transition:background .25s,border-color .25s,color .25s}}
nav{{max-width:1240px;min-height:68px;padding:9px 20px;gap:7px;flex-wrap:nowrap}}nav b{{display:flex;align-items:center;gap:11px;color:var(--header-fg);font-size:18px;letter-spacing:-.02em;min-width:0}}.brand-icon{{width:36px;height:36px;flex:0 0 36px;display:grid;place-items:center;padding:8px;border-radius:11px;background:var(--brand-tile);color:var(--primary);box-shadow:inset 0 0 0 1px var(--header-border),0 8px 22px #356df31c}}.brand-icon svg{{width:100%;height:100%}}
nav a{{color:var(--header-muted);padding:9px 12px;border-radius:10px;font-weight:650;transition:background .18s,color .18s,transform .18s}}nav a:hover{{background:var(--header-hover);color:var(--header-fg)}}nav a.active{{background:var(--header-active);color:var(--header-fg);box-shadow:inset 0 0 0 1px var(--header-border)}}
main{{max-width:1240px;margin:0 auto;padding:34px 20px 64px}}h1,h2,h3{{letter-spacing:-.025em;line-height:1.22}}h1{{font-size:clamp(26px,4vw,36px)}}h2{{font-size:19px}}.grid{{grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px}}
.card{{position:relative;background:var(--card);border-color:var(--border);border-radius:18px;padding:24px;box-shadow:var(--shadow);backdrop-filter:blur(16px);animation:card-in .38s cubic-bezier(.2,.75,.25,1) both;transition:transform .22s,border-color .22s,box-shadow .22s}}.card:hover{{border-color:var(--primary);box-shadow:var(--shadow-hover)}}main>.card{{margin-top:26px}}.grid>.card:nth-child(2){{animation-delay:.05s}}.grid>.card:nth-child(3){{animation-delay:.1s}}
@keyframes card-in{{from{{opacity:0;transform:translateY(10px)}}to{{opacity:1;transform:none}}}}@keyframes pulse{{50%{{opacity:.45;transform:scale(.78)}}}}@keyframes shimmer{{to{{background-position:200% 0}}}}@keyframes spin{{to{{transform:rotate(360deg)}}}}
.muted{{color:var(--muted)}}.ok{{color:var(--success)}}.bad{{color:var(--danger)}}label{{margin-top:16px;font-weight:680}}input,select{{padding:11px 12px;border-radius:10px;outline:0;transition:border-color .18s,box-shadow .18s}}input:hover,select:hover{{border-color:var(--primary)}}input:focus,select:focus{{border-color:var(--primary);box-shadow:0 0 0 4px var(--ring)}}input[type=checkbox]{{accent-color:var(--primary)}}
button,.btn{{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:40px;border:1px solid transparent;border-radius:10px;padding:9px 14px;background:var(--primary);font-weight:720;box-shadow:0 8px 20px #356df324;transition:transform .16s,background .16s,box-shadow .16s,opacity .16s}}button:hover,.btn:hover{{background:var(--primary-hover);transform:translateY(-1px);box-shadow:0 11px 25px #356df338}}button:active,.btn:active{{transform:translateY(1px) scale(.985)}}button:disabled{{opacity:.65;cursor:wait;transform:none}}.danger{{background:var(--danger);box-shadow:none}}.secondary{{background:var(--card-solid);color:var(--fg);border-color:var(--border);box-shadow:none}}.secondary:hover{{background:var(--bg-soft)}}small{{display:block;margin-top:6px}}
.theme-switch{{display:flex;align-items:center;gap:2px;padding:3px;border:1px solid var(--header-border);border-radius:12px;background:var(--brand-tile);box-shadow:inset 0 1px 2px #0000000a}}.theme-option{{width:31px;height:31px;min-height:31px;padding:7px;border:0;border-radius:9px;background:transparent;color:var(--header-muted);box-shadow:none}}.theme-option svg{{width:100%;height:100%}}.theme-option:hover{{background:var(--header-hover);color:var(--header-fg);box-shadow:none;transform:none}}.theme-option.active{{background:var(--card-solid);color:var(--primary);box-shadow:0 3px 10px #17243b1c}}.theme-switch.changed .theme-option.active{{animation:theme-pop .24s ease}}@keyframes theme-pop{{50%{{transform:scale(.82) rotate(-8deg)}}}}
.badge{{display:inline-flex;align-items:center;gap:7px;padding:5px 9px;border-radius:999px;background:var(--bg-soft);color:var(--muted);font-size:12px;font-weight:750}}.badge.running{{background:var(--primary-soft);color:var(--primary)}}.badge.success{{background:var(--success-soft);color:var(--success)}}.badge.failed{{background:var(--danger-soft);color:var(--danger)}}.badge.waiting{{background:var(--warning-soft);color:var(--warning)}}.status-dot{{width:7px;height:7px;border-radius:50%;background:currentColor}}.running .status-dot{{animation:pulse 1.25s infinite}}
.donut{{position:relative;width:156px;height:156px;box-shadow:inset 0 0 0 1px var(--border)}}.donut:after{{position:absolute;width:112px;height:112px;background:var(--card-solid);box-shadow:0 5px 20px #0001}}.donut-value{{position:absolute;z-index:1;font-size:25px;font-weight:820;letter-spacing:-.04em}}.disk-tip{{bottom:18px;display:block;opacity:0;pointer-events:none;transform:translate(-50%,8px);border-radius:11px;box-shadow:0 18px 40px #0005;transition:opacity .18s,transform .18s}}.disk-wrap:hover .disk-tip{{opacity:1;transform:translate(-50%,0)}}
pre{{padding:16px;border-radius:12px;max-height:520px;box-shadow:inset 0 1px 7px #0000000b;font:12px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace}}.log-shell{{position:relative;padding-top:28px}}.log-shell pre{{margin:0}}.log-shell:before{{content:'LIVE';position:absolute;right:2px;top:0;z-index:2;padding:3px 7px;border-radius:6px;background:var(--success-soft);color:var(--success);font-size:10px;font-weight:850;letter-spacing:.1em}}
.progress{{height:9px}}.progress>span{{background:linear-gradient(90deg,var(--primary),#83a5ff,var(--primary));background-size:200% 100%;transition:width .45s cubic-bezier(.2,.8,.2,1);animation:shimmer 2.2s linear infinite}}.metric{{font-size:30px;font-weight:800;letter-spacing:-.04em}}th{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
.running-list{{display:grid;gap:13px}}.running-card{{padding:16px;border:1px solid var(--border);border-radius:13px;background:var(--input);animation:card-in .25s both}}.running-top{{display:flex;gap:10px;align-items:center;margin-bottom:10px;min-width:0}}.running-top b{{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.running-meta{{display:flex;justify-content:space-between;gap:12px;margin:8px 0 0;color:var(--muted);font-size:13px}}.task-card{{display:flex;flex-direction:column;gap:12px;min-width:0;overflow:hidden}}.task-card>*{{min-width:0}}.task-card .card-heading>div{{min-width:0;overflow:hidden}}.task-title,.task-endpoint,.task-value,.task-meta code{{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.task-card .row:last-child{{margin-top:auto;padding-top:5px}}.empty-state{{text-align:center;padding:30px 18px;color:var(--muted)}}
.page-heading{{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:24px}}.page-heading h1{{margin:0 0 4px}}.page-heading p{{margin:0}}.card-heading{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:16px}}.card-heading h1,.card-heading h2{{margin:0}}.card-kicker{{color:var(--primary);font-size:11px;font-weight:850;letter-spacing:.11em;text-transform:uppercase}}
.task-meta{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 18px;padding:13px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border)}}.task-meta>span{{min-width:0;overflow:hidden}}.task-meta b{{display:block;color:var(--muted);font-size:11px;letter-spacing:.06em;text-transform:uppercase}}.task-meta code{{min-width:0;color:var(--fg)}}
.backup-list{{display:grid;gap:12px}}.backup-file{{display:grid;grid-template-columns:44px minmax(0,1fr) auto;align-items:center;gap:14px;padding:14px 15px;border:1px solid var(--border);border-radius:14px;background:var(--input);transition:transform .18s,border-color .18s,box-shadow .18s}}.backup-file:hover{{transform:translateY(-1px);border-color:var(--primary);box-shadow:0 12px 28px #223a6a12}}.backup-file-icon{{width:44px;height:44px;display:grid;place-items:center;padding:11px;border-radius:12px;background:var(--primary-soft);color:var(--primary)}}.backup-file-icon svg{{width:100%;height:100%}}.backup-file-info{{min-width:0}}.file-name{{display:block;min-width:0;color:var(--fg);font-weight:720;line-height:1.45;white-space:normal;overflow-wrap:anywhere;word-break:break-word}}.file-meta{{display:flex;gap:8px 16px;flex-wrap:wrap;margin-top:5px;color:var(--muted);font-size:12px}}.backup-delete{{background:transparent;color:var(--danger);border-color:var(--border);box-shadow:none}}.backup-delete:hover{{background:var(--danger-soft);border-color:var(--danger);color:var(--danger);box-shadow:none}}
.danger-zone{{max-width:980px;margin:26px auto 0;display:flex;align-items:center;justify-content:space-between;gap:22px;padding:20px 22px;border:1px solid var(--border);border-left:4px solid var(--danger);border-radius:16px;background:var(--danger-soft)}}.danger-zone-copy{{min-width:0}}.danger-zone h2{{margin:2px 0 5px;color:var(--danger)}}.danger-zone p{{margin:0;color:var(--muted)}}.danger-outline{{background:transparent;color:var(--danger);border-color:var(--danger);box-shadow:none;white-space:nowrap}}.danger-outline:hover{{background:var(--danger);color:#fff;box-shadow:0 10px 24px #cf3f4f22}}
.form-shell{{max-width:980px;margin-inline:auto}}.form-section{{margin-top:22px;padding:22px;border:1px solid var(--border);border-radius:15px;background:var(--input)}}.form-section:first-of-type{{margin-top:0}}.section-heading{{display:flex;align-items:flex-start;gap:12px;margin-bottom:17px}}.section-icon{{flex:0 0 34px;width:34px;height:34px;display:grid;place-items:center;border-radius:10px;background:var(--primary-soft);color:var(--primary);font-weight:850}}.section-heading h2{{margin:0 0 3px}}.section-heading p{{margin:0;color:var(--muted);font-size:13px}}.form-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 18px}}.form-grid>.wide{{grid-column:1/-1}}.form-actions{{position:sticky;bottom:12px;z-index:5;display:flex;justify-content:flex-end;gap:10px;margin-top:22px;padding:12px;border:1px solid var(--border);border-radius:14px;background:var(--card);box-shadow:0 12px 38px #0002;backdrop-filter:blur(14px)}}.check-row{{display:flex;gap:18px;flex-wrap:wrap}}.check-row label{{margin:0;display:flex;align-items:center;gap:8px}}
.settings-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}}.settings-grid .card{{margin:0}}.form-section.compact{{padding:18px;margin-top:18px}}.form-actions.inner{{position:static;justify-content:flex-start;padding:0;margin-top:18px;border:0;background:transparent;box-shadow:none;backdrop-filter:none}}.settings-actions{{margin-top:24px}}.table-scroll{{overflow:auto;border:1px solid var(--border);border-radius:13px}}.table-scroll table{{min-width:680px}}.table-scroll th,.table-scroll td{{padding:12px 14px}}.slot-speed{{font-weight:800;color:var(--primary)}}.mini-progress{{width:96px;height:5px;margin-top:5px;border-radius:99px;background:var(--border);overflow:hidden}}.mini-progress span{{display:block;height:100%;background:var(--primary)}}
.metric.flash{{animation:metric-flash .28s ease}}@keyframes metric-flash{{50%{{color:var(--primary);transform:translateY(-1px)}}}}.inline-error{{padding:12px 14px;border:1px solid var(--danger);border-radius:11px;background:var(--danger-soft);color:var(--danger)}}
.toast-stack{{position:fixed;z-index:60;right:20px;top:82px;display:grid;gap:10px;width:min(390px,calc(100% - 28px))}}.toast{{display:flex;align-items:flex-start;gap:11px;padding:14px 15px;background:var(--card-solid);border:1px solid var(--border);border-left:4px solid var(--primary);border-radius:13px;box-shadow:0 20px 55px #0003;animation:toast-in .3s cubic-bezier(.2,.8,.2,1) both}}.toast.success{{border-left-color:var(--success)}}.toast.error{{border-left-color:var(--danger)}}.toast.out{{opacity:0;transform:translateX(15px);transition:.22s}}@keyframes toast-in{{from{{opacity:0;transform:translateX(20px)}}}}
dialog{{width:min(430px,calc(100% - 28px));padding:0;border:1px solid var(--border);border-radius:18px;background:var(--card-solid);color:var(--fg);box-shadow:0 28px 90px #0007}}dialog::backdrop{{background:#07101fb8;backdrop-filter:blur(4px)}}.dialog-body{{padding:24px}}.dialog-body h2{{margin-top:0}}.dialog-actions{{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}}
.is-loading:before{{content:'';width:13px;height:13px;border:2px solid #ffffff70;border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}}
@media(max-width:850px){{nav{{flex-wrap:wrap}}nav b{{width:calc(100% - 112px)}}nav a{{flex:1;text-align:center}}nav a[href='/task']{{order:3;flex-basis:100%}}main{{padding-top:24px}}.settings-grid{{grid-template-columns:1fr}}}}
@media(max-width:640px){{header{{position:sticky;top:0}}nav{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px 4px;padding:9px 10px 10px}}nav b{{grid-column:1/5;grid-row:1;width:auto;min-width:0;margin:0;padding:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.brand-icon{{width:32px;height:32px;flex-basis:32px;padding:7px}}.theme-switch{{grid-column:5/7;grid-row:1;justify-self:end;margin-left:0}}nav>a:not([href='/logout']){{grid-row:2;min-width:0;min-height:42px;display:flex;align-items:center;justify-content:center;padding:8px 2px;background:var(--brand-tile);border:1px solid var(--header-border);font-size:12px;line-height:1;white-space:nowrap;text-align:center;box-shadow:none}}nav>a[href='/']{{grid-column:1}}nav>a[href='/tasks']{{grid-column:2}}nav>a[href='/logs']{{grid-column:3}}nav>a[href='/offsite']{{grid-column:4}}nav>a[href='/settings']{{grid-column:5}}nav>a[href='/task']{{grid-column:6}}nav a[href='/logout']{{display:none}}main{{padding:20px 11px 44px}}.grid{{gap:18px}}.card{{padding:18px;border-radius:15px}}main>.card{{margin-top:20px}}.page-heading{{display:block;margin-bottom:18px}}.page-heading .btn{{margin-top:12px;width:100%}}.task-card .row button,.task-card .row .btn{{flex:1}}.task-meta,.form-grid{{grid-template-columns:1fr}}.form-section{{padding:16px;margin-top:16px}}.form-actions{{bottom:7px}}.form-actions button{{flex:1}}.backup-file{{grid-template-columns:38px minmax(0,1fr);gap:11px;padding:13px}}.backup-file-icon{{width:38px;height:38px;padding:9px}}.backup-file form{{grid-column:1/-1;display:block}}.backup-file button{{width:100%}}.danger-zone{{align-items:stretch;flex-direction:column;padding:18px}}.danger-zone form,.danger-zone button{{width:100%}}.toast-stack{{top:12px;right:14px}}.disk-tip{{opacity:1;transform:none;position:static;margin-top:12px}}}}
@media(max-width:380px){{nav b{{font-size:16px;gap:8px}}nav>a:not([href='/logout']){{font-size:11px;letter-spacing:-.02em}}}}
@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{scroll-behavior:auto!important;animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}}}
</style></head><body><header><nav><b><span class="brand-icon">{BRAND_ICON}</span>Simple Backup</b><a href="/">首页</a><a href="/tasks">任务</a>
<a href="/logs">日志</a><a href="/offsite">容灾</a><a href="/settings">设置</a><a href="/task">新建任务</a><div class="theme-switch" id="theme-switch" role="group" aria-label="主题模式"><button type="button" class="theme-option" data-theme-value="auto" aria-label="跟随系统" title="跟随系统">{THEME_ICONS['auto']}</button><button type="button" class="theme-option" data-theme-value="light" aria-label="日间模式" title="日间模式">{THEME_ICONS['light']}</button><button type="button" class="theme-option" data-theme-value="dark" aria-label="夜间模式" title="夜间模式">{THEME_ICONS['dark']}</button></div><a href="/logout">退出</a></nav></header>
<main>{body}</main><div class='toast-stack' id='toast-stack' aria-live='polite'></div><dialog id='confirm-dialog'><div class='dialog-body'><h2>确认操作</h2><p id='confirm-message'></p><div class='dialog-actions'><button type='button' class='secondary' id='confirm-cancel'>取消</button><button type='button' class='danger' id='confirm-ok'>确认</button></div></div></dialog><script>
const addHidden=(f,n,v)=>{{let i=f.querySelector('input[name='+n+']');if(!i){{i=document.createElement('input');i.type='hidden';i.name=n;f.appendChild(i)}}i.value=v}};
document.querySelectorAll('form').forEach(f=>{{if(f.method.toLowerCase()==='post'){{addHidden(f,'csrf','{csrf}');addHidden(f,'return_to',location.pathname+location.search)}}}});
let current=location.pathname==='/'?'home':location.pathname==='/tasks'||location.pathname==='/task'&&location.search?'tasks':location.pathname==='/task'?'new':location.pathname.startsWith('/logs')?'logs':location.pathname==='/offsite'?'offsite':location.pathname==='/settings'?'settings':'';
let navLinks=[...document.querySelectorAll('nav a')];let activeLink=current==='home'?navLinks.find(a=>a.getAttribute('href')==='/'):navLinks.find(a=>current==='tasks'&&a.getAttribute('href')==='/tasks'||current==='new'&&a.getAttribute('href')==='/task'||current==='logs'&&a.getAttribute('href')==='/logs'||current==='offsite'&&a.getAttribute('href')==='/offsite'||current==='settings'&&a.getAttribute('href')==='/settings');activeLink?.classList.add('active');
const tailLogs=()=>document.querySelectorAll('pre.tail-log').forEach(p=>p.scrollTop=p.scrollHeight);
addEventListener('pageshow',()=>requestAnimationFrame(tailLogs));
const themeSwitch=document.getElementById('theme-switch'),themeOptions=[...themeSwitch.querySelectorAll('[data-theme-value]')];
function ts(t,feedback=false){{document.documentElement.dataset.theme=t;localStorage.setItem('sb_theme',t);themeOptions.forEach(button=>{{const active=button.dataset.themeValue===t;button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active))}});if(feedback){{themeSwitch.classList.remove('changed');void themeSwitch.offsetWidth;themeSwitch.classList.add('changed');setTimeout(()=>themeSwitch.classList.remove('changed'),260)}}}}
themeOptions.forEach(button=>button.onclick=()=>ts(button.dataset.themeValue,true));ts(document.documentElement.dataset.theme);
const params=new URLSearchParams(location.search),notice=params.get('notice'),tone=params.get('tone')||'success';if(notice){{let box=document.getElementById('toast-stack'),toast=document.createElement('div');toast.className='toast '+tone;let dot=document.createElement('span'),copy=document.createElement('div'),heading=document.createElement('b'),detail=document.createElement('div');dot.className='status-dot';heading.textContent=tone==='error'?'操作失败':'操作完成';detail.textContent=notice;copy.append(heading,detail);toast.append(dot,copy);box.append(toast);setTimeout(()=>{{toast.classList.add('out');setTimeout(()=>toast.remove(),240)}},4200);params.delete('notice');params.delete('tone');history.replaceState(null,'',location.pathname+(params.size?'?'+params.toString():'')+location.hash)}}
const dialog=document.getElementById('confirm-dialog'),message=document.getElementById('confirm-message');let pending=null,confirmed=false;document.querySelectorAll('form').forEach(f=>{{let action=f.getAttribute('action');if(action==='/backup/stop'){{f.removeAttribute('onsubmit');f.dataset.confirm='停止后会清除本次已下载的数据，且无法断点续传。确定停止并清除？'}}if(action==='/task/delete'){{f.removeAttribute('onsubmit');f.dataset.confirm='只删除任务设置，不删除已有备份。确定删除？'}}}});
document.getElementById('confirm-cancel').onclick=()=>{{pending=null;dialog.close()}};document.getElementById('confirm-ok').onclick=()=>{{let item=pending;pending=null;confirmed=true;dialog.close();item?.form.requestSubmit(item.submitter)}};
document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{{let submitter=e.submitter||f.querySelector('button'),text=submitter?.dataset.confirm||f.dataset.confirm;if(text&&!confirmed){{e.preventDefault();pending={{form:f,submitter}};message.textContent=text;dialog.showModal();return}}confirmed=false;if(submitter){{submitter.disabled=true;submitter.classList.add('is-loading');submitter.dataset.original=submitter.textContent;submitter.textContent=submitter.dataset.loading||'处理中…'}}}}));
const am=document.getElementById('auth-method'),ka=document.getElementById('key-auth'),pa=document.getElementById('password-auth');
function authUI(){{if(!am)return;ka.hidden=am.value!=='key';pa.hidden=am.value!=='password'}}if(am){{am.onchange=authUI;authUI()}}
const so=document.getElementById('source-type'),fm=document.getElementById('file-mode'),fs=document.getElementById('file-source'),ds=document.getElementById('database-source'),ft=document.getElementById('file-threads'),rs=document.getElementById('retention-settings'),rp=document.getElementById('remote-path'),du=document.getElementById('database-user'),dn=document.getElementById('database-name');
function sourceUI(){{if(!so)return;let files=so.value==='files',sql=so.value==='mysql'||so.value==='postgresql',persistent=files&&fm.value!=='snapshot';fs.hidden=!files;ds.hidden=files;ft.hidden=!files;rs.hidden=persistent;rp.required=files;du.required=sql;dn.required=sql}}if(so){{so.onchange=sourceUI;fm.onchange=sourceUI;sourceUI()}}
const st=document.getElementById('schedule-times'),sv=document.getElementById('schedule-times-value'),add=document.getElementById('add-time');
if(st){{add.onclick=()=>{{if(st.querySelectorAll('.schedule-time').length>=24)return;st.insertAdjacentHTML('beforeend','<div class="time-row"><input class="schedule-time" type="time" value="12:00" required><button type="button" class="remove-time secondary" title="删除时间">×</button></div>')}};
st.onclick=e=>{{if(e.target.classList.contains('remove-time')&&st.querySelectorAll('.schedule-time').length>1)e.target.parentElement.remove()}};
st.closest('form').addEventListener('submit',()=>{{sv.value=[...st.querySelectorAll('.schedule-time')].map(i=>i.value).filter(Boolean).join(',')}})}}
</script></body></html>"""

    @staticmethod
    def network_counters():
        try:
            received, sent = 0, 0
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
                name, values = line.split(":", 1)
                fields = values.split()
                if name.strip() != "lo":
                    received += int(fields[0])
                    sent += int(fields[8])
            return {"rx": received, "tx": sent}
        except (OSError, ValueError, IndexError):
            return {"rx": 0, "tx": 0}

    def home_html(self, token):
        disks = {}
        for task in self.config["tasks"]:
            path = Path(task["backup_dir"])
            try:
                path.mkdir(parents=True, exist_ok=True)
                device = os.stat(path).st_dev
                entry = disks.setdefault(device, {"path": str(path), "usage": shutil.disk_usage(path), "tasks": []})
                size = sum(directory_size(item) for item in self.backups(task))
                entry["tasks"].append((task["name"], size))
            except OSError as exc:
                self.log(f"读取磁盘信息失败：{path}：{exc}", "ERROR")
        disk_cards = []
        for entry in disks.values():
            usage = entry["usage"]
            used = usage.total - usage.free
            percent = round(used / usage.total * 100, 1) if usage.total else 0
            details = "\n".join(f"{name}：{human_size(size)}" for name, size in entry["tasks"]) or "暂无任务备份"
            disk_cards.append(f"""<section class="card disk-wrap"><div class="card-heading"><div><span class="card-kicker">Storage</span><h2>备份磁盘</h2></div><span class="badge waiting"><span class="status-dot"></span>{human_size(usage.free)} 可用</span></div>
<div class="donut" style="background:conic-gradient(var(--primary) {percent}%,var(--border) 0)"><span class="donut-value">{percent}%</span></div>
<p><b>{percent}%</b> · 已用 {human_size(used)} / {human_size(usage.total)}<br><span class="muted">{self.esc(entry['path'])}</span></p>
<div class="disk-tip">{self.esc(details)}</div></section>""")
        queue = []
        for task in self.config["tasks"]:
            if not task["enabled"]:
                continue
            state = self.task_state(task["id"])
            stamp = state.get("next_run") or self.next_scheduled(task, state)
            for _ in range(4):
                queue.append((stamp, task))
                stamp = self.next_scheduled(task, state, stamp + 1)
        queue.sort(key=lambda item: item[0])
        queue_items = [
            f"<div class='queue-item'><b>{self.esc(task['name'])}</b><time>{datetime.fromtimestamp(stamp).strftime('%Y-%m-%d %H:%M') if stamp else '待安排'}</time></div>"
            for stamp, task in queue[:8]
        ]
        queue_html = (
            "<div class='queue-list'>" + "".join(queue_items[:4])
            + (f"<details><summary>再显示 {len(queue_items) - 4} 项</summary>{''.join(queue_items[4:])}</details>" if len(queue_items) > 4 else "")
            + "</div>"
            if queue_items else "<p class='muted'>暂无启用的自动任务</p>"
        )
        body = f"""<div class="page-heading"><div><span class="card-kicker">Overview</span><h1>备份控制台</h1><p class="muted">磁盘、网络、队列和任务状态集中在这里。</p></div><a class="btn" href="/task">＋ 新建备份任务</a></div>
<div class="grid">{''.join(disk_cards) or '<section class="card"><h2>备份磁盘</h2><p class="muted">创建任务后显示</p></section>'}
<section class="card"><div class="card-heading"><div><span class="card-kicker">Network</span><h2>当前网速</h2></div><span class="badge running"><span class="status-dot"></span>实时</span></div><div class="row"><div style="flex:1"><span class="muted">↓ 下载</span><p class="metric" id="net-rx">计算中…</p></div><div style="flex:1"><span class="muted">↑ 上传</span><p class="metric" id="net-tx">计算中…</p></div></div><p class="muted">统计本机除回环接口外的实时流量</p></section>
<section class="card"><div class="card-heading"><div><span class="card-kicker">Schedule</span><h2>后续备份队列</h2></div></div>{queue_html}</section></div>
<section class="card"><div class="card-heading"><div><span class="card-kicker">Live Jobs</span><h2>正在运行</h2></div><a href="/tasks">管理任务</a></div><div class="running-list" id="running"><p class="muted">读取中…</p></div></section>
<section class="card"><div class="card-heading"><div><span class="card-kicker">Activity</span><h2>最近日志</h2></div><a href="/logs">查看全部完整日志</a></div>
<div class="log-shell"><pre class="tail-log">{self.esc(self.read_log(40_000))}</pre></div></section>
<script>let nr=0,nw=0,nt=0;async function live(){{let r=await fetch('/api/status'),d=await r.json(),now=Date.now();
if(nt){{let seconds=(now-nt)/1000;[['net-rx',Math.max(0,d.network_rx-nr)],['net-tx',Math.max(0,d.network_tx-nw)]].forEach(([id,value])=>{{let el=document.getElementById(id);el.textContent=(value/1024/1024/seconds).toFixed(2)+' MB/s';el.classList.remove('flash');void el.offsetWidth;el.classList.add('flash')}})}}
nr=d.network_rx;nw=d.network_tx;nt=now;let box=document.getElementById('running');box.replaceChildren();
if(d.running.length)d.running.forEach(x=>{{let card=document.createElement('div'),top=document.createElement('div'),name=document.createElement('b'),badge=document.createElement('span'),dot=document.createElement('span'),bar=document.createElement('div'),fill=document.createElement('span'),meta=document.createElement('div'),left=document.createElement('span'),right=document.createElement('span');card.className='running-card';top.className='running-top';name.textContent=x.name;badge.className='badge running';dot.className='status-dot';badge.append(dot,x.phase);top.append(name,badge);bar.className='progress';fill.style.width=x.total_bytes?x.progress+'%':'18%';bar.append(fill);meta.className='running-meta';left.textContent=x.total_bytes?x.progress+'% · '+fmt(x.transferred_bytes)+' / '+fmt(x.total_bytes):fmt(x.transferred_bytes)+' · 正在计算总大小';right.textContent=fmt(x.speed_bps)+'/s';meta.append(left,right);card.append(top,bar,meta);box.append(card)}});
else{{let p=document.createElement('p');p.className='muted';p.textContent='当前没有运行中的备份';box.append(p)}}}}
function fmt(n){{let u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){{n/=1024;i++}}return n.toFixed(1)+' '+u[i]}}live();setInterval(live,2000);</script>"""
        return self.page("首页", body, token)

    def logs_html(self, token):
        return self.page("日志", f"""<div class="page-heading"><div><span class="card-kicker">Diagnostics</span><h1>全部应用日志</h1><p class="muted">包含当前日志和轮转日志，打开时自动定位到最新一行。</p></div><a class="btn secondary" href="/logs/raw">下载全部日志</a></div>
<section class="card"><div class="log-shell"><pre class="tail-log">{self.esc(self.read_log(None))}</pre></div></section>""", token)

    def dashboard_html(self, token):
        cards = []
        for task in self.config["tasks"]:
            state = self.task_state(task["id"])
            job = self.jobs.get(task["id"])
            status = (
                f"{job.get('phase', '运行中')} {job['progress']}%"
                if job and job.get("total_bytes") else
                f"{job.get('phase', '运行中')} · 已传输 {human_size(job.get('transferred_bytes', 0))} · {human_size(job.get('speed_bps', 0))}/s"
                if job else state.get("last_result", "尚未运行")
            )
            result = state.get("last_result", "尚未运行")
            status_kind = "running" if job else "failed" if state.get("last_error") or result == "失败" else "success" if result == "成功" else "waiting"
            next_run = datetime.fromtimestamp(state["next_run"]).strftime("%Y-%m-%d %H:%M") if state.get("next_run") else "待安排"
            error = f"<p class='bad'>原因：{self.esc(state.get('last_error'))}</p>" if state.get("last_error") else ""
            partial = incremental_ledger(task) if task.get("file_mode") == "incremental" else Path(task["backup_dir"]) / f".partial-{task['id']}"
            if job:
                action = (
                    f"<form class='inline' method='post' action='/backup/pause'><input type='hidden' name='id' value='{task['id']}'><button class='secondary' data-loading='正在暂停…'>临时暂停</button></form>"
                    f"<form class='inline' method='post' action='/backup/stop' onsubmit=\"return confirm('停止后会清除本次已下载的数据，且无法断点续传。确定？')\"><input type='hidden' name='id' value='{task['id']}'><button class='danger' data-loading='正在停止…'>停止并清除</button></form>"
                )
            else:
                label = "继续备份" if partial.exists() or state.get("last_result") == "已暂停" else "立即备份"
                action = f"<form class='inline' method='post' action='/backup/start'><input type='hidden' name='id' value='{task['id']}'><button data-loading='正在启动…'>{label}</button></form>"
            if task["source_type"] == "files":
                mode = {"incremental": "（增量归档，只新增）", "mirror": "（完全镜像同步）"}.get(task.get("file_mode"), "")
                source = self.esc(task["remote_path"] + mode)
            else:
                port = task["database_port"] or {"mysql": 3306, "postgresql": 5432, "redis": 6379}[task["source_type"]]
                source = self.esc(f"{task['source_type']}://{task['database_host']}:{port}/{task['database_name'] or '整个实例'}")
            task_name = self.esc(task["name"])
            endpoint = self.esc(f"ID {task['id']} · {task['remote_user']}@{task['remote_host']}:{task['remote_port']}")
            last_backup = self.esc(state.get("last_backup") or "无")
            backup_dir = self.esc(task["backup_dir"])
            cards.append(f"""<section class="card task-card"><div class="card-heading"><div><span class="card-kicker">Backup Task</span><h2 class="task-title" title="{task_name}">{task_name}</h2></div><span class="badge {status_kind}"><span class="status-dot"></span>{self.esc(status)}</span></div>
<p class="muted task-endpoint" title="{endpoint}">{endpoint}</p>
<div class="task-meta"><span><b>下次执行</b><span class="task-value" title="{next_run}">{next_run}</span></span><span><b>最近备份</b><span class="task-value" title="{last_backup}">{last_backup}</span></span><span><b>备份来源</b><code title="{source}">{source}</code></span><span><b>本地目录</b><code title="{backup_dir}">{backup_dir}</code></span></div>
{error}<div class="row">{action}
<a class="btn secondary" href="/task/detail?id={task['id']}">详情</a><a class="btn secondary" href="/task?id={task['id']}">编辑</a></div></section>""")
        empty = "<section class='card empty-state'><h2>还没有备份任务</h2><p>点击“新建任务”，只需填写服务器和路径即可开始。</p><a class='btn' href='/task'>创建第一个任务</a></section>"
        heading = "<div class='page-heading'><div><span class='card-kicker'>Tasks</span><h1>备份任务</h1><p class='muted'>查看状态、立即运行或进入任务详情。</p></div><a class='btn' href='/task'>＋ 新建任务</a></div>"
        return self.page("任务", heading + "<div class='grid'>" + ("".join(cards) or empty) + "</div>", token)

    def task_detail_html(self, task, token):
        if not task:
            return self.page("任务不存在", "<section class='card'><h1>任务不存在</h1></section>", token)
        task_id = task["id"]
        state = self.task_state(task_id)
        job = self.jobs.get(task_id)
        phase = job.get("phase", "运行中") if job else state.get("last_result", "尚未运行")
        progress = job.get("progress", 0) if job else 0
        transferred = job.get("transferred_bytes", 0) if job else 0
        total = job.get("total_bytes", 0) if job else 0
        plan = f"并行连接 {job.get('parallel_files', 1)} 条 · 固定清单传输" if job else "等待任务开始"
        status_kind = "running" if job else "failed" if state.get("last_error") or phase == "失败" else "success" if phase == "成功" else "waiting"
        partial = incremental_ledger(task) if task.get("file_mode") == "incremental" else Path(task["backup_dir"]) / f".partial-{task_id}"
        if job:
            action = (
                f"<form class='inline' method='post' action='/backup/pause'><input type='hidden' name='id' value='{task_id}'><button class='secondary' data-loading='正在暂停…'>临时暂停</button></form>"
                f"<form class='inline' method='post' action='/backup/stop'><input type='hidden' name='id' value='{task_id}'><button class='danger' data-loading='正在停止…'>停止并清除</button></form>"
            )
        else:
            label = "继续备份" if partial.exists() or state.get("last_result") == "已暂停" else "立即备份"
            action = f"<form class='inline' method='post' action='/backup/start'><input type='hidden' name='id' value='{task_id}'><button data-loading='正在启动…'>{label}</button></form>"
        body = f"""<div class="page-heading"><div><span class="card-kicker">Task Detail</span><h1>{self.esc(task['name'])}</h1><p class="muted">任务 ID {task_id} · {self.esc(task['remote_user'])}@{self.esc(task['remote_host'])}</p></div><div class="row">{action}<a class="btn secondary" href="/task?id={task_id}">编辑设置</a></div></div>
<section class="card"><div class="card-heading"><div><span class="card-kicker">Overall Progress</span><h2 id="detail-phase">{self.esc(phase)}</h2></div><span class="badge {status_kind}" id="detail-badge"><span class="status-dot"></span>{self.esc(phase)}</span></div><div class="progress"><span id="detail-bar" style="width:{progress}%"></span></div>
<p id="detail-summary">{progress}% · {human_size(transferred)} / {human_size(total) if total else '总大小暂未取得'}</p><p class="muted" id="detail-plan">并发策略：{plan}</p>
<p class="muted">多线程模式下显示活跃传输槽位。槽位速度和已传输量来自本地断点文件的实际增长；百分比为整个任务的总体进度。</p></section>
<section class="card"><div class="card-heading"><div><span class="card-kicker">Transfers</span><h2>活跃传输槽位</h2></div><span class="muted">每 2 秒刷新</span></div><div class="table-scroll"><table><thead><tr><th>槽位</th><th>当前文件</th><th>速度</th><th>已传输</th><th>任务进度</th></tr></thead><tbody id="slot-rows"><tr><td colspan="5" class="muted">暂无活跃传输</td></tr></tbody></table></div></section>
<section class="card"><div class="card-heading"><div><span class="card-kicker">Task Logs</span><h2>该任务的全部日志</h2></div><a class="btn secondary" href="/logs">全部应用日志</a></div><div class="log-shell"><pre class="tail-log" id="task-log">{self.esc(self.read_task_log(task_id))}</pre></div></section>
<script>const taskId={json.dumps(task_id)};function fmt(n){{let u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){{n/=1024;i++}}return n.toFixed(1)+' '+u[i]}}
async function detail(){{let r=await fetch('/api/status'),d=await r.json(),x=d.running.find(v=>v.id===taskId),rows=document.getElementById('slot-rows');rows.replaceChildren();if(!x){{let tr=rows.insertRow(),td=tr.insertCell();td.colSpan=5;td.className='muted';td.textContent='当前没有活跃传输';return}}document.getElementById('detail-phase').textContent=x.phase;let badge=document.getElementById('detail-badge');badge.className='badge running';badge.lastChild.textContent=x.phase;document.getElementById('detail-bar').style.width=x.progress+'%';document.getElementById('detail-summary').textContent=(x.total_bytes?x.progress+'% · '+fmt(x.transferred_bytes)+' / '+fmt(x.total_bytes):fmt(x.transferred_bytes)+' · '+fmt(x.speed_bps)+'/s · 正在计算总大小');document.getElementById('detail-plan').textContent='并发策略：'+x.parallel_files+' 条 rsync 连接 · 固定清单传输';if(!x.slots.length){{let tr=rows.insertRow(),td=tr.insertCell();td.colSpan=5;td.className='muted';td.textContent='正在等待文件数据';return}}x.slots.forEach(s=>{{let tr=rows.insertRow(),slot=tr.insertCell(),file=tr.insertCell(),speed=tr.insertCell(),bytes=tr.insertCell(),progressCell=tr.insertCell(),mini=document.createElement('div'),fill=document.createElement('span');slot.textContent='#'+s.slot;file.textContent=s.name;speed.textContent=fmt(s.speed_bps)+'/s';speed.className='slot-speed';bytes.textContent=fmt(s.bytes);progressCell.append(s.progress+'%');mini.className='mini-progress';fill.style.width=s.progress+'%';mini.append(fill);progressCell.append(mini)}})}}
async function taskLog(){{let r=await fetch('/api/task-log?id='+encodeURIComponent(taskId)),p=document.getElementById('task-log'),t=await r.text(),follow=p.scrollHeight-p.scrollTop-p.clientHeight<40;p.textContent=t;if(follow)p.scrollTop=p.scrollHeight}}detail();setInterval(detail,2000);setInterval(taskLog,5000);</script>"""
        return self.page("任务详情", body, token)

    def task_form_html(self, task, token):
        task = dict(TASK_DEFAULTS if task is None else task)
        task_id = self.esc(task.get("id", ""))
        checked = lambda key: "checked" if task.get(key) else ""
        selected = lambda value: "selected" if task.get("auth_method") == value else ""
        source_selected = lambda value: "selected" if task.get("source_type") == value else ""
        file_mode_selected = lambda value: "selected" if task.get("file_mode") == value else ""
        time_inputs = "".join(
            f'<div class="time-row"><input class="schedule-time" type="time" value="{self.esc(value)}" required>'
            '<button type="button" class="remove-time secondary" title="删除时间">×</button></div>'
            for value in task["schedule_times"]
        )
        backups = self.backups(task) if task.get("id") else []
        backup_rows = []
        for path in reversed(backups[-30:]):
            try:
                size = human_size(directory_size(path))
                modified = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            except OSError:
                size = "大小未知"
                modified = "文件状态已变化"
            backup_rows.append(
                "<article class='backup-file'>"
                f"<span class='backup-file-icon'>{ARCHIVE_ICON}</span>"
                "<div class='backup-file-info'>"
                f"<code class='file-name' title='{self.esc(path.name)}'>{self.esc(path.name)}</code>"
                f"<div class='file-meta'><span>{size}</span><span>{modified}</span></div></div>"
                f"<form class='inline' method='post' action='/backup/delete'><input type='hidden' name='id' value='{task_id}'>"
                f"<input type='hidden' name='name' value='{self.esc(path.name)}'><button class='backup-delete' data-loading='正在删除…' data-confirm='确定删除这个备份文件？此操作不可恢复。'>删除文件</button></form></article>"
            )
        backup_rows = "".join(backup_rows)
        delete_task = (
            "<section class='danger-zone'><div class='danger-zone-copy'><span class='card-kicker'>Danger zone</span>"
            "<h2>删除任务</h2><p>只删除任务设置，不会删除已经保存的备份文件。</p></div>"
            f"<form method='post' action='/task/delete'><input type='hidden' name='id' value='{task_id}'>"
            "<button class='danger-outline' data-loading='正在删除…' data-confirm='只删除任务设置，不删除已有备份。确定删除此任务？'>删除此任务</button></form></section>"
            if task_id else ""
        )
        body = f"""<div class="page-heading"><div><span class="card-kicker">Task Setup</span><h1>{'编辑任务' if task_id else '新建备份任务'}</h1><p class="muted">按区域填写即可，隐藏的选项不会参与保存。</p></div><a class="btn secondary" href="/tasks">返回任务列表</a></div>
<section class="card form-shell"><form method="post" action="/task/save"><input type="hidden" name="id" value="{task_id}">
<div class="form-section"><div class="section-heading"><span class="section-icon">1</span><div><h2>基本信息</h2><p>给任务命名并选择要备份的数据类型。</p></div></div><div class="form-grid"><div><label>任务名称</label><input name="name" required maxlength="50" value="{self.esc(task['name'])}"></div><div><label>备份类型</label><select id="source-type" name="source_type"><option value="files" {source_selected('files')}>文件 / 目录</option><option value="mysql" {source_selected('mysql')}>MySQL / MariaDB</option><option value="postgresql" {source_selected('postgresql')}>PostgreSQL</option><option value="redis" {source_selected('redis')}>Redis</option></select></div></div></div>
<div class="form-section"><div class="section-heading"><span class="section-icon">2</span><div><h2>远程服务器与认证</h2><p>程序通过 SSH 安全连接远程服务器。</p></div></div><div class="form-grid"><div><label>远程服务器 IP / 域名</label><input name="remote_host" required value="{self.esc(task['remote_host'])}"></div><div><label>SSH 端口</label><input name="remote_port" type="number" min="1" max="65535" required value="{task['remote_port']}"></div><div><label>SSH 用户名</label><input name="remote_user" required value="{self.esc(task['remote_user'])}"></div><div><label>SSH 登录方式</label><select id="auth-method" name="auth_method"><option value="key" {selected('key')}>SSH 私钥</option><option value="password" {selected('password')}>SSH 密码</option></select></div><div class="wide" id="key-auth"><label>SSH 私钥路径</label><input name="ssh_key" value="{self.esc(task['ssh_key'])}"><small class="muted">填写备份服务器上的绝对路径，例如 /root/.ssh/id_ed25519。</small></div><div class="wide" id="password-auth"><label>SSH 密码</label><input name="ssh_password" type="password" maxlength="512" autocomplete="new-password"><small class="muted">编辑已有任务时留空表示不修改。密码单独保存在仅 root 可读的文件中。</small></div></div></div>
<div class="form-section"><div class="section-heading"><span class="section-icon">3</span><div><h2>备份来源</h2><p>只会显示当前备份类型需要的字段。</p></div></div><div id="file-source"><label>远程文件或目录</label><input id="remote-path" name="remote_path" required value="{self.esc(task['remote_path'])}"><label>文件保存方式</label><select id="file-mode" name="file_mode"><option value="snapshot" {file_mode_selected('snapshot')}>快照压缩包</option><option value="incremental" {file_mode_selected('incremental')}>增量归档（只新增、不压缩）</option><option value="mirror" {file_mode_selected('mirror')}>完全镜像同步（不压缩）</option></select><small class="muted">增量归档只添加新文件；完全镜像会同步新增、修改和删除。两种模式都使用一个固定目录。</small></div><div id="database-source" class="form-grid"><div><label>数据库地址</label><input name="database_host" value="{self.esc(task['database_host'])}"><small class="muted">数据库在同一台远程服务器通常填 127.0.0.1。</small></div><div><label>数据库端口</label><input name="database_port" type="number" min="0" max="65535" value="{task['database_port']}"><small class="muted">填 0 自动使用默认端口。</small></div><div><label>数据库用户名</label><input id="database-user" name="database_user" maxlength="128" value="{self.esc(task['database_user'])}"></div><div><label>数据库名称</label><input id="database-name" name="database_name" maxlength="128" value="{self.esc(task['database_name'])}"><small class="muted">MySQL / PostgreSQL 必填；Redis 无需填写。</small></div><div class="wide"><label>数据库密码</label><input name="database_password" type="password" maxlength="512" autocomplete="new-password"><small class="muted">可留空用于免密连接；编辑时留空表示不修改。密码不会写入普通任务配置或命令行。</small></div></div></div>
<div class="form-section"><div class="section-heading"><span class="section-icon">4</span><div><h2>存储与传输</h2><p>设置保存位置、保留策略与文件传输并发。</p></div></div><label>本地备份目录</label><input name="backup_dir" required value="{self.esc(task['backup_dir'])}"><div class="form-grid"><div id="retention-settings"><label>最多保留多少份</label><input name="retention_limit" type="number" min="0" required value="{task['retention_limit']}"><small class="muted">填 0 表示全部保留。</small></div><div id="file-threads"><label>并行线程数（1-16）</label><input name="transfer_threads" type="number" min="1" max="16" step="1" required value="{task['transfer_threads']}" oninput="if(+this.value>16)this.value=16;if(+this.value<1)this.value=1"><small class="muted">小文件较多时可适当提高。</small></div></div></div>
<div class="form-section"><div class="section-heading"><span class="section-icon">5</span><div><h2>自动执行计划</h2><p>备份周期和一天内的时间点可以分别设置。</p></div></div><div class="form-grid"><div><label>每隔几天备份</label><input name="interval_days" type="number" min="1" max="3650" step="1" required value="{task['interval_days']}"></div><div><label>在这些时间点备份</label><div id="schedule-times">{time_inputs}</div><button type="button" class="secondary" id="add-time">＋ 添加时间</button><input type="hidden" id="schedule-times-value" name="schedule_times"><small class="muted">例如每隔 1 天，设置 02:00 和 14:00，就是每天备份两次。</small></div></div></div>
<div class="form-section"><div class="section-heading"><span class="section-icon">6</span><div><h2>自动化选项</h2><p>这些选项可以随时回来修改。</p></div></div><div class="check-row"><label><input type="checkbox" name="enabled" {checked('enabled')}> 启用自动备份</label><label><input type="checkbox" name="auto_install_dependencies" {checked('auto_install_dependencies')}> 首次连接自动安装对应备份客户端</label></div></div>
<div class="form-actions"><a class="btn secondary" href="/tasks">取消</a><button data-loading="正在保存…">保存任务</button></div></form></section>
<section class="card form-shell"><div class="card-heading"><div><span class="card-kicker">Archives</span><h2>已有备份</h2></div><span class="badge waiting">{len(backups)} 项</span></div><div class="backup-list">{backup_rows or '<div class="empty-state">暂无备份文件</div>'}</div></section>{delete_task}"""
        return self.page("任务设置", body, token)

    def settings_html(self, token):
        body = f"""<div class="page-heading"><div><span class="card-kicker">Preferences</span><h1>面板与通知设置</h1><p class="muted">管理登录凭据和 Telegram 通知，保存后立即生效。</p></div></div>
<form method="post" action="/settings" class="settings-form"><div class="settings-grid">
<section class="card form-shell"><div class="card-heading"><div><span class="card-kicker">Account</span><h2>面板账户</h2></div><span class="badge success"><span class="status-dot"></span>安全会话</span></div>
<div class="form-section compact"><div class="section-heading"><span class="section-icon">A</span><div><h2>登录身份</h2><p>修改用户名或密码后，当前登录会自动退出。</p></div></div>
<label>面板用户名</label><input name="admin_username" required maxlength="64" autocomplete="username" value="{self.esc(self.config['admin_username'])}">
<label>新密码</label><input name="password" type="password" minlength="10" maxlength="256" autocomplete="new-password" placeholder="不修改请留空">
<small class="muted">新密码至少 10 位，建议使用密码管理器生成随机密码。</small></div></section>
<section class="card form-shell"><div class="card-heading"><div><span class="card-kicker">Notifications</span><h2>Telegram 通知</h2></div><span class="badge waiting">可选</span></div>
<div class="form-section compact"><div class="section-heading"><span class="section-icon">T</span><div><h2>机器人连接</h2><p>用于推送备份状态，也可通过机器人管理任务。</p></div></div>
<label>Telegram Bot Token</label><input name="telegram_bot_token" autocomplete="off" spellcheck="false" value="{self.esc(self.config.get('telegram_bot_token', ''))}" placeholder="例如 123456:ABC...">
<label>Telegram Chat ID</label><input name="telegram_chat_id" autocomplete="off" spellcheck="false" value="{self.esc(self.config.get('telegram_chat_id', ''))}" placeholder="个人或群组 Chat ID">
<small class="muted">建议先保存，再发送测试消息确认机器人和 Chat ID 均可用。</small>
<div class="form-actions inner"><button class="secondary" formaction="/telegram/test" data-loading="正在发送…">发送测试消息</button></div></div></section></div>
<div class="form-actions settings-actions"><a class="btn secondary" href="/">取消</a><button data-loading="正在保存…">保存全部设置</button></div></form>"""
        return self.page("设置", body, token)

    def offsite_html(self, token):
        cfg = self.config
        checked = "checked" if cfg.get("offsite_enabled") else ""
        selected = lambda value: "selected" if cfg.get("offsite_auth_method") == value else ""
        state = self.state.get("offsite", {})
        status = state.get("last_result") or "尚未上传"
        detail = state.get("last_error") or state.get("last_backup") or "启用后，每次备份成功都会自动上传一份到容灾服务器。"
        body = f"""<div class="page-heading"><div><span class="card-kicker">Offsite</span><h1>容灾备份</h1><p class="muted">把本机生成的备份文件再上传到另一台服务器，防止备份服务器自身丢数据。</p></div></div>
<form method="post" action="/offsite" class="settings-form"><section class="card form-shell"><div class="card-heading"><div><span class="card-kicker">Target</span><h2>容灾目标服务器</h2></div><span class="badge {'success' if status == '成功' else 'failed' if status == '失败' else 'waiting'}"><span class="status-dot"></span>{self.esc(status)}</span></div>
<div class="form-section compact"><div class="section-heading"><span class="section-icon">R</span><div><h2>上传设置</h2><p>保存后会在后续备份成功时自动上传。</p></div></div>
<div class="check-row"><label><input type="checkbox" name="enabled" {checked}> 启用容灾上传</label></div>
<div class="form-grid"><div><label>容灾服务器 IP / 域名</label><input name="offsite_host" value="{self.esc(cfg.get('offsite_host', ''))}" placeholder="例如 backup2.example.com"></div><div><label>SSH 端口</label><input name="offsite_port" type="number" min="1" max="65535" required value="{cfg.get('offsite_port', 22)}"></div>
<div><label>SSH 用户名</label><input name="offsite_user" required value="{self.esc(cfg.get('offsite_user', 'root'))}"></div><div><label>SSH 登录方式</label><select id="auth-method" name="offsite_auth_method"><option value="key" {selected('key')}>SSH 私钥</option><option value="password" {selected('password')}>SSH 密码</option></select></div>
<div class="wide" id="key-auth"><label>SSH 私钥路径</label><input name="offsite_ssh_key" value="{self.esc(cfg.get('offsite_ssh_key', ''))}"><small class="muted">填写备份服务器上的绝对路径。</small></div><div class="wide" id="password-auth"><label>SSH 密码</label><input name="offsite_password" type="password" maxlength="512" autocomplete="new-password"><small class="muted">编辑时留空表示不修改，密码只保存在 root 可读的密钥文件中。</small></div>
<div class="wide"><label>远端保存目录</label><input name="offsite_remote_path" required value="{self.esc(cfg.get('offsite_remote_path', ''))}"><small class="muted">程序会自动创建这个目录。</small></div></div></div>
<div class="form-section compact"><div class="section-heading"><span class="section-icon">S</span><div><h2>最近上传状态</h2><p>{self.esc(detail)}</p></div></div><p class="muted">最近时间：{self.esc(state.get('last_time', '暂无'))}</p></div>
<div class="form-actions settings-actions"><a class="btn secondary" href="/">取消</a><button data-loading="正在保存…">保存容灾设置</button></div></section></form>"""
        return self.page("容灾备份", body, token)

    @staticmethod
    def login_html(error=""):
        alert = f"<div class='login-alert' role='alert'><span>!</span><p>{html.escape(error)}</p></div>" if error else ""
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - Simple Backup</title>
<link rel="icon" href="{BRAND_FAVICON}">
<script>document.documentElement.dataset.theme=localStorage.getItem('sb_theme')||'auto'</script><style>
:root{{--bg:#f4f7fc;--bg-soft:#e8efff;--fg:#162033;--muted:#68758a;--card:#ffffffed;--border:#dce4f0;--input:#fff;--primary:#356df3;--primary-hover:#285dd8;--primary-soft:#eaf0ff;--success:#15805d;--success-soft:#e6f7f1;--danger:#cf3f4f;--danger-soft:#fff0f2;--shadow:0 28px 80px #21365c20;--ring:#356df333}}
html[data-theme=dark]{{--bg:#0b1320;--bg-soft:#11203a;--fg:#edf3ff;--muted:#9baac0;--card:#131f32ed;--border:#2a3952;--input:#0e1929;--primary:#7198ff;--primary-hover:#8aaaff;--primary-soft:#1b315f;--success:#4bcca0;--success-soft:#153a35;--danger:#ff7585;--danger-soft:#411e29;--shadow:0 30px 90px #0009;--ring:#7fa1ff44}}
@media(prefers-color-scheme:dark){{html[data-theme=auto]{{--bg:#0b1320;--bg-soft:#11203a;--fg:#edf3ff;--muted:#9baac0;--card:#131f32ed;--border:#2a3952;--input:#0e1929;--primary:#7198ff;--primary-hover:#8aaaff;--primary-soft:#1b315f;--success:#4bcca0;--success-soft:#153a35;--danger:#ff7585;--danger-soft:#411e29;--shadow:0 30px 90px #0009;--ring:#7fa1ff44}}}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;background:radial-gradient(circle at 12% 8%,var(--bg-soft),transparent 34rem),radial-gradient(circle at 90% 90%,var(--primary-soft),transparent 30rem),var(--bg);color:var(--fg);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;-webkit-font-smoothing:antialiased;display:grid;place-items:center;padding:42px 22px;overflow-x:hidden}}
body:before,body:after{{content:'';position:fixed;border-radius:999px;filter:blur(1px);pointer-events:none;opacity:.48;animation:float 9s ease-in-out infinite}}body:before{{width:270px;height:270px;left:-90px;top:-80px;background:linear-gradient(135deg,#6f91ff44,#8f70ff18)}}body:after{{width:220px;height:220px;right:-70px;bottom:-60px;background:linear-gradient(135deg,#53d8be35,#5e83ff22);animation-delay:-4s}}
.login-layout{{position:relative;z-index:1;width:min(960px,100%);display:grid;grid-template-columns:minmax(0,1.05fr) minmax(360px,.8fr);overflow:hidden;background:var(--card);border:1px solid var(--border);border-radius:26px;box-shadow:var(--shadow);backdrop-filter:blur(22px);animation:rise .55s cubic-bezier(.2,.8,.2,1) both}}
.brand-panel{{padding:54px;background:linear-gradient(145deg,#13284e 0%,#1c3975 54%,#315ec2 100%);color:white;position:relative;overflow:hidden}}.brand-panel:after{{content:'';position:absolute;width:300px;height:300px;border:1px solid #ffffff28;border-radius:50%;right:-170px;top:-120px;box-shadow:0 0 0 58px #ffffff0a,0 0 0 116px #ffffff08}}
.brand-mark{{width:52px;height:52px;display:grid;place-items:center;padding:12px;border-radius:16px;background:#ffffff17;border:1px solid #ffffff2e;box-shadow:inset 0 1px #ffffff3b;margin-bottom:32px}}.brand-mark svg{{width:100%;height:100%}}.eyebrow{{font-size:12px;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:#bcd0ff}}.brand-panel h1{{font-size:clamp(32px,5vw,48px);line-height:1.04;letter-spacing:-.045em;margin:10px 0 18px;max-width:430px}}.brand-panel>p{{color:#d9e4ff;max-width:440px;font-size:16px}}
.security-list{{display:grid;gap:12px;margin-top:38px;position:relative;z-index:1}}.security-item{{display:flex;align-items:flex-start;gap:11px;color:#e9efff}}.security-icon{{width:25px;height:25px;flex:0 0 25px;display:grid;place-items:center;border-radius:8px;background:#ffffff15;border:1px solid #ffffff24;font-size:12px;font-weight:800}}.security-item b{{display:block;font-size:13px}}.security-item small{{display:block;color:#bfcff2;margin-top:1px}}
.login-panel{{padding:48px 44px;display:flex;flex-direction:column;justify-content:center;min-width:0}}.login-panel h2{{font-size:27px;letter-spacing:-.025em;margin:0 0 6px}}.login-panel>.muted{{color:var(--muted);margin:0 0 26px}}label{{display:block;font-weight:700;margin:15px 0 7px}}input{{width:100%;padding:13px 14px;border:1px solid var(--border);border-radius:11px;background:var(--input);color:var(--fg);font:inherit;outline:0;transition:border-color .18s,box-shadow .18s,transform .18s}}input:hover{{border-color:#a9b8cf}}input:focus{{border-color:var(--primary);box-shadow:0 0 0 4px var(--ring);transform:translateY(-1px)}}
.login-submit{{width:100%;min-height:48px;margin-top:24px;border:0;border-radius:11px;background:linear-gradient(135deg,var(--primary),#5c78f4);color:white;font:inherit;font-weight:700;cursor:pointer;box-shadow:0 10px 24px #356df331;transition:transform .18s,box-shadow .18s,filter .18s;position:relative}}.login-submit:hover{{transform:translateY(-2px);box-shadow:0 14px 30px #356df342;filter:saturate(1.12)}}.login-submit:active{{transform:translateY(0)}}.login-submit:disabled{{cursor:wait;opacity:.78}}.login-submit.is-loading{{color:transparent}}.login-submit.is-loading:after{{content:'';position:absolute;inset:0;margin:auto;width:19px;height:19px;border:2px solid #ffffff70;border-top-color:white;border-radius:50%;animation:spin .7s linear infinite}}
.login-alert{{display:flex;gap:10px;align-items:center;background:var(--danger-soft);color:var(--danger);border:1px solid currentColor;border-radius:11px;padding:10px 12px;margin:16px 0}}.login-alert span{{width:22px;height:22px;display:grid;place-items:center;border-radius:50%;background:currentColor;color:white;font-weight:800}}.login-alert p{{margin:0;font-size:13px;font-weight:650}}.transport{{display:flex;gap:7px;align-items:center;margin-top:20px;color:var(--muted);font-size:12px}}.transport-dot{{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 4px var(--success-soft)}}.transport.insecure{{color:var(--danger)}}.transport.insecure .transport-dot{{background:var(--danger);box-shadow:0 0 0 4px var(--danger-soft)}}
.login-theme-switch{{position:fixed;z-index:4;right:18px;top:18px;display:flex;align-items:center;gap:2px;padding:4px;border:1px solid var(--border);border-radius:14px;background:var(--card);box-shadow:0 10px 28px #17243b18;backdrop-filter:blur(14px)}}.theme-option{{width:33px;height:33px;padding:8px;display:grid;place-items:center;border:0;border-radius:10px;background:transparent;color:var(--muted);cursor:pointer;transition:background .18s,color .18s,transform .18s,box-shadow .18s}}.theme-option svg{{width:100%;height:100%}}.theme-option:hover{{color:var(--fg);background:var(--primary-soft)}}.theme-option.active{{color:var(--primary);background:var(--input);box-shadow:0 4px 12px #17243b18}}.login-theme-switch.changed .theme-option.active{{animation:theme-pop .24s ease}}@keyframes theme-pop{{50%{{transform:scale(.82) rotate(-8deg)}}}}
@keyframes rise{{from{{opacity:0;transform:translateY(18px) scale(.985)}}to{{opacity:1;transform:none}}}}@keyframes float{{50%{{transform:translateY(18px) rotate(5deg)}}}}@keyframes spin{{to{{transform:rotate(360deg)}}}}
@media(max-width:760px){{body{{padding:76px 14px 22px}}.login-layout{{grid-template-columns:1fr;border-radius:20px}}.brand-panel{{padding:28px 25px}}.brand-mark{{margin-bottom:18px}}.brand-panel h1{{font-size:31px;margin-bottom:11px}}.brand-panel>p{{font-size:14px}}.security-list{{display:none}}.login-panel{{padding:30px 25px 34px}}}}
@media(max-width:420px){{.brand-panel{{padding:24px 21px}}.login-panel{{padding:27px 21px 30px}}.login-theme-switch{{right:12px;top:12px}}}}
@media(prefers-reduced-motion:reduce){{*,*:before,*:after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}}}</style></head><body>
<div class="login-theme-switch" id="theme-switch" role="group" aria-label="主题模式"><button type="button" class="theme-option" data-theme-value="auto" aria-label="跟随系统" title="跟随系统">{THEME_ICONS['auto']}</button><button type="button" class="theme-option" data-theme-value="light" aria-label="日间模式" title="日间模式">{THEME_ICONS['light']}</button><button type="button" class="theme-option" data-theme-value="dark" aria-label="夜间模式" title="夜间模式">{THEME_ICONS['dark']}</button></div><main class="login-layout">
<section class="brand-panel"><div class="brand-mark" aria-hidden="true">{BRAND_ICON}</div><span class="eyebrow">Simple Backup</span><h1>你的服务器备份控制中心</h1><p>集中管理跨服务器文件与数据库备份，随时掌握任务进度和存储状态。</p>
<div class="security-list"><div class="security-item"><span class="security-icon">TLS</span><div><b>HTTPS 安全会话</b><small>浏览器与面板之间的敏感数据使用加密通道传输</small></div></div><div class="security-item"><span class="security-icon">5×</span><div><b>登录失败限速</b><small>单个来源 15 分钟内最多尝试 5 次，并设有全局限制</small></div></div><div class="security-item"><span class="security-icon">CK</span><div><b>安全 Cookie</b><small>Secure、HttpOnly、SameSite=Strict，降低会话泄漏风险</small></div></div><div class="security-item"><span class="security-icon">CS</span><div><b>CSRF 防护</b><small>登录后的每个写操作都需要独立请求令牌</small></div></div></div></section>
<form class="login-panel" id="login-form" method="post" action="/login"><h2>欢迎回来</h2><p class="muted">登录后管理你的备份任务</p>{alert}<label for="username">用户名</label>
<input id="username" name="username" required autofocus maxlength="64" autocomplete="username" placeholder="请输入面板用户名"><label for="password">密码</label>
<input id="password" name="password" type="password" required maxlength="256" autocomplete="current-password" placeholder="请输入面板密码"><button class="login-submit" id="login-submit" data-loading="正在验证…">登录面板</button>
<div class="transport" id="transport-status"><span class="transport-dot"></span><span>正在检查连接安全性…</span></div></form></main><script>const themeSwitch=document.getElementById('theme-switch'),themeOptions=[...themeSwitch.querySelectorAll('[data-theme-value]')];
function ts(t,feedback=false){{document.documentElement.dataset.theme=t;localStorage.setItem('sb_theme',t);themeOptions.forEach(button=>{{const active=button.dataset.themeValue===t;button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active))}});if(feedback){{themeSwitch.classList.remove('changed');void themeSwitch.offsetWidth;themeSwitch.classList.add('changed');setTimeout(()=>themeSwitch.classList.remove('changed'),260)}}}}
themeOptions.forEach(button=>button.onclick=()=>ts(button.dataset.themeValue,true));ts(document.documentElement.dataset.theme);
const transport=document.getElementById('transport-status'),transportText=transport.querySelector('span:last-child');if(location.protocol==='https:'){{transportText.textContent='当前连接已通过 HTTPS 加密'}}else{{transport.classList.add('insecure');transportText.textContent='当前为 HTTP，请通过 HTTPS 或反向代理访问'}}
document.getElementById('login-form').addEventListener('submit',()=>{{let button=document.getElementById('login-submit');button.classList.add('is-loading');button.disabled=true;button.setAttribute('aria-busy','true')}});</script></body></html>"""

    def save_task_form(self, form):
        task_id = form.get("id", "")
        old = self.task(task_id) if task_id else None
        raw = {key: form[key] for key in (
            "name", "remote_host", "remote_port", "remote_user", "remote_path", "ssh_key",
            "backup_dir", "interval_days", "retention_limit", "transfer_threads", "auth_method",
            "schedule_times", "source_type", "file_mode", "database_host", "database_port", "database_user",
            "database_name",
        ) if key in form}
        raw["enabled"] = "enabled" in form
        raw["auto_install_dependencies"] = "auto_install_dependencies" in form
        task = validate_task(raw, task_id)
        ssh_password = form.get("ssh_password", "")
        if "\0" in ssh_password or len(ssh_password) > 512:
            raise ValueError("SSH 密码无效")
        if task["auth_method"] == "password" and not ssh_password and not self.task_password(task_id):
            raise ValueError("选择密码登录时必须填写 SSH 密码")
        database_password = form.get("database_password", "")
        if len(database_password) > 512 or any(ord(char) < 32 for char in database_password):
            raise ValueError("数据库密码不能超过 512 位或包含控制字符")
        with self.lock:
            if old:
                index = self.config["tasks"].index(old)
                self.config["tasks"][index] = task
                connection = (
                    "remote_host", "remote_port", "remote_user", "ssh_key", "auth_method",
                    "source_type", "database_host", "database_port",
                )
                if any(old[k] != task[k] for k in connection):
                    self.task_state(task_id)["dependencies_ready"] = False
            else:
                if any(item["id"] == task["id"] for item in self.config["tasks"]):
                    task["id"] = secrets.token_hex(4)
                self.config["tasks"].append(task)
            state = self.task_state(task["id"])
            state["schedule_anchor"] = datetime.now().date().isoformat()
            state["next_run"] = self.next_scheduled(task, state)
            self._save_config()
            self._save_state()
            if task["auth_method"] == "password":
                if ssh_password:
                    self.set_task_password(task["id"], ssh_password)
            else:
                self.set_task_password(task["id"], "")
            if task["source_type"] == "files":
                self.set_task_secret(task["id"], "database_password", "")
            elif database_password:
                self.set_task_secret(task["id"], "database_password", database_password)
        return task

    def save_offsite_form(self, form):
        enabled = "enabled" in form
        host = form.get("offsite_host", "").strip()
        user = form.get("offsite_user", "").strip()
        auth_method = form.get("offsite_auth_method", "key").strip()
        ssh_key = form.get("offsite_ssh_key", "").strip()
        remote_path = form.get("offsite_remote_path", "").strip()
        password = form.get("offsite_password", "")
        try:
            port = int(form.get("offsite_port", 22))
        except (TypeError, ValueError) as exc:
            raise ValueError("容灾 SSH 端口必须是数字") from exc
        if not 1 <= port <= 65535:
            raise ValueError("容灾 SSH 端口必须在 1-65535 之间")
        if auth_method not in ("key", "password"):
            raise ValueError("容灾 SSH 认证方式无效")
        if password and ("\0" in password or len(password) > 512):
            raise ValueError("容灾 SSH 密码无效")
        if enabled:
            if not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
                raise ValueError("容灾服务器地址只能使用域名、IP 或 IPv6 地址字符")
            if not re.fullmatch(r"[A-Za-z0-9._-]+", user):
                raise ValueError("容灾 SSH 用户名格式无效")
            if not remote_path.startswith("/") or any(ord(c) < 32 for c in remote_path):
                raise ValueError("容灾远端保存目录必须是绝对路径")
            if auth_method == "key" and (not ssh_key or not Path(ssh_key).is_absolute()):
                raise ValueError("容灾 SSH 私钥路径必须是绝对路径")
            if auth_method == "password" and not password and not self.offsite_password():
                raise ValueError("选择密码登录时必须填写容灾 SSH 密码")
        with self.lock:
            self.config.update(
                offsite_enabled=enabled, offsite_host=host, offsite_port=port,
                offsite_user=user, offsite_auth_method=auth_method,
                offsite_ssh_key=ssh_key, offsite_remote_path=remote_path,
            )
            self._save_config()
            if auth_method == "password":
                if password:
                    self.set_offsite_password(password)
            else:
                self.set_offsite_password("")


class Handler(BaseHTTPRequestHandler):
    app = None
    server_version = "SimpleBackup"

    def log_message(self, fmt, *args):
        pass

    def send_html(self, body, status=200, headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'")
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def send_data(self, data, content_type):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.close_connection = True
        self.end_headers()

    @staticmethod
    def safe_return_to(form, fallback='/'):
        target = form.get('return_to', '').strip()
        parsed = urllib.parse.urlsplit(target)
        if (
            target.startswith('/')
            and not target.startswith('//')
            and not parsed.scheme
            and not parsed.netloc
        ):
            return target
        return fallback

    def redirect_notice(self, form, message, fallback='/', tone='success', target=None):
        destination = target or self.safe_return_to(form, fallback)
        parsed = urllib.parse.urlsplit(destination)
        query = [
            (name, value)
            for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if name not in ('notice', 'tone')
        ]
        query.extend((('notice', message), ('tone', tone)))
        location = urllib.parse.urlunsplit(('', '', parsed.path, urllib.parse.urlencode(query), parsed.fragment))
        self.redirect(location)

    def form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 1024 * 1024:
            raise ValueError("请求内容过大")
        parsed = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}

    def session_token(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            return jar["sb_session"].value
        except (cookies.CookieError, KeyError):
            return ""

    def authenticated(self):
        return self.app.verify_session(self.session_token())

    def csrf_valid(self, form):
        token = self.session_token()
        expected = hmac.new(
            self.app.config["session_secret"].encode(), token.encode(), hashlib.sha256
        ).hexdigest()
        return token and hmac.compare_digest(form.get("csrf", ""), expected)

    def require_auth(self):
        if self.authenticated():
            return True
        self.redirect("/login")
        return False

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path == "/login":
            if self.authenticated():
                self.redirect("/")
            else:
                self.send_html(self.app.login_html())
            return
        if path.path == "/logout":
            self.redirect("/login", "sb_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            return
        if not self.require_auth():
            return
        token = self.session_token()
        query = urllib.parse.parse_qs(path.query)
        if path.path == "/":
            self.send_html(self.app.home_html(token))
        elif path.path == "/tasks":
            self.send_html(self.app.dashboard_html(token))
        elif path.path == "/task":
            task = self.app.task(query.get("id", [""])[0])
            self.send_html(self.app.task_form_html(task, token))
        elif path.path == "/task/detail":
            task = self.app.task(query.get("id", [""])[0])
            self.send_html(self.app.task_detail_html(task, token))
        elif path.path == "/settings":
            self.send_html(self.app.settings_html(token))
        elif path.path == "/offsite":
            self.send_html(self.app.offsite_html(token))
        elif path.path == "/logs":
            self.send_html(self.app.logs_html(token))
        elif path.path == "/logs/raw":
            self.send_data(self.app.read_log(None), "text/plain; charset=utf-8")
        elif path.path == "/api/task-log":
            task_id = query.get("id", [""])[0]
            if self.app.task(task_id):
                self.send_data(self.app.read_task_log(task_id), "text/plain; charset=utf-8")
            else:
                self.send_data("任务不存在", "text/plain; charset=utf-8")
        elif path.path == "/api/status":
            running = [
                {
                    "id": task_id, "name": self.app.task(task_id)["name"],
                    "phase": job.get("phase", "运行中"), "progress": job.get("progress", 0),
                    "speed_bps": job.get("speed_bps", 0),
                    "transferred_bytes": job.get("transferred_bytes", 0),
                    "total_bytes": job.get("total_bytes", 0),
                    "slots": job.get("slots", []),
                    "parallel_files": job.get("parallel_files", 1),
                    "segments_per_file": job.get("segments_per_file", 1),
                }
                for task_id, job in list(self.app.jobs.items()) if self.app.task(task_id)
            ]
            network = self.app.network_counters()
            self.send_data(
                json.dumps({"network_rx": network["rx"], "network_tx": network["tx"], "running": running}),
                "application/json; charset=utf-8",
            )
        else:
            self.send_html(self.app.page("未找到", "<section class='card'><h1>页面不存在</h1></section>", token), 404)

    def do_POST(self):
        form = {}
        try:
            form = self.form()
            if self.path == "/login":
                self.handle_login(form)
                return
            if not self.require_auth():
                return
            if not self.csrf_valid(form):
                self.send_html(self.app.page("请求无效", "<section class='card'><h1>页面已过期，请刷新后重试</h1></section>"), 403)
                return
            self.handle_action(form)
        except (ValueError, OSError) as exc:
            self.app.log(f"网页操作失败 {self.path}：{exc}", "ERROR")
            if self.authenticated():
                self.redirect_notice(form, str(exc), '/tasks', 'error')
            else:
                token = self.session_token()
                self.send_html(self.app.page("操作失败", f"<section class='card'><h1>操作失败</h1><p class='bad'>{html.escape(str(exc))}</p></section>", token), 400)

    def handle_login(self, form):
        address = self.client_address[0]
        password = form.get("password", "")
        with self.app.login_lock:
            allowed = self.app.login_allowed(address)
            username_ok = password_ok = False
            if allowed:
                username_ok = hmac.compare_digest(
                    form.get("username", ""), self.app.config["admin_username"]
                )
                password_ok = verify_password(self.app.config, password)
            valid = allowed and username_ok and password_ok
            if allowed and not valid:
                self.app.login_failed(address)
            elif valid:
                self.app.login_failures.pop(address, None)
                self.app.account_failures.clear()
                if int(self.app.config.get("password_iterations", 200_000)) < 600_000:
                    self.app.config.update(password_fields(password))
                    self.app._save_config()
        if not allowed:
            self.send_html(self.app.login_html("失败次数过多，请 15 分钟后重试"), 429)
            return
        if not valid:
            time.sleep(0.5)
            self.send_html(self.app.login_html("用户名或密码错误"), 401)
            return
        token = self.app.sign_session(self.app.config["admin_username"])
        cookie = f"sb_session={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
        self.redirect("/", cookie)

    def handle_action(self, form):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/task/save":
            task = self.app.save_task_form(form)
            self.redirect_notice(form, '任务设置已保存', target=f"/task?id={task['id']}")
        elif path == "/task/delete":
            task = self.app.task(form.get("id", ""))
            if not task:
                raise ValueError("任务不存在")
            if task["id"] in self.app.jobs:
                raise ValueError("请先停止正在运行的任务")
            self.app.config["tasks"].remove(task)
            self.app.state["tasks"].pop(task["id"], None)
            self.app.set_task_password(task["id"], "")
            self.app.set_task_secret(task["id"], "database_password", "")
            self.app._save_config()
            self.app._save_state()
            self.redirect_notice(form, '任务已删除，已有备份文件未受影响', target='/tasks')
        elif path == "/backup/start":
            task_id = form.get("id", "")
            task = self.app.task(task_id)
            partial = (incremental_ledger(task) if task.get("file_mode") == "incremental" else Path(task["backup_dir"]) / f".partial-{task_id}") if task else None
            source = "网页断点续传" if partial and partial.exists() else "网页"
            ok, message = self.app.start_backup(task_id, source)
            if not ok:
                raise ValueError(message)
            self.redirect_notice(form, message, '/tasks')
        elif path in ("/backup/pause", "/backup/stop"):
            ok, message = self.app.stop_backup(
                form.get("id", ""), path == "/backup/stop", "网页"
            )
            if not ok:
                raise ValueError(message)
            self.redirect_notice(form, message, '/tasks')
        elif path == "/backup/delete":
            task = self.app.task(form.get("id", ""))
            allowed = {p.name: p for p in self.app.backups(task)} if task else {}
            target = allowed.get(form.get("name", ""))
            if not target:
                raise ValueError("备份不存在")
            self.app.delete_backup(target)
            self.app.notify(f"已删除备份：{task['name']} / {target.name}", task["id"])
            self.redirect_notice(form, f'已删除备份：{target.name}', f"/task?id={task['id']}")
        elif path == "/settings":
            username = form.get("admin_username", "").strip()
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,50}", username):
                raise ValueError("用户名只能包含字母、数字和 . _ @ -")
            changed = username != self.app.config["admin_username"] or bool(form.get("password"))
            self.app.config["admin_username"] = username
            if form.get("password"):
                self.app.config.update(password_fields(form["password"]))
            self.app.config["telegram_bot_token"] = form.get("telegram_bot_token", "").strip()
            self.app.config["telegram_chat_id"] = form.get("telegram_chat_id", "").strip()
            if changed:
                self.app.config["session_secret"] = secrets.token_hex(32)
            self.app._save_config()
            if changed:
                self.redirect("/login", "sb_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            else:
                self.redirect_notice(form, '面板与通知设置已保存', '/settings')
        elif path == "/telegram/test":
            token = form.get("telegram_bot_token", "").strip()
            chat_id = form.get("telegram_chat_id", "").strip()
            if not token or not chat_id:
                raise ValueError("请先填写 Bot Token 和 Chat ID")
            ok, error = self.app.send_telegram(token, chat_id, "Simple Backup 测试成功：Telegram 通知配置正确。")
            if not ok:
                self.app.log(f"Telegram 测试失败：{error}", "ERROR")
                raise ValueError("Telegram 测试失败：" + error)
            self.app.log("Telegram 测试消息发送成功")
            self.redirect_notice(form, 'Telegram 测试消息已发送，请检查机器人会话', '/settings')
        elif path == "/offsite":
            self.app.save_offsite_form(form)
            self.redirect_notice(form, '容灾设置已保存', '/offsite')
        else:
            raise ValueError("未知操作")


def initialize(app, username, password, port, host=None, cert=None, key=None, tls_enabled=True):
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,50}", username):
        raise ValueError("用户名格式无效")
    app.config["admin_username"] = username
    app.config["listen_port"] = int(port)
    app.config["tls_enabled"] = bool(tls_enabled)
    if not tls_enabled:
        app.config["listen_host"] = "127.0.0.1"
    elif host:
        app.config["listen_host"] = host
    if cert:
        app.config["tls_cert"] = cert
    if key:
        app.config["tls_key"] = key
    app.config["session_secret"] = secrets.token_hex(32)
    app.config.update(password_fields(password))
    app._save_config()


def serve(app):
    cert, key = app.config["tls_cert"], app.config["tls_key"]
    tls_enabled = app.config.get("tls_enabled", True)
    if tls_enabled and (not Path(cert).is_file() or not Path(key).is_file()):
        raise SystemExit("HTTPS 证书不存在，请重新运行安装器申请 IP 证书")
    if not tls_enabled and app.config["listen_host"] not in ("127.0.0.1", "::1"):
        raise SystemExit("无内置 HTTPS 时只能监听本机回环地址，请重新运行安装器")
    Handler.app = app
    server = ThreadingHTTPServer((app.config["listen_host"], int(app.config["listen_port"])), Handler)
    if tls_enabled:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    resumed = app.resume_interrupted()
    threading.Thread(target=app.scheduler_loop, daemon=True).start()
    scheme = "HTTPS" if tls_enabled else "HTTP（仅限本机反向代理）"
    app.log(f"服务启动：{scheme} {app.config['listen_host']}:{app.config['listen_port']}")
    if resumed:
        app.log(f"服务重启后已自动恢复 {resumed} 个中断任务")
    try:
        server.serve_forever()
    finally:
        app.stop_daemon.set()
        app.stop_all("服务正在停止")
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Simple Backup 多任务备份管理器")
    parser.add_argument("--data-dir", default="/var/lib/simple-backup")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    init = sub.add_parser("init")
    init.add_argument("--username", required=True)
    init.add_argument("--password", required=True)
    init.add_argument("--port", type=int, required=True)
    init.add_argument("--host")
    init.add_argument("--cert")
    init.add_argument("--key")
    init.add_argument("--no-tls", action="store_true")
    args = parser.parse_args()
    app = BackupApp(args.data_dir)
    if args.command == "init":
        initialize(app, args.username, args.password, args.port, args.host, args.cert, args.key, not args.no_tls)
    else:
        serve(app)


if __name__ == "__main__":
    main()
