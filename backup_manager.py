#!/usr/bin/env python3
"""Simple Backup: multi-task Linux backup daemon and Chinese web panel."""

import argparse
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
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

GIB = 1024 ** 3
MIN_FREE = 3 * GIB
DEFAULTS = {
    "tasks": [],
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "admin_username": "admin",
    "listen_host": "0.0.0.0",
    "listen_port": 8088,
    "tls_cert": "/var/lib/simple-backup/server.crt",
    "tls_key": "/var/lib/simple-backup/server.key",
    "session_secret": "",
}
TASK_DEFAULTS = {
    "id": "", "name": "新备份任务", "remote_host": "", "remote_port": 22,
    "remote_user": "root", "remote_path": "/", "ssh_key": "/root/.ssh/id_ed25519",
    "backup_dir": "/var/backups/simple-backup", "interval_days": 3,
    "retention_limit": 0, "transfer_threads": 4, "enabled": True,
    "auto_install_dependencies": True,
}


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def password_fields(password):
    if len(password) < 10 or any(ord(char) < 32 for char in password):
        raise ValueError("管理密码至少需要 10 位，且不能包含控制字符")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return {"password_salt": salt.hex(), "password_hash": digest.hex()}


def verify_password(config, password):
    try:
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(config["password_salt"]), 200_000
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


def directory_size(path):
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


def validate_task(raw, existing_id=""):
    task = dict(TASK_DEFAULTS)
    task.update(raw)
    task["id"] = str(existing_id or task.get("id") or secrets.token_hex(4)).lower()
    for key in ("name", "remote_host", "remote_user", "remote_path", "ssh_key", "backup_dir"):
        task[key] = str(task.get(key, "")).strip()
    try:
        task["remote_port"] = int(task["remote_port"])
        task["interval_days"] = float(task["interval_days"])
        task["retention_limit"] = int(task["retention_limit"])
        task["transfer_threads"] = int(task["transfer_threads"])
    except (TypeError, ValueError) as exc:
        raise ValueError("端口、周期、保留份数和线程数必须是数字") from exc
    task["enabled"] = bool(task.get("enabled"))
    task["auto_install_dependencies"] = bool(task.get("auto_install_dependencies"))
    if not re.fullmatch(r"[a-f0-9]{8}", task["id"]):
        raise ValueError("任务 ID 无效")
    if not 1 <= len(task["name"]) <= 50 or any(ord(c) < 32 for c in task["name"]):
        raise ValueError("任务名称需要 1-50 个可见字符")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", task["remote_host"]):
        raise ValueError("服务器地址只能使用域名、IP 或 IPv6 地址字符")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", task["remote_user"]):
        raise ValueError("SSH 用户名格式无效")
    if not task["remote_path"].startswith("/") or any(ord(c) < 32 for c in task["remote_path"]):
        raise ValueError("远程路径必须是绝对路径")
    if not Path(task["backup_dir"]).is_absolute() or Path(task["backup_dir"]) == Path("/"):
        raise ValueError("本地备份目录必须是绝对路径，且不能是根目录")
    if task["ssh_key"] and not Path(task["ssh_key"]).is_absolute():
        raise ValueError("SSH 密钥路径必须是绝对路径")
    if not 1 <= task["remote_port"] <= 65535:
        raise ValueError("SSH 端口必须在 1-65535 之间")
    if not 0.01 <= task["interval_days"] <= 3650:
        raise ValueError("备份周期必须在 0.01-3650 天之间")
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
        old.update(id=secrets.token_hex(4), name=config.get("task_name") or f"{config['remote_host']} 备份")
        merged["tasks"] = [validate_task(old)]
    else:
        merged["tasks"] = [validate_task(item, item.get("id", "")) for item in config.get("tasks", [])]
    merged["session_secret"] = merged.get("session_secret") or secrets.token_hex(32)
    return merged


REMOTE_SETUP = r'''set -eu
has_sftp=0
for p in /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
  [ -x "$p" ] && has_sftp=1
done
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -Eq '^subsystem sftp (internal-sftp|/)' && has_sftp=1 || true
fi
command -v rsync >/dev/null 2>&1 && [ "$has_sftp" -eq 1 ] && exit 0
if [ "$(id -u)" -eq 0 ]; then run() { "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then run() { sudo -n "$@"; }
else echo "缺少 rsync/SFTP，且当前 SSH 用户没有 root 或免密 sudo 权限" >&2; exit 42; fi
if command -v apt-get >/dev/null 2>&1; then run apt-get update; run apt-get install -y rsync openssh-sftp-server
elif command -v dnf >/dev/null 2>&1; then run dnf install -y rsync openssh-server
elif command -v yum >/dev/null 2>&1; then run yum install -y rsync openssh-server
elif command -v zypper >/dev/null 2>&1; then run zypper --non-interactive install rsync openssh
elif command -v pacman >/dev/null 2>&1; then run pacman -Sy --noconfirm rsync openssh
elif command -v apk >/dev/null 2>&1; then run apk add rsync openssh-server
else echo "不支持的远程包管理器，请手动安装 rsync 和 OpenSSH SFTP 服务" >&2; exit 43; fi
'''


class BackupApp:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.config_path = self.data_dir / "config.json"
        self.state_path = self.data_dir / "state.json"
        self.lock = threading.RLock()
        self.config = migrate_config(self._read_json(self.config_path, {}))
        self.state = self._read_json(self.state_path, {"tasks": {}, "telegram_offset": 0, "low_disks": {}})
        self.state.setdefault("tasks", {})
        self.state.setdefault("low_disks", {})
        self.jobs = {}
        self.login_failures = {}
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
            "last_error": "", "dependencies_ready": False,
        })

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
        self.login_failures[address] = attempts
        return len(attempts) < 5 or now - attempts[-1] >= 900

    def login_failed(self, address):
        self.login_failures.setdefault(address, []).append(time.time())

    def notify(self, message):
        token = self.config.get("telegram_bot_token")
        chat_id = self.config.get("telegram_chat_id")
        if not token or not chat_id:
            return
        try:
            data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode()
            urllib.request.urlopen(
                f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=15
            ).read()
        except Exception:
            pass

    def ssh_options(self, task):
        options = [
            "-p", str(task["remote_port"]), "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4", "-o", "StrictHostKeyChecking=accept-new",
        ]
        if task["ssh_key"]:
            options += ["-i", task["ssh_key"]]
        return options

    def remote_setup(self, task, job):
        state = self.task_state(task["id"])
        if state.get("dependencies_ready") or not task["auto_install_dependencies"]:
            return
        command = ["ssh", *self.ssh_options(task), f"{task['remote_user']}@{task['remote_host']}", "sh", "-s"]
        code, output = self.execute(command, task, job, stdin=REMOTE_SETUP)
        if code:
            raise RuntimeError("远程依赖自动安装失败：" + (output[-500:] or f"退出码 {code}"))
        state["dependencies_ready"] = True
        self._save_state()

    @staticmethod
    def lftp_quote(value):
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

    def transfer_command(self, task, staging):
        destination = str(staging) + "/"
        if task["transfer_threads"] == 1:
            ssh = "ssh " + " ".join(shlex.quote(item) for item in self.ssh_options(task))
            return [
                "rsync", "-a", "--partial", "--append-verify", "--info=progress2",
                "--protect-args", "--delete", "-e", ssh,
                f"{task['remote_user']}@{task['remote_host']}:{task['remote_path'].rstrip('/')}/",
                destination,
            ]
        threads = task["transfer_threads"]
        parallel = max(1, int(threads ** 0.5))
        segments = max(2, threads // parallel)
        ssh = "ssh -a -x " + " ".join(shlex.quote(item) for item in self.ssh_options(task))
        script = (
            f"set sftp:connect-program {self.lftp_quote(ssh)}; "
            "set net:timeout 20; set net:max-retries 5; set net:reconnect-interval-base 3; "
            f"open {self.lftp_quote('sftp://' + task['remote_user'] + '@' + task['remote_host'])}; "
            f"mirror --verbose --continue --delete --parallel={parallel} --use-pget-n={segments} "
            f"{self.lftp_quote(task['remote_path'])} {self.lftp_quote(destination)}"
        )
        return ["lftp", "-e", script + "; bye"]

    def free_space(self, task):
        path = Path(task["backup_dir"])
        path.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(path).free

    def stop_all(self, reason="用户要求停止"):
        with self.lock:
            jobs = list(self.jobs.values())
        for job in jobs:
            job["reason"] = reason
            job["stop"].set()

    def disk_guard(self, task):
        free = self.free_space(task)
        key = str(Path(task["backup_dir"]).resolve())
        if free < MIN_FREE:
            self.stop_all("剩余硬盘容量低于 3 GB")
            if not self.state["low_disks"].get(key):
                self.state["low_disks"][key] = True
                self._save_state()
                self.notify(f"容量不足：{task['name']} 的备份盘仅剩 {human_size(free)}，已停止所有备份和自动备份。")
            return False
        if self.state["low_disks"].pop(key, None):
            self._save_state()
        return True

    def execute(self, command, task, job, stdin=None):
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", bufsize=1, start_new_session=True,
            )
        except FileNotFoundError as exc:
            return 127, f"本机缺少命令：{command[0]}（{exc}）"
        job["process"] = process
        if stdin is not None:
            process.stdin.write(stdin)
            process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output, last_check = [], 0
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
            for key, _ in selector.select(1):
                line = key.fileobj.readline()
                if not line:
                    continue
                output.append(line)
                if len(output) > 120:
                    del output[:40]
                match = re.search(r"(\d{1,3})%", line)
                if match:
                    job["progress"] = min(100, int(match.group(1)))
                    if job["progress"] >= job.get("next_progress_notice", 25) and job["progress"] < 100:
                        milestone = job["progress"] // 25 * 25
                        job["next_progress_notice"] = milestone + 25
                        threading.Thread(
                            target=self.notify,
                            args=(f"备份进度：{task['name']} 已完成约 {milestone}%",),
                            daemon=True,
                        ).start()
        rest = process.stdout.read()
        if rest:
            output.append(rest)
        job["process"] = None
        return process.returncode, "".join(output)[-6000:]

    def backups(self, task):
        root = Path(task["backup_dir"])
        suffix = "_" + backup_prefix(task)
        try:
            return sorted(
                [p for p in root.iterdir() if p.is_dir() and p.name.endswith(suffix)],
                key=lambda p: p.stat().st_mtime,
            )
        except FileNotFoundError:
            return []

    def apply_retention(self, task):
        limit = task["retention_limit"]
        if not limit:
            return
        items = self.backups(task)
        while len(items) >= limit:
            oldest = items.pop(0)
            shutil.rmtree(oldest)
            self.notify(f"已删除旧备份：{task['name']} / {oldest.name}")

    def backup_once(self, task, job):
        if not self.disk_guard(task):
            raise RuntimeError("剩余硬盘容量低于 3 GB")
        if task["ssh_key"] and not Path(task["ssh_key"]).is_file():
            raise RuntimeError(f"SSH 密钥不存在：{task['ssh_key']}")
        self.remote_setup(task, job)
        root = Path(task["backup_dir"])
        root.mkdir(parents=True, exist_ok=True)
        staging = root / f".partial-{task['id']}"
        staging.mkdir(exist_ok=True)
        code, output = self.execute(self.transfer_command(task, staging), task, job)
        if job["stop"].is_set():
            raise RuntimeError(job.get("reason") or "备份已停止")
        if code:
            raise RuntimeError(output[-800:] or f"传输程序退出码 {code}")
        self.apply_retention(task)
        final = root / f"{datetime.now():%Y%m%d-%H%M%S}_{backup_prefix(task)}"
        os.replace(staging, final)
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
                "reason": "", "next_progress_notice": 25,
            }
            self.jobs[task_id] = job
        threading.Thread(target=self._backup_worker, args=(dict(task), job, source), daemon=True).start()
        return True, "备份已在后台启动"

    def _backup_worker(self, task, job, source):
        state = self.task_state(task["id"])
        state.update(last_result="运行中", last_error="")
        self._save_state()
        self.notify(f"备份任务开始：{task['name']}（{source}）")
        error = ""
        try:
            for attempt in range(1, 7):
                try:
                    final, size, free = self.backup_once(task, job)
                    state.update(
                        last_result="成功", last_backup=final.name, last_error="",
                        next_run=time.time() + task["interval_days"] * 86400,
                    )
                    self._save_state()
                    self.notify(
                        f"备份成功：{task['name']}\n文件名：{final.name}\n大小：{human_size(size)}\n"
                        f"时间：{datetime.now():%Y-%m-%d %H:%M:%S}\n剩余容量：{human_size(free)}"
                    )
                    return
                except Exception as exc:
                    error = str(exc)
                    if job["stop"].is_set() or attempt == 6:
                        break
                    time.sleep(min(30, attempt * 5))
            if job["stop"].is_set():
                state.update(last_result="已停止", last_error=error)
                self._save_state()
                self.notify(f"备份已停止：{task['name']}\n原因：{error}")
                return
            state.update(
                last_result="失败", last_error=error,
                next_run=time.time() + task["interval_days"] * 86400,
            )
            self._save_state()
            self.notify(f"备份失败：{task['name']}\n已连续失败 6 次并停止。\n原因：{error}")
        finally:
            with self.lock:
                self.jobs.pop(task["id"], None)

    def scheduler_loop(self):
        last_telegram = 0
        while not self.stop_daemon.wait(2):
            now = time.time()
            for task in list(self.config["tasks"]):
                if not task["enabled"] or task["id"] in self.jobs:
                    continue
                state = self.task_state(task["id"])
                if not state.get("next_run"):
                    state["next_run"] = now + task["interval_days"] * 86400
                    self._save_state()
                elif state["next_run"] <= now and self.disk_guard(task):
                    self.start_backup(task["id"], "定时")
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
                "/stop 任务ID（或 all）停止\n/status [任务ID]\n/list 任务ID\n"
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
                self.stop_all("Telegram 强制停止")
                self.notify("已要求停止所有正在运行的备份")
            else:
                task = self.resolve_task(argument)
                job = self.jobs.get(task["id"]) if task else None
                if job:
                    job["reason"] = "Telegram 强制停止"
                    job["stop"].set()
                self.notify("已发送停止指令" if job else "任务不存在或当前未运行")
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
                shutil.rmtree(allowed[name])
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
<title>{self.esc(title)} - Simple Backup</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f4f7fb;color:#182230;font:15px system-ui,sans-serif}}
header{{background:#17243b;color:white;padding:16px}}nav{{max-width:1100px;margin:auto;display:flex;gap:18px;align-items:center}}
nav b{{font-size:20px;margin-right:auto}}a{{color:#1769aa;text-decoration:none}}nav a{{color:white}}
main{{max-width:1100px;margin:24px auto;padding:0 14px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:16px}}
.card{{background:white;border:1px solid #dde5ef;border-radius:12px;padding:18px;box-shadow:0 3px 12px #2030400d}}
.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}.muted{{color:#667085}}.ok{{color:#08783f}}.bad{{color:#b42318}}
label{{display:block;margin:12px 0 4px;font-weight:600}}input{{width:100%;padding:10px;border:1px solid #b9c5d4;border-radius:7px}}
input[type=checkbox]{{width:auto}}button,.btn{{border:0;border-radius:7px;padding:9px 14px;background:#1769aa;color:white;cursor:pointer}}
.danger{{background:#b42318}}.secondary{{background:#667085}}form.inline{{display:inline}}small{{line-height:1.5}}
</style></head><body><header><nav><b>Simple Backup</b><a href="/">任务</a>
<a href="/task">新建任务</a><a href="/settings">设置</a><a href="/logout">退出</a></nav></header>
<main>{body}</main><script>document.querySelectorAll('form').forEach(f=>{{
if(f.method.toLowerCase()==='post'){{let i=document.createElement('input');i.type='hidden';i.name='csrf';i.value='{csrf}';f.appendChild(i)}}}});
</script></body></html>"""

    def dashboard_html(self, token):
        cards = []
        for task in self.config["tasks"]:
            state = self.task_state(task["id"])
            job = self.jobs.get(task["id"])
            status = f"运行中 {job['progress']}%" if job else state.get("last_result", "尚未运行")
            next_run = datetime.fromtimestamp(state["next_run"]).strftime("%Y-%m-%d %H:%M") if state.get("next_run") else "待安排"
            error = f"<p class='bad'>原因：{self.esc(state.get('last_error'))}</p>" if state.get("last_error") else ""
            action = (
                f"<form class='inline' method='post' action='/backup/stop'><input type='hidden' name='id' value='{task['id']}'><button class='danger'>强制停止</button></form>"
                if job else
                f"<form class='inline' method='post' action='/backup/start'><input type='hidden' name='id' value='{task['id']}'><button>立即备份</button></form>"
            )
            cards.append(f"""<section class="card"><h2>{self.esc(task['name'])}</h2>
<p class="muted">ID {task['id']} · {self.esc(task['remote_user'])}@{self.esc(task['remote_host'])}:{task['remote_port']}</p>
<p><b>状态：</b>{self.esc(status)}　<b>下次：</b>{next_run}</p>
<p><b>远程：</b>{self.esc(task['remote_path'])}<br><b>本地：</b>{self.esc(task['backup_dir'])}</p>
<p><b>最近备份：</b>{self.esc(state.get('last_backup') or '无')}</p>{error}<div class="row">{action}
<a class="btn secondary" href="/task?id={task['id']}">编辑</a></div></section>""")
        empty = "<section class='card'><h2>还没有备份任务</h2><p>点击“新建任务”，只需填写服务器和路径即可开始。</p></section>"
        return self.page("任务", "<div class='grid'>" + ("".join(cards) or empty) + "</div>", token)

    def task_form_html(self, task, token):
        task = dict(TASK_DEFAULTS if task is None else task)
        task_id = self.esc(task.get("id", ""))
        checked = lambda key: "checked" if task.get(key) else ""
        backups = self.backups(task) if task.get("id") else []
        backup_rows = "".join(
            f"<div class='row'><code>{self.esc(p.name)}</code><span class='muted'>{human_size(directory_size(p))}</span>"
            f"<form class='inline' method='post' action='/backup/delete'><input type='hidden' name='id' value='{task_id}'>"
            f"<input type='hidden' name='name' value='{self.esc(p.name)}'><button class='danger'>删除</button></form></div>"
            for p in reversed(backups[-30:])
        )
        delete_task = (
            f"<form method='post' action='/task/delete' onsubmit=\"return confirm('只删除任务设置，不删除已有备份。确定？')\">"
            f"<input type='hidden' name='id' value='{task_id}'><button class='danger'>删除此任务</button></form>"
            if task_id else ""
        )
        body = f"""<section class="card"><h1>{'编辑任务' if task_id else '新建备份任务'}</h1>
<form method="post" action="/task/save"><input type="hidden" name="id" value="{task_id}">
<label>任务名称</label><input name="name" required maxlength="50" value="{self.esc(task['name'])}">
<div class="grid"><div><label>远程服务器 IP / 域名</label><input name="remote_host" required value="{self.esc(task['remote_host'])}">
<label>SSH 端口</label><input name="remote_port" type="number" min="1" max="65535" required value="{task['remote_port']}">
<label>SSH 用户名</label><input name="remote_user" required value="{self.esc(task['remote_user'])}">
<label>SSH 私钥路径</label><input name="ssh_key" value="{self.esc(task['ssh_key'])}">
<small class="muted">填写备份服务器上的私钥绝对路径，例如 /root/.ssh/id_ed25519。</small></div>
<div><label>远程文件或目录</label><input name="remote_path" required value="{self.esc(task['remote_path'])}">
<label>本地备份目录</label><input name="backup_dir" required value="{self.esc(task['backup_dir'])}">
<label>每隔几天备份一次</label><input name="interval_days" type="number" min="0.01" max="3650" step="0.01" required value="{task['interval_days']}">
<label>最多保留多少份</label><input name="retention_limit" type="number" min="0" required value="{task['retention_limit']}">
<small class="muted">填 0 表示全部保留，不自动删除。</small>
<label>并行线程数</label><input name="transfer_threads" type="number" min="1" max="16" required value="{task['transfer_threads']}"></div></div>
<p><label><input type="checkbox" name="enabled" {checked('enabled')}> 启用自动备份</label>
<label><input type="checkbox" name="auto_install_dependencies" {checked('auto_install_dependencies')}> 首次连接自动安装远端 rsync / SFTP 依赖</label></p>
<button>保存任务</button></form></section>
{delete_task}<section class="card"><h2>已有备份</h2>{backup_rows or '<p class="muted">暂无备份</p>'}</section>"""
        return self.page("任务设置", body, token)

    def settings_html(self, token):
        body = f"""<section class="card"><h1>面板与通知设置</h1><form method="post" action="/settings">
<label>面板用户名</label><input name="admin_username" required value="{self.esc(self.config['admin_username'])}">
<label>新密码</label><input name="password" type="password" minlength="10" autocomplete="new-password">
<small class="muted">不修改请留空；新密码至少 10 位。</small>
<label>Telegram Bot Token</label><input name="telegram_bot_token" value="{self.esc(self.config.get('telegram_bot_token', ''))}">
<label>Telegram Chat ID</label><input name="telegram_chat_id" value="{self.esc(self.config.get('telegram_chat_id', ''))}">
<p><button>保存设置</button></p></form></section>"""
        return self.page("设置", body, token)

    @staticmethod
    def login_html(error=""):
        alert = f"<p class='bad'>{html.escape(error)}</p>" if error else ""
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - Simple Backup</title>
<style>*{{box-sizing:border-box}}body{{margin:0;background:#eef3f9;font:15px system-ui;color:#182230;display:grid;place-items:center;min-height:100vh}}
.login{{width:min(390px,calc(100% - 28px));background:white;padding:30px;border-radius:14px;box-shadow:0 12px 36px #17243b24}}
input{{width:100%;padding:12px;margin:6px 0 16px;border:1px solid #b9c5d4;border-radius:8px}}button{{width:100%;padding:12px;border:0;border-radius:8px;background:#1769aa;color:white}}
.bad{{color:#b42318}}</style></head><body><form class="login" method="post" action="/login">
<h1>Simple Backup</h1><p>登录备份管理面板</p>{alert}<label>用户名</label>
<input name="username" required autofocus autocomplete="username"><label>密码</label>
<input name="password" type="password" required autocomplete="current-password"><button>登录</button>
</form></body></html>"""

    def save_task_form(self, form):
        task_id = form.get("id", "")
        old = self.task(task_id) if task_id else None
        raw = {key: form.get(key, "") for key in (
            "name", "remote_host", "remote_port", "remote_user", "remote_path", "ssh_key",
            "backup_dir", "interval_days", "retention_limit", "transfer_threads",
        )}
        raw["enabled"] = "enabled" in form
        raw["auto_install_dependencies"] = "auto_install_dependencies" in form
        task = validate_task(raw, task_id)
        with self.lock:
            if old:
                index = self.config["tasks"].index(old)
                self.config["tasks"][index] = task
                connection = ("remote_host", "remote_port", "remote_user", "ssh_key")
                if any(old[k] != task[k] for k in connection):
                    self.task_state(task_id)["dependencies_ready"] = False
            else:
                if any(item["id"] == task["id"] for item in self.config["tasks"]):
                    task["id"] = secrets.token_hex(4)
                self.config["tasks"].append(task)
            state = self.task_state(task["id"])
            state["next_run"] = time.time() + task["interval_days"] * 86400
            self._save_config()
            self._save_state()
        return task

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
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

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
            self.send_html(self.app.dashboard_html(token))
        elif path.path == "/task":
            task = self.app.task(query.get("id", [""])[0])
            self.send_html(self.app.task_form_html(task, token))
        elif path.path == "/settings":
            self.send_html(self.app.settings_html(token))
        else:
            self.send_html(self.app.page("未找到", "<section class='card'><h1>页面不存在</h1></section>", token), 404)

    def do_POST(self):
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
            token = self.session_token()
            self.send_html(self.app.page("操作失败", f"<section class='card'><h1>操作失败</h1><p class='bad'>{html.escape(str(exc))}</p></section>", token), 400)

    def handle_login(self, form):
        address = self.client_address[0]
        if not self.app.login_allowed(address):
            self.send_html(self.app.login_html("失败次数过多，请 15 分钟后重试"), 429)
            return
        username_ok = hmac.compare_digest(
            form.get("username", ""), self.app.config["admin_username"]
        )
        if not username_ok or not verify_password(self.app.config, form.get("password", "")):
            self.app.login_failed(address)
            time.sleep(0.5)
            self.send_html(self.app.login_html("用户名或密码错误"), 401)
            return
        self.app.login_failures.pop(address, None)
        token = self.app.sign_session(self.app.config["admin_username"])
        cookie = f"sb_session={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
        self.redirect("/", cookie)

    def handle_action(self, form):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/task/save":
            task = self.app.save_task_form(form)
            self.redirect(f"/task?id={task['id']}")
        elif path == "/task/delete":
            task = self.app.task(form.get("id", ""))
            if not task:
                raise ValueError("任务不存在")
            if task["id"] in self.app.jobs:
                raise ValueError("请先停止正在运行的任务")
            self.app.config["tasks"].remove(task)
            self.app.state["tasks"].pop(task["id"], None)
            self.app._save_config()
            self.app._save_state()
            self.redirect("/")
        elif path == "/backup/start":
            ok, message = self.app.start_backup(form.get("id", ""), "网页")
            if not ok:
                raise ValueError(message)
            self.redirect("/")
        elif path == "/backup/stop":
            job = self.app.jobs.get(form.get("id", ""))
            if not job:
                raise ValueError("任务当前未运行")
            job["reason"] = "网页强制停止"
            job["stop"].set()
            self.redirect("/")
        elif path == "/backup/delete":
            task = self.app.task(form.get("id", ""))
            allowed = {p.name: p for p in self.app.backups(task)} if task else {}
            target = allowed.get(form.get("name", ""))
            if not target:
                raise ValueError("备份不存在")
            shutil.rmtree(target)
            self.app.notify(f"已删除备份：{task['name']} / {target.name}")
            self.redirect(f"/task?id={task['id']}")
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
                self.redirect("/settings")
        else:
            raise ValueError("未知操作")


def initialize(app, username, password, port, host=None, cert=None, key=None):
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,50}", username):
        raise ValueError("用户名格式无效")
    app.config["admin_username"] = username
    app.config["listen_port"] = int(port)
    if host:
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
    if not Path(cert).is_file() or not Path(key).is_file():
        raise SystemExit("HTTPS 证书不存在，请重新运行安装器申请 IP 证书")
    Handler.app = app
    server = ThreadingHTTPServer((app.config["listen_host"], int(app.config["listen_port"])), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=app.scheduler_loop, daemon=True).start()
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
    args = parser.parse_args()
    app = BackupApp(args.data_dir)
    if args.command == "init":
        initialize(app, args.username, args.password, args.port, args.host, args.cert, args.key)
    else:
        serve(app)


if __name__ == "__main__":
    main()
