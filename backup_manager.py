#!/usr/bin/env python3
"""Simple Backup: a small Linux backup daemon with a Chinese web UI."""

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


GIB = 1024 ** 3
MIN_FREE = 3 * GIB
DEFAULTS = {
    "remote_host": "",
    "remote_port": 22,
    "remote_user": "root",
    "remote_path": "/",
    "ssh_key": "/root/.ssh/id_ed25519",
    "backup_dir": "/var/backups/simple-backup",
    "interval_days": 3,
    "retention_limit": 0,
    "transfer_threads": 4,
    "enabled": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "admin_username": "admin",
    "listen_host": "0.0.0.0",
    "listen_port": 8088,
    "tls_cert": "/var/lib/simple-backup/server.crt",
    "tls_key": "/var/lib/simple-backup/server.key",
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
        raise ValueError("管理密码至少需要 10 位且不能包含控制字符")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return {"password_salt": salt.hex(), "password_hash": digest.hex()}


def human_size(size):
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
            except FileNotFoundError:
                pass
    return total


def validate_config(data):
    host = str(data.get("remote_host", "")).strip()
    user = str(data.get("remote_user", "")).strip()
    remote_path = str(data.get("remote_path", "")).strip()
    backup_dir = str(data.get("backup_dir", "")).strip()
    ssh_key = str(data.get("ssh_key", "")).strip()
    admin_username = str(data.get("admin_username", "admin")).strip()
    if host and not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise ValueError("服务器地址只能包含字母、数字、点、横线和冒号")
    if user and not re.fullmatch(r"[A-Za-z0-9._-]+", user):
        raise ValueError("SSH 用户名格式不正确")
    if not remote_path.startswith("/") or any(c in remote_path for c in "\r\n\0"):
        raise ValueError("远程目录必须是绝对路径")
    if any(c in backup_dir or c in ssh_key for c in "\r\n\0"):
        raise ValueError("本机路径不能包含换行符")
    if not Path(backup_dir).is_absolute():
        raise ValueError("本机备份目录必须是绝对路径")
    if backup_dir.rstrip("/") == "":
        raise ValueError("不能把整个根目录作为备份目录")
    if ssh_key and not Path(ssh_key).is_absolute():
        raise ValueError("SSH 密钥必须是绝对路径")
    port = int(data.get("remote_port", 22))
    days = float(data.get("interval_days", 3))
    keep = int(data.get("retention_limit", 0))
    threads = int(data.get("transfer_threads", 4))
    listen_port = int(data.get("listen_port", 8088))
    if not 1 <= port <= 65535 or not 1 <= listen_port <= 65535:
        raise ValueError("端口必须在 1 到 65535 之间")
    if not 0.01 <= days <= 3650:
        raise ValueError("备份周期必须在 0.01 到 3650 天之间")
    if not 0 <= keep <= 100000:
        raise ValueError("保留份数不能小于 0")
    if not 1 <= threads <= 16:
        raise ValueError("下载线程数必须在 1 到 16 之间")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", admin_username):
        raise ValueError("管理用户名需要 3-32 位，只能使用字母、数字、点、横线和下划线")
    data.update(remote_host=host, remote_user=user, remote_path=remote_path,
                backup_dir=backup_dir, ssh_key=ssh_key, remote_port=port,
                interval_days=days, retention_limit=keep, transfer_threads=threads,
                admin_username=admin_username, listen_port=listen_port)
    return data


class BackupApp:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.config_path = self.data_dir / "config.json"
        self.state_path = self.data_dir / "state.json"
        self.config = self.load(self.config_path, DEFAULTS.copy())
        self.state = self.load(self.state_path, {
            "next_run": 0, "last_result": "尚未备份", "last_backup": "",
            "last_error": "", "low_disk": False, "telegram_offset": 0,
        })
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.running = False
        self.process = None
        self.csrf = secrets.token_urlsafe(24)
        self.shutdown = threading.Event()

    @staticmethod
    def load(path, default):
        try:
            default.update(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            pass
        return default

    def save_config(self):
        with self.lock:
            atomic_json(self.config_path, self.config)

    def save_state(self):
        with self.lock:
            saved = {k: v for k, v in self.state.items() if k not in ("progress",)}
            atomic_json(self.state_path, saved)

    def free_space(self):
        path = Path(self.config["backup_dir"])
        path.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(path).free

    def backups(self):
        path = Path(self.config["backup_dir"])
        if not path.exists():
            return []
        pattern = re.compile(r"^\d{8}-\d{6}_[A-Za-z0-9._-]+(?:_[0-9a-f]{4})?$")
        return sorted((p for p in path.iterdir() if p.is_dir() and pattern.fullmatch(p.name)),
                      key=lambda p: p.name)

    def notify(self, message):
        token = self.config.get("telegram_bot_token", "").strip()
        chat = self.config.get("telegram_chat_id", "").strip()
        if not token or not chat:
            return
        try:
            body = urllib.parse.urlencode({"chat_id": chat, "text": "🗄 Simple Backup\n" + message}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage",
                                   body, timeout=15).read()
        except Exception as exc:
            print(f"Telegram 通知失败: {exc}", flush=True)

    def check_space(self, stop_running=True):
        try:
            free = self.free_space()
        except OSError as exc:
            self.state["last_error"] = f"无法读取备份磁盘: {exc}"
            return False
        if free < MIN_FREE:
            first = not self.state.get("low_disk")
            self.state["low_disk"] = True
            self.state["last_error"] = f"剩余容量 {human_size(free)}，低于 3 GB，备份已暂停"
            self.save_state()
            if stop_running and self.running:
                self.stop_event.set()
                self.terminate_process()
            if first:
                self.notify("⚠️ 容量不足：剩余 %s，低于 3 GB，所有备份已暂停。" % human_size(free))
            return False
        if self.state.get("low_disk"):
            self.state["low_disk"] = False
            self.state["last_error"] = ""
            self.save_state()
            self.notify("✅ 磁盘容量已恢复，自动备份将继续运行。")
        return True

    def start_backup(self, source="手动"):
        with self.lock:
            if self.running:
                return False, "已有备份正在进行"
            if not self.config.get("remote_host"):
                return False, "请先填写远程服务器地址"
            if not self.check_space(False):
                return False, self.state["last_error"]
            self.running = True
            self.stop_event.clear()
            self.state["progress"] = "准备中"
            threading.Thread(target=self.backup_job, args=(source,), daemon=True).start()
            return True, "备份已在后台开始"

    def backup_job(self, source):
        started = time.time()
        threads = int(self.config.get("transfer_threads", 4))
        self.notify(f"▶️ 备份任务开始（{source}，{threads} 线程）")
        try:
            error = ""
            retention_done = False
            for attempt in range(1, 6):
                if self.stop_event.is_set():
                    error = "用户强制停止"
                    break
                try:
                    if not retention_done:
                        self.apply_retention()
                        retention_done = True
                    ok, result = self.run_transfer()
                except Exception as exc:
                    ok, result = False, str(exc)
                if ok:
                    final = result
                    size = directory_size(final)
                    duration = int(time.time() - started)
                    free = self.free_space()
                    self.state.update(last_result="备份成功", last_backup=final.name,
                                      last_error="", progress="100%",
                                      next_run=time.time() + float(self.config["interval_days"]) * 86400)
                    self.save_state()
                    self.notify("✅ 备份成功\n文件名：%s\n大小：%s\n耗时：%d 秒\n完成时间：%s\n剩余容量：%s" % (
                        final.name, human_size(size), duration,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"), human_size(free)))
                    return
                error = result
                if self.stop_event.is_set() or self.state.get("low_disk"):
                    error = self.state.get("last_error") if self.state.get("low_disk") else "用户强制停止"
                    break
                self.state.update(last_result="备份失败", last_error=error,
                                  progress=f"第 {attempt}/5 次失败")
                self.save_state()
                self.notify(f"❌ 备份失败（第 {attempt}/5 次）\n原因：{error}")
                if attempt < 5:
                    self.stop_event.wait(60)
            if not self.stop_event.is_set() and not self.state.get("low_disk"):
                self.config["enabled"] = False
                self.save_config()
                self.notify(f"⛔ 连续 5 次失败，自动备份已关闭。\n最后原因：{error}")
            self.state.update(last_result="备份已停止" if self.stop_event.is_set() else "备份失败",
                              last_error=error, progress="已停止")
            self.save_state()
        except Exception as exc:
            self.state.update(last_result="备份失败", last_error=str(exc), progress="异常")
            self.save_state()
            self.notify(f"❌ 备份失败\n原因：{exc}")
        finally:
            with self.lock:
                self.process = None
                self.running = False

    def apply_retention(self):
        limit = int(self.config.get("retention_limit", 0))
        if not limit:
            return
        items = self.backups()
        while len(items) >= limit:
            oldest = items.pop(0)
            shutil.rmtree(oldest)
            self.notify(f"🗑 已删除最旧备份：{oldest.name}")

    @staticmethod
    def lftp_quote(value):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`") + '"'

    def run_transfer(self):
        cfg = self.config.copy()
        root = Path(cfg["backup_dir"])
        partial = root / ".partial"
        partial.mkdir(parents=True, exist_ok=True)
        host = cfg["remote_host"]
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        ssh = ["ssh", "-p", str(cfg["remote_port"]), "-o", "BatchMode=yes",
               "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"]
        if cfg.get("ssh_key"):
            ssh += ["-i", cfg["ssh_key"]]
        import shlex
        threads = int(cfg.get("transfer_threads", 4))
        if threads > 1:
            parallel = max(1, int(threads ** 0.5))
            segments = max(2, threads // parallel)
            ssh_program = ["ssh", "-a", "-x", "-o", "BatchMode=yes",
                           "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"]
            if cfg.get("ssh_key"):
                ssh_program += ["-i", cfg["ssh_key"]]
            script = "; ".join((
                "set cmd:fail-exit yes",
                "set net:max-retries 2",
                "set net:timeout 30",
                "set mirror:parallel-directories true",
                f"set sftp:connect-program {self.lftp_quote(' '.join(shlex.quote(x) for x in ssh_program))}",
                f"open -p {cfg['remote_port']} -u {self.lftp_quote(cfg['remote_user'])} {self.lftp_quote('sftp://' + host)}",
                f"mirror -a --continue --delete --parallel={parallel} --use-pget-n={segments} --verbose=1 {self.lftp_quote(cfg['remote_path'])} {self.lftp_quote(str(partial))}",
                "bye",
            ))
            cmd = ["lftp", "--norc", "-c", script]
            self.state["progress"] = f"{threads} 线程传输中"
            tool_name = "lftp"
        else:
            cmd = ["rsync", "-a", "--delete", "--partial", "-s",
                   "--info=progress2", "--human-readable",
                   "-e", " ".join(shlex.quote(x) for x in ssh)]
            source = f"{cfg['remote_user']}@{host}:{cfg['remote_path'].rstrip('/')}/"
            cmd += [source, str(partial) + "/"]
            tool_name = "rsync"
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            start_new_session=True)
        except (FileNotFoundError, OSError) as exc:
            return False, str(exc)
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        output = bytearray()
        progress_sent = 0
        last_space_check = 0
        while self.process.poll() is None:
            for key, _ in selector.select(timeout=1):
                chunk = os.read(key.fileobj.fileno(), 8192)
                output.extend(chunk)
                if len(output) > 200_000:
                    del output[:-100_000]
                percentages = re.findall(rb"\b(\d{1,3})%", chunk)
                if percentages:
                    percent = min(100, int(percentages[-1]))
                    self.state["progress"] = f"{percent}%"
                    if percent < 100 and percent >= progress_sent + 10:
                        progress_sent = percent - percent % 10
                        threading.Thread(target=self.notify, args=(f"⏳ 备份进度：{percent}%",), daemon=True).start()
            if self.stop_event.is_set():
                self.terminate_process()
            if time.time() - last_space_check >= 5:
                last_space_check = time.time()
                if not self.check_space(True):
                    self.stop_event.set()
        remaining = self.process.stdout.read() or b""
        output.extend(remaining)
        code = self.process.wait()
        selector.close()
        self.process.stdout.close()
        self.process = None
        if code != 0:
            message = output.decode(errors="replace").strip().replace("\r", "\n")
            lines = [line.strip() for line in message.splitlines() if line.strip()]
            return False, (lines[-1] if lines else f"{tool_name} 退出码 {code}")[:1000]
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", cfg["remote_host"])
        final = root / f"{stamp}_{safe_host}"
        if final.exists():
            final = root / f"{stamp}_{safe_host}_{secrets.token_hex(2)}"
        os.replace(partial, final)
        return True, final

    def terminate_process(self):
        proc = self.process
        if not proc or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()

    def stop_backup(self):
        if not self.running:
            return False, "当前没有正在运行的备份"
        self.stop_event.set()
        self.terminate_process()
        self.notify("⏹ 用户已强制停止备份；未完成文件会保留用于下次续传。")
        return True, "已发送停止指令"

    def delete_backup(self, name):
        if self.running:
            return False, "备份运行中，请先停止再删除"
        if not name or name.startswith(".") or Path(name).name != name:
            return False, "备份名称不正确"
        root = Path(self.config["backup_dir"]).resolve()
        target = (root / name).resolve()
        known = {p.resolve() for p in self.backups()}
        if target.parent != root or target not in known:
            return False, "找不到该备份"
        shutil.rmtree(target)
        self.notify(f"🗑 用户删除了备份：{name}")
        return True, f"已删除 {name}"

    def status(self):
        try:
            free = human_size(self.free_space())
        except OSError:
            free = "无法读取"
        next_run = self.state.get("next_run", 0)
        return {
            "running": self.running,
            "progress": self.state.get("progress", "-"),
            "last_result": self.state.get("last_result", "尚未备份"),
            "last_error": self.state.get("last_error", ""),
            "free": free,
            "enabled": bool(self.config.get("enabled")),
            "next_run": datetime.fromtimestamp(next_run).strftime("%Y-%m-%d %H:%M:%S") if next_run else "保存设置后开始计时",
        }

    def scheduler(self):
        while not self.shutdown.wait(5):
            if not self.check_space(True):
                continue
            if self.config.get("enabled") and not self.running:
                next_run = float(self.state.get("next_run", 0))
                if not next_run:
                    self.state["next_run"] = time.time() + float(self.config["interval_days"]) * 86400
                    self.save_state()
                elif time.time() >= next_run:
                    self.start_backup("自动")

    def telegram(self):
        offset = int(self.state.get("telegram_offset", 0))
        while not self.shutdown.is_set():
            token = self.config.get("telegram_bot_token", "").strip()
            chat = self.config.get("telegram_chat_id", "").strip()
            if not token or not chat:
                self.shutdown.wait(5)
                continue
            try:
                query = urllib.parse.urlencode({"timeout": 25, "offset": offset})
                with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getUpdates?{query}", timeout=35) as response:
                    updates = json.load(response).get("result", [])
                for update in updates:
                    offset = max(offset, update["update_id"] + 1)
                    self.state["telegram_offset"] = offset
                    self.save_state()
                    message = update.get("message", {})
                    if str(message.get("chat", {}).get("id", "")) != chat:
                        continue
                    text = message.get("text", "").strip()
                    self.telegram_command(text)
            except Exception as exc:
                print(f"Telegram 轮询失败: {exc}", flush=True)
                self.shutdown.wait(5)

    def telegram_command(self, text):
        command, _, arg = text.partition(" ")
        command = command.split("@")[0].lower()
        if command == "/backup":
            _, message = self.start_backup("Telegram 手动")
        elif command == "/stop":
            _, message = self.stop_backup()
        elif command == "/status":
            s = self.status()
            message = "状态：%s\n进度：%s\n剩余容量：%s\n下次备份：%s" % (
                "运行中" if s["running"] else s["last_result"], s["progress"], s["free"], s["next_run"])
        elif command == "/list":
            names = [p.name for p in self.backups()]
            message = "备份列表：\n" + ("\n".join(names[-30:]) if names else "暂无备份")
        elif command == "/delete":
            _, message = self.delete_backup(arg.strip())
        else:
            message = "命令：\n/backup 开始备份\n/stop 强制停止\n/status 查看状态\n/list 备份列表\n/delete 文件名 删除备份"
        self.notify(message)


class Handler(BaseHTTPRequestHandler):
    app = None
    server_version = "SimpleBackup"
    sys_version = ""
    failures = {}
    failure_lock = threading.Lock()

    def log_message(self, fmt, *args):
        print("Web:", fmt % args, flush=True)

    def auth_ok(self):
        expected = self.app.config.get("password_hash")
        if not expected:
            return False
        ip = self.client_address[0]
        now = time.time()
        with self.failure_lock:
            count, started, blocked = self.failures.get(ip, (0, now, 0))
            if blocked > now:
                return False
        try:
            header = self.headers.get("Authorization", "")
            raw = base64.b64decode(header[6:] if header.startswith("Basic ") else "").decode()
            user, password = raw.split(":", 1)
            salt = bytes.fromhex(self.app.config["password_salt"])
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()
            valid = user == self.app.config.get("admin_username", "admin") and hmac.compare_digest(actual, expected)
        except Exception:
            valid = False
        with self.failure_lock:
            if valid:
                self.failures.pop(ip, None)
            else:
                if now - started > 300:
                    count, started = 0, now
                count += 1
                self.failures[ip] = (count, started, now + 900 if count >= 5 else 0)
        return valid

    def authenticate(self):
        if self.auth_ok():
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Simple Backup"')
        self.security_headers()
        self.end_headers()
        return False

    def security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def send_json(self, value, code=200):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.authenticate():
            return
        if self.path == "/api/status":
            self.send_json(self.app.status())
            return
        if self.path != "/":
            self.send_error(404)
            return
        body = self.page().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.authenticate():
            return
        length = min(int(self.headers.get("Content-Length", "0")), 64 * 1024)
        form = {k: v[-1] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}
        if not hmac.compare_digest(form.get("csrf", ""), self.app.csrf):
            self.send_json({"ok": False, "message": "页面已过期，请刷新后重试"}, 403)
            return
        try:
            if self.path == "/save":
                self.save_settings(form)
                result = (True, "设置已保存；备份将在后台按新周期运行")
            elif self.path == "/action/backup":
                result = self.app.start_backup("网页手动")
            elif self.path == "/action/stop":
                result = self.app.stop_backup()
            elif self.path == "/action/delete":
                result = self.app.delete_backup(form.get("name", ""))
            else:
                self.send_error(404)
                return
            self.send_json({"ok": result[0], "message": result[1]}, 200 if result[0] else 400)
        except (ValueError, OSError) as exc:
            self.send_json({"ok": False, "message": str(exc)}, 400)

    def save_settings(self, form):
        if self.app.running:
            raise ValueError("备份运行中，请先停止再修改设置")
        old_enabled = self.app.config.get("enabled")
        old_days = float(self.app.config.get("interval_days", 3))
        old_token = self.app.config.get("telegram_bot_token", "")
        updated = self.app.config.copy()
        for key in ("remote_host", "remote_user", "remote_path", "ssh_key", "backup_dir",
                    "remote_port", "interval_days", "retention_limit", "transfer_threads",
                    "admin_username", "telegram_bot_token", "telegram_chat_id"):
            updated[key] = form.get(key, "")
        updated["enabled"] = form.get("enabled") == "on"
        validate_config(updated)
        password = form.get("new_password", "")
        if password:
            if len(password) < 10:
                raise ValueError("新管理密码至少需要 10 位")
            updated.update(password_fields(password))
        Path(updated["backup_dir"]).mkdir(parents=True, exist_ok=True)
        self.app.config = updated
        self.app.save_config()
        if updated["telegram_bot_token"] != old_token:
            self.app.state["telegram_offset"] = 0
            self.app.save_state()
        if (updated["enabled"] and not old_enabled) or float(updated["interval_days"]) != old_days:
            self.app.state["next_run"] = time.time() + float(updated["interval_days"]) * 86400
            self.app.save_state()

    def page(self):
        c = self.app.config
        esc = lambda key: html.escape(str(c.get(key, "")), quote=True)
        checked = "checked" if c.get("enabled") else ""
        rows = "".join(f'<li><code>{html.escape(p.name)}</code><button onclick="act(\'/action/delete\',\'{html.escape(p.name, quote=True)}\')">删除</button></li>' for p in reversed(self.app.backups()[-30:]))
        return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simple Backup</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f4f7fb;color:#18212f;font:15px system-ui,sans-serif}}main{{max-width:940px;margin:auto;padding:24px}}h1{{margin:0 0 18px}}.card{{background:white;border:1px solid #dce3ed;border-radius:14px;padding:20px;margin-bottom:16px;box-shadow:0 4px 16px #17345a0d}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}label{{display:block;font-weight:650}}input{{width:100%;margin-top:6px;padding:10px;border:1px solid #b9c5d5;border-radius:8px;font:inherit}}small{{display:block;color:#66758a;margin-top:5px}}button{{border:0;border-radius:8px;padding:10px 16px;background:#1769e0;color:#fff;font-weight:700;cursor:pointer}}button.danger{{background:#c93535}}.actions{{display:flex;gap:10px;flex-wrap:wrap}}#status{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}#status div{{background:#eef4ff;padding:12px;border-radius:9px}}#msg{{position:fixed;right:20px;bottom:20px;padding:12px 16px;border-radius:9px;background:#172033;color:#fff;display:none}}ul{{padding:0;list-style:none}}li{{display:flex;justify-content:space-between;align-items:center;border-top:1px solid #edf0f5;padding:9px 0}}li button{{padding:6px 10px;background:#d84b4b}}.toggle{{display:flex;align-items:center;gap:8px}}.toggle input{{width:auto;margin:0}}@media(max-width:650px){{.grid,#status{{grid-template-columns:1fr}}main{{padding:12px}}}}
</style></head><body><main><h1>🗄 Simple Backup</h1>
<section class="card"><h2>运行状态</h2><div id="status"><div>状态<br><b id="run">读取中</b></div><div>进度<br><b id="progress">-</b></div><div>剩余容量<br><b id="free">-</b></div><div>下次备份<br><b id="next">-</b></div></div><p id="error"></p><div class="actions"><button onclick="act('/action/backup')">立即备份</button><button class="danger" onclick="act('/action/stop')">强制停止</button></div></section>
<form class="card" id="settings" onsubmit="save(event)"><h2>备份设置</h2><input type="hidden" name="csrf" value="{self.app.csrf}"><div class="grid">
<label>远程服务器地址<input name="remote_host" required value="{esc('remote_host')}" placeholder="例如 192.168.1.20"><small>域名或 IP 地址</small></label>
<label>SSH 用户名<input name="remote_user" required value="{esc('remote_user')}"></label>
<label>远程目录<input name="remote_path" required value="{esc('remote_path')}" placeholder="/home/data"></label>
<label>SSH 端口<input name="remote_port" type="number" min="1" max="65535" required value="{esc('remote_port')}"></label>
<label>SSH 私钥<input name="ssh_key" value="{esc('ssh_key')}" placeholder="/root/.ssh/id_ed25519"><small>请先把公钥放到远程服务器</small></label>
<label>本机备份目录<input name="backup_dir" required value="{esc('backup_dir')}"></label>
<label>每几天备份一次<input name="interval_days" type="number" min="0.01" max="3650" step="0.01" required value="{esc('interval_days')}" placeholder="3"><small>例如填 3，就是每 3 天一次</small></label>
<label>最多保留几份<input name="retention_limit" type="number" min="0" value="{esc('retention_limit')}"><small>填 0 表示全部保留</small></label>
<label>下载线程数<input name="transfer_threads" type="number" min="1" max="16" required value="{esc('transfer_threads')}"><small>推荐 4；填 1 使用兼容模式</small></label>
</div><p><label class="toggle"><input name="enabled" type="checkbox" {checked}>开启定时自动备份</label></p>
<h3>面板安全</h3><div class="grid"><label>管理用户名<input name="admin_username" required minlength="3" maxlength="32" value="{esc('admin_username')}"></label><label>修改管理密码<input name="new_password" type="password" minlength="10" placeholder="留空表示不修改"></label></div>
<h3>Telegram 通知与控制（可选）</h3><div class="grid"><label>机器人 Token<input name="telegram_bot_token" type="password" value="{esc('telegram_bot_token')}"></label><label>允许控制的 Chat ID<input name="telegram_chat_id" value="{esc('telegram_chat_id')}"></label></div>
<p><button type="submit">保存全部设置</button></p></form>
<section class="card"><h2>已有备份</h2><ul>{rows or '<li>暂无备份</li>'}</ul></section></main><div id="msg"></div>
<script>const csrf={json.dumps(self.app.csrf)};function toast(s){{let m=document.querySelector('#msg');m.textContent=s;m.style.display='block';setTimeout(()=>m.style.display='none',4000)}}async function post(url,data={{}}){{let b=new URLSearchParams({{csrf,...data}}),r=await fetch(url,{{method:'POST',body:b}}),j=await r.json();toast(j.message);if(j.ok&&url.includes('delete'))setTimeout(()=>location.reload(),700);return j}}function act(url,name){{if(url.includes('delete')&&!confirm('确定删除 '+name+'？此操作不可恢复。'))return;post(url,name?{{name}}:{{}})}}async function save(e){{e.preventDefault();let r=await fetch('/save',{{method:'POST',body:new URLSearchParams(new FormData(e.target))}}),j=await r.json();toast(j.message)}}async function status(){{let s=await(await fetch('/api/status')).json();run.textContent=s.running?'备份运行中':(s.enabled?'自动备份已开启':'自动备份已关闭');progress.textContent=s.progress;free.textContent=s.free;next.textContent=s.next_run;error.textContent=s.last_error||s.last_result}}status();setInterval(status,3000)</script></body></html>'''


def initialize(data_dir, username="admin", password="", listen_host="0.0.0.0", listen_port=8088,
               tls_cert="/var/lib/simple-backup/server.crt", tls_key="/var/lib/simple-backup/server.key"):
    path = Path(data_dir) / "config.json"
    if path.exists():
        print("配置已存在，未覆盖。")
        return
    password = password or secrets.token_urlsafe(12)
    if len(password) < 10:
        raise ValueError("管理密码至少需要 10 位")
    config = DEFAULTS.copy()
    config.update(admin_username=username, listen_host=listen_host, listen_port=int(listen_port),
                  tls_cert=tls_cert, tls_key=tls_key)
    config.update(password_fields(password))
    validate_config(config)
    atomic_json(path, config)
    atomic_json(Path(data_dir) / "state.json", {"next_run": 0, "last_result": "尚未备份", "last_backup": "", "last_error": "", "low_disk": False, "telegram_offset": 0})
    print(f"管理用户名：{username}\n管理密码：{password}")


def configure_panel(data_dir, username="", password="", listen_host="", listen_port="",
                    tls_cert="", tls_key=""):
    app = BackupApp(data_dir)
    updated = app.config.copy()
    if username:
        updated["admin_username"] = username
    if listen_host:
        updated["listen_host"] = listen_host
    if listen_port:
        updated["listen_port"] = int(listen_port)
    if tls_cert:
        updated["tls_cert"] = tls_cert
    if tls_key:
        updated["tls_key"] = tls_key
    if password:
        if len(password) < 10:
            raise ValueError("管理密码至少需要 10 位")
        updated.update(password_fields(password))
    validate_config(updated)
    app.config = updated
    app.save_config()
    print(f"面板设置已更新：{updated['admin_username']}@{updated['listen_host']}:{updated['listen_port']}")


def main():
    parser = argparse.ArgumentParser(description="Simple Backup")
    parser.add_argument("--data-dir", default=os.environ.get("SIMPLE_BACKUP_HOME", "/var/lib/simple-backup"))
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--configure-panel", action="store_true")
    parser.add_argument("--panel-user", default=os.environ.get("SIMPLE_BACKUP_PANEL_USER", ""))
    parser.add_argument("--panel-password", default=os.environ.get("SIMPLE_BACKUP_PANEL_PASSWORD", ""))
    parser.add_argument("--panel-host", default=os.environ.get("SIMPLE_BACKUP_PANEL_HOST", ""))
    parser.add_argument("--panel-port", default=os.environ.get("SIMPLE_BACKUP_PANEL_PORT", ""))
    parser.add_argument("--tls-cert", default=os.environ.get("SIMPLE_BACKUP_TLS_CERT", ""))
    parser.add_argument("--tls-key", default=os.environ.get("SIMPLE_BACKUP_TLS_KEY", ""))
    args = parser.parse_args()
    if args.init:
        initialize(args.data_dir, args.panel_user or "admin", args.panel_password,
                   args.panel_host or "0.0.0.0", args.panel_port or 8088,
                   args.tls_cert or DEFAULTS["tls_cert"], args.tls_key or DEFAULTS["tls_key"])
        return
    if args.configure_panel:
        configure_panel(args.data_dir, args.panel_user, args.panel_password, args.panel_host,
                        args.panel_port, args.tls_cert, args.tls_key)
        return
    app = BackupApp(args.data_dir)
    validate_config(app.config)
    Handler.app = app
    threading.Thread(target=app.scheduler, daemon=True).start()
    threading.Thread(target=app.telegram, daemon=True).start()
    server = ThreadingHTTPServer((app.config["listen_host"], int(app.config["listen_port"])), Handler)
    cert, key = Path(app.config["tls_cert"]), Path(app.config["tls_key"])
    if not cert.is_file() or not key.is_file():
        raise SystemExit("HTTPS 证书不存在，请运行 simple-backup 管理菜单重新生成")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Simple Backup 已启动：https://{app.config['listen_host']}:{app.config['listen_port']}", flush=True)
    try:
        server.serve_forever()
    finally:
        app.shutdown.set()
        app.stop_backup()


if __name__ == "__main__":
    main()
