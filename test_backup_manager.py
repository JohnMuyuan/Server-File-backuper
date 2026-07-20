import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path

from backup_manager import (
    BackupApp, Handler, TASK_DEFAULTS, backup_prefix, human_size, initialize,
    command_error, incremental_ledger, incremental_path, migrate_config, mirror_path, password_fields, source_changed_only,
    serve, validate_task, verify_password,
)


def sample_task(local_dir, **changes):
    task = dict(TASK_DEFAULTS)
    task.update({
        "id": "a1b2c3d4", "name": "数据库", "remote_host": "db.example.com",
        "remote_path": "/srv/data", "backup_dir": str(local_dir), "ssh_key": "",
    })
    task.update(changes)
    return validate_task(task, task["id"])


class BackupManagerTest(unittest.TestCase):
    def test_task_validation_commands_and_retention(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = sample_task(root / "backups", retention_limit=2)
            config = {"tasks": [task], **password_fields("long-enough-password")}
            data = root / "state"
            data.mkdir()
            (data / "config.json").write_text(json.dumps(config), encoding="utf-8")
            app = BackupApp(data)
            app.notify = lambda _: None

            suffix = backup_prefix(task)
            for stamp in ("20260101-010101", "20260102-010101"):
                (Path(task["backup_dir"]) / f"{stamp}_{suffix}").mkdir(parents=True)
            unrelated = Path(task["backup_dir"]) / "unrelated-user-data"
            unrelated.mkdir()
            app.apply_retention(task)
            self.assertEqual([p.name for p in app.backups(task)], [f"20260102-010101_{suffix}"])
            self.assertTrue(unrelated.is_dir())
            archive = Path(task["backup_dir"]) / f"20260103-010101_{suffix}.tar.zst"
            archive.write_bytes(b"archive")
            self.assertIn(archive, app.backups(task))

            chunk = root / "files.chunk.0"
            chunk.write_bytes(b"./mail/cur/message\0")
            rsync = app.transfer_command(task, root / "partial", chunk)
            self.assertEqual(rsync[0], "rsync")
            self.assertIn("--partial", rsync)
            self.assertIn("--partial-dir=.rsync-partial", rsync)
            self.assertIn("--from0", rsync)
            self.assertIn(f"--files-from={chunk}", rsync)
            self.assertIn("--relative", rsync)
            self.assertNotIn("--delete-after", rsync)
            fallback = app.transfer_command(task, root / "partial")
            self.assertIn("--delete-after", fallback)
            incremental_task = {**task, "file_mode": "incremental"}
            incremental_command = app.transfer_command(incremental_task, root / "incremental", chunk)
            self.assertIn("--ignore-existing", incremental_command)
            self.assertNotIn("--delete-after", incremental_command)
            mirror_task = sample_task(root / "mirror-command", id="e1b2c3d4", file_mode="mirror")
            mirror_path(mirror_task).mkdir(parents=True)
            mirror_command = app.transfer_command(mirror_task, root / "mirror-staging", chunk)
            self.assertIn(f"--link-dest={mirror_path(mirror_task)}", mirror_command)
            parallel_staging = root / "parallel-staging"
            parallel_staging.mkdir()
            chunks = []
            for index in range(4):
                part = root / f"chunk-{index}"
                part.write_bytes(f"./file-{index}\0".encode())
                chunks.append(part)
            calls = []
            app.scan_remote_manifest = lambda *_: chunks
            app.execute = lambda command, *_args, **_kwargs: (calls.append(command) or (0, ""))
            app.transfer_manifest(task, parallel_staging, root / "state", {"progress": 0})
            self.assertEqual(len(calls), 4)
            self.assertEqual({next(arg for arg in call if arg.startswith("--files-from=")) for call in calls}, {
                f"--files-from={chunk}" for chunk in chunks
            })
            password_task = {**task, "auth_method": "password"}
            app.set_task_password(task["id"], "remote secret")
            self.assertIn("sshpass -e ssh", " ".join(app.transfer_command(password_task, root / "partial")))
            mysql_task = sample_task(
                root / "mysql", source_type="mysql", database_user="backup",
                database_name="app", database_port=0,
            )
            mysql_command = " ".join(app.database_command(mysql_task))
            self.assertIn("mysqldump", mysql_command)
            self.assertNotIn("database-secret", mysql_command)
            self.assertIn("redis-cli", " ".join(app.database_command({
                **mysql_task, "source_type": "redis", "database_user": "", "database_name": "",
            })))
            self.assertEqual(human_size(3 * 1024 ** 3), "3.0 GB")

            compressed_task = sample_task(root / "compressed", id="b1b2c3d4", retention_limit=0)
            app.remote_setup = lambda *_: None
            app.disk_guard = lambda *_: True
            app.free_space = lambda *_: 10 * 1024 ** 3
            def fake_transfer(_task, partial, _state, _job):
                (partial / "downloaded.txt").write_text("data", encoding="utf-8")
            app.transfer_manifest = fake_transfer
            def fake_execute(command, *_args, **_kwargs):
                if command[0] == "tar":
                    Path(command[3]).write_bytes(b"zstd")
                return 0, ""
            app.execute = fake_execute
            final, size, _ = app.backup_once(
                compressed_task,
                {"stop": threading.Event(), "phase": "", "progress": 0},
            )
            self.assertTrue(final.name.endswith(".tar.zst"))
            self.assertEqual(size, 4)
            self.assertFalse((Path(compressed_task["backup_dir"]) / f".partial-{compressed_task['id']}").exists())

            incremental_task = sample_task(
                root / "incremental-backup", id="d1b2c3d4", file_mode="incremental",
            )
            final, size, _ = app.backup_once(
                incremental_task,
                {"stop": threading.Event(), "phase": "", "progress": 0},
            )
            self.assertEqual(final, incremental_path(incremental_task))
            self.assertTrue(final.is_dir())
            self.assertEqual(size, 4)
            self.assertFalse(incremental_ledger(incremental_task).exists())
            kept = final / "kept.txt"
            new = final / "new.txt"
            partial = final / ".rsync-partial"
            kept.write_text("old", encoding="utf-8")
            new.write_text("new", encoding="utf-8")
            partial.mkdir()
            incremental_ledger(incremental_task).write_bytes(b"./new.txt\0")
            app.clear_partial(incremental_task)
            self.assertTrue(kept.exists())
            self.assertFalse(new.exists())
            self.assertFalse(partial.exists())
            old_snapshot = Path(incremental_task["backup_dir"]) / f"20260101-010101_{backup_prefix(incremental_task)}.tar.zst"
            old_snapshot.write_bytes(b"old")
            app.apply_retention({**incremental_task, "file_mode": "snapshot", "retention_limit": 1})
            self.assertTrue(final.exists())
            self.assertFalse(old_snapshot.exists())

            mirror_task = sample_task(
                root / "mirror-backup", id="f1b2c3d4", file_mode="mirror",
            )
            current = mirror_path(mirror_task)
            current.mkdir(parents=True)
            (current / "deleted-remotely.txt").write_text("old", encoding="utf-8")
            final, size, _ = app.backup_once(
                mirror_task,
                {"stop": threading.Event(), "phase": "", "progress": 0},
            )
            self.assertEqual(final, current)
            self.assertEqual(size, 4)
            self.assertTrue((current / "downloaded.txt").exists())
            self.assertFalse((current / "deleted-remotely.txt").exists())
            self.assertFalse((Path(mirror_task["backup_dir"]) / f".partial-{mirror_task['id']}").exists())
            old_snapshot = Path(mirror_task["backup_dir"]) / f"20260101-010101_{backup_prefix(mirror_task)}.tar.zst"
            old_snapshot.write_bytes(b"old")
            app.apply_retention({**mirror_task, "file_mode": "snapshot", "retention_limit": 1})
            self.assertTrue(current.exists())
            self.assertFalse(old_snapshot.exists())

            database_backup = sample_task(
                root / "database-compressed", id="c1b2c3d4", source_type="postgresql",
                database_user="backup", database_name="app",
            )
            app.dump_database = lambda _task, staging, _job: (
                (staging / "postgresql-app.sql").write_bytes(b"sql") and 0, ""
            )
            final, _, _ = app.backup_once(
                database_backup,
                {"stop": threading.Event(), "phase": "", "progress": 0},
            )
            self.assertTrue(final.name.endswith(".tar.zst"))

    def test_validation_migration_credentials_and_sessions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for change in (
                {"remote_host": "bad host;rm"}, {"backup_dir": "/"},
                {"transfer_threads": 16999}, {"remote_path": "relative"},
                {"file_mode": "replace-existing"},
            ):
                with self.assertRaises(ValueError):
                    sample_task(root / "backup", **change)

            old = {
                "remote_host": "old.example.com", "remote_path": "/old",
                "backup_dir": str(root / "old-backups"), "ssh_key": "", "interval_days": 0.5,
            }
            migrated = migrate_config(old)
            self.assertEqual(len(migrated["tasks"]), 1)
            self.assertEqual(migrated["tasks"][0]["remote_host"], "old.example.com")
            self.assertEqual(migrated["tasks"][0]["schedule_times"], ["00:00", "12:00"])

            app = BackupApp(root / "data")
            initialize(app, "panel-user", "a-secure-password", 9443, "0.0.0.0", "/c", "/k")
            self.assertTrue(verify_password(app.config, "a-secure-password"))
            self.assertEqual(app.config["password_iterations"], 600_000)
            token = app.sign_session("panel-user")
            self.assertTrue(app.verify_session(token))
            self.assertFalse(app.verify_session(token + "x"))
            saved = json.loads((root / "data" / "config.json").read_text(encoding="utf-8"))
            self.assertEqual((saved["admin_username"], saved["listen_port"]), ("panel-user", 9443))

            proxy_app = BackupApp(root / "proxy-data")
            initialize(proxy_app, "proxy-user", "a-secure-password", 8088, "0.0.0.0", tls_enabled=False)
            self.assertFalse(proxy_app.config["tls_enabled"])
            self.assertEqual(proxy_app.config["listen_host"], "127.0.0.1")
            proxy_app.config["listen_host"] = "0.0.0.0"
            with self.assertRaises(SystemExit):
                serve(proxy_app)

            form = {
                "name": "密码服务器", "remote_host": "pw.example.com", "remote_port": "22",
                "remote_user": "root", "remote_path": "/data", "ssh_key": "",
                "backup_dir": str(root / "password-backups"), "interval_days": "3",
                "retention_limit": "0", "transfer_threads": "4", "auth_method": "password",
                "ssh_password": "only-in-secret-file", "enabled": "on",
            }
            created = app.save_task_form(form)
            self.assertEqual(app.task_password(created["id"]), "only-in-secret-file")
            config_text = (root / "data" / "config.json").read_text(encoding="utf-8")
            self.assertNotIn("only-in-secret-file", config_text)

            database_form = {
                **form, "name": "MySQL", "remote_host": "mysql.example.com",
                "backup_dir": str(root / "mysql-backups"), "source_type": "mysql",
                "database_host": "127.0.0.1", "database_port": "0",
                "database_user": "backup", "database_name": "app",
                "database_password": "database-secret", "ssh_password": "ssh-secret",
            }
            database_task = app.save_task_form(database_form)
            self.assertEqual(app.task_database_password(database_task["id"]), "database-secret")
            secret_text = app.secret_path(database_task["id"]).read_text(encoding="utf-8")
            self.assertIn("ssh-secret", secret_text)
            self.assertIn("database-secret", secret_text)
            self.assertNotIn("database-secret", app.config_path.read_text(encoding="utf-8"))

            for _ in range(5):
                app.login_failed("192.0.2.1")
            self.assertFalse(app.login_allowed("192.0.2.1"))

            scheduled = sample_task(
                root / "scheduled", interval_days=1, schedule_times=["02:00", "14:00"]
            )
            state = {"schedule_anchor": "2026-07-18"}
            first = app.next_scheduled(scheduled, state, datetime(2026, 7, 18, 10).timestamp())
            second = app.next_scheduled(scheduled, state, first + 1)
            self.assertEqual(datetime.fromtimestamp(first).strftime("%Y-%m-%d %H:%M"), "2026-07-18 14:00")
            self.assertEqual(datetime.fromtimestamp(second).strftime("%Y-%m-%d %H:%M"), "2026-07-19 02:00")
            self.assertIn("donut", app.home_html(app.sign_session("panel-user")))
            self.assertIn("net-rx", app.home_html(app.sign_session("panel-user")))
            self.assertIn("queue-item", app.home_html(app.sign_session("panel-user")))
            self.assertIn("tail-log", app.home_html(app.sign_session("panel-user")))
            self.assertIn("scrollHeight", app.logs_html(app.sign_session("panel-user")))
            self.assertIn("pageshow", app.logs_html(app.sign_session("panel-user")))
            self.assertIn("@media(max-width:640px)", app.home_html(app.sign_session("panel-user")))
            self.assertIn('/telegram/test', app.settings_html(app.sign_session("panel-user")))
            self.assertIn('source-type', app.task_form_html(database_task, app.sign_session("panel-user")))

            progress_task = sample_task(root / "progress", transfer_threads=4)
            staging = root / "staging"
            staging.mkdir()
            growing = staging / "large.bin"
            growing.write_bytes(b"x" * 512)
            job = {
                "total_bytes": 1024, "progress": 0, "next_progress_notice": 75,
                "_sample_time": time.time() - 1, "_sample_total": 0,
                "_file_samples": {"large.bin": (0, time.time() - 1)},
            }
            app.sample_transfer(staging, progress_task, job)
            self.assertEqual(job["progress"], 50)
            self.assertGreater(job["speed_bps"], 0)
            self.assertEqual(job["slots"][0]["name"], "large.bin")

            job.update(
                _sample_time=time.time() - 1, _sample_total=512,
                _file_samples={"large.bin": (512, time.time() - 1)},
            )
            tiny = staging / "new-tiny.txt"
            tiny.write_bytes(b"tiny")
            os.utime(tiny, (1, 1))
            app.sample_transfer(staging, progress_task, job)
            self.assertIn("new-tiny.txt", [slot["name"] for slot in job["slots"]])

            job.update(progress=80, _sample_time=time.time() - 1, _sample_total=516)
            tiny.unlink()
            app.sample_transfer(staging, progress_task, job)
            self.assertEqual(job["progress"], 80)

            vanished = "mirror: Access failed: No such file (/live/temporary.log)\nmirror: 1 error detected\n"
            self.assertTrue(source_changed_only(vanished))
            self.assertFalse(source_changed_only(vanished + "mirror: Permission denied (/private)\n"))
            rsync_vanished = (
                'rsync: [sender] link_stat "/live/gone" failed: No such file or directory (2)\n'
                'rsync error: some files/attrs were not transferred (see previous errors) (code 23)\n'
            )
            self.assertTrue(source_changed_only(rsync_vanished))
            self.assertIn("No such file", command_error(vanished + "Transferring file normal\n", 1))
            self.assertNotIn("error.log", command_error("Transferring file `log/error.log'\n", 1))

            manifest_root = root / "manifest-staging"
            (manifest_root / "mail" / "cur").mkdir(parents=True)
            (manifest_root / "mail" / "cur" / "keep").write_text("keep", encoding="utf-8")
            (manifest_root / "mail" / "cur" / "stale").write_text("stale", encoding="utf-8")
            (manifest_root / ".rsync-partial").mkdir()
            (manifest_root / ".rsync-partial" / "part").write_text("part", encoding="utf-8")
            manifest = root / "manifest.chunk"
            manifest.write_bytes(b"./mail\0./mail/cur\0./mail/cur/keep\0")
            app.clean_staging_from_manifest(manifest_root, [manifest])
            self.assertTrue((manifest_root / "mail" / "cur" / "keep").is_file())
            self.assertFalse((manifest_root / "mail" / "cur" / "stale").exists())
            self.assertFalse((manifest_root / ".rsync-partial").exists())

            app.config["tasks"].append(progress_task)
            app.log("只属于这个任务", task_id=progress_task["id"])
            self.assertIn("只属于这个任务", app.read_task_log(progress_task["id"]))
            detail = app.task_detail_html(progress_task, app.sign_session("panel-user"))
            self.assertIn("活跃传输槽位", detail)
            self.assertIn("该任务的全部日志", detail)
            self.assertIn("theme-switch", detail)
            self.assertIn('data-theme-value="light"', detail)

    def test_pause_discard_and_restart_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            task = sample_task(root / "backups")
            app = BackupApp(root / "data")
            app.config["tasks"] = [task]
            partial = Path(task["backup_dir"]) / f".partial-{task['id']}"
            partial.mkdir(parents=True)
            (partial / "part.bin").write_bytes(b"partial")

            app.task_state(task["id"])["last_result"] = "运行中"
            resumed = []
            app.start_backup = lambda task_id, source: (resumed.append((task_id, source)) or True, "ok")
            self.assertEqual(app.resume_interrupted(), 1)
            self.assertEqual(resumed[0][0], task["id"])

            app.task_state(task["id"])["last_result"] = "已暂停"
            self.assertIn("继续备份", app.dashboard_html(app.sign_session("admin")))
            event = threading.Event()
            app.jobs[task["id"]] = {"stop": event, "discard_partial": False}
            running_page = app.dashboard_html(app.sign_session("admin"))
            self.assertIn("临时暂停", running_page)
            self.assertIn("停止并清除", running_page)
            ok, _ = app.stop_backup(task["id"], True)
            self.assertTrue(ok)
            self.assertTrue(event.is_set())
            self.assertTrue(app.jobs[task["id"]]["discard_partial"])
            history = Path(task["backup_dir"]) / f"20260719-010101_{backup_prefix(task)}.tar.zst"
            history.write_bytes(b"history")
            app.clear_partial(task)
            self.assertFalse(partial.exists())
            self.assertTrue(history.exists())

    def test_redirect_is_framed_and_closed(self):
        class Response:
            def __init__(self):
                self.headers = []
            def send_response(self, status):
                self.status = status
            def send_header(self, name, value):
                self.headers.append((name, value))
            def end_headers(self):
                pass

        response = Response()
        Handler.redirect(response, "/tasks")
        self.assertEqual(response.status, 303)
        self.assertIn(("Content-Length", "0"), response.headers)
        self.assertIn(("Connection", "close"), response.headers)
        self.assertTrue(response.close_connection)

    def test_frontend_feedback_security_and_safe_return(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = BackupApp(root / "data")
            task = sample_task(root / "backups")
            app.config["tasks"] = [task]
            token = app.sign_session("panel-user")

            home = app.home_html(token)
            for marker in (
                "toast-stack", "notice", "tone", "confirm-dialog", "is-loading",
                "prefers-reduced-motion", "badge", "running", "success", "failed",
                "@media(max-width:640px)", 'rel="icon"', "brand-icon",
                "theme-switch", "theme-option", "--header-fg",
            ):
                self.assertIn(marker, home)

            backup_dir = Path(task["backup_dir"])
            backup_dir.mkdir(parents=True, exist_ok=True)
            long_name = "20260720-120000_" + ("very-long-backup-name-" * 7) + "_" + backup_prefix(task) + ".tar.zst"
            (backup_dir / long_name).write_bytes(b"backup")
            task_form = app.task_form_html(task, token)
            for marker in (
                "backup-list", "backup-file", "file-name", "overflow-wrap:anywhere",
                "danger-zone", "danger-outline", "删除文件", long_name,
            ):
                self.assertIn(marker, task_form)

            settings = app.settings_html(token)
            self.assertIn("settings-grid", settings)
            self.assertIn('data-loading="正在保存…"', settings)
            self.assertIn('data-loading="正在发送…"', settings)
            self.assertIn("/telegram/test", settings)

            login = app.login_html()
            for marker in (
                "HttpOnly", "SameSite=Strict", "登录失败限速", "CSRF 防护",
                "prefers-reduced-motion", "正在验证", "HTTPS", 'rel="icon"',
                "brand-mark", "login-theme-switch", 'data-theme-value="dark"',
            ):
                self.assertIn(marker, login)

            self.assertEqual(Handler.safe_return_to({"return_to": "/tasks"}), "/tasks")
            self.assertEqual(
                Handler.safe_return_to({"return_to": "/task?id=abc"}), "/task?id=abc"
            )
            self.assertEqual(
                Handler.safe_return_to({"return_to": "https://evil.example"}, "/fallback"),
                "/fallback",
            )
            self.assertEqual(
                Handler.safe_return_to({"return_to": "//evil.example"}, "/fallback"),
                "/fallback",
            )
            self.assertEqual(Handler.safe_return_to({}, "/fallback"), "/fallback")

    def test_installer_does_not_overwrite_panel_port(self):
        script = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn('firewall_port=$1', script)
        self.assertNotIn('open_firewall() {\n    port=$1', script)
        self.assertIn('socket.SO_REUSEADDR', script)
        self.assertIn('verify_panel_tls()', script)
        self.assertIn('2>&1', script)
        self.assertIn('tls_attempt', script)
        self.assertIn('SB_ACME_WEBROOT', script)
        self.assertIn('verify_webroot_route()', script)
        self.assertIn('.well-known/acme-challenge', script)
        self.assertIn('probe_body', script)
        self.assertIn('probe_status', script)
        self.assertIn('--max-redirs 10', script)
        self.assertIn('--alpn --tlsport 443', script)
        self.assertIn('--nginx', script)
        self.assertIn('--apache', script)
        self.assertIn('SB_REVERSE_PROXY', script)
        self.assertIn('--host "127.0.0.1" --no-tls', script)
        self.assertIn('当前由 1Panel 管理 HTTPS', script)
        self.assertNotIn('port_free 80 || {', script)
        self.assertIn('tar zstd', script)
        self.assertNotIn(' rsync lftp', script)


if __name__ == "__main__":
    unittest.main()
