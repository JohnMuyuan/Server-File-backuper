import json
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path

from backup_manager import (
    BackupApp, TASK_DEFAULTS, backup_prefix, human_size, initialize,
    migrate_config, password_fields, validate_task, verify_password,
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

            lftp = app.transfer_command(task, root / "partial")
            self.assertEqual(lftp[0], "lftp")
            self.assertIn("--parallel=2 --use-pget-n=2", lftp[2])
            rsync = app.transfer_command({**task, "transfer_threads": 1}, root / "partial")
            self.assertEqual(rsync[0], "rsync")
            self.assertIn("--append-verify", rsync)
            password_task = {**task, "auth_method": "password"}
            app.set_task_password(task["id"], "remote secret")
            self.assertIn("sshpass -e ssh", app.transfer_command(password_task, root / "partial")[2])
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
            def fake_execute(command, *_args, **_kwargs):
                if command[0] == "lftp":
                    partial = Path(compressed_task["backup_dir"]) / f".partial-{compressed_task['id']}"
                    (partial / "downloaded.txt").write_text("data", encoding="utf-8")
                elif command[0] == "tar":
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

            app.config["tasks"].append(progress_task)
            app.log("只属于这个任务", task_id=progress_task["id"])
            self.assertIn("只属于这个任务", app.read_task_log(progress_task["id"]))
            detail = app.task_detail_html(progress_task, app.sign_session("panel-user"))
            self.assertIn("活跃传输槽位", detail)
            self.assertIn("该任务的全部日志", detail)
            self.assertIn("☀", detail)

    def test_installer_does_not_overwrite_panel_port(self):
        script = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn('firewall_port=$1', script)
        self.assertNotIn('open_firewall() {\n    port=$1', script)
        self.assertIn('socket.SO_REUSEADDR', script)
        self.assertIn('verify_panel_tls()', script)
        self.assertIn('2>&1', script)
        self.assertIn('tls_attempt', script)
        self.assertIn('tar zstd', script)


if __name__ == "__main__":
    unittest.main()
