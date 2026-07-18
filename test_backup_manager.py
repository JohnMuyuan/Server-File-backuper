import json
import tempfile
import unittest
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

            lftp = app.transfer_command(task, root / "partial")
            self.assertEqual(lftp[0], "lftp")
            self.assertIn("--parallel=2 --use-pget-n=2", lftp[2])
            rsync = app.transfer_command({**task, "transfer_threads": 1}, root / "partial")
            self.assertEqual(rsync[0], "rsync")
            self.assertIn("--append-verify", rsync)
            password_task = {**task, "auth_method": "password"}
            app.set_task_password(task["id"], "remote secret")
            self.assertIn("sshpass -e ssh", app.transfer_command(password_task, root / "partial")[2])
            self.assertEqual(human_size(3 * 1024 ** 3), "3.0 GB")

    def test_validation_migration_credentials_and_sessions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for change in (
                {"remote_host": "bad host;rm"}, {"backup_dir": "/"},
                {"transfer_threads": 17}, {"remote_path": "relative"},
            ):
                with self.assertRaises(ValueError):
                    sample_task(root / "backup", **change)

            old = {
                "remote_host": "old.example.com", "remote_path": "/old",
                "backup_dir": str(root / "old-backups"), "ssh_key": "",
            }
            migrated = migrate_config(old)
            self.assertEqual(len(migrated["tasks"]), 1)
            self.assertEqual(migrated["tasks"][0]["remote_host"], "old.example.com")

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

            for _ in range(5):
                app.login_failed("192.0.2.1")
            self.assertFalse(app.login_allowed("192.0.2.1"))

    def test_installer_does_not_overwrite_panel_port(self):
        script = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn('firewall_port=$1', script)
        self.assertNotIn('open_firewall() {\n    port=$1', script)


if __name__ == "__main__":
    unittest.main()
