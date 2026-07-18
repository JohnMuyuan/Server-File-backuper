import tempfile
import unittest
from pathlib import Path

from backup_manager import BackupApp, DEFAULTS, human_size, password_fields, validate_config


class BackupManagerTest(unittest.TestCase):
    def test_validation_and_retention(self):
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp) / "data"
            backups = Path(temp) / "backups"
            config = DEFAULTS.copy()
            config.update(password_fields("long-enough-password"))
            config.update({
                "remote_host": "server.example.com", "remote_path": "/data",
                "backup_dir": str(backups), "ssh_key": "", "retention_limit": 2,
            })
            validate_config(config)
            data.mkdir()
            (data / "config.json").write_text(__import__("json").dumps(config), encoding="utf-8")
            for name in ("20260101-010101_host", "20260102-010101_host"):
                (backups / name).mkdir(parents=True)
            (backups / "unrelated-user-data").mkdir()
            app = BackupApp(data)
            app.notify = lambda _: None
            app.apply_retention()
            self.assertEqual([p.name for p in app.backups()], ["20260102-010101_host"])
            self.assertTrue((backups / "unrelated-user-data").is_dir())
            self.assertEqual(human_size(3 * 1024 ** 3), "3.0 GB")
            with self.assertRaises(ValueError):
                invalid = config.copy()
                invalid["remote_host"] = "bad host;rm"
                validate_config(invalid)
            with self.assertRaises(ValueError):
                invalid = config.copy()
                invalid["backup_dir"] = "/"
                validate_config(invalid)


if __name__ == "__main__":
    unittest.main()
