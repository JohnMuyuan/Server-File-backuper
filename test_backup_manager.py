import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backup_manager import BackupApp, DEFAULTS, human_size, initialize, password_fields, validate_config


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
            self.assertEqual(BackupApp.lftp_quote('/data/a b'), '"/data/a b"')
            with mock.patch("backup_manager.subprocess.Popen", side_effect=FileNotFoundError) as popen:
                self.assertFalse(app.run_transfer()[0])
                command = popen.call_args.args[0]
                self.assertEqual(command[:3], ["lftp", "--norc", "-c"])
                self.assertIn("--parallel=2 --use-pget-n=2", command[3])
            app.config["transfer_threads"] = 1
            with mock.patch("backup_manager.subprocess.Popen", side_effect=FileNotFoundError) as popen:
                self.assertFalse(app.run_transfer()[0])
                self.assertEqual(popen.call_args.args[0][0], "rsync")
            with self.assertRaises(ValueError):
                invalid = config.copy()
                invalid["remote_host"] = "bad host;rm"
                validate_config(invalid)
            with self.assertRaises(ValueError):
                invalid = config.copy()
                invalid["backup_dir"] = "/"
                validate_config(invalid)
            with self.assertRaises(ValueError):
                invalid = config.copy()
                invalid["transfer_threads"] = 17
                validate_config(invalid)
            with self.assertRaises(ValueError):
                invalid = config.copy()
                invalid["admin_username"] = "bad user"
                validate_config(invalid)
            init_data = Path(temp) / "init"
            with mock.patch.dict(DEFAULTS, {"backup_dir": str(backups), "ssh_key": ""}), mock.patch("builtins.print"):
                initialize(init_data, "panel-user", "a-secure-password", "0.0.0.0", 9443,
                           str(init_data / "server.crt"), str(init_data / "server.key"))
            initialized = json.loads((init_data / "config.json").read_text(encoding="utf-8"))
            self.assertEqual((initialized["admin_username"], initialized["listen_port"]), ("panel-user", 9443))


if __name__ == "__main__":
    unittest.main()
