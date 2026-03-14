from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


class MintPackagingTests(unittest.TestCase):
    def test_systemd_units_reference_env_file(self) -> None:
        root = Path(__file__).parent / "systemd"
        server_unit = (root / "selfcoin-mint-server.service").read_text(encoding="utf-8")
        worker_unit = (root / "selfcoin-mint-worker.service").read_text(encoding="utf-8")
        self.assertIn("EnvironmentFile=-/etc/selfcoin-mint/selfcoin-mint.env", server_unit)
        self.assertIn("EnvironmentFile=-/etc/selfcoin-mint/selfcoin-mint.env", worker_unit)
        self.assertIn("--mode server", server_unit)
        self.assertIn("--mode worker", worker_unit)

    def test_install_script_installs_helper_and_tmpfiles(self) -> None:
        root = Path(__file__).parent / "systemd"
        install_script = (root / "install_selfcoin_mint.sh").read_text(encoding="utf-8")
        self.assertIn("selfcoin-mint-secret-helper", install_script)
        self.assertIn("selfcoin-mint.tmpfiles.conf", install_script)
        self.assertIn("selfcoin-mint.env", install_script)

    def test_env_template_exposes_secret_helper(self) -> None:
        root = Path(__file__).parent / "systemd"
        env_text = (root / "selfcoin-mint.env.example").read_text(encoding="utf-8")
        self.assertIn("SELFCOIN_MINT_NOTIFIER_SECRET_HELPER_CMD=/usr/local/libexec/selfcoin-mint-secret-helper", env_text)
        self.assertIn("SELFCOIN_MINT_WORKER_LOCK_FILE=", env_text)

    def test_install_script_smoke_to_temp_prefix(self) -> None:
        root = Path(__file__).parent / "systemd"
        script = root / "install_selfcoin_mint.sh"
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as td:
            systemd_dir = Path(td) / "systemd"
            etc_dir = Path(td) / "etc" / "selfcoin-mint"
            libexec_dir = Path(td) / "libexec"
            state_dir = Path(td) / "var" / "lib" / "selfcoin-mint"
            run_dir = Path(td) / "run" / "selfcoin-mint"
            proc = subprocess.run(
                ["bash", str(script), "/opt/selfcoin-core", str(systemd_dir), str(etc_dir), str(libexec_dir), str(state_dir), str(run_dir)],
                cwd=repo_root,
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertIn("Installed unit files into", proc.stdout)
            self.assertTrue((systemd_dir / "selfcoin-mint-server.service").exists())
            self.assertTrue((systemd_dir / "selfcoin-mint-worker.service").exists())
            self.assertTrue((etc_dir / "selfcoin-mint.env").exists())
            self.assertTrue((etc_dir / "selfcoin-mint.tmpfiles.conf").exists())
            self.assertTrue((libexec_dir / "selfcoin-mint-secret-helper").exists())
            self.assertTrue(state_dir.exists())
            self.assertTrue(run_dir.exists())


if __name__ == "__main__":
    unittest.main()
