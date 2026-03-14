from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
