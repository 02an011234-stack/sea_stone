from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from os_guard_agent.models import OperatingCredential
from os_guard_agent.token_store import TokenStore, TokenStoreError


class TokenStoreTests(unittest.TestCase):
    def test_save_and_load_operating_credential(self) -> None:
        credential = OperatingCredential(
            server_id="srv-1",
            agent_id="agt-1",
            credential_id="cred-1",
            token="operating-secret",
            expires_at="2026-10-01T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "private" / "credentials.json"
            store = TokenStore(path)
            store.save(credential)
            loaded = store.load()

            self.assertEqual(loaded, credential)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_clear_allows_reenrollment(self) -> None:
        credential = OperatingCredential("srv", "agt", "cred", "token", "expiry")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "credentials.json"
            store = TokenStore(path)
            store.save(credential)
            store.clear()
            self.assertFalse(path.exists())

    def test_parent_symlink_is_rejected(self) -> None:
        credential = OperatingCredential("srv", "agt", "cred", "token", "expiry")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            try:
                linked.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(TokenStoreError):
                TokenStore(linked / "credentials.json").save(credential)


if __name__ == "__main__":
    unittest.main()
