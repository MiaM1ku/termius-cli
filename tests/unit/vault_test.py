# -*- coding: utf-8 -*-
import os
import stat
import tempfile
import unittest

from termius.runtime import Runtime
from termius import vault


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.runtime = Runtime(directory_path=self.tmpdir.name)
        self._env = os.environ.pop(vault.VAULT_ENV, None)

    def tearDown(self):
        if self._env is None:
            os.environ.pop(vault.VAULT_ENV, None)
        else:
            os.environ[vault.VAULT_ENV] = self._env
        self.tmpdir.cleanup()

    def test_remember_writes_0600(self):
        vault.remember(self.runtime, 'secret')
        path = vault.vault_path(self.runtime)
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text(), 'secret')
        mode = stat.S_IMODE(os.stat(str(path)).st_mode)
        self.assertEqual(mode, 0o600)

    def test_env_wins_over_file(self):
        vault.remember(self.runtime, 'file-pass')
        os.environ[vault.VAULT_ENV] = 'env-pass'
        self.assertEqual(vault.resolve(self.runtime), 'env-pass')

    def test_forget_removes_file(self):
        vault.remember(self.runtime, 'secret')
        vault.forget(self.runtime)
        self.assertFalse(vault.vault_path(self.runtime).is_file())
        self.assertIsNone(vault.resolve(self.runtime))

    def test_require_raises_when_missing(self):
        with self.assertRaises(vault.VaultPasswordRequired):
            vault.require(self.runtime)
