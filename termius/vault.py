# -*- coding: utf-8 -*-
"""Resolve and remember the Termius vault encryption password."""
import os
import stat

VAULT_ENV = 'TERMIUS_VAULT_PASSWORD'
VAULT_FILENAME = 'vault'


class VaultPasswordRequired(Exception):
    """No vault password in the environment or the remember file."""


def vault_path(runtime):
    """Return ``~/.termius/vault`` (or the runtime directory)."""
    return runtime.directory_path / VAULT_FILENAME


def resolve(runtime):
    """Return the vault password or None.

    Order: ``TERMIUS_VAULT_PASSWORD``, then the remember file.
    """
    env = os.environ.get(VAULT_ENV)
    if env:
        return env
    path = vault_path(runtime)
    if path.is_file():
        text = path.read_text()
        if text.endswith('\n'):
            text = text[:-1]
        return text or None
    return None


def require(runtime):
    """Return the vault password or raise VaultPasswordRequired."""
    password = resolve(runtime)
    if not password:
        raise VaultPasswordRequired(
            'Vault password is not available. Call login or sync with '
            'remember=true, or set {}'.format(VAULT_ENV)
        )
    return password


def remember(runtime, password):
    """Write the password to the remember file with mode 0600."""
    if not password:
        raise VaultPasswordRequired('Cannot remember an empty vault password')
    path = vault_path(runtime)
    path.write_text(password)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def forget(runtime):
    """Delete the remember file if it exists."""
    path = vault_path(runtime)
    if path.is_file():
        path.unlink()


def is_available(runtime):
    """True when env or the remember file can supply a password."""
    return resolve(runtime) is not None
