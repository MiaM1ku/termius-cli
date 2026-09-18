# -*- coding: utf-8 -*-
"""Process-wide Termius paths, config, and local storage."""
from os.path import expanduser

from pathlib2 import Path

from .core.settings import Config
from .core.signals import (
    post_create_instance,
    post_delete_instance,
    post_logout,
    post_update_instance,
)
from .core.storage import ApplicationStorage
from .core.storage.strategies import RelatedGetStrategy, SyncSaveStrategy
from .core.subscribers import clean_data, delete_ssh_key, store_ssh_key
from .core.models.terminal import SshKey


class Runtime(object):
    """Application context used by MCP tools. Not a CLI app."""

    def __init__(self, directory_path=None):
        if directory_path is None:
            directory_path = expanduser('~/.termius/')
        self.directory_path = Path(directory_path)
        if not self.directory_path.is_dir():
            self.directory_path.mkdir(parents=True)
        self.configure_signals()
        self.config = Config(self)
        self.storage = ApplicationStorage(
            self,
            get_strategy=RelatedGetStrategy,
            save_strategy=SyncSaveStrategy,
        )

    def configure_signals(self):
        """Bind SSH key file I/O and logout cleanup."""
        post_create_instance.connect(store_ssh_key, sender=SshKey)
        post_update_instance.connect(store_ssh_key, sender=SshKey)
        post_delete_instance.connect(delete_ssh_key, sender=SshKey)
        post_logout.connect(clean_data)

    def reload_storage(self):
        """Re-open storage after another writer flushed the JSON file."""
        self.storage = ApplicationStorage(
            self,
            get_strategy=RelatedGetStrategy,
            save_strategy=SyncSaveStrategy,
        )
