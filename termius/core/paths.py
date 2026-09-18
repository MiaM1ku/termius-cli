# -*- coding: utf-8 -*-
"""Resolve the application directory from a Runtime or test double."""
from pathlib2 import Path


def directory_of(owner):
    """Return ``directory_path`` from ``owner`` or ``owner.app``."""
    path = getattr(owner, 'directory_path', None)
    if _usable_path(path):
        return path
    return owner.app.directory_path


def _usable_path(path):
    if path is None:
        return False
    if isinstance(path, (str, bytes, Path)):
        return True
    return False
