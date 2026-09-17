"""Persistent device identity used by Termius Cloud login."""
import socket
import uuid

from .constants import APP_VERSION


class DeviceIdentity(object):
    """Desktop device payload matching Termius 10.x login."""

    def __init__(self, config):
        self.config = config

    @property
    def token(self):
        """Stable per-install device token."""
        token = self.config.get_safe('Device', 'token')
        if token:
            return token
        token = str(uuid.uuid4())
        self.config.set('Device', 'token', token)
        self.config.write()
        return token

    def to_json(self):
        """Serialize device object for login requests."""
        return {
            'token': self.token,
            'app_version': APP_VERSION,
            'os_version': '{} {}'.format(socket.gethostname(), 'linux'),
            'name': socket.gethostname(),
            'sub_name': '',
            'mobile_type': 'Desktop',
        }
