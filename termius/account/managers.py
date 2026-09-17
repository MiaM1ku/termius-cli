# -*- coding: utf-8 -*-
"""Module with Account manager."""
import uuid

from six.moves import configparser
from ..core.api import API
from ..core.device import DeviceIdentity
from ..core.exceptions import (
    ApiError, AuthyTokenIssue, NotMigratedError,
    OptionNotSetException, OtpTokenRequired,
)
from ..cloud.client.grpc_login import GrpcLoginClient


class AccountManager(object):
    """Class to keep logic for login and logout."""

    setting_names = ('synchronize_key', 'agent_forwarding')

    def __init__(self, config):
        """Create new account manager."""
        self.config = config
        self.api = API()
        self.device = DeviceIdentity(config)

    def login(self, username, password, authy_token=None):
        """Retrieve apikey and crypto settings from server."""
        device = self.device.to_json()
        payload = None
        try:
            payload = self.api.login(
                username, password, authy_token=authy_token, device=device
            )
        except (AuthyTokenIssue, OtpTokenRequired):
            raise
        except (NotMigratedError, ApiError, Exception):
            payload = None

        if payload is None:
            payload = GrpcLoginClient().login(
                username, password, device, authy_token=authy_token
            )

        credentials = payload.get('credentials') or payload
        token = credentials.get('token') or payload.get('token')
        hmac_salt = credentials.get('hmac_salt') or payload.get('hmac_salt')
        salt = credentials.get('salt') or payload.get('salt')
        if not token:
            raise OptionNotSetException('Login response did not include a token')

        self.config.set('User', 'username', username)
        self.config.set('User', 'apikey', token)
        self.config.set('User', 'token_type', 'device')
        if hmac_salt:
            self.config.set('User', 'hmac_salt', hmac_salt)
        if salt:
            self.config.set('User', 'salt', salt)

        bulk = payload.get('bulk_account') or {}
        account = bulk.get('account') or payload.get('account') or {}
        schema = (
            (account.get('feature_toggles') or {}).get('encryption_schema')
            or payload.get('encryption_schema')
            or 'v3'
        )
        self.config.set('User', 'encryption_schema', schema)
        user_id = account.get('user_id')
        if user_id:
            self.config.set('User', 'user_id', str(user_id))
        team = bulk.get('team') or payload.get('team') or {}
        if team:
            self.config.set('User', 'is_team', 'yes')
            self.config.set(
                'User', 'can_manage_team',
                'yes' if team.get('is_owner') else 'no',
            )
        pkset = credentials.get('personal_keyset') or {}
        if isinstance(pkset, dict):
            for key in (
                'public_key', 'encrypted_private_key', 'encrypted_personal_key',
            ):
                if pkset.get(key):
                    self.config.set('User', key, pkset[key])
        self.config.write()
        return payload

    def set_settings(self, dictionary):
        """Store settings."""
        filtered_settings = {
            k: (dictionary[k] and 'yes') or 'no' for k in self.setting_names
        }
        for k, i in filtered_settings.items():
            self.config.set('Settings', k, i)
        self.config.write()

    def get_settings(self):
        """Get settings or return default."""
        return {
            i: self.config.get_safe('Settings', i, default='yes') == 'yes'
            for i in self.setting_names
        }

    def logout(self):
        """Remove apikey and other credentials."""
        self.config.remove_section('User')
        self.config.remove_section('Settings')
        self.config.remove_section('CloudSynchronization')
        self.config.write()

    @property
    def analytics_id(self):
        """Get or create analytics id for device."""
        try:
            client_id = self.config.get('User', 'analytics_id')
        except (configparser.NoSectionError, configparser.NoOptionError):
            client_id = uuid.uuid4()

            self.config.set('User', 'analytics_id', client_id)
            self.config.write()

        return client_id

    @property
    def username(self):
        """Get username."""
        try:
            return self.config.get('User', 'username')
        except (configparser.NoSectionError, configparser.NoOptionError):
            raise OptionNotSetException

    @property
    def encryption_schema(self):
        """Return stored encryption schema (v3 or v5)."""
        return self.config.get_safe('User', 'encryption_schema', default='v3')
