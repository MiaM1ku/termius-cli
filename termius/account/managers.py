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
from ..cloud.client.browser_sso import BrowserSso


class AccountManager(object):
    """Class to keep logic for login and logout."""

    setting_names = ('synchronize_key', 'agent_forwarding')

    def __init__(self, config):
        """Create new account manager."""
        self.config = config
        self.api = API()
        self.device = DeviceIdentity(config)

    def login(self, username, password, authy_token=None, firebase_token=None):
        """Retrieve apikey and crypto settings from server."""
        device = self.device.to_json()
        payload = None
        login_email = '' if firebase_token else username
        try:
            if firebase_token:
                payload = GrpcLoginClient().login(
                    login_email, password, device,
                    authy_token=authy_token,
                    firebase_token=firebase_token,
                )
            else:
                payload = self.api.login(
                    username, password, authy_token=authy_token, device=device
                )
        except (AuthyTokenIssue, OtpTokenRequired):
            raise
        except (NotMigratedError, ApiError, Exception):
            payload = None

        if payload is None:
            if firebase_token:
                payload = self.api.login(
                    login_email, password, authy_token=authy_token,
                    device=device, firebase_token=firebase_token,
                )
            else:
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

    def login_with_sso(self, password, provider='google', authy_token=None,
                       callback_url=None, log=None):
        """Browser SSO, then encryption-password login."""
        identity = self.prepare_sso(
            provider=provider, callback_url=callback_url, log=log,
            open_browser=False,
        )
        return self.login(
            identity['email'], password, authy_token=authy_token,
            firebase_token=identity['firebase_token'],
        )

    def prepare_sso(self, provider='google', callback_url=None, log=None,
                    open_browser=False):
        """Run browser Google/Apple SSO and detect the Termius account."""
        sso = BrowserSso(
            provider=provider, open_browser=open_browser, log=log
        ).authenticate(
            callback_url=callback_url
        )
        detected = self.api.detect_sso_action(sso['firebase_token'])
        action = detected.get('action')
        email = detected.get('email') or sso.get('email')
        firebase_token = (
            detected.get('firebase_token') or sso['firebase_token']
        )
        if action == 'sign-up':
            raise ApiError(
                'This Google account is not a Termius account yet. '
                'Finish sign-up in the Termius app first, then retry.'
            )
        if not email:
            raise ApiError('SSO did not return an email address')
        return {'email': email, 'firebase_token': firebase_token, 'action': action}

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
