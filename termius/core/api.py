# -*- coding: utf-8 -*-
"""Termius Cloud HTTP client aligned with desktop 10.0.6."""
from __future__ import unicode_literals

import hashlib
import logging

import requests
from requests.auth import AuthBase
import six

from .constants import (
    API_BASE_URL, APP_VERSION, DEVICE_PLATFORM,
)
from .exceptions import (
    ApiError, AuthyTokenIssue, NotMigratedError, OtpTokenRequired,
    OutdatedVersion,
)


class TermiusAuth(AuthBase):
    """Authorization header for Termius Cloud."""

    header_name = 'Authorization'

    def __init__(self, token, token_type='device'):
        self.token = token
        self.token_type = token_type or 'device'

    @property
    def auth_header(self):
        prefix = {
            'device': 'DeviceToken',
            'temp': 'TempToken',
            'token': 'Token',
            'apikey': 'ApiKey',
        }.get(self.token_type, 'DeviceToken')
        return '{} {}'.format(prefix, self.token)

    def __call__(self, request):
        request.headers[self.header_name] = self.auth_header
        return request


def hash_password(password):
    """SHA-256 hex digest used by REST login."""
    password = six.b(password)
    return hashlib.sha256(password).hexdigest()


class API(object):
    """HTTPS client for api.termius.com."""

    host = 'api.termius.com'
    base_url = API_BASE_URL
    logger = logging.getLogger(__name__)
    timeout = 180

    def __init__(self, username=None, apikey=None, token_type='device'):
        self.username = username
        if username and apikey:
            # Legacy ApiKey username:token still accepted as fallback.
            if ':' not in str(apikey) and token_type == 'apikey':
                self.auth = TermiusAuth(
                    '{}:{}'.format(username, apikey), token_type='apikey'
                )
            else:
                self.auth = TermiusAuth(apikey, token_type=token_type)
        else:
            self.auth = None

    def set_auth(self, username, apikey, token_type='device'):
        """Store credentials for subsequent calls."""
        self.username = username
        self.auth = TermiusAuth(apikey, token_type=token_type)

    def request_url(self, endpoint):
        """Create full url to endpoint."""
        endpoint = endpoint.lstrip('/')
        if not endpoint.startswith('api/'):
            endpoint = 'api/' + endpoint
        return self.base_url + endpoint

    def _headers(self):
        return {
            'Content-Type': 'application/json; charset=utf-8',
            'X-DEVICE-APP-VERSION': APP_VERSION,
            'X-DEVICE-PLATFORM': DEVICE_PLATFORM,
        }

    def login(self, email, password, authy_token=None, device=None,
              firebase_token=None):
        """Sign in via REST ``/api/v3.3/auth/device/login/``.

        Falls back to the legacy hashed-password form when the desktop-shaped
        payload is rejected. gRPC/SRP login is attempted first by AccountManager.
        """
        payload = {
            'email': '' if firebase_token else email,
            'password': hash_password(password),
        }
        if authy_token is not None:
            payload['authy_token'] = authy_token
        if device is not None:
            payload['device'] = device
        if firebase_token is not None:
            payload['firebase_token'] = firebase_token

        response = requests.post(
            self.request_url('v3.3/auth/device/login/'),
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if response.status_code >= 400 and not firebase_token:
            # Older accounts still accept the v3.1 form.
            legacy = dict(password=hash_password(password), email=email)
            if authy_token is not None:
                legacy['authy_token'] = authy_token
            legacy_response = requests.post(
                self.request_url('v3.1/login/'),
                data=legacy,
                headers=self._headers(),
                timeout=self.timeout,
            )
            if legacy_response.status_code < 400:
                response = legacy_response

        self.__check_login_response(response)
        response_payload = response.json()
        token = self._extract_token(response_payload)
        self.set_auth(email, token, token_type='device')
        return response_payload

    def detect_sso_action(self, firebase_token, apple_id_token=None):
        """POST ``/api/v4.1/auth/sso/firebase/detect_action/``."""
        payload = {'firebase_token': firebase_token}
        if apple_id_token:
            payload['apple_id_token'] = apple_id_token
        response = requests.post(
            self.request_url('v4.1/auth/sso/firebase/detect_action/'),
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if not (200 <= response.status_code < 300):
            raise ApiError(
                'detect_action HTTP {}: {}'.format(
                    response.status_code, (response.text or '')[:300]
                ),
                status=response.status_code,
            )
        data = response.json()
        if not isinstance(data, dict):
            raise ApiError('detect_action returned a non-object')
        return data

    @staticmethod
    def _extract_token(payload):
        if not isinstance(payload, dict):
            return None
        if payload.get('token'):
            return payload['token']
        credentials = payload.get('credentials') or {}
        return credentials.get('token')

    def __check_login_response(self, response):
        if response.status_code == 487:
            raise AuthyTokenIssue(response.json() if response.content else {})
        if response.status_code in (401, 403):
            body = {}
            try:
                body = response.json()
            except ValueError:
                pass
            code = (body or {}).get('code')
            if code == 7:
                raise NotMigratedError(response.text)
            if code in (3, 10):
                raise OtpTokenRequired(response.text)
        if response.status_code != 200:
            body = response.text if isinstance(response.text, str) else ''
            self.logger.warning(
                'REST login failed status=%s body=%s',
                response.status_code,
                body[:200],
            )
        self.__check_response(response, (200,))

    def __check_response(self, response, success_statuses=None):
        if response.status_code == 490:
            raise OutdatedVersion(
                'The current version of termius is incompatible '
                'with the Termius Cloud. Please upgrade.'
            )
        success_statuses = success_statuses or (200, 201, 202, 204)
        if response.status_code not in success_statuses:
            raise ApiError(
                response.text or response.reason,
                status=response.status_code,
            )
        return response

    def post(self, endpoint, data):
        """Send authorized post request."""
        self.logger.debug('send post %s', endpoint)
        response = requests.post(
            self.request_url(endpoint),
            json=data, auth=self.auth,
            headers=self._headers(),
            timeout=self.timeout,
        )
        self.logger.debug('get response = %s', response.status_code)
        self.__check_response(response, (200, 201, 202))
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()

    def get(self, endpoint, params=None):
        """Send authorized get request."""
        response = requests.get(
            self.request_url(endpoint),
            auth=self.auth,
            headers=self._headers(),
            params=params,
            timeout=self.timeout,
        )
        self.__check_response(response, (200,))
        return response.json()

    def delete(self, endpoint):
        """Send authorized delete request."""
        response = requests.delete(
            self.request_url(endpoint),
            auth=self.auth,
            headers=self._headers(),
            timeout=self.timeout,
        )
        self.__check_response(response, (200, 204))
        if not response.content:
            return {}
        return response.json()

    def put(self, endpoint, data):
        """Send authorized put request."""
        response = requests.put(
            self.request_url(endpoint),
            json=data, auth=self.auth,
            headers=self._headers(),
            timeout=self.timeout,
        )
        self.__check_response(response, (200, 202))
        return response.json()

    def patch(self, endpoint, data):
        """Send authorized patch request."""
        response = requests.patch(
            self.request_url(endpoint),
            json=data, auth=self.auth,
            headers=self._headers(),
            timeout=self.timeout,
        )
        self.__check_response(response, (200, 202))
        return response.json()
