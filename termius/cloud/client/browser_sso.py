"""Google SSO using Termius desktop continue-sso.

Builds ``https://account.termius.com/sso/desktop`` and accepts a pasted
``termius://app/continue-sso?...`` callback. Does not open a browser.
"""
from __future__ import unicode_literals

import logging
import uuid
from six.moves import input as wait_input
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

from ...core.constants import (
    FIREBASE_API_KEY,
    FIREBASE_AUTH_REFERER,
    FIREBASE_SIGN_IN_WITH_IDP,
    SSO_DESKTOP_URL,
)
from ...core.exceptions import ApiError

LOGGER = logging.getLogger(__name__)


def parse_continue_sso_url(raw_url):
    """Extract email / firebase token from a desktop continue-sso URL."""
    if not raw_url:
        raise ApiError('Empty SSO callback URL')
    raw_url = raw_url.strip().strip('"').strip("'")
    if raw_url.startswith('continue-sso?') or raw_url.startswith('app/continue-sso?'):
        raw_url = 'termius://' + raw_url.lstrip('/')
    if raw_url.startswith('email=') or raw_url.startswith('firebaseToken='):
        raw_url = 'termius://app/continue-sso?' + raw_url

    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)
    if not query and parsed.fragment:
        query = parse_qs(parsed.fragment)
    nested = query.get('url') or query.get('u')
    if nested:
        return parse_continue_sso_url(unquote(nested[0]))

    path = (parsed.path or '').rstrip('/')
    host = parsed.netloc or ''
    is_continue = (
        path.endswith('continue-sso')
        or host in ('continue-sso', 'app')
        or path.endswith('continue-enterprise-sso')
        or 'firebaseToken' in query
        or 'firebase_token' in query
    )
    if not is_continue:
        raise ApiError(
            'Not a Termius SSO callback. Paste termius://app/continue-sso?...'
        )

    email = _first(query, 'email')
    token = _first(query, 'firebaseToken', 'firebase_token', 'accessToken')
    request_id = _first(query, 'requestId', 'request_id', 'request')
    if not token or not request_id:
        raise ApiError('SSO callback is missing firebaseToken or requestId')
    return {
        'email': email or '',
        'firebase_token': token,
        'request_id': request_id,
        'raw_url': raw_url,
    }


def parse_google_callback(raw_url):
    """Read a Google id_token from a localhost redirect URL or fragment."""
    if not raw_url:
        return None
    raw_url = raw_url.strip().strip('"').strip("'")
    parsed = urlparse(raw_url)
    params = parse_qs(parsed.fragment)
    if not params:
        params = parse_qs(parsed.query)
    token = _first(params, 'id_token')
    error = _first(params, 'error', 'error_description')
    if error and not token:
        raise ApiError('Google sign-in failed: {}'.format(error))
    if not token:
        return None
    return {'id_token': token, 'raw_url': raw_url}


def _first(query, *keys):
    for key in keys:
        values = query.get(key)
        if values:
            return values[0]
    return None


def desktop_sso_url(provider, request_id):
    """Build the account.termius.com desktop SSO start URL."""
    return '{}?provider={}&request={}'.format(
        SSO_DESKTOP_URL, quote(provider, safe=''), quote(request_id, safe='')
    )


def exchange_google_id_token(id_token, request_uri, session_id=None):
    """Turn a Google id_token into a Firebase idToken + email."""
    body = {
        'postBody': 'id_token={}&providerId=google.com'.format(id_token),
        'requestUri': request_uri,
        'returnIdpCredential': True,
        'returnSecureToken': True,
    }
    if session_id:
        body['sessionId'] = session_id
    response = requests.post(
        FIREBASE_SIGN_IN_WITH_IDP,
        params={'key': FIREBASE_API_KEY},
        headers={
            'Content-Type': 'application/json',
            'Referer': FIREBASE_AUTH_REFERER,
            'Origin': 'https://account.termius.com',
        },
        json=body,
        timeout=30,
    )
    payload = response.json()
    if response.status_code >= 400:
        raise ApiError(
            payload.get('error', {}).get('message') or response.text,
            status=response.status_code,
        )
    firebase_token = payload.get('idToken')
    email = payload.get('email') or ''
    if not firebase_token:
        raise ApiError('Firebase did not return an idToken')
    return {'email': email, 'firebase_token': firebase_token}


class BrowserSso(object):
    """Print the desktop SSO URL and wait for a pasted continue-sso callback."""

    def __init__(self, provider='google', open_browser=False, timeout=300,
                 log=None):
        self.provider = provider
        self.open_browser = open_browser
        self.timeout = timeout
        self.log = log or LOGGER

    def authenticate(self, callback_url=None):
        """Return ``{email, firebase_token}``."""
        if callback_url:
            return self._from_pasted(callback_url)

        request_id = str(uuid.uuid4())
        start_url = desktop_sso_url(self.provider, request_id)
        self.log.info('Open this URL in any browser (do not use w3m):')
        self.log.info('')
        self.log.info('  %s', start_url)
        self.log.info('')
        self.log.info(
            'Sign in with Google. When the page tries to open Termius, copy '
            'termius://app/continue-sso?... from the address bar or from the '
            '"Open Termius?" prompt, then paste it below.'
        )
        captured = wait_input('Paste callback URL: ').strip()
        if not captured:
            raise ApiError('Google sign-in cancelled (empty callback URL)')
        result = self._from_pasted(captured)
        if result.get('request_id') and result['request_id'] != request_id:
            raise ApiError(
                'SSO request id did not match. Open the URL printed above.'
            )
        return result

    def _from_pasted(self, callback_url):
        google = parse_google_callback(callback_url)
        if google:
            parsed = urlparse(callback_url.strip())
            request_uri = '{}://{}{}'.format(
                parsed.scheme or 'http',
                parsed.netloc or '127.0.0.1',
                parsed.path or '/callback',
            )
            return exchange_google_id_token(google['id_token'], request_uri)
        return parse_continue_sso_url(callback_url)
