"""Paste-the-callback Google/Apple SSO for Termius Cloud.

The desktop app opens ``https://account.termius.com/sso/desktop`` and then
receives ``termius://app/continue-sso?...``. The CLI cannot own that custom
scheme on a remote box, so it prints the start URL and waits for you to paste
the callback from any browser.
"""
from __future__ import unicode_literals

import logging
import uuid
import webbrowser
from six.moves import input as wait_input
from urllib.parse import parse_qs, quote, unquote, urlparse

from ...core.constants import SSO_DESKTOP_URL
from ...core.exceptions import ApiError

LOGGER = logging.getLogger(__name__)


def parse_continue_sso_url(raw_url):
    """Extract email, firebase token and request id from a continue-sso URL."""
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
            'Not a Termius SSO callback. Paste the termius://app/continue-sso '
            'URL shown after Google sign-in.'
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


class BrowserSso(object):
    """Print a Google SSO URL and wait for the pasted continue-sso callback."""

    def __init__(self, provider='google', open_browser=False, log=None):
        self.provider = provider
        self.open_browser = open_browser
        self.log = log or LOGGER

    def authenticate(self, callback_url=None):
        """Return ``{email, firebase_token, request_id}``."""
        if callback_url:
            return parse_continue_sso_url(callback_url)

        request_id = str(uuid.uuid4())
        start_url = desktop_sso_url(self.provider, request_id)
        self.log.info(
            'Open this URL on any device (phone, laptop, another SSH session):'
        )
        self.log.info('')
        self.log.info('  %s', start_url)
        self.log.info('')
        self.log.info(
            'Sign in with Google. When the page says "Redirecting to Termius", '
            'copy the termius://app/continue-sso?... URL from the address bar '
            '(or from the "Open Termius?" prompt) and paste it below.'
        )
        if self.open_browser:
            opened = webbrowser.open(start_url, new=1, autoraise=True)
            if not opened:
                self.log.warning('Could not open a local browser; use the URL above.')

        captured = wait_input('Paste callback URL: ').strip()
        if not captured:
            raise ApiError('Google sign-in cancelled (empty callback URL)')

        result = parse_continue_sso_url(captured)
        if result['request_id'] != request_id:
            raise ApiError(
                'SSO request id did not match. Open the URL printed above, '
                'not an old callback.'
            )
        return result
