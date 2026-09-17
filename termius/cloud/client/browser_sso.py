"""Google SSO via Firebase + a local HTTP callback.

Termius desktop uses ``termius://``, which browsers hide. Firebase allows
``localhost``, so the CLI starts ``http://127.0.0.1:<port>/callback`` and lets
Google redirect there with ``#id_token=``. The page posts the token back; if
the browser is on another machine, paste that visible http URL instead.
"""
from __future__ import unicode_literals

import json
import logging
import select
import sys
import threading
import time
import webbrowser
from six.moves import input as wait_input
from urllib.parse import parse_qs, unquote, urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

from ...core.constants import (
    FIREBASE_API_KEY,
    FIREBASE_AUTH_REFERER,
    FIREBASE_CREATE_AUTH_URI,
    FIREBASE_SIGN_IN_WITH_IDP,
)
from ...core.exceptions import ApiError

LOGGER = logging.getLogger(__name__)

CALLBACK_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>Termius CLI</title>
<p id="m">Finishing Google sign-in&hellip;</p>
<script>
const params = new URLSearchParams(location.hash.slice(1) || location.search.slice(1));
const body = {
  id_token: params.get("id_token"),
  error: params.get("error") || params.get("error_description"),
  raw: location.href
};
fetch("/finish", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify(body)
}).then(() => {
  document.getElementById("m").textContent = "Signed in. You can close this tab.";
}).catch(() => {
  document.getElementById("m").textContent =
    "Could not reach the CLI. Copy the address bar (including #id_token=) and paste it in the terminal.";
});
</script>
"""


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
            'Not a Termius SSO callback. Paste the http://127.0.0.1 callback '
            'or the termius://app/continue-sso URL.'
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


def _firebase_headers():
    return {
        'Content-Type': 'application/json',
        'Referer': FIREBASE_AUTH_REFERER,
        'Origin': 'https://account.termius.com',
    }


def create_google_auth_uri(continue_uri):
    """Ask Firebase for a Google OAuth URL bound to ``continue_uri``."""
    response = requests.post(
        FIREBASE_CREATE_AUTH_URI,
        params={'key': FIREBASE_API_KEY},
        headers=_firebase_headers(),
        json={'providerId': 'google.com', 'continueUri': continue_uri},
        timeout=30,
    )
    payload = response.json()
    if response.status_code >= 400:
        raise ApiError(
            payload.get('error', {}).get('message') or response.text,
            status=response.status_code,
        )
    auth_uri = payload.get('authUri')
    session_id = payload.get('sessionId')
    if not auth_uri or not session_id:
        raise ApiError('Firebase did not return a Google auth URL')
    return auth_uri, session_id


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
        headers=_firebase_headers(),
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


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path not in ('/', '/callback'):
            self.send_error(404)
            return
        google = parse_google_callback('http://127.0.0.1' + self.path)
        body = CALLBACK_PAGE.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if google and google.get('id_token'):
            self.server.result = google
            self.server.event.set()

    def do_POST(self):  # noqa: N802
        if urlparse(self.path).path != '/finish':
            self.send_error(404)
            return
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length).decode('utf-8') if length else '{}'
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        body = b'ok'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if payload.get('error') and not payload.get('id_token'):
            self.server.error = payload.get('error')
            self.server.event.set()
            return
        if payload.get('id_token'):
            self.server.result = {
                'id_token': payload['id_token'],
                'raw_url': payload.get('raw') or '',
            }
            self.server.event.set()

    def log_message(self, format, *args):  # noqa: A003
        LOGGER.debug(format, *args)


class LocalCallbackServer(object):
    """Serve the Google redirect target on 127.0.0.1."""

    def __init__(self):
        self.server = HTTPServer(('127.0.0.1', 0), _CallbackHandler)
        self.server.event = threading.Event()
        self.server.result = None
        self.server.error = None
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True

    @property
    def callback_url(self):
        return 'http://127.0.0.1:{}/callback'.format(
            self.server.server_address[1]
        )

    def start(self):
        self.thread.start()

    def wait(self, timeout):
        deadline = time.time() + timeout
        stdin = getattr(sys.stdin, 'fileno', lambda: None)()
        can_select = stdin is not None and sys.stdin.isatty()
        while time.time() < deadline:
            if self.server.event.is_set():
                if self.server.error:
                    raise ApiError(
                        'Google sign-in failed: {}'.format(self.server.error)
                    )
                return self.server.result
            wait = min(0.4, deadline - time.time())
            if can_select:
                ready, _, _ = select.select([sys.stdin], [], [], wait)
                if ready:
                    line = sys.stdin.readline().strip()
                    if line:
                        return _parse_pasted_callback(line)
            else:
                self.server.event.wait(wait)
        return None

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=2)


def _parse_pasted_callback(raw):
    google = parse_google_callback(raw)
    if google:
        return google
    parsed = parse_continue_sso_url(raw)
    parsed['from_continue_sso'] = True
    return parsed


class BrowserSso(object):
    """Run Google SSO and return a Firebase token for Termius login."""

    def __init__(self, provider='google', open_browser=True, timeout=300,
                 log=None):
        self.provider = provider
        self.open_browser = open_browser
        self.timeout = timeout
        self.log = log or LOGGER

    def authenticate(self, callback_url=None):
        """Return ``{email, firebase_token}``."""
        if self.provider != 'google':
            raise ApiError('Only Google SSO is supported')
        if callback_url:
            return self._from_pasted(callback_url)

        server = LocalCallbackServer()
        server.start()
        try:
            continue_uri = server.callback_url
            auth_uri, session_id = create_google_auth_uri(continue_uri)
            self.log.info('Open this Google sign-in URL:')
            self.log.info('')
            self.log.info('  %s', auth_uri)
            self.log.info('')
            self.log.info(
                'After Google, the browser should land on %s and this '
                'command continues by itself.',
                continue_uri,
            )
            self.log.info(
                'If you are not on this machine, copy the address bar '
                '(it will contain #id_token=) and paste it here.'
            )
            if self.open_browser:
                opened = webbrowser.open(auth_uri, new=1, autoraise=True)
                if not opened:
                    self.log.warning('Could not open a local browser.')
            captured = server.wait(self.timeout)
        finally:
            server.close()

        if not captured:
            pasted = wait_input(
                'Paste the http://127.0.0.1 callback URL: '
            ).strip()
            if not pasted:
                raise ApiError('Google sign-in timed out or was cancelled')
            captured = _parse_pasted_callback(pasted)

        if captured.get('from_continue_sso') or captured.get('firebase_token'):
            return {
                'email': captured.get('email') or '',
                'firebase_token': captured['firebase_token'],
                'request_id': captured.get('request_id'),
            }
        return exchange_google_id_token(
            captured['id_token'], continue_uri, session_id
        )

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
