"""Termius gRPC-over-Socket.IO login (encryption schema v5 / SRP)."""
from __future__ import unicode_literals

import base64
import logging
import re

from ...core.constants import (
    API_HOST, GRPC_MOBILE_TYPE_DESKTOP, LOGIN_NAMESPACE, SOCKETIO_GRPC_PATH,
)
from ...core.exceptions import ApiError, NotMigratedError, OtpTokenRequired
from .sodium import SodiumSecretCryptor
from .srp_session import ClientSession, botan_bigint_to_wire

LOGGER = logging.getLogger(__name__)

UNAUTHENTICATED = 2
OTP_TOKEN_REQUIRED = 3
THROTTLED = 4
APP_OUTDATED = 6
NOT_MIGRATED = 7
INVALID_PROOF = 8
INVALID_PUBLIC_DATA = 9
OTP_TOKEN_ERROR = 10
LOGIN_APPROVE_REQUIRED = 12


def omit_none(value):
    """Drop ``None`` entries so JSON matches JS ``JSON.stringify``."""
    if isinstance(value, dict):
        return {
            key: omit_none(item)
            for key, item in value.items()
            if item is not None
        }
    return value


def _public_kind(value):
    """Classify the server public B encoding without logging secrets."""
    if value is None:
        return ''
    if isinstance(value, (bytes, bytearray)):
        return 'bytes:{}'.format(len(value))
    if isinstance(value, dict):
        return 'object'
    text = str(value).strip()
    if text.startswith('0x') or text.startswith('0X'):
        return '0x-hex'
    hexchars = set('0123456789abcdefABCDEF')
    if text and all(c in hexchars for c in text) and len(text) >= 8:
        return 'hex'
    return 'other'


def grpc_device(device):
    """Desktop gRPC device: ``mobile_type`` is enum 3, not ``"Desktop"``."""
    payload = dict(device or {})
    payload['sub_name'] = payload.get('sub_name') or ''
    payload['mobile_type'] = GRPC_MOBILE_TYPE_DESKTOP
    return omit_none(payload)


def build_initial_request(email, device, authy_token=None,
                          firebase_token=None, domain_sso_token=None):
    """Build ``initialRequest`` matching Termius desktop 10.x."""
    return omit_none({
        'email': email or '',
        'device': grpc_device(device),
        'otp_token': authy_token,
        'firebase_token': firebase_token,
        'domain_sso_token': domain_sso_token,
    })


def _b64(data):
    if data is None:
        return None
    if isinstance(data, str):
        return data
    return base64.b64encode(data).decode('ascii')


def _unb64(data):
    if data is None:
        return None
    if isinstance(data, bytes):
        return data
    return base64.b64decode(data)


def bytes_field(value):
    """Accept base64, raw bytes, or Node ``{type: Buffer, data: [...]}``."""
    if value is None:
        return None
    if isinstance(value, dict) and value.get('type') == 'Buffer':
        return bytes(value.get('data') or [])
    if isinstance(value, list):
        return bytes(value)
    return _unb64(value)


def _first(payload, *keys):
    for key in keys:
        if payload.get(key) not in (None, ''):
            return payload.get(key)
    return None


_CAMEL_1 = re.compile(r'(.)([A-Z][a-z]+)')
_CAMEL_2 = re.compile(r'([a-z0-9])([A-Z])')


def to_snake_case(name):
    """lodash ``snakeCase`` used by desktop on gRPC JSON keys."""
    if not isinstance(name, str) or not name:
        return name
    if name.endswith('List') and len(name) > 4:
        name = name[:-4]
    name = _CAMEL_1.sub(r'\1_\2', name)
    name = _CAMEL_2.sub(r'\1_\2', name)
    return name.lower()


def snake_case_payload(value):
    """Recursively convert proto-JSON camelCase keys to snake_case.

    Desktop does ``Sfe(response, (_, key) => snakeCase(key.replace(/List$/, '')))``.
    Without this, ``hmacSalt`` is dropped and pull cannot open the vault.
    """
    if isinstance(value, dict):
        if value.get('type') == 'Buffer' and isinstance(value.get('data'), list):
            return value
        return {
            to_snake_case(key): snake_case_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [snake_case_payload(item) for item in value]
    return value


def unwrap_device_token(session, session_salt, token):
    """Decrypt ``credentials.token`` with the SRP session key.

    Desktop ``tSt``: ``FromEncryptionKey(getSaltedSecretKey(sessionSalt)).decrypt(token)``.
    """
    if not token:
        raise ApiError('Login response did not include a device token')
    if not session_salt:
        raise ApiError('Login response did not include session_salt')
    salt = bytes_field(session_salt)
    ciphertext = bytes_field(token)
    if salt is None or ciphertext is None:
        raise ApiError('Login response session_salt/token could not be decoded')
    try:
        key = session.get_salted_secret_key(salt)
        return SodiumSecretCryptor(key).decrypt(ciphertext)
    except Exception as exc:
        raise ApiError(
            'Could not unwrap DeviceToken with the SRP session key: {}'.format(
                exc
            )
        )


class GrpcLoginClient(object):
    """Login via ``wss://api.termius.com/login_v2`` Socket.IO proxy."""

    def __init__(self, host=API_HOST):
        self.url = 'https://{}'.format(host)

    def login(self, email, password, device, authy_token=None,
              firebase_token=None, domain_sso_token=None,
              account_email=None):
        """Run the SRP login handshake and return the desktop-shaped payload."""
        try:
            import socketio
        except ImportError as exc:
            raise ApiError(
                'python-socketio is required for SRP login: {}'.format(exc)
            )

        sio = socketio.Client(
            reconnection=False, logger=False, handle_sigint=False,
            request_timeout=120,
        )
        events = {}
        namespace = LOGIN_NAMESPACE

        def on_connect():
            events['connected'] = True

        def on_initial(data):
            events['initial'] = data

        def on_final(data):
            events['final'] = data

        def on_error(data):
            events['error'] = data

        def on_disconnect(*args):
            events['disconnected'] = True
            if args:
                events['disconnect_reason'] = args[0]

        sio.on('connect', on_connect, namespace=namespace)
        sio.on('disconnect', on_disconnect, namespace=namespace)
        sio.on('initialResponse', on_initial, namespace=namespace)
        sio.on('finalResponse', on_final, namespace=namespace)
        sio.on('grpc-error-response', on_error, namespace=namespace)
        sio.on('grpc-stream-error', on_error, namespace=namespace)
        sio.on('proxy-error', on_error, namespace=namespace)
        sio.on('error', on_error, namespace=namespace)

        try:
            sio.connect(
                self.url,
                namespaces=[namespace],
                socketio_path=SOCKETIO_GRPC_PATH,
                transports=['websocket'],
                wait_timeout=120,
            )
            # Desktop waits 120s; keep Engine.IO from dropping while the
            # server computes 8192-bit SRP (handshake advertises 20s).
            eio = getattr(sio, 'eio', None)
            if eio is not None:
                eio.ping_timeout = 120
                ws = getattr(eio, 'ws', None)
                if ws is not None:
                    # websocket-client recv timeout. Browsers wait forever;
                    # Python defaults to pingInterval+pingTimeout (~45s) and
                    # aborts with "transport error" while the server is busy.
                    ws.settimeout(180)
            sio.emit(
                'initialRequest',
                build_initial_request(
                    email, device,
                    authy_token=authy_token,
                    firebase_token=firebase_token,
                    domain_sso_token=domain_sso_token,
                ),
                namespace=namespace,
            )
            self._wait(sio, events, ('initial', 'error'))
            self._raise_if_error(events.get('error'))
            initial = events.get('initial')
            if not initial:
                raise ApiError(self._timeout_message(
                    'salt', events, firebase_token=firebase_token,
                ))
            initial = snake_case_payload(initial)

            identifier = (
                _first(initial, 'identifier', 'Identifier')
                or account_email
                or email
            )
            salt = bytes_field(_first(initial, 'salt'))
            public_data = _first(initial, 'publicData', 'public_data')
            version = initial.get('version')
            public_text = (
                public_data if isinstance(public_data, str) else str(public_data)
            )
            events['srp_meta'] = {
                'keys': sorted(initial.keys()) if isinstance(initial, dict) else str(type(initial)),
                'identifier_len': len(identifier or ''),
                'identifier_source': (
                    'server' if _first(initial, 'identifier', 'Identifier')
                    else 'account_email' if account_email else 'email'
                ),
                'salt_len': len(salt or b''),
                'public_prefix': public_text[:4] if public_data else '',
                'public_len': len(public_text) if public_data else 0,
                'public_kind': _public_kind(public_data),
                'version': version,
            }
            LOGGER.debug(
                'SRP initial field types=%s',
                {k: type(v).__name__ for k, v in initial.items()},
            )
            if not identifier or not salt or not public_data:
                raise ApiError(
                    'SRP salt response was missing identifier/salt/publicData'
                )

            session = ClientSession()
            try:
                session.configure(identifier, password, salt, version=version)
            except ValueError as exc:
                raise ApiError(str(exc))
            if not session.agree_server_public_value(public_data):
                raise ApiError('Invalid SRP server public value')

            sio.emit(
                'finalRequest',
                {
                    'public_data': botan_bigint_to_wire(session.A),
                    'proof': botan_bigint_to_wire(session.generate_proof()),
                },
                namespace=namespace,
            )
            self._wait(sio, events, ('final', 'error'))
            self._raise_if_error(
                events.get('error'), meta=events.get('srp_meta'),
            )
            final = events.get('final')
            if not final:
                raise ApiError(self._timeout_message(
                    'proof', events, firebase_token=firebase_token,
                ))
            final = snake_case_payload(final)

            if not session.validate_server_proof(
                _first(final, 'proof')
            ):
                LOGGER.warning('SRP server proof did not validate; continuing')

            credentials = dict(
                _first(final, 'credentials') or {}
            )
            token = credentials.get('token')
            session_salt = _first(final, 'sessionSalt', 'session_salt')
            credentials['token'] = unwrap_device_token(
                session, session_salt, token,
            )

            return {
                'credentials': credentials,
                'bulk_account': _first(final, 'bulk_account', 'bulkAccount'),
                'device': final.get('device'),
            }
        finally:
            try:
                sio.disconnect()
            except Exception:
                pass

    @staticmethod
    def _wait(sio, events, keys, timeout=120.0):
        steps = max(int(timeout / 0.25), 1)
        for _ in range(steps):
            if any(key in events for key in keys):
                return
            if events.get('disconnected'):
                sio.sleep(0.5)
                return
            sio.sleep(0.25)

    @staticmethod
    def _timeout_message(stage, events, firebase_token=None):
        bits = ['SRP login timed out waiting for {}'.format(stage)]
        if events.get('disconnected'):
            reason = events.get('disconnect_reason')
            if reason:
                bits.append('socket closed ({})'.format(reason))
            else:
                bits.append('socket closed before the server replied')
        log = events.get('log') or []
        if log:
            bits.append('events={}'.format(','.join(log)))
        if firebase_token:
            bits.append('call login with method=google again')
        return '; '.join(bits)

    @staticmethod
    def _raise_if_error(error, meta=None):
        if not error:
            return
        if not isinstance(error, dict):
            raise ApiError(str(error))
        code = error.get('code')
        key = error.get('key') or ''
        message = (
            error.get('message') or error.get('details') or str(error)
        )
        if code == NOT_MIGRATED or key == 'NOT_MIGRATED':
            raise NotMigratedError(message)
        if code in (OTP_TOKEN_REQUIRED, OTP_TOKEN_ERROR) or key in (
            'OTP_TOKEN_REQUIRED', 'OTP_TOKEN_ERROR',
        ):
            raise OtpTokenRequired(message)
        if code == UNAUTHENTICATED or key == 'UNAUTHENTICATED':
            raise ApiError(
                'Firebase session expired or invalid. '
                'Call login with method=google again.',
                payload=error,
            )
        if code == APP_OUTDATED or key == 'APP_OUTDATED':
            raise ApiError(
                'Termius Cloud rejected this client version. '
                'Upgrade termius-cli.',
                payload=error,
            )
        if code == THROTTLED or key == 'THROTTLED':
            raise ApiError(
                'Termius login is throttled. Wait and retry.',
                payload=error,
            )
        if code == LOGIN_APPROVE_REQUIRED or key == 'LOGIN_APPROVE_REQUIRED':
            raise ApiError(
                'This login needs approval in the Termius app.',
                payload=error,
            )
        if code == INVALID_PROOF or key == 'INVALID_PROOF':
            raise ApiError(
                'SRP proof rejected (not 2FA — that would ask for an '
                'authenticator code). The vault password is Argon2id-hashed '
                'then proven; a mismatch usually means the encryption '
                'password is wrong. meta={}'.format(meta),
                payload=error,
            )
        if code == INVALID_PUBLIC_DATA or key == 'INVALID_PUBLIC_DATA':
            raise ApiError(
                'SRP public value rejected by Termius Cloud.',
                payload=error,
            )
        label = key or code
        if label not in (None, ''):
            message = '{} [{}]'.format(message, label)
        raise ApiError(message, payload=error)
