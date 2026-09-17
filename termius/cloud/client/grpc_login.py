"""Termius gRPC-over-Socket.IO login (encryption schema v5 / SRP)."""
from __future__ import unicode_literals

import base64
import logging

from ...core.constants import API_HOST, LOGIN_NAMESPACE, SOCKETIO_GRPC_PATH
from ...core.exceptions import ApiError, NotMigratedError, OtpTokenRequired
from .sodium import SodiumSecretCryptor
from .srp_session import ClientSession

LOGGER = logging.getLogger(__name__)

NOT_MIGRATED = 7
OTP_TOKEN_REQUIRED = 3
OTP_TOKEN_ERROR = 10


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


class GrpcLoginClient(object):
    """Login via ``wss://api.termius.com/login_v2`` Socket.IO proxy."""

    def __init__(self, host=API_HOST):
        self.url = 'https://{}'.format(host)

    def login(self, email, password, device, authy_token=None,
              firebase_token=None, domain_sso_token=None):
        """Run the SRP login handshake and return the desktop-shaped payload."""
        try:
            import socketio
        except ImportError as exc:
            raise ApiError(
                'python-socketio is required for SRP login: {}'.format(exc)
            )

        sio = socketio.Client(reconnection=False, logger=False)
        events = {}

        def on_connect():
            events['connected'] = True

        def on_initial(data):
            events['initial'] = data

        def on_final(data):
            events['final'] = data

        def on_error(data):
            events['error'] = data

        namespace = LOGIN_NAMESPACE
        sio.on('connect', on_connect, namespace=namespace)
        sio.on('initialResponse', on_initial, namespace=namespace)
        sio.on('finalResponse', on_final, namespace=namespace)
        sio.on('grpc-error-response', on_error, namespace=namespace)
        sio.on('error', on_error, namespace=namespace)

        try:
            sio.connect(
                self.url,
                namespaces=[namespace],
                socketio_path=SOCKETIO_GRPC_PATH,
                transports=['websocket'],
                wait_timeout=30,
            )
            sio.emit(
                'initialRequest',
                {
                    'otp_token': authy_token,
                    'email': email,
                    'domain_sso_token': domain_sso_token,
                    'device': dict(device, sub_name='', mobile_type='Desktop'),
                    'firebase_token': firebase_token,
                },
                namespace=namespace,
            )
            for _ in range(60):
                if 'initial' in events or 'error' in events:
                    break
                sio.sleep(0.5)
            self._raise_if_error(events.get('error'))
            initial = events.get('initial')
            if not initial:
                raise ApiError('SRP login timed out waiting for salt')

            session = ClientSession()
            session.configure(
                initial.get('identifier') or email,
                password,
                _unb64(initial.get('salt')),
            )
            if not session.agree_server_public_value(initial.get('public_data')):
                raise ApiError('Invalid SRP server public value')

            sio.emit(
                'finalRequest',
                {
                    'public_data': _b64(session.get_public_value()),
                    'proof': _b64(session.generate_proof()),
                },
                namespace=namespace,
            )
            for _ in range(60):
                if 'final' in events or 'error' in events:
                    break
                sio.sleep(0.5)
            self._raise_if_error(events.get('error'))
            final = events.get('final')
            if not final:
                raise ApiError('SRP login timed out waiting for proof')

            if not session.validate_server_proof(final.get('proof')):
                LOGGER.warning('SRP server proof did not validate; continuing')

            credentials = dict(final.get('credentials') or {})
            token = credentials.get('token')
            session_salt = final.get('sessionSalt') or final.get('session_salt')
            if token and session_salt:
                key = session.get_salted_secret_key(_unb64(session_salt))
                cryptor = SodiumSecretCryptor(key)
                try:
                    credentials['token'] = cryptor.decrypt(_unb64(token))
                except Exception:
                    LOGGER.debug('DeviceToken unwrap failed; using raw token')

            return {
                'credentials': credentials,
                'bulk_account': (
                    final.get('bulk_account') or final.get('bulkAccount')
                ),
                'device': final.get('device'),
            }
        finally:
            try:
                sio.disconnect()
            except Exception:
                pass

    @staticmethod
    def _raise_if_error(error):
        if not error:
            return
        if isinstance(error, dict):
            code = error.get('code')
            message = error.get('message') or error.get('details') or str(error)
            if code == NOT_MIGRATED:
                raise NotMigratedError(message)
            if code in (OTP_TOKEN_REQUIRED, OTP_TOKEN_ERROR):
                raise OtpTokenRequired(message)
            raise ApiError(message, payload=error)
        raise ApiError(str(error))
