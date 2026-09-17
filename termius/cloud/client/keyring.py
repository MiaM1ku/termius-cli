"""Personal keypair and team vault key ring (encrypted_with)."""
from __future__ import unicode_literals

import base64
import logging

from .cryptor import CryptorException
from .sodium import (
    KEY_SIZE,
    SodiumBoxCryptor,
    SodiumSecretCryptor,
    box_for_peer,
    generate_keypair,
)

LOGGER = logging.getLogger(__name__)


def _b64e(raw):
    return base64.b64encode(raw).decode('ascii')


def _b64d(text):
    if text is None:
        return None
    if isinstance(text, bytes):
        return text
    return base64.b64decode(text)


def _as_key_bytes(value):
    """Accept a 32-byte key as raw bytes, latin1, or standard base64.

    Desktop password-decrypts ``encrypted_private_key`` to raw 32 bytes
    then ``toString('base64')``. Our ``decrypt()`` yields those raw bytes
    as a latin1 string, which ``b64decode`` rejects with
    ``string argument should contain only ASCII characters``.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == KEY_SIZE:
            return raw
        try:
            decoded = base64.b64decode(raw)
        except Exception:
            return raw
        return decoded if len(decoded) == KEY_SIZE else raw
    try:
        ascii_bytes = value.encode('ascii')
    except UnicodeEncodeError:
        return value.encode('latin1')
    try:
        decoded = base64.b64decode(ascii_bytes)
    except Exception:
        return ascii_bytes
    if len(decoded) == KEY_SIZE:
        return decoded
    if len(ascii_bytes) == KEY_SIZE:
        return ascii_bytes
    return decoded


def _as_list(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ('objects', 'keys', 'results', 'vault_keys'):
            if isinstance(payload.get(key), list):
                return payload[key]
        if payload.get('original_key') or payload.get('encrypted_key'):
            return [payload]
    return []


def _encrypted_with_id(value):
    if value is None:
        return None
    if isinstance(value, dict):
        return (
            value.get('original_key')
            or value.get('id')
            or value.get('public_key')
        )
    return value


class VaultKeyRing(object):
    """Map ``encrypted_with`` ids to sodium secret cryptors."""

    def __init__(self):
        self.vaults = {}
        self.public_key = None
        self.private_key = None
        self.personal_v4_key = None

    @property
    def personal_v4(self):
        if self.personal_v4_key:
            return SodiumSecretCryptor(self.personal_v4_key)
        return None

    def resolve(self, payload):
        """Pick the cryptor for a sync entity payload."""
        if not isinstance(payload, dict):
            return None
        encrypted_with = _encrypted_with_id(payload.get('encrypted_with'))
        is_shared = bool(payload.get('is_shared'))
        if not is_shared and encrypted_with is None:
            return None  # caller uses personal cryptor
        if encrypted_with is None:
            return None
        return self.vaults.get(str(encrypted_with)) or self.vaults.get(encrypted_with)

    def unwrap_personal(self, password_cryptor, personal_keyset):
        """Decrypt personal keypair + v4 key from a keyserver record."""
        if not personal_keyset:
            return
        enc_priv = personal_keyset.get('encrypted_private_key')
        public_b64 = personal_keyset.get('public_key')
        enc_personal = personal_keyset.get('encrypted_personal_key')
        if not enc_priv or not public_b64:
            return
        decrypt_bytes = getattr(password_cryptor, 'decrypt_bytes', None)
        private_plain = None
        if decrypt_bytes:
            try:
                private_plain = decrypt_bytes(enc_priv)
            except Exception:
                private_plain = None
        if private_plain is None:
            private_plain = password_cryptor.decrypt(enc_priv)
        private_key = _as_key_bytes(private_plain)
        public_key = _as_key_bytes(public_b64)
        if len(private_key) != KEY_SIZE or len(public_key) != KEY_SIZE:
            raise CryptorException('personal keypair has unexpected size')
        self.private_key = private_key
        self.public_key = public_key
        if enc_personal:
            box = SodiumBoxCryptor(public_key, private_key)
            self.personal_v4_key = box.unwrap_secret(_b64d(enc_personal))

    def load_vault_keys(self, records):
        """Build per-vault cryptors from ``GET /api/v4/team/vault/keys/``."""
        if not self.private_key:
            return
        for record in _as_list(records):
            try:
                cryptor = self._cryptor_for_record(record)
            except Exception as exc:
                LOGGER.warning('Skipping vault key: %s', exc)
                continue
            if cryptor is None:
                continue
            original = record.get('original_key')
            vault_id = record.get('vault')
            for key in (original, vault_id, str(original) if original is not None else None,
                        str(vault_id) if vault_id is not None else None):
                if key is not None:
                    self.vaults[key] = cryptor

    def _cryptor_for_record(self, record):
        wrapping_pub = _b64d(
            (record.get('encrypted_with') or {}).get('public_key')
        )
        encrypted_key = record.get('encrypted_key')
        if not wrapping_pub or not encrypted_key:
            return None
        blob = _b64d(encrypted_key)
        box = SodiumBoxCryptor(wrapping_pub, self.private_key)
        try:
            vault_key = box.unwrap_secret(blob)
        except CryptorException:
            # Some member keys may be a raw 32-byte ECDH secret.
            if len(blob) == KEY_SIZE:
                vault_key = blob
            else:
                raise
        return SodiumSecretCryptor(vault_key)

    def generate_and_wrap_personal(self, password_cryptor):
        """Create a new personal keyset for POST /keyserver/key/my/."""
        from os import urandom
        public_key, private_key = generate_keypair()
        personal_key = urandom(KEY_SIZE)
        own_box = SodiumBoxCryptor(public_key, private_key)
        enc_personal = own_box.wrap_secret(personal_key)
        enc_private = password_cryptor.encrypt(_b64e(private_key), schema='v5')
        self.public_key = public_key
        self.private_key = private_key
        self.personal_v4_key = personal_key
        return {
            'public_key': _b64e(public_key),
            'encrypted_private_key': enc_private,
            'encrypted_personal_key': _b64e(enc_personal),
        }

    def persist(self, config):
        """Save unwrapped keys next to the API token."""
        if self.public_key:
            config.set('User', 'public_key', _b64e(self.public_key))
        if self.private_key:
            config.set('User', 'private_key', _b64e(self.private_key))
        if self.personal_v4_key:
            config.set('User', 'personal_v4_key', _b64e(self.personal_v4_key))
        config.write()

    def restore(self, config):
        """Load previously unwrapped keys."""
        self.public_key = _b64d(config.get_safe('User', 'public_key'))
        self.private_key = _b64d(config.get_safe('User', 'private_key'))
        self.personal_v4_key = _b64d(config.get_safe('User', 'personal_v4_key'))
        if self.public_key and len(self.public_key) != KEY_SIZE:
            self.public_key = None
        if self.private_key and len(self.private_key) != KEY_SIZE:
            self.private_key = None
        if self.personal_v4_key and len(self.personal_v4_key) != KEY_SIZE:
            self.personal_v4_key = None


def load_keyring(api, config, password_cryptor, personal_keyset=None):
    """Build a key ring from login payload + live API."""
    ring = VaultKeyRing()
    ring.restore(config)
    if personal_keyset:
        try:
            ring.unwrap_personal(password_cryptor, personal_keyset)
        except Exception as exc:
            LOGGER.warning('Could not unwrap login personal_keyset: %s', exc)
    if ring.private_key is None:
        try:
            remote = api.get('v3/keyserver/key/my/')
        except Exception as exc:
            LOGGER.debug('No remote keypair: %s', exc)
            remote = None
        if remote and remote.get('encrypted_private_key'):
            try:
                ring.unwrap_personal(password_cryptor, remote)
            except Exception as exc:
                LOGGER.warning('Could not unwrap remote keypair: %s', exc)
    if ring.private_key:
        ring.persist(config)
        try:
            records = api.get('v4/team/vault/keys/')
            ring.load_vault_keys(records)
            LOGGER.info('Loaded %s vault key(s)', len(ring.vaults))
        except Exception as exc:
            LOGGER.debug('No vault keys: %s', exc)
    return ring
