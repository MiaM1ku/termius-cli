"""Termius v4/v5 secret-key crypto (Argon2id + NaCl secretbox/box).

Reversed from Termius 7.10 / 10 ``libtermius``:

* KDF: ``crypto_pwhash`` Argon2id, opslimit=2, memlimit=64MiB, 16-byte salt
* Secret: ``crypto_secretbox_easy`` (XSalsa20-Poly1305), not XChaCha20
* Public: ``crypto_box_easy`` (X25519-XSalsa20-Poly1305)
* Envelope: ``version | type | nonce(24) | mac(16) | ciphertext``
"""
from __future__ import unicode_literals

import base64
import os

from nacl.bindings import (
    crypto_box_easy,
    crypto_box_open_easy,
    crypto_secretbox_easy,
    crypto_secretbox_open_easy,
    crypto_scalarmult_base,
    randombytes,
)
from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id

from .cryptor import CryptorException

VERSION_BYTE = 4
TYPE_SECRET = 1
TYPE_PUBLIC = 2
NONCE_SIZE = 24
TAG_SIZE = 16
HEADER_SIZE = 2
OVERHEAD = HEADER_SIZE + NONCE_SIZE + TAG_SIZE  # 42
SALT_SIZE = 16
KEY_SIZE = 32


def ciphertext_version(blob):
    """Return Termius ciphertext version from raw or base64-looking bytes."""
    if not blob:
        return 0
    if isinstance(blob, str):
        first = blob[0]
        if first == 'B':
            return 4
        if first == 'A':
            return 3
        return 0
    return blob[0]


def derive_key_from_password(password, salt):
    """Derive a 32-byte secret key with libsodium interactive Argon2id."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if len(salt) != SALT_SIZE:
        raise CryptorException(
            'Sodium salt must be 16 bytes, got {}'.format(len(salt))
        )
    return argon2id.kdf(
        KEY_SIZE,
        password,
        salt,
        opslimit=argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=argon2id.MEMLIMIT_INTERACTIVE,
    )


def hash_srp_password(password, salt):
    """Vault password as used by libtermius ``ClientSession.configure``.

    Native login runs ``crypto_pwhash`` (Argon2id, opslimit=2, memlimit=64MiB)
    over the encryption password and the 16-byte SRP salt, then Botan-base64
    encodes the 32-byte key (standard alphabet, ``=`` padding). That ASCII
    string is the SRP password ``P`` in ``x = H(s | H(I | ":" | P))``.
    """
    return base64.b64encode(derive_key_from_password(password, salt)).decode('ascii')


class SodiumSecretCryptor(object):
    """NaCl secretbox cryptor used by DeviceToken and encryption schema v5."""

    bad_encrypted_exception = CryptorException

    def __init__(self, key):
        if len(key) != KEY_SIZE:
            raise CryptorException(
                'Sodium key must be 32 bytes, got {}'.format(len(key))
            )
        self.key = key

    @classmethod
    def from_password(cls, password, encryption_salt, hmac_salt):
        """Build cryptor from account password and RNCryptor-style salts."""
        salt = encryption_salt + hmac_salt
        return cls(derive_key_from_password(password, salt))

    def encrypt(self, plaintext):
        """Encrypt unicode/bytes and return raw ciphertext bytes."""
        if plaintext is None:
            raise TypeError('plaintext must not be None')
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        nonce = os.urandom(NONCE_SIZE)
        combined = crypto_secretbox_easy(plaintext, nonce, self.key)
        return bytes([VERSION_BYTE, TYPE_SECRET]) + nonce + combined

    def decrypt_bytes(self, ciphertext):
        """Decrypt raw ciphertext bytes to raw plaintext bytes."""
        if ciphertext is None:
            raise CryptorException('ciphertext must not be None')
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('ascii')
        if len(ciphertext) < OVERHEAD:
            raise CryptorException('incomplete sodium ciphertext')
        if ciphertext[0] not in (3, VERSION_BYTE):
            raise CryptorException(
                'unsupported sodium version {}'.format(ciphertext[0])
            )
        nonce = ciphertext[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
        try:
            return crypto_secretbox_open_easy(
                ciphertext[HEADER_SIZE + NONCE_SIZE:], nonce, self.key,
            )
        except CryptoError as exc:
            raise CryptorException('sodium decryption failed') from exc

    def decrypt(self, ciphertext):
        """Decrypt raw ciphertext bytes to unicode."""
        plaintext = self.decrypt_bytes(ciphertext)
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext.decode('latin1')


def generate_keypair():
    """X25519 keypair as used by ``ar.utils.generateKeyPair``."""
    secret = randombytes(KEY_SIZE)
    public = crypto_scalarmult_base(secret)
    return public, secret
class SodiumBoxCryptor(object):
    """NaCl ``crypto_box`` envelope used for personal/vault key wrapping.

    ``public_key`` is the other party's X25519 public key: recipient on
    encrypt, sender on decrypt. ``private_key`` is ours.
    """

    bad_encrypted_exception = CryptorException

    def __init__(self, public_key, private_key):
        if len(public_key) != KEY_SIZE or len(private_key) != KEY_SIZE:
            raise CryptorException('X25519 keys must be 32 bytes')
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, plaintext):
        if plaintext is None:
            raise TypeError('plaintext must not be None')
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        nonce = os.urandom(NONCE_SIZE)
        combined = crypto_box_easy(
            plaintext, nonce, self.public_key, self.private_key,
        )
        return bytes([VERSION_BYTE, TYPE_PUBLIC]) + nonce + combined

    def decrypt(self, ciphertext):
        plaintext = self.decrypt_bytes(ciphertext)
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext.decode('latin1')

    def decrypt_bytes(self, ciphertext):
        if ciphertext is None:
            raise CryptorException('ciphertext must not be None')
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('ascii')
        if len(ciphertext) < OVERHEAD:
            raise CryptorException('incomplete sodium ciphertext')
        if ciphertext[0] not in (3, VERSION_BYTE):
            raise CryptorException(
                'unsupported sodium version {}'.format(ciphertext[0])
            )
        nonce = ciphertext[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
        try:
            return crypto_box_open_easy(
                ciphertext[HEADER_SIZE + NONCE_SIZE:],
                nonce,
                self.public_key,
                self.private_key,
            )
        except CryptoError as exc:
            raise CryptorException('sodium box decryption failed') from exc

    def wrap_secret(self, secret_32):
        """Encrypt a 32-byte vault/personal key; return raw ciphertext bytes."""
        if isinstance(secret_32, str):
            secret_32 = secret_32.encode('utf-8')
        return self.encrypt(secret_32)

    def unwrap_secret(self, ciphertext):
        """Decrypt a wrapped 32-byte key to raw bytes."""
        plain = self.decrypt_bytes(ciphertext)
        if len(plain) != KEY_SIZE:
            raise CryptorException(
                'unwrapped key has length {}'.format(len(plain))
            )
        return plain


def box_for_peer(my_private_key, peer_public_key):
    """ECDH box used to wrap a vault key for another member."""
    return SodiumBoxCryptor(peer_public_key, my_private_key)
