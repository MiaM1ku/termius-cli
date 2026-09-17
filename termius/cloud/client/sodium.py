"""Termius v4/v5 secret-key crypto (Argon2id + XChaCha20-Poly1305).

Reversed from Termius 10.0.6 ``@termius/libtermius``:

* KDF: ``crypto_pwhash`` Argon2id, opslimit=2, memlimit=64MiB, 16-byte salt
* Ciphertext: ``version(4) | type(1) | nonce(24) | tag(16) | ciphertext``
"""
from __future__ import unicode_literals

import base64
import os

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
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
    """XChaCha20-Poly1305 secret-key cryptor used by encryption schema v5."""

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
        combined = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, None, nonce, self.key
        )
        body, tag = combined[:-TAG_SIZE], combined[-TAG_SIZE:]
        return bytes([VERSION_BYTE, TYPE_SECRET]) + nonce + tag + body

    def decrypt_bytes(self, ciphertext):
        """Decrypt raw ciphertext bytes to raw plaintext bytes."""
        if ciphertext is None:
            raise CryptorException('ciphertext must not be None')
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('ascii')
        if len(ciphertext) < OVERHEAD:
            raise CryptorException('incomplete sodium ciphertext')
        if ciphertext[0] != VERSION_BYTE:
            raise CryptorException(
                'unsupported sodium version {}'.format(ciphertext[0])
            )
        nonce = ciphertext[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
        tag = ciphertext[HEADER_SIZE + NONCE_SIZE:OVERHEAD]
        body = ciphertext[OVERHEAD:]
        try:
            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                body + tag, None, nonce, self.key
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



def _rotl32(value, bits):
    value &= 0xffffffff
    return ((value << bits) | (value >> (32 - bits))) & 0xffffffff


def _chacha_qr(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] = _rotl32(state[b] ^ state[c], 7)


def crypto_core_hchacha20(nonce16, key32):
    """HChaCha20; matches libsodium crypto_core_hchacha20 (c=NULL)."""
    import struct
    sigma = b'expand 32-byte k'
    state = list(struct.unpack('<16I', sigma + key32 + nonce16))
    for _ in range(10):
        _chacha_qr(state, 0, 4, 8, 12)
        _chacha_qr(state, 1, 5, 9, 13)
        _chacha_qr(state, 2, 6, 10, 14)
        _chacha_qr(state, 3, 7, 11, 15)
        _chacha_qr(state, 0, 5, 10, 15)
        _chacha_qr(state, 1, 6, 11, 12)
        _chacha_qr(state, 2, 7, 8, 13)
        _chacha_qr(state, 3, 4, 9, 14)
    return struct.pack('<8I', *(state[0:4] + state[12:16]))

def ecdh_aead_key(private_key, public_key):
    """X25519 + HChaCha20(zero nonce) as in crypto_box_curve25519xchacha20poly1305."""
    shared = crypto_scalarmult(private_key, public_key)
    return crypto_core_hchacha20(b'\x00' * 16, shared)


class SodiumBoxCryptor(object):
    """FromKeyPair / ForOwner wrapping: ECDH then the v4 secret envelope."""

    bad_encrypted_exception = CryptorException

    def __init__(self, public_key, private_key):
        if len(public_key) != KEY_SIZE or len(private_key) != KEY_SIZE:
            raise CryptorException('X25519 keys must be 32 bytes')
        self.public_key = public_key
        self.private_key = private_key
        self._secret = SodiumSecretCryptor(
            ecdh_aead_key(private_key, public_key)
        )

    def encrypt(self, plaintext):
        blob = self._secret.encrypt(plaintext)
        if blob and blob[1] == TYPE_SECRET:
            blob = bytes([blob[0], TYPE_PUBLIC]) + blob[2:]
        return blob

    def decrypt(self, ciphertext):
        return self._secret.decrypt(ciphertext)

    def wrap_secret(self, secret_32):
        """Encrypt a 32-byte vault/personal key; return raw ciphertext bytes."""
        return self.encrypt(secret_32)

    def unwrap_secret(self, ciphertext):
        """Decrypt a wrapped 32-byte key to raw bytes."""
        plain = self._secret.decrypt_bytes(ciphertext)
        if len(plain) != KEY_SIZE:
            raise CryptorException(
                'unwrapped key has length {}'.format(len(plain))
            )
        return plain


def box_for_peer(my_private_key, peer_public_key):
    """ECDH box used to wrap a vault key for another member."""
    return SodiumBoxCryptor(peer_public_key, my_private_key)
