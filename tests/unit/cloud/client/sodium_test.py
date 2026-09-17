# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from os import urandom
from unittest import TestCase

from termius.cloud.client.cryptor import UnifiedCryptor
from termius.cloud.client.sodium import SodiumSecretCryptor, hash_srp_password


class SodiumCryptorTest(TestCase):
    def test_roundtrip(self):
        key = urandom(32)
        cryptor = SodiumSecretCryptor(key)
        text = 'hello-termius'
        blob = cryptor.encrypt(text)
        self.assertEqual(blob[0], 4)
        self.assertEqual(blob[1], 1)
        self.assertEqual(cryptor.decrypt(blob), text)

    def test_hash_srp_password_is_padded_base64_of_32_bytes(self):
        salt = b'\x00' * 16
        hashed = hash_srp_password('vault-pass', salt)
        self.assertEqual(len(hashed), 44)
        self.assertTrue(hashed.endswith('='))
        import base64
        raw = base64.b64decode(hashed)
        self.assertEqual(len(raw), 32)
        self.assertNotEqual(hash_srp_password('other', salt), hashed)

    def test_from_password(self):
        password = 'secret'
        enc_salt = urandom(8)
        hmac_salt = urandom(8)
        cryptor = SodiumSecretCryptor.from_password(password, enc_salt, hmac_salt)
        self.assertEqual(cryptor.decrypt(cryptor.encrypt('abc')), 'abc')

    def test_unified_detects_sodium(self):
        password = 'secret'
        enc_salt = urandom(8)
        hmac_salt = urandom(8)
        unified = UnifiedCryptor(password, enc_salt, hmac_salt)
        encoded = unified.encrypt('payload', schema='v5')
        self.assertTrue(encoded.startswith('B') or encoded[0] in 'ABC')
        self.assertEqual(unified.decrypt(encoded), 'payload')
