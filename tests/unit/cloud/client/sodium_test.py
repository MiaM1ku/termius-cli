# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from os import urandom
from unittest import TestCase

from termius.cloud.client.cryptor import UnifiedCryptor
from termius.cloud.client.sodium import SodiumSecretCryptor


class SodiumCryptorTest(TestCase):
    def test_roundtrip(self):
        key = urandom(32)
        cryptor = SodiumSecretCryptor(key)
        text = 'hello-termius'
        blob = cryptor.encrypt(text)
        self.assertEqual(blob[0], 4)
        self.assertEqual(blob[1], 1)
        self.assertEqual(cryptor.decrypt(blob), text)

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
