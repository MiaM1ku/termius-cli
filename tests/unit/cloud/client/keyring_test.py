# -*- coding: utf-8 -*-
from os import urandom
from unittest import TestCase

from termius.cloud.client.sodium import (
    SodiumBoxCryptor,
    SodiumSecretCryptor,
    box_for_peer,
    generate_keypair,
)
from termius.cloud.client.keyring import _as_key_bytes


class KeyPairBoxTest(TestCase):
    def test_self_wrap_secret(self):
        public, private = generate_keypair()
        box = SodiumBoxCryptor(public, private)
        secret = urandom(32)
        blob = box.wrap_secret(secret)
        self.assertEqual(blob[0], 4)
        self.assertEqual(box.unwrap_secret(blob), secret)

    def test_member_wrap_matches_ecdh(self):
        owner_pub, owner_priv = generate_keypair()
        member_pub, member_priv = generate_keypair()
        secret = urandom(32)
        wrapped = box_for_peer(owner_priv, member_pub).wrap_secret(secret)
        opened = box_for_peer(member_priv, owner_pub).unwrap_secret(wrapped)
        self.assertEqual(opened, secret)

    def test_personal_v4_text_roundtrip(self):
        key = urandom(32)
        cryptor = SodiumSecretCryptor(key)
        self.assertEqual(cryptor.decrypt(cryptor.encrypt('vault-host')), 'vault-host')


class AsKeyBytesTest(TestCase):
    def test_latin1_raw_key(self):
        key = bytes(range(32))
        self.assertEqual(_as_key_bytes(key.decode('latin1')), key)

    def test_standard_base64(self):
        import base64
        key = urandom(32)
        self.assertEqual(_as_key_bytes(base64.b64encode(key).decode('ascii')), key)

    def test_raw_bytes(self):
        key = urandom(32)
        self.assertEqual(_as_key_bytes(key), key)
