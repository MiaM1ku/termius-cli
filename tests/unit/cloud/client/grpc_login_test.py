# -*- coding: utf-8 -*-
from unittest import TestCase

from termius.cloud.client.grpc_login import (
    GrpcLoginClient, build_initial_request, bytes_field, grpc_device,
    omit_none, snake_case_payload, to_snake_case,
)
from termius.cloud.client.srp_session import (
    G, N, P_BYTES, ClientSession, _H, _blake2b, _minimal, _pad,
    botan_bigint_from_str, botan_bigint_to_str, botan_bigint_to_wire,
)
from termius.core.exceptions import ApiError, NotMigratedError, OtpTokenRequired


class BuildInitialRequestTest(TestCase):
    def test_omits_null_tokens_and_uses_enum_mobile_type(self):
        payload = build_initial_request(
            '',
            {
                'token': 'dev-1',
                'app_version': '10.0.6',
                'os_version': 'linux',
                'name': 'box',
                'sub_name': '',
                'mobile_type': 'Desktop',
            },
            firebase_token='tok',
        )
        self.assertEqual(payload['email'], '')
        self.assertEqual(payload['firebase_token'], 'tok')
        self.assertEqual(payload['device']['mobile_type'], 3)
        self.assertEqual(payload['device']['token'], 'dev-1')
        self.assertNotIn('otp_token', payload)
        self.assertNotIn('domain_sso_token', payload)

    def test_keeps_otp_when_set(self):
        payload = build_initial_request(
            'you@example.com', {'token': 'dev-1'}, authy_token='123456',
        )
        self.assertEqual(payload['otp_token'], '123456')
        self.assertEqual(payload['email'], 'you@example.com')


class OmitNoneTest(TestCase):
    def test_nested(self):
        self.assertEqual(
            omit_none({'a': 1, 'b': None, 'c': {'d': None, 'e': 2}}),
            {'a': 1, 'c': {'e': 2}},
        )


class GrpcDeviceTest(TestCase):
    def test_overrides_string_desktop(self):
        self.assertEqual(
            grpc_device({'mobile_type': 'Desktop', 'token': 'x'})['mobile_type'],
            3,
        )


class BytesFieldTest(TestCase):
    def test_node_buffer(self):
        self.assertEqual(bytes_field({'type': 'Buffer', 'data': [65, 66]}), b'AB')

    def test_base64(self):
        self.assertEqual(bytes_field('QUI='), b'AB')


class RaiseIfErrorTest(TestCase):
    def test_not_migrated(self):
        with self.assertRaises(NotMigratedError):
            GrpcLoginClient._raise_if_error({
                'code': 7, 'key': 'NOT_MIGRATED', 'message': 'User is not migrated.',
            })

    def test_otp(self):
        with self.assertRaises(OtpTokenRequired):
            GrpcLoginClient._raise_if_error({'code': 3, 'message': 'otp'})

    def test_expired_firebase(self):
        with self.assertRaises(ApiError) as ctx:
            GrpcLoginClient._raise_if_error({
                'code': 2, 'key': 'UNAUTHENTICATED',
                'message': 'Invalid Firebase ID Token.',
            })
        self.assertIn('termius login --google', str(ctx.exception))

class BotanBigIntTest(TestCase):
    def test_uppercase_0x_even_hex(self):
        self.assertEqual(botan_bigint_to_str(10), '0x0A')
        self.assertEqual(botan_bigint_to_str(0xAB), '0xAB')
        self.assertEqual(botan_bigint_to_str(b'\x01\x02'), '0x0102')

    def test_wire_hex_strips_0x(self):
        self.assertEqual(botan_bigint_to_wire(10), '0A')
        self.assertEqual(botan_bigint_to_wire(0xAB), 'AB')
        self.assertFalse(botan_bigint_to_wire(0xDEADBEEF).startswith('0x'))

    def test_parse_0x(self):
        self.assertEqual(botan_bigint_from_str('0x0A'), 10)
        self.assertEqual(botan_bigint_from_str('0xab'), 0xAB)

    def test_parse_hex_without_0x(self):
        # Short all-hex strings can also be base64; require >= 8 hex chars.
        self.assertEqual(botan_bigint_from_str('DEADBEEF'), 0xDEADBEEF)
        self.assertEqual(botan_bigint_from_str('994B00FF'), 0x994B00FF)

    def test_roundtrip_bytes(self):
        value = int.from_bytes(b'\xde\xad\xbe\xef', 'big')
        encoded = botan_bigint_to_str(value)
        self.assertTrue(encoded.startswith('0x'))
        self.assertEqual(botan_bigint_from_str(encoded), value)


class SrpEncodingTest(TestCase):
    def test_g_is_single_byte(self):
        self.assertEqual(_minimal(G), b'\x13')

    def test_n_is_group_size(self):
        self.assertEqual(len(_minimal(N)), P_BYTES)
        self.assertEqual(P_BYTES, 1024)

    def test_srp_hash_is_blake2b_512(self):
        digest = _blake2b(b'abc')
        self.assertEqual(len(digest), 64)
        self.assertEqual(
            digest.hex(),
            'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
            '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
        )

    def test_pad_n_is_the_modulus_not_zero(self):
        padded = _pad(N)
        self.assertEqual(len(padded), P_BYTES)
        self.assertEqual(padded, _minimal(N))
        self.assertNotEqual(padded, b'\x00' * P_BYTES)

    def test_k_uses_real_modulus(self):
        k_wrong = _blake2b(b'\x00' * P_BYTES, _pad(G))
        k = _H(N, G)
        self.assertNotEqual(k, int.from_bytes(k_wrong, 'big'))


class SrpPasswordHashTest(TestCase):
    def test_configure_rejects_short_salt(self):
        session = ClientSession()
        with self.assertRaises(ValueError):
            session.configure('id', 'pass', b'short')

    def test_configure_does_not_use_raw_password(self):
        salt = b'\x11' * 16
        identifier = '11111111-1111-1111-1111-111111111111'
        session = ClientSession()
        session.configure(identifier, 'vault-pass', salt)
        self.assertNotEqual(session.password, b'vault-pass')
        self.assertEqual(len(session.password), 44)


class ProtoJsonSnakeCaseTest(TestCase):
    def test_login_fields(self):
        self.assertEqual(to_snake_case('hmacSalt'), 'hmac_salt')
        self.assertEqual(to_snake_case('sessionSalt'), 'session_salt')
        self.assertEqual(to_snake_case('personalKeyset'), 'personal_keyset')
        self.assertEqual(to_snake_case('featureToggles'), 'feature_toggles')
        self.assertEqual(to_snake_case('encryptionSchema'), 'encryption_schema')
        self.assertEqual(to_snake_case('hmac_salt'), 'hmac_salt')

    def test_nested_credentials(self):
        payload = snake_case_payload({
            'sessionSalt': 'abc',
            'credentials': {
                'hmacSalt': 'hmac',
                'salt': 'salt',
                'personalKeyset': {'publicKey': 'pk'},
            },
            'bulkAccount': {
                'account': {
                    'featureToggles': {'encryptionSchema': 2},
                    'userId': 7,
                }
            },
        })
        self.assertEqual(payload['session_salt'], 'abc')
        self.assertEqual(payload['credentials']['hmac_salt'], 'hmac')
        self.assertEqual(payload['credentials']['salt'], 'salt')
        self.assertEqual(
            payload['credentials']['personal_keyset']['public_key'], 'pk',
        )
        account = payload['bulk_account']['account']
        self.assertEqual(account['user_id'], 7)
        self.assertEqual(account['feature_toggles']['encryption_schema'], 2)


class SrpServerProofTest(TestCase):
    def test_amk_hashes_h_k_and_strips_leading_zeros_on_m(self):
        session = ClientSession()
        session.A = 19
        session.K = b'\x01' * P_BYTES
        session.M1 = b'\x00' + b'\xab' * 63
        actual = session._server_proof()
        expected = _blake2b(
            _minimal(19),
            _minimal(int.from_bytes(session.M1, 'big')),
            _blake2b(session.K),
        )
        self.assertEqual(actual, expected)
        self.assertNotEqual(
            actual, _blake2b(_minimal(19), session.M1, session.K),
        )

    def test_validate_accepts_wire_hex(self):
        session = ClientSession()
        session.M2 = b'\x0a' + b'\x11' * 63
        wire = botan_bigint_to_wire(int.from_bytes(session.M2, 'big'))
        self.assertTrue(session.validate_server_proof(wire))
        self.assertFalse(session.validate_server_proof('FF' * 64))


class SaltedSecretKeyTest(TestCase):
    def test_uses_argon2id_of_base64_k_not_sha256(self):
        import hashlib
        from termius.cloud.client.sodium import derive_key_from_password

        session = ClientSession()
        session.K = b'\x03' * P_BYTES
        salt = b'\x22' * 16
        key = session.get_salted_secret_key(salt)
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, hashlib.sha256(session.K + salt).digest())
        self.assertEqual(
            key,
            derive_key_from_password(
                __import__('base64').b64encode(session.K), salt,
            ),
        )
