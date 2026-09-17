# -*- coding: utf-8 -*-
from unittest import TestCase

from termius.cloud.client.grpc_login import (
    GrpcLoginClient, build_initial_request, bytes_field, grpc_device,
    omit_none,
)
from termius.cloud.client.srp_session import (
    botan_bigint_from_str, botan_bigint_to_str,
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

    def test_parse_0x(self):
        self.assertEqual(botan_bigint_from_str('0x0A'), 10)
        self.assertEqual(botan_bigint_from_str('0xab'), 0xAB)

    def test_roundtrip_bytes(self):
        value = int.from_bytes(b'\xde\xad\xbe\xef', 'big')
        encoded = botan_bigint_to_str(value)
        self.assertTrue(encoded.startswith('0x'))
        self.assertEqual(botan_bigint_from_str(encoded), value)
