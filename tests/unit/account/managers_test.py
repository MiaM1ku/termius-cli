# -*- coding: utf-8 -*-
from unittest import TestCase
from unittest.mock import Mock, patch
from six.moves import configparser

from termius.account.managers import (
    AccountManager, _encryption_schema,
)
from termius.core.exceptions import OptionNotSetException


class AccountManagerTest(TestCase):
    def test_get_yes_settings(self):
        manager = self.get_manager(lambda *args, **kwargs: 'yes')
        settings = manager.get_settings()
        self.assertEqual(settings, {
            'synchronize_key': True,
            'agent_forwarding': True,
        })

    def test_fail_settings(self):
        manager = self.get_manager(KeyError)
        with self.assertRaises(KeyError):
            manager.get_settings()

    def get_manager(self, config_side_effect):
        config_mock = Mock(**{'get_safe.side_effect': config_side_effect})
        return AccountManager(config_mock)

    def test_get_analytics_id_when_exists(self):
        aid = 'id'
        config_mock = Mock()
        config_mock.get.return_value = aid

        manager = AccountManager(config_mock)
        self.assertEqual(aid, manager.analytics_id)

        config_mock.get.assert_called_once_with('User', 'analytics_id')

    @patch('termius.account.managers.uuid')
    def test_get_analytics_id_when_not_exists(self, uuid):
        aid = 'id'
        uuid.uuid4.return_value = aid

        config_mock = Mock()
        config_mock.get.side_effect = configparser.NoSectionError('msg')

        manager = AccountManager(config_mock)
        self.assertEqual(aid, manager.analytics_id)

        config_mock.set.assert_called_once_with('User', 'analytics_id', aid)
        config_mock.write.assert_called_once()

    def test_encryption_schema_maps_proto_enum(self):
        self.assertEqual(_encryption_schema(1), 'v3')
        self.assertEqual(_encryption_schema(2), 'v5')
        self.assertEqual(_encryption_schema('v5'), 'v5')
        self.assertEqual(_encryption_schema(None), 'v3')

    @patch('termius.account.managers.GrpcLoginClient')
    def test_login_persists_hmac_salt(self, grpc_cls):
        grpc_cls.return_value.login.return_value = {
            'credentials': {
                'token': 'device-token',
                'salt': 'c2FsdHNhbHQ=',
                'hmac_salt': 'aG1hY3NhbHQ=',
                'personal_keyset': {'public_key': 'pk'},
            },
            'bulk_account': {
                'account': {
                    'user_id': 9,
                    'feature_toggles': {'encryption_schema': 2},
                },
                'team': {'is_owner': False},
            },
        }
        config_mock = Mock()
        manager = AccountManager(config_mock)
        manager.device = Mock()
        manager.device.to_json.return_value = {'token': 'dev'}
        manager.login('you@example.com', 'vault')
        config_mock.set.assert_any_call('User', 'hmac_salt', 'aG1hY3NhbHQ=')
        config_mock.set.assert_any_call('User', 'salt', 'c2FsdHNhbHQ=')
        config_mock.set.assert_any_call('User', 'encryption_schema', 'v5')
        config_mock.set.assert_any_call('User', 'public_key', 'pk')

    @patch('termius.account.managers.GrpcLoginClient')
    def test_login_rejects_missing_hmac_salt(self, grpc_cls):
        grpc_cls.return_value.login.return_value = {
            'credentials': {
                'token': 'device-token',
                'salt': 'c2FsdHNhbHQ=',
            },
        }
        manager = AccountManager(Mock())
        manager.device = Mock()
        manager.device.to_json.return_value = {'token': 'dev'}
        with self.assertRaises(OptionNotSetException):
            manager.login('you@example.com', 'vault')
