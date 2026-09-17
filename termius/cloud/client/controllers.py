# -*- coding: utf-8 -*-
"""Module for sync api controller."""
from logging import getLogger
from .transformers.many import BulkTransformer
from .transformers.single import SettingsTransformer
from ...core.api import API
from ...account.managers import AccountManager
from ...core.exceptions import ApiError


class CryptoController(object):
    """Controller for encrypting/decrypting data."""

    def __init__(self, cryptor):
        """Construct new crypto Controller."""
        self.cryptor = cryptor
        self.bad_encrypted_exception = cryptor.bad_encrypted_exception

    # pylint: disable=no-self-use
    def _mutate_fields(self, model, mutator):
        for i in model.crypto_fields:
            crypto_field = getattr(model, i)
            if crypto_field:
                setattr(model, i, mutator(crypto_field))
        return model

    def _decrypt_value(self, cryptor, value):
        if value is None or value == '' or cryptor is None:
            return value
        if cryptor is self.cryptor:
            return cryptor.decrypt(value)
        import base64
        from ...core.utils import to_bytes
        raw = value
        if isinstance(value, str):
            raw = base64.b64decode(to_bytes(value))
        return cryptor.decrypt(raw)

    def decrypt_payload(self, payload, crypto_fields=None):
        """Decrypt a raw sync payload, including v5 ``content`` blobs."""
        if not isinstance(payload, dict):
            return payload
        resolver = getattr(self.cryptor, 'resolve', None)
        cryptor = resolver(payload) if resolver else self.cryptor
        if cryptor is None:
            payload = dict(payload)
            payload['_undecryptable'] = True
            return payload
        content = payload.get('content')
        if isinstance(content, str) and content:
            try:
                plain = self._decrypt_value(cryptor, content)
            except Exception:
                payload = dict(payload)
                payload['_undecryptable'] = True
                return payload
            if isinstance(plain, str) and plain.startswith('{'):
                import json
                try:
                    blob = json.loads(plain)
                except ValueError:
                    blob = {}
                if isinstance(blob, dict):
                    payload = dict(payload)
                    payload.update(blob)
                    payload.pop('content', None)
            return payload
        if crypto_fields:
            payload = dict(payload)
            for field in crypto_fields:
                value = payload.get(field)
                if isinstance(value, str) and value:
                    try:
                        payload[field] = self._decrypt_value(cryptor, value)
                    except Exception:
                        pass
        return payload

    def encrypt(self, model):
        """Encrypt fields."""
        return self._mutate_fields(model, self.cryptor.encrypt)

    def decrypt(self, model):
        """Decrypt fields."""
        return self._mutate_fields(model, self.cryptor.decrypt)


class ApiController(object):
    """Controller to call API."""

    mapping = dict(
        bulk=dict(url='v4/terminal/sync/', transformer=BulkTransformer),
        bulk_legacy=dict(url='v3/terminal/bulk/', transformer=BulkTransformer),
        settings=dict(url='v3/setting/mobile/',
                      transformer=SettingsTransformer),
    )
    log = getLogger(__name__)

    def __init__(self, storage, config, cryptor):
        """Create new API controller."""
        self.config = config
        username = self.config.get('User', 'username')
        apikey = self.config.get('User', 'apikey')
        token_type = self.config.get_safe('User', 'token_type', default='device')
        assert username
        assert apikey
        self.api = API(username, apikey, token_type=token_type)
        self.storage = storage
        self.crypto_controller = CryptoController(cryptor)
        self.account_manager = AccountManager(config)

    def get_bulk(self):
        """Get remote instances."""
        try:
            mapped = self.mapping['bulk']
            model = self._get(mapped)
        except ApiError:
            mapped = self.mapping['bulk_legacy']
            model = self._get(mapped)
        self.config.set('CloudSynchronization', 'last_synced',
                        model['last_synced'])
        self.config.write()

    def get_settings(self):
        """Get remote settings."""
        mapped = self.mapping['settings']
        model = self._get(mapped)
        self.account_manager.set_settings(model)

    def post_bulk(self):
        """Send local instances."""
        mapped = self.mapping['bulk']
        model = {}
        model['last_synced'] = self.config.get(
            'CloudSynchronization', 'last_synced'
        )
        assert model['last_synced']
        try:
            out_model = self._post(mapped, model)
        except Exception:
            mapped = self.mapping['bulk_legacy']
            out_model = self._post(mapped, model)
        self.config.set('CloudSynchronization', 'last_synced',
                        out_model['last_synced'])
        self.config.write()

    def put_setting(self):
        """Send local settings."""
        mapped = self.mapping['settings']
        model = self.account_manager.get_settings()
        out_model = self._put(mapped, model)
        self.account_manager.set_settings(out_model)

    def _post(self, mapped, request_model):
        transformer = self._create_transformer(mapped)
        payload = transformer.to_payload(request_model)
        response = self.api.post(mapped['url'], payload)
        response_model = transformer.to_model(response)
        return response_model

    def _put(self, mapped, request_model):
        transformer = self._create_transformer(mapped)
        payload = transformer.to_payload(request_model)
        response = self.api.put(mapped['url'], payload)
        response_model = transformer.to_model(response)
        return response_model

    def _get(self, mapped):
        transformer = self._create_transformer(mapped)
        response = self.api.get(mapped['url'])

        model = transformer.to_model(response)
        return model

    def _create_transformer(self, mapped):
        return mapped['transformer'](
            storage=self.storage,
            crypto_controller=self.crypto_controller,
            account_manager=self.account_manager,
        )
