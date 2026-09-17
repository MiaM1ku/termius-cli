# -*- coding: utf-8 -*-
from unittest import TestCase

from termius.cloud.client.transformers.many import _ref_id


class RefIdTest(TestCase):
    def test_dict(self):
        self.assertEqual(_ref_id({'id': 9}), 9)

    def test_int(self):
        self.assertEqual(_ref_id(9), 9)

    def test_none(self):
        self.assertIsNone(_ref_id(None))
