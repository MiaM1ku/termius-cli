# -*- coding: utf-8 -*-
from unittest import TestCase

from nose.tools import eq_, assert_raises

from termius.cloud.client.browser_sso import (
    desktop_sso_url, parse_continue_sso_url,
)
from termius.core.exceptions import ApiError


class ParseContinueSsoUrlTest(TestCase):
    def test_desktop_callback(self):
        parsed = parse_continue_sso_url(
            'termius://app/continue-sso?email=you@example.com'
            '&firebaseToken=abc.def.ghi&requestId=req-1'
        )
        eq_(parsed['email'], 'you@example.com')
        eq_(parsed['firebase_token'], 'abc.def.ghi')
        eq_(parsed['request_id'], 'req-1')

    def test_nested_url_query(self):
        parsed = parse_continue_sso_url(
            'http://127.0.0.1:9/cb?url='
            'termius%3A%2F%2Fapp%2Fcontinue-sso%3Femail%3Da%40b.c'
            '%26firebaseToken%3Dtok%26requestId%3Drid'
        )
        eq_(parsed['email'], 'a@b.c')
        eq_(parsed['firebase_token'], 'tok')
        eq_(parsed['request_id'], 'rid')

    def test_rejects_garbage(self):
        with assert_raises(ApiError):
            parse_continue_sso_url('https://example.com/')

    def test_query_string_only(self):
        parsed = parse_continue_sso_url(
            'email=you@example.com&firebaseToken=tok&requestId=rid'
        )
        eq_(parsed['email'], 'you@example.com')
        eq_(parsed['firebase_token'], 'tok')
        eq_(parsed['request_id'], 'rid')


class DesktopSsoUrlTest(TestCase):
    def test_builds_account_url(self):
        url = desktop_sso_url('google', 'abc-123')
        eq_(
            url,
            'https://account.termius.com/sso/desktop?provider=google&request=abc-123',
        )
