# -*- coding: utf-8 -*-
"""Login and logout for the MCP process."""
import uuid

from .account.managers import AccountManager
from .cloud.client.browser_sso import desktop_sso_url
from .core.exceptions import (
    ApiError, AuthyTokenIssue, OptionNotSetException, OtpTokenRequired,
)
from .core.signals import post_logout
from .vault import forget, remember


def _previous_username(manager):
    try:
        return manager.username
    except OptionNotSetException:
        return None


def _clean_if_account_changed(runtime, manager, previous):
    current = _previous_username(manager)
    if previous and previous != current:
        post_logout.send(runtime, command=runtime, email=previous)


def login_email(runtime, username, password, otp=None, remember_password=True):
    """Sign in with email and vault/account password."""
    if not username:
        raise ValueError('username is required for email login')
    if not password:
        raise ValueError('password is required for email login')
    manager = AccountManager(runtime.config)
    previous = _previous_username(manager)
    try:
        manager.login(username, password, authy_token=otp)
    except (AuthyTokenIssue, OtpTokenRequired):
        if not otp:
            raise ValueError(
                'This account requires otp. Call login again with otp.'
            )
        manager.login(username, password, authy_token=otp)
    _clean_if_account_changed(runtime, manager, previous)
    if remember_password:
        remember(runtime, password)
    return {
        'ok': True,
        'username': username,
        'encryption_schema': runtime.config.get_safe(
            'User', 'encryption_schema', default=''
        ),
        'vault_remembered': remember_password,
    }


def login_google_start():
    """Return the desktop SSO URL. Does not wait for a browser."""
    request_id = str(uuid.uuid4())
    url = desktop_sso_url('google', request_id)
    return {
        'ok': True,
        'method': 'google',
        'url': url,
        'request_id': request_id,
        'next': 'login_complete',
        'instructions': (
            'Open url in a browser, sign in with Google, then call '
            'login_complete with the termius://app/continue-sso?... '
            'callback and the vault encryption password.'
        ),
    }


def login_google_complete(runtime, callback_url, password, otp=None,
                          remember_password=True):
    """Finish Google SSO with the pasted callback and vault password."""
    if not callback_url:
        raise ValueError('callback_url is required')
    if not password:
        raise ValueError(
            'password is required. Use the Termius vault encryption password.'
        )
    manager = AccountManager(runtime.config)
    previous = _previous_username(manager)
    identity = manager.prepare_sso(
        provider='google',
        callback_url=callback_url,
        open_browser=False,
    )
    try:
        manager.login(
            identity['email'], password,
            authy_token=otp,
            firebase_token=identity['firebase_token'],
        )
    except (AuthyTokenIssue, OtpTokenRequired):
        if not otp:
            raise ValueError(
                'This account requires otp. Call login_complete again with otp.'
            )
        manager.login(
            identity['email'], password,
            authy_token=otp,
            firebase_token=identity['firebase_token'],
        )
    except ApiError:
        raise
    _clean_if_account_changed(runtime, manager, previous)
    if remember_password:
        remember(runtime, password)
    return {
        'ok': True,
        'username': identity['email'],
        'encryption_schema': runtime.config.get_safe(
            'User', 'encryption_schema', default=''
        ),
        'vault_remembered': remember_password,
    }


def logout(runtime):
    """Clear the cloud session, remembered vault password, and local inventory."""
    manager = AccountManager(runtime.config)
    previous = _previous_username(manager)
    manager.logout()
    forget(runtime)
    if previous:
        post_logout.send(runtime, command=runtime, email=previous)
    return {'ok': True, 'logged_in': False}
