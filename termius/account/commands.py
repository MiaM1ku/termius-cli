# -*- coding: utf-8 -*-
"""Module to keep login and logout command."""
from contextlib import contextmanager
import getpass
import six
from ..core.commands import AbstractCommand
from ..core.signals import post_logout
from ..core.commands.arg_types import boolean_yes_no
from ..core.exceptions import OptionNotSetException
from ..core.api import AuthyTokenIssue
from ..core.exceptions import ApiError, OtpTokenRequired
from .managers import AccountManager


# pylint: disable=abstract-method
class BaseAccountCommand(AbstractCommand):
    """Base class for login and logout commands."""

    def __init__(self, app, app_args, cmd_name=None):
        """Construct new instance."""
        super(BaseAccountCommand, self).__init__(app, app_args, cmd_name)
        self.manager = AccountManager(self.config)


class LoginCommand(BaseAccountCommand):
    """sign into the Termius Cloud"""

    # pylint: disable=no-self-use
    def prompt_username(self):
        """Ask username prompt."""
        return six.moves.input('Username: ')

    # pylint: disable=no-self-use
    def prompt_authy_token(self):
        """Ask authy token prompt."""
        return six.moves.input('Authy token: ')

    # pylint: disable=no-self-use
    def prompt_encryption_password(self):
        """Ask for the vault encryption password after Google SSO."""
        return getpass.getpass('Encryption password: ')

    def extend_parser(self, parser):
        """Add more arguments to parser."""
        parser.add_argument('-u', '--username', metavar='USERNAME')
        parser.add_argument('-p', '--password', metavar='PASSWORD')
        parser.add_argument(
            '--google', action='store_true',
            help='Google SSO: print account.termius.com/sso/desktop, paste termius:// callback',
        )
        parser.add_argument(
            '--sso', choices=('google',),
            help='same as --google (currently only google)',
        )
        parser.add_argument(
            '--callback-url',
            help='termius://app/continue-sso?... URL (non-interactive)',
        )
        parser.add_argument(
            '--no-browser', action='store_true',
            help='ignored; the CLI never opens a browser',
        )
        parser.add_argument(
            '--otp', metavar='CODE',
            help='authenticator / Authy code if the account has 2FA',
        )
        return parser

    def take_action(self, parsed_args):
        """Process CLI call."""
        provider = (
            'google' if getattr(parsed_args, 'google', False)
            else getattr(parsed_args, 'sso', None)
        )
        callback_url = getattr(parsed_args, 'callback_url', None)
        if provider:
            self.log.info(
                'Google only proves who you are. After pasting the callback, '
                'Termius still needs the encryption password to unlock the vault.'
            )
            with on_clean_when_logout(self, self.manager):
                try:
                    identity = self.manager.prepare_sso(
                        provider=provider,
                        callback_url=callback_url,
                        log=self.log,
                        open_browser=False,
                    )
                except Exception as exc:
                    raise SystemExit(
                        'Google SSO failed ({}): {}'.format(
                            type(exc).__name__, exc
                        )
                    )
                self.log.info(
                    'Google identity: %s (%s)',
                    identity['email'], identity.get('action') or 'sign-in',
                )
                self.log.info(
                    'Enter the Termius encryption password to finish login.'
                )
                password = (
                    parsed_args.password or self.prompt_encryption_password()
                )
                if not password:
                    raise SystemExit(
                        'Encryption password is required after Google sign-in.'
                    )
                try:
                    self.manager.login(
                        identity['email'], password,
                        authy_token=getattr(parsed_args, 'otp', None),
                        firebase_token=identity['firebase_token'],
                    )
                except (AuthyTokenIssue, OtpTokenRequired):
                    authy_token = parsed_args.otp or self.prompt_authy_token()
                    self.manager.login(
                        identity['email'], password,
                        authy_token=authy_token,
                        firebase_token=identity['firebase_token'],
                    )
                except ApiError as exc:
                    raise SystemExit('Login failed: {}'.format(exc))
            self.log.info('\nSigned in as %s', identity['email'])
            return None
        else:
            username = parsed_args.username or self.prompt_username()
            password = parsed_args.password or self.prompt_password()
            with on_clean_when_logout(self, self.manager):
                try:
                    self.manager.login(
                        username, password,
                        authy_token=getattr(parsed_args, 'otp', None),
                    )
                except (AuthyTokenIssue, OtpTokenRequired):
                    authy_token = parsed_args.otp or self.prompt_authy_token()
                    self.manager.login(username, password, authy_token=authy_token)
                except ApiError as exc:
                    raise SystemExit('Login failed: {}'.format(exc))
        self.log.info('\nSigned in successfully')
        return None


class LogoutCommand(BaseAccountCommand):
    """sign out of the Termius Cloud"""

    def take_action(self, _):
        """Process CLI call."""
        with on_clean_when_logout(self, self.manager):
            self.manager.logout()
        self.log.info('Signed out')


class SettingsCommand(BaseAccountCommand):
    """update the account settings"""

    def extend_parser(self, parser):
        """Add more arguments to parser."""
        parser.add_argument(
            '--synchronize-key', action='store', type=boolean_yes_no,
            choices=(False, True), default=True,
            help='enable/disable ssh keys and identities sync'
        )
        parser.add_argument(
            '--agent-forwarding', action='store', type=boolean_yes_no,
            choices=(False, True), default=True,
            help='enable/disable agent forwarding'
        )
        return parser

    def take_action(self, parsed_args):
        """Process CLI call."""
        settings = {
            k: getattr(parsed_args, k)
            for k in ('synchronize_key', 'agent_forwarding')
        }
        self.manager.set_settings(settings)
        self.log.info('Settings updated')


@contextmanager
def on_clean_when_logout(command, manager):
    """Monitor is account changed and call data clean."""
    try:
        old_username = manager.username
    except OptionNotSetException:
        old_username = None
    yield
    try:
        new_username = manager.username
    except OptionNotSetException:
        new_username = None

    is_username_changed = (
        old_username and old_username != new_username
    )
    if is_username_changed:
        post_logout.send(command, command=command, email=old_username)
