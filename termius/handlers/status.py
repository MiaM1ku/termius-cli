"""Show local Termius CLI session status."""
from cliff.show import ShowOne

from ..core.commands import AbstractCommand
from ..core.models.terminal import Group, Host, Identity, SshKey, Snippet
from ..core.storage.strategies import RelatedGetStrategy


class StatusCommand(ShowOne, AbstractCommand):
    """show login and local inventory status"""

    get_strategy = RelatedGetStrategy

    def take_action(self, parsed_args):
        try:
            username = self.config.get('User', 'username')
            logged_in = True
        except Exception:
            username = ''
            logged_in = False
        schema = self.config.get_safe('User', 'encryption_schema', default='')
        last_synced = self.config.get_safe(
            'CloudSynchronization', 'last_synced', default=''
        )
        has_keypair = bool(self.config.get_safe('User', 'private_key', default=''))
        is_team = self.config.get_safe('User', 'is_team', default='no')
        counts = {
            'hosts': len(self.storage.get_all(Host)),
            'groups': len(self.storage.get_all(Group)),
            'identities': len(self.storage.get_all(Identity)),
            'keys': len(self.storage.get_all(SshKey)),
            'snippets': len(self.storage.get_all(Snippet)),
        }
        keys = (
            'logged_in', 'username', 'encryption_schema', 'is_team',
            'has_keypair', 'last_synced', 'hosts', 'groups',
            'identities', 'keys', 'snippets',
        )
        values = (
            logged_in, username, schema, is_team == 'yes',
            has_keypair, last_synced,
            counts['hosts'], counts['groups'], counts['identities'],
            counts['keys'], counts['snippets'],
        )
        return keys, values
