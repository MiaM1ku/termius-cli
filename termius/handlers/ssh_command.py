"""Print an ssh(1) command for a host without connecting."""
from ..account.managers import AccountManager
from ..core.commands import AbstractCommand
from ..core.commands.mixins import GetRelationMixin, SshConfigMergerMixin
from ..core.models.terminal import Host
from ..core.storage.strategies import RelatedGetStrategy
from ..formatters.mixins import SshCommandFormatterMixin


class SshCommandCommand(SshCommandFormatterMixin, SshConfigMergerMixin,
                        GetRelationMixin, AbstractCommand):
    """print an ssh command for a host (AI-friendly, no TTY)"""

    get_strategy = RelatedGetStrategy

    def extend_parser(self, parser):
        parser.add_argument('entry', metavar='ID or NAME')
        return parser

    def take_action(self, parsed_args):
        host = self.get_relation(Host, parsed_args.entry)
        ssh_config = self.get_merged_ssh_config(host)
        ssh_key = ssh_config.get_ssh_key()
        ssh_key_path = ssh_key and ssh_key.file_path(self)
        ssh_config['agent_forwarding'] = (
            AccountManager(self.config).get_settings().get('agent_forwarding')
        )
        command = self.render_command(ssh_config, host.address, ssh_key_path)
        self.app.stdout.write(command)
