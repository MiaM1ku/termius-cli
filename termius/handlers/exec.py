# -*- coding: utf-8 -*-
"""Run a command on a saved Termius host."""
from ..core.commands import AbstractCommand
from ..core.commands.mixins import GetRelationMixin, SshConfigMergerMixin
from ..core.models.terminal import Host
from ..core.ssh_exec import SshExecError, run_host_command
from ..core.storage.strategies import RelatedGetStrategy


class ExecCommand(SshConfigMergerMixin, GetRelationMixin,
                  AbstractCommand):
    """run a command on a host over SSH"""

    get_strategy = RelatedGetStrategy

    def extend_parser(self, parser):
        parser.add_argument('host', metavar='HOST', help='host id or label')
        parser.add_argument(
            '-t', '--timeout', type=int, default=60,
            help='SSH timeout in seconds',
        )
        parser.add_argument(
            'command', nargs='+', help='command to run on the host',
        )
        return parser

    def take_action(self, parsed_args):
        host = self.get_relation(Host, parsed_args.host)
        ssh_config = self.get_merged_ssh_config(host)
        command = ' '.join(parsed_args.command)
        try:
            result = run_host_command(
                host, ssh_config, command, timeout=parsed_args.timeout,
            )
        except SshExecError as exc:
            self.app.stdout.write('{}\n'.format(exc))
            raise SystemExit(1)
        if result['stdout']:
            self.app.stdout.write(result['stdout'])
            if not result['stdout'].endswith('\n'):
                self.app.stdout.write('\n')
        if result['stderr']:
            self.app.stderr.write(result['stderr'])
            if not result['stderr'].endswith('\n'):
                self.app.stderr.write('\n')
        if result['exit_code']:
            raise SystemExit(result['exit_code'])
