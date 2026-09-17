"""Stdio MCP server exposing Termius inventory to AI agents."""
from __future__ import unicode_literals

import json
import sys
from argparse import Namespace

from ..account.managers import AccountManager
from ..app import TermiusApp
from ..core.commands.mixins import SshConfigMergerMixin
from ..core.models.terminal import Group, Host, Identity, SshKey, Snippet
from ..core.settings import Config
from ..core.storage import ApplicationStorage
from ..core.storage.strategies import RelatedGetStrategy
from ..formatters.mixins import SshCommandFormatterMixin


PROTOCOL_VERSION = '2024-11-05'

TOOLS = [
    {
        'name': 'termius_status',
        'description': 'Show Termius CLI login state and inventory counts.',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'termius_hosts',
        'description': 'List saved Termius hosts (label, address, group, id).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'query': {
                    'type': 'string',
                    'description': 'Optional substring filter on label or address',
                }
            },
        },
    },
    {
        'name': 'termius_host_info',
        'description': 'Get one host plus merged SSH settings and ssh command.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'name': {
                    'type': 'string',
                    'description': 'Host id or label',
                }
            },
            'required': ['name'],
        },
    },
    {
        'name': 'termius_identities',
        'description': 'List identities (usernames / keys). Passwords are omitted.',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'termius_keys',
        'description': 'List SSH keys. Private key material is omitted.',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'termius_groups',
        'description': 'List host groups.',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'termius_snippets',
        'description': 'List saved snippets / scripts.',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'termius_ssh_command',
        'description': 'Render an ssh(1) command line for a host.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'name': {'type': 'string', 'description': 'Host id or label'}
            },
            'required': ['name'],
        },
    },
]


class _Context(SshCommandFormatterMixin, SshConfigMergerMixin):
    def __init__(self):
        from os.path import expanduser
        from pathlib2 import Path as P
        self.app = TermiusApp()
        self.app.NAME = 'termius'
        self.app.directory_path = P(expanduser('~/.termius/'))
        if not self.app.directory_path.is_dir():
            self.app.directory_path.mkdir(parents=True)
        self.app_args = Namespace(verbose_level=1, debug=False, log_file=None)
        self.config = Config(self)
        self.storage = ApplicationStorage(self, get_strategy=RelatedGetStrategy)


def _ok(result):
    return {
        'content': [{'type': 'text', 'text': json.dumps(result, default=str, indent=2)}]
    }


def _find(storage, model, name):
    try:
        relation_id = int(name)
    except (TypeError, ValueError):
        relation_id = None
    return storage.get(model, query_union=any, id=relation_id, label=name)


def handle_tool(ctx, name, arguments):
    arguments = arguments or {}
    if name == 'termius_status':
        username = ctx.config.get_safe('User', 'username', default='')
        return _ok({
            'logged_in': bool(username),
            'username': username,
            'encryption_schema': ctx.config.get_safe(
                'User', 'encryption_schema', default=''
            ),
            'last_synced': ctx.config.get_safe(
                'CloudSynchronization', 'last_synced', default=''
            ),
            'hosts': len(ctx.storage.get_all(Host)),
            'groups': len(ctx.storage.get_all(Group)),
            'identities': len(ctx.storage.get_all(Identity)),
            'keys': len(ctx.storage.get_all(SshKey)),
            'snippets': len(ctx.storage.get_all(Snippet)),
        })
    if name == 'termius_hosts':
        query = (arguments.get('query') or '').lower()
        rows = []
        for host in ctx.storage.get_all(Host):
            row = {
                'id': host.id,
                'label': host.label,
                'address': host.address,
                'group': getattr(host.group, 'label', None),
            }
            blob = json.dumps(row).lower()
            if not query or query in blob:
                rows.append(row)
        return _ok(rows)
    if name == 'termius_host_info':
        host = _find(ctx.storage, Host, arguments['name'])
        ssh_config = ctx.get_merged_ssh_config(host)
        identity = ssh_config.identity
        ssh_key = ssh_config.get_ssh_key()
        ssh_config['agent_forwarding'] = (
            AccountManager(ctx.config).get_settings().get('agent_forwarding')
        )
        command = ctx.render_command(
            ssh_config, host.address, ssh_key and ssh_key.file_path(ctx)
        ).strip()
        return _ok({
            'id': host.id,
            'label': host.label,
            'address': host.address,
            'port': ssh_config.port,
            'username': identity.username if identity else None,
            'has_password': bool(identity and identity.password),
            'ssh_key': ssh_key.label if ssh_key else None,
            'ssh_command': command,
        })
    if name == 'termius_identities':
        rows = []
        for ident in ctx.storage.get_all(Identity):
            if ident.is_visible is False:
                continue
            rows.append({
                'id': ident.id,
                'label': ident.label,
                'username': ident.username,
                'has_password': bool(ident.password),
                'ssh_key': ident.ssh_key.label if ident.ssh_key else None,
            })
        return _ok(rows)
    if name == 'termius_keys':
        return _ok([
            {'id': key.id, 'label': key.label, 'has_private_key': bool(key.private_key)}
            for key in ctx.storage.get_all(SshKey)
        ])
    if name == 'termius_groups':
        return _ok([
            {'id': group.id, 'label': group.label}
            for group in ctx.storage.get_all(Group)
        ])
    if name == 'termius_snippets':
        return _ok([
            {'id': snippet.id, 'label': snippet.label, 'script': snippet.script}
            for snippet in ctx.storage.get_all(Snippet)
        ])
    if name == 'termius_ssh_command':
        host = _find(ctx.storage, Host, arguments['name'])
        ssh_config = ctx.get_merged_ssh_config(host)
        ssh_key = ssh_config.get_ssh_key()
        ssh_config['agent_forwarding'] = (
            AccountManager(ctx.config).get_settings().get('agent_forwarding')
        )
        command = ctx.render_command(
            ssh_config, host.address, ssh_key and ssh_key.file_path(ctx)
        ).strip()
        return _ok({'ssh_command': command})
    raise ValueError('Unknown tool: {}'.format(name))


def _respond(message_id, result=None, error=None):
    payload = {'jsonrpc': '2.0', 'id': message_id}
    if error is not None:
        payload['error'] = error
    else:
        payload['result'] = result
    sys.stdout.write(json.dumps(payload) + '\n')
    sys.stdout.flush()


def run_stdio():
    """Serve MCP over stdin/stdout."""
    ctx = _Context()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        method = message.get('method')
        message_id = message.get('id')
        params = message.get('params') or {}
        if method == 'initialize':
            _respond(message_id, {
                'protocolVersion': PROTOCOL_VERSION,
                'capabilities': {'tools': {}},
                'serverInfo': {'name': 'termius', 'version': '2.0.0'},
            })
        elif method == 'notifications/initialized':
            continue
        elif method == 'tools/list':
            _respond(message_id, {'tools': TOOLS})
        elif method == 'tools/call':
            try:
                result = handle_tool(ctx, params.get('name'), params.get('arguments'))
                _respond(message_id, result)
            except Exception as exc:
                _respond(message_id, {
                    'content': [{'type': 'text', 'text': str(exc)}],
                    'isError': True,
                })
        elif method == 'ping':
            _respond(message_id, {})
        elif message_id is not None:
            _respond(message_id, error={
                'code': -32601, 'message': 'Method not found: {}'.format(method)
            })
