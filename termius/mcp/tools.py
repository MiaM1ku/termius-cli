# -*- coding: utf-8 -*-
"""MCP tool definitions and handlers."""
from __future__ import unicode_literals

from ..account.managers import AccountManager
from ..core.exceptions import ApiError, NotSignedIn
from ..core.models.terminal import Group, Host, Identity, Snippet, SshKey
from ..core.ssh_command import render_command
from ..core.ssh_exec import SshExecError, run_host_command
from ..core.ssh_merge import HostLookupError, find_host, get_merged_ssh_config
from ..session import (
    login_email, login_google_complete, login_google_start, logout,
)
from ..sync import (
    ensure_fresh, inventory_counts, last_synced_raw, pull, status_payload,
)
from ..vault import VaultPasswordRequired, remember


class ToolError(Exception):
    """User-facing tool failure."""

    def __init__(self, message, code=None):
        super(ToolError, self).__init__(message)
        self.code = code


TOOLS = [
    {
        'name': 'status',
        'description': (
            'Show Termius login state, last cloud sync time, whether the '
            'local vault cache is stale, whether the vault password is '
            'remembered, and inventory counts. Does not sync. Call this '
            'first when you do not know if the user is signed in.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'login',
        'description': (
            'Sign in to Termius Cloud. method=email needs username and '
            'password (the vault encryption password). method=google returns '
            'a URL; after the user pastes termius://app/continue-sso?... '
            'call login_complete. Does not pull inventory; hosts/exec will '
            'auto-sync after a password is remembered.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'method': {
                    'type': 'string',
                    'enum': ['email', 'google'],
                    'description': 'email or google (default email)',
                },
                'username': {
                    'type': 'string',
                    'description': 'Termius email (email method)',
                },
                'password': {
                    'type': 'string',
                    'description': 'Vault / account password (email method)',
                },
                'otp': {
                    'type': 'string',
                    'description': 'Authenticator / Authy code if 2FA is on',
                },
                'remember': {
                    'type': 'boolean',
                    'description': (
                        'Store the vault password in ~/.termius/vault '
                        '(mode 0600). Default true.'
                    ),
                },
            },
        },
    },
    {
        'name': 'login_complete',
        'description': (
            'Finish Google SSO. Pass the termius:// callback from login '
            'and the vault encryption password (not the Google password).'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'callback_url': {
                    'type': 'string',
                    'description': 'termius://app/continue-sso?... URL',
                },
                'password': {
                    'type': 'string',
                    'description': 'Termius vault encryption password',
                },
                'otp': {
                    'type': 'string',
                    'description': 'Authenticator / Authy code if 2FA is on',
                },
                'remember': {
                    'type': 'boolean',
                    'description': (
                        'Store the vault password in ~/.termius/vault. '
                        'Default true.'
                    ),
                },
            },
            'required': ['callback_url', 'password'],
        },
    },
    {
        'name': 'logout',
        'description': (
            'Sign out, delete the remembered vault password, and wipe the '
            'local inventory.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'sync',
        'description': (
            'Force a pull from Termius Cloud now. Password comes from the '
            'password argument, TERMIUS_VAULT_PASSWORD, or ~/.termius/vault. '
            'Use this when status.stale is true and auto-sync failed, or '
            'when you just changed hosts in the Termius app.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'password': {
                    'type': 'string',
                    'description': 'Vault password if it is not remembered',
                },
                'remember': {
                    'type': 'boolean',
                    'description': (
                        'Store password in ~/.termius/vault when supplied. '
                        'Default true.'
                    ),
                },
            },
        },
    },
    {
        'name': 'hosts',
        'description': (
            'List Termius hosts (id, label, address, group, username). '
            'Auto-pulls a stale vault first. Filter with query against '
            'label, address, group, or username. Use host for full SSH '
            'settings. Use exec to run a command.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'query': {
                    'type': 'string',
                    'description': (
                        'Optional case-insensitive substring on label, '
                        'address, group, or username'
                    ),
                },
            },
        },
    },
    {
        'name': 'host',
        'description': (
            'One host plus merged SSH settings and a generated ssh(1) '
            'command. Auto-pulls a stale vault first. name is id or label. '
            'Does not return passwords or private keys.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'name': {
                    'type': 'string',
                    'description': 'Host numeric id or exact label',
                },
            },
            'required': ['name'],
        },
    },
    {
        'name': 'exec',
        'description': (
            'Run a shell command on a Termius host over SSH. Uses the '
            'username, password, or key from the vault. Auto-pulls a stale '
            'vault first. Returns stdout, stderr, and exit_code. Never echo '
            'secrets from the output unless the user asked for that command.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'name': {
                    'type': 'string',
                    'description': 'Host numeric id or exact label',
                },
                'command': {
                    'type': 'string',
                    'description': 'Remote shell command',
                },
                'timeout': {
                    'type': 'integer',
                    'description': 'Seconds to wait (default 60)',
                },
            },
            'required': ['name', 'command'],
        },
    },
    {
        'name': 'inventory',
        'description': (
            'List groups, identities, SSH keys, or snippets. Auto-pulls a '
            'stale vault first. Identities and keys omit secret material. '
            'Snippets include the script text.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'kind': {
                    'type': 'string',
                    'enum': ['groups', 'identities', 'keys', 'snippets'],
                    'description': 'Which inventory set to list',
                },
            },
            'required': ['kind'],
        },
    },
]


def _bool_arg(arguments, key, default=True):
    if key not in arguments or arguments.get(key) is None:
        return default
    value = arguments.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes')
    return bool(value)


def _auto_sync(runtime):
    try:
        return ensure_fresh(runtime)
    except NotSignedIn as exc:
        raise ToolError(str(exc), code='not_signed_in')
    except VaultPasswordRequired as exc:
        raise ToolError(str(exc), code='vault_password_required')
    except Exception as exc:
        raise ToolError(
            'Cloud pull failed: {}'.format(exc), code='sync_failed'
        )


def _host_row(runtime, host):
    ssh_config = get_merged_ssh_config(host)
    identity = ssh_config.identity
    return {
        'id': host.id,
        'label': host.label,
        'address': host.address,
        'group': getattr(host.group, 'label', None),
        'username': identity.username if identity else None,
        'has_password': bool(identity and identity.password),
    }


def _matches_query(row, query):
    if not query:
        return True
    needle = query.lower()
    haystacks = (
        str(row.get('label') or ''),
        str(row.get('address') or ''),
        str(row.get('group') or ''),
        str(row.get('username') or ''),
    )
    return any(needle in item.lower() for item in haystacks)


def handle_status(runtime, arguments):
    data = status_payload(runtime)
    return data, _status_summary(data)


def _status_summary(data):
    if not data['logged_in']:
        return 'Not signed in. Call login.'
    stale = 'stale' if data['stale'] else 'fresh'
    return 'Signed in as {}, {} hosts, cache {}.'.format(
        data['username'] or 'unknown', data['hosts'], stale
    )


def handle_login(runtime, arguments):
    method = (arguments.get('method') or 'email').strip().lower()
    remember_password = _bool_arg(arguments, 'remember', True)
    if method == 'google':
        data = login_google_start()
        return data, data['instructions']
    if method != 'email':
        raise ToolError(
            'method must be email or google', code='invalid_argument'
        )
    try:
        data = login_email(
            runtime,
            arguments.get('username'),
            arguments.get('password'),
            otp=arguments.get('otp'),
            remember_password=remember_password,
        )
    except (ValueError, ApiError) as exc:
        raise ToolError(str(exc), code='login_failed')
    return data, 'Signed in as {}.'.format(data['username'])


def handle_login_complete(runtime, arguments):
    remember_password = _bool_arg(arguments, 'remember', True)
    try:
        data = login_google_complete(
            runtime,
            arguments.get('callback_url'),
            arguments.get('password'),
            otp=arguments.get('otp'),
            remember_password=remember_password,
        )
    except (ValueError, ApiError) as exc:
        raise ToolError(str(exc), code='login_failed')
    return data, 'Signed in as {}.'.format(data['username'])


def handle_logout(runtime, arguments):
    data = logout(runtime)
    return data, 'Signed out.'


def handle_sync(runtime, arguments):
    from ..vault import resolve
    password = arguments.get('password') or resolve(runtime)
    if not password:
        raise ToolError(
            'Vault password is not available. Pass password, set '
            'TERMIUS_VAULT_PASSWORD, or call login with remember=true.',
            code='vault_password_required',
        )
    remember_password = _bool_arg(arguments, 'remember', True)
    try:
        data = pull(runtime, password)
    except NotSignedIn as exc:
        raise ToolError(str(exc), code='not_signed_in')
    except Exception as exc:
        raise ToolError(
            'Cloud pull failed: {}'.format(exc), code='sync_failed'
        )
    if remember_password and arguments.get('password'):
        remember(runtime, arguments.get('password'))
        data['vault_remembered'] = True
    else:
        data['vault_remembered'] = remember_password and bool(resolve(runtime))
    data['counts'] = inventory_counts(runtime)
    return data, 'Pulled inventory. last_synced={}.'.format(
        data.get('last_synced') or last_synced_raw(runtime.config)
    )


def handle_hosts(runtime, arguments):
    _auto_sync(runtime)
    query = arguments.get('query') or ''
    rows = []
    for host in runtime.storage.get_all(Host):
        row = _host_row(runtime, host)
        if _matches_query(row, query):
            rows.append(row)
    data = {'hosts': rows, 'count': len(rows)}
    return data, '{} hosts.'.format(len(rows))


def handle_host(runtime, arguments):
    _auto_sync(runtime)
    try:
        host = find_host(runtime.storage, arguments.get('name'))
    except HostLookupError as exc:
        raise ToolError(str(exc), code='host_not_found')
    ssh_config = get_merged_ssh_config(host)
    identity = ssh_config.identity
    ssh_key = ssh_config.get_ssh_key()
    ssh_config['agent_forwarding'] = (
        AccountManager(runtime.config).get_settings().get('agent_forwarding')
    )
    key_path = ssh_key.file_path(runtime) if ssh_key else None
    command = render_command(
        ssh_config, host.address, key_path
    )
    snippet = ssh_config.startup_snippet
    data = {
        'id': host.id,
        'label': host.label,
        'address': host.address,
        'group': getattr(host.group, 'label', None),
        'port': ssh_config.port,
        'username': identity.username if identity else None,
        'has_password': bool(identity and identity.password),
        'ssh_key': ssh_key.label if ssh_key else None,
        'ssh_key_path': str(key_path) if key_path else None,
        'strict_host_key_check': ssh_config.strict_host_key_check,
        'use_ssh_key': ssh_config.use_ssh_key,
        'timeout': ssh_config.timeout,
        'keep_alive_packages': ssh_config.keep_alive_packages,
        'agent_forwarding': ssh_config.agent_forwarding,
        'startup_snippet': snippet.label if snippet else None,
        'ssh_command': command,
    }
    return data, '{} ({})'.format(host.label or host.address, host.address)


def handle_exec(runtime, arguments):
    _auto_sync(runtime)
    command = arguments.get('command')
    if not command or not str(command).strip():
        raise ToolError('command is required', code='invalid_argument')
    try:
        host = find_host(runtime.storage, arguments.get('name'))
    except HostLookupError as exc:
        raise ToolError(str(exc), code='host_not_found')
    ssh_config = get_merged_ssh_config(host)
    timeout = arguments.get('timeout') or 60
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        raise ToolError('timeout must be an integer', code='invalid_argument')
    try:
        result = run_host_command(
            host, ssh_config, command, timeout=timeout,
        )
    except SshExecError as exc:
        raise ToolError(str(exc), code='ssh_failed')
    result['ok'] = result.get('exit_code') == 0
    summary = 'exit {} on {}.'.format(
        result.get('exit_code'), result.get('host')
    )
    return result, summary


def handle_inventory(runtime, arguments):
    _auto_sync(runtime)
    kind = (arguments.get('kind') or '').strip().lower()
    if kind == 'groups':
        rows = [
            {'id': group.id, 'label': group.label}
            for group in runtime.storage.get_all(Group)
        ]
    elif kind == 'identities':
        rows = []
        for ident in runtime.storage.get_all(Identity):
            if ident.is_visible is False:
                continue
            rows.append({
                'id': ident.id,
                'label': ident.label,
                'username': ident.username,
                'has_password': bool(ident.password),
                'ssh_key': ident.ssh_key.label if ident.ssh_key else None,
            })
    elif kind == 'keys':
        rows = [
            {
                'id': key.id,
                'label': key.label,
                'has_private_key': bool(key.private_key),
            }
            for key in runtime.storage.get_all(SshKey)
        ]
    elif kind == 'snippets':
        rows = [
            {
                'id': snippet.id,
                'label': snippet.label,
                'script': snippet.script,
            }
            for snippet in runtime.storage.get_all(Snippet)
        ]
    else:
        raise ToolError(
            'kind must be groups, identities, keys, or snippets',
            code='invalid_argument',
        )
    data = {'kind': kind, 'items': rows, 'count': len(rows)}
    return data, '{} {}.'.format(len(rows), kind)


HANDLERS = {
    'status': handle_status,
    'login': handle_login,
    'login_complete': handle_login_complete,
    'logout': handle_logout,
    'sync': handle_sync,
    'hosts': handle_hosts,
    'host': handle_host,
    'exec': handle_exec,
    'inventory': handle_inventory,
}


def call_tool(runtime, name, arguments):
    """Dispatch a tool. Returns (data, summary) or raises ToolError."""
    handler = HANDLERS.get(name)
    if handler is None:
        raise ToolError('Unknown tool: {}'.format(name), code='unknown_tool')
    return handler(runtime, arguments or {})
