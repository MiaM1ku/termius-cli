# -*- coding: utf-8 -*-
"""Merge inherited SSH settings and look up hosts."""
from .exceptions import DoesNotExistException, TooManyEntriesException
from .models.terminal import Host, Identity, SshConfig
from .models.utils import GroupStackGenerator, Merger


class HostLookupError(ValueError):
    """Host id or label did not resolve to a single host."""


def get_group_stack(instance):
    """Return parent groups from nearest to root."""
    return GroupStackGenerator(instance).generate()


def get_merged_ssh_config(instance):
    """Return the host or group SSH config after group inheritance."""
    full_stack = [instance] + get_group_stack(instance)
    return merge_ssh_config(full_stack)


def merge_ssh_config(full_stack):
    """Squash a host/group stack into one SshConfig."""
    ssh_config_merger = Merger(full_stack, 'ssh_config', SshConfig())
    ssh_config = ssh_config_merger.merge()
    visible_identity = _visible_identity(ssh_config_merger)
    if visible_identity:
        ssh_config.identity = visible_identity
    else:
        ssh_config.identity = _identity_merger(ssh_config_merger).merge()
    return ssh_config


def _visible_identity(ssh_config_merger):
    stack = [
        item.identity for item in ssh_config_merger.get_entry_stack()
        if item.identity and item.identity.get('is_visible')
    ]
    return stack[0] if stack else None


def _identity_merger(ssh_config_merger):
    stack = [
        item for item in ssh_config_merger.get_entry_stack()
        if item.identity and not item.identity.get('is_visible')
    ]
    return Merger(stack, 'identity', Identity())


def find_host(storage, name):
    """Return one Host by numeric id or exact label."""
    if name is None or str(name).strip() == '':
        raise HostLookupError('Host id or label is required')
    name = str(name)
    try:
        relation_id = int(name)
    except (TypeError, ValueError):
        relation_id = None
    try:
        return storage.get(Host, query_union=any, id=relation_id, label=name)
    except DoesNotExistException:
        raise HostLookupError('Host not found: {}'.format(name))
    except TooManyEntriesException:
        raise HostLookupError(
            'Multiple hosts match "{}". Use the numeric id from hosts.'.format(
                name
            )
        )
