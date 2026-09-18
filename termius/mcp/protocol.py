# -*- coding: utf-8 -*-
"""MCP stdio framing: newline-delimited JSON-RPC.

The MCP stdio transport is JSONL. OMP, Codex, and the spec send one JSON
object per line with no Content-Length headers. LSP-style Content-Length
frames are still accepted on read so an old client does not deadlock.
"""
from __future__ import unicode_literals

import json


class ProtocolError(ValueError):
    """Malformed MCP stdio frame."""


def encode_message(payload):
    """Return bytes for one MCP JSONL message."""
    body = json.dumps(payload, default=str, separators=(',', ':')).encode('utf-8')
    if b'\n' in body:
        raise ProtocolError('MCP JSONL payload must not contain newlines')
    return body + b'\n'


def write_message(stream, payload):
    """Write one JSONL message and flush."""
    stream.write(encode_message(payload))
    stream.flush()


def read_message(stream):
    """Read one JSON-RPC object from a binary stream.

    Returns None on EOF. Accepts JSONL (MCP) and Content-Length (legacy).
    """
    line = stream.readline()
    if not line:
        return None
    stripped = line.lstrip()
    if stripped.startswith(b'{') or stripped.startswith(b'['):
        return _loads(line)
    return _read_content_length(stream, line)


def _read_content_length(stream, first_line):
    headers = {}
    lines = [first_line]
    while True:
        line = lines.pop(0) if lines else stream.readline()
        if not line:
            return None
        if line in (b'\r\n', b'\n'):
            break
        try:
            decoded = line.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('MCP header is not ASCII')
        if ':' not in decoded:
            raise ProtocolError('MCP header is missing a colon')
        key, value = decoded.split(':', 1)
        headers[key.strip().lower()] = value.strip()
    raw_length = headers.get('content-length')
    if raw_length is None:
        raise ProtocolError('MCP frame is missing Content-Length')
    try:
        length = int(raw_length)
    except ValueError:
        raise ProtocolError('Content-Length is not an integer')
    if length < 0:
        raise ProtocolError('Content-Length is negative')
    body = _read_exact(stream, length)
    if body is None:
        return None
    return _loads(body)


def _loads(body):
    try:
        return json.loads(body.decode('utf-8'))
    except ValueError as exc:
        raise ProtocolError('MCP body is not JSON: {}'.format(exc))


def _read_exact(stream, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)
