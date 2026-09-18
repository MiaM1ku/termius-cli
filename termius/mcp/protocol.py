# -*- coding: utf-8 -*-
"""MCP stdio framing: Content-Length headers + JSON-RPC."""
from __future__ import unicode_literals

import json


class ProtocolError(ValueError):
    """Malformed MCP stdio frame."""


def encode_message(payload):
    """Return bytes for one MCP message (headers + JSON body)."""
    body = json.dumps(payload, default=str, separators=(',', ':')).encode('utf-8')
    header = 'Content-Length: {}\r\n\r\n'.format(len(body)).encode('ascii')
    return header + body


def write_message(stream, payload):
    """Write one framed message and flush."""
    stream.write(encode_message(payload))
    stream.flush()


def read_message(stream):
    """Read one framed JSON-RPC object from a binary stream.

    Returns None on EOF. Accepts ``\\r\\n`` or ``\\n`` header line endings.
    """
    headers = {}
    saw_header = False
    while True:
        line = stream.readline()
        if not line:
            return None if not saw_header else None
        if line in (b'\r\n', b'\n'):
            break
        saw_header = True
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
