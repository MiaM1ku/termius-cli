#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Start the Termius MCP server on stdio."""
import logging
import sys

from termius.mcp.server import run_stdio


def _configure_logging():
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.WARNING,
        format='%(levelname)s %(name)s: %(message)s',
    )
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('paramiko').setLevel(logging.WARNING)


def main(argv=None):
    """Process start from an MCP client or a terminal."""
    del argv
    _configure_logging()
    if sys.stdin.isatty():
        sys.stderr.write(
            'Termius MCP server. Point your MCP client at this binary '
            '(no args). Waiting on stdin.\n'
        )
        sys.stderr.flush()
    run_stdio()
    return 0


if __name__ == '__main__':
    sys.exit(main())
