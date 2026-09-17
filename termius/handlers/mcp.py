"""Run the Termius MCP server on stdio."""
from ..core.commands import AbstractCommand
from ..mcp.server import run_stdio


class McpCommand(AbstractCommand):
    """run an MCP server on stdio for AI agents"""

    def take_action(self, parsed_args):
        run_stdio()
