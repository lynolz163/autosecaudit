"""Package entrypoint for `python -m autosecaudit`."""

from __future__ import annotations

import sys

from . import cli
from .commands import doctor as doctor_command
from .commands import init as init_command
from .commands import users as users_command
from .webapp import server as web_server


def main() -> int:
    """Dispatch package-level subcommands while preserving legacy CLI behavior."""
    argv = sys.argv[1:]
    if argv and argv[0] == "init":
        return init_command.main(argv[1:])
    if argv and argv[0] == "doctor":
        return doctor_command.main(argv[1:])
    if argv and argv[0] == "users":
        return users_command.main(argv[1:])
    if argv and argv[0] == "web":
        return web_server.main(argv[1:])
    return cli.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
