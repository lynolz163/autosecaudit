"""Offline user management for the web console database."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from autosecaudit.webapp.auth import AuthService
from autosecaudit.webapp.job_index import JobIndexStore


def build_parser() -> argparse.ArgumentParser:
    """Build parser for `python -m autosecaudit users`."""
    parser = argparse.ArgumentParser(
        prog="python -m autosecaudit users",
        description="Manage persisted web-console users without opening the UI.",
    )
    parser.add_argument(
        "--workspace",
        default=str(Path.cwd()),
        help="Workspace path. Default: current directory.",
    )
    parser.add_argument(
        "--output-root",
        default="output/web-jobs",
        help="Web output root relative to workspace. Default: output/web-jobs",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Explicit SQLite DB path. Overrides --workspace/--output-root.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List all persisted users.")

    create = subparsers.add_parser("create", help="Create one user.")
    create.add_argument("--username", required=True, help="Username")
    create.add_argument("--password", required=True, help="Password")
    create.add_argument("--role", choices=("admin", "operator", "viewer"), default="viewer", help="Role")
    create.add_argument("--display-name", default=None, help="Display name")
    create.add_argument("--disabled", action="store_true", help="Create the user in disabled state")

    create_admin = subparsers.add_parser("create-admin", help="Create or reset an admin user.")
    create_admin.add_argument("--username", required=True, help="Admin username")
    create_admin.add_argument("--password", required=True, help="Admin password")
    create_admin.add_argument("--display-name", default=None, help="Display name")
    create_admin.add_argument(
        "--if-missing",
        action="store_true",
        help="Only create when the user does not already exist.",
    )

    freeze = subparsers.add_parser("freeze", help="Freeze one user account.")
    freeze.add_argument("--username", required=True, help="Username")

    unfreeze = subparsers.add_parser("unfreeze", help="Unfreeze one user account.")
    unfreeze.add_argument("--username", required=True, help="Username")

    delete = subparsers.add_parser("delete", help="Delete one user account.")
    delete.add_argument("--username", required=True, help="Username")

    set_password = subparsers.add_parser("set-password", help="Reset password for one user.")
    set_password.add_argument("--username", required=True, help="Username")
    set_password.add_argument("--password", required=True, help="New password")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint for `autosecaudit users`."""
    args = build_parser().parse_args(argv)
    db_path = _resolve_db_path(
        workspace=Path(args.workspace),
        output_root=Path(args.output_root),
        db_path=(Path(args.db_path) if args.db_path else None),
    )
    store = JobIndexStore(db_path)
    auth = AuthService(store, bootstrap_token=None)
    try:
        command = str(args.command)
        if command == "list":
            _print_users(auth.list_users())
            return 0
        if command == "create":
            item = auth.create_user(
                username=str(args.username),
                password=str(args.password),
                role=str(args.role),
                display_name=(str(args.display_name).strip() or None) if args.display_name is not None else None,
                enabled=not bool(args.disabled),
            )
            print(f"created user: {item['username']} role={item['role']} enabled={item['enabled']}")
            return 0
        if command == "create-admin":
            item = auth.ensure_admin_user(
                username=str(args.username),
                password=str(args.password),
                display_name=(str(args.display_name).strip() or None) if args.display_name is not None else None,
                enabled=True,
                only_if_missing=bool(args.if_missing),
            )
            print(f"admin ready: {item['username']} role={item['role']} enabled={item['enabled']}")
            return 0
        if command == "freeze":
            user = store.get_user_by_username(str(args.username))
            item = auth.update_user(int(user["user_id"]), enabled=False)
            print(f"frozen user: {item['username']}")
            return 0
        if command == "unfreeze":
            user = store.get_user_by_username(str(args.username))
            item = auth.update_user(int(user["user_id"]), enabled=True)
            print(f"unfrozen user: {item['username']}")
            return 0
        if command == "delete":
            user = store.get_user_by_username(str(args.username))
            auth.delete_user(int(user["user_id"]))
            print(f"deleted user: {user['username']}")
            return 0
        if command == "set-password":
            user = store.get_user_by_username(str(args.username))
            item = auth.update_user(int(user["user_id"]), password=str(args.password))
            print(f"password updated: {item['username']}")
            return 0
        print(f"unknown command: {command}")
        return 2
    except KeyError:
        print("user_not_found")
        return 2
    except Exception as exc:  # noqa: BLE001
        print(str(exc))
        return 2
    finally:
        store.close()


def _resolve_db_path(*, workspace: Path, output_root: Path, db_path: Path | None) -> Path:
    if db_path is not None:
        return db_path.expanduser().resolve()
    resolved_workspace = workspace.expanduser().resolve()
    resolved_output_root = output_root.expanduser()
    if not resolved_output_root.is_absolute():
        resolved_output_root = (resolved_workspace / resolved_output_root).resolve()
    else:
        resolved_output_root = resolved_output_root.resolve()
    return resolved_output_root / ".autosecaudit-web.sqlite3"


def _print_users(users: list[dict[str, object]]) -> None:
    if not users:
        print("no users")
        return
    for item in users:
        print(
            "{username}\t{role}\t{enabled}\t{display_name}\t{last_login_at}".format(
                username=item.get("username") or "",
                role=item.get("role") or "",
                enabled="enabled" if bool(item.get("enabled")) else "frozen",
                display_name=item.get("display_name") or "-",
                last_login_at=item.get("last_login_at") or "-",
            )
        )


if __name__ == "__main__":
    raise SystemExit(main())
