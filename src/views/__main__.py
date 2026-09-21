"""
CLI for src.views.  Run as:  python -m src.views <command> [...]

Commands:
    install <db>              create the analysis views in a SQLite .db
    dump <sql>                append CREATE VIEW DDL to a .sql dump
    emit [--dialect sqlite|pgsql]        print CREATE VIEW DDL to stdout
    artifacts <out_dir>       write views.sqlite.sql / views.pgsql.sql / catalog.json
    list <db>                 list the views installed in a .db
    read <db> [--view NAME] [--limit N]  read installed view(s) and print them
"""

from __future__ import annotations

import argparse
import sys

from . import (
    append_views_to_sql_dump,
    install_views_sqlite,
    list_views,
    read_all_views,
    read_view,
    views_ddl,
    write_sql_artifacts,
)


def _print_view(name, cols, rows) -> None:
    print(f"== {name} ==")
    print(" | ".join(cols))
    for r in rows:
        print(" | ".join("NULL" if c is None else str(c) for c in r))
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m src.views")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("install", help="create analysis views in a SQLite .db")
    sp.add_argument("db")
    sp.add_argument("--drop", action="store_true", help="drop existing views first")

    sp = sub.add_parser("dump", help="append CREATE VIEW DDL to a .sql dump")
    sp.add_argument("sql")
    sp.add_argument("--dialect", choices=["sqlite", "pgsql"], default=None)

    sp = sub.add_parser("emit", help="print CREATE VIEW DDL")
    sp.add_argument("--dialect", choices=["sqlite", "pgsql"], default="sqlite")

    sp = sub.add_parser("artifacts", help="write static sql/ artifacts")
    sp.add_argument("out_dir")

    sp = sub.add_parser("list", help="list views installed in a .db")
    sp.add_argument("db")

    sp = sub.add_parser("read", help="read installed views")
    sp.add_argument("db")
    sp.add_argument("--view", default=None)
    sp.add_argument("--limit", type=int, default=50)

    args = p.parse_args(argv)

    if args.cmd == "install":
        names = install_views_sqlite(args.db, drop_existing=args.drop)
        print(f"installed {len(names)} view(s): {', '.join(names)}")
    elif args.cmd == "dump":
        names = append_views_to_sql_dump(args.sql, dialect=args.dialect)
        print(f"appended {len(names)} view(s) to {args.sql}")
    elif args.cmd == "emit":
        print(views_ddl(args.dialect))
    elif args.cmd == "artifacts":
        for path in write_sql_artifacts(args.out_dir):
            print(f"wrote {path}")
    elif args.cmd == "list":
        for name in list_views(args.db):
            print(name)
    elif args.cmd == "read":
        if args.view:
            cols, rows = read_view(args.db, args.view, limit=args.limit)
            _print_view(args.view, cols, rows)
        else:
            for name, res in read_all_views(args.db, limit=args.limit).items():
                if "error" in res:
                    print(f"== {name} ==\nERROR: {res['error']}\n")
                else:
                    _print_view(name, res["columns"], res["rows"])
    else:  # pragma: no cover
        p.print_help()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
