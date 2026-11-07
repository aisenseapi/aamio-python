"""The format on local files, for a website owner who runs no aamio: make a list of several keys, or check a file.

    python -m aamio_domain_keys make KEY[:NAME] ...    the file for these keys, on standard output
    python -m aamio_domain_keys make --empty           a list that lists no key, on purpose
    python -m aamio_domain_keys check FILE [--key KEY [--name NAME]]

Nothing here reads a domain, and every answer says so. An aamio user has
`aamio addon domain file` for their own key and `aamio addon domain validate`
for a file.
"""

import argparse
import json
import sys

from . import lists


def _entry_argument(text: str) -> dict:
    # KEY or KEY:NAME. Neither base64url nor a name holds a colon.
    key, _, name = text.partition(":")
    return {"key": key, "name": name} if name else {"key": key}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aamio_domain_keys",
        description="The domain key list format, on local files only. Nothing here reads a domain.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check a local file, and whether it lists a key")
    check.add_argument("file")
    check.add_argument("--key", help="a public key to look for in the file")
    check.add_argument("--name", help="and the name it should be listed under")
    made = commands.add_parser("make", help="write the file for a list of public keys to standard output")
    made.add_argument("entries", nargs="*", metavar="KEY[:NAME]")
    made.add_argument("--empty", action="store_true", help="write a list with no key, on purpose")
    args = parser.parse_args(argv)

    if args.command == "make":
        if not args.entries and not args.empty:
            parser.error("give at least one KEY[:NAME], or --empty for a list that lists no key")
        try:
            raw = lists.make([_entry_argument(text) for text in args.entries])
        except lists.InvalidDocument as error:
            print(json.dumps({"error": error.reason}), file=sys.stderr)
            return 2
        sys.stdout.buffer.write(raw)
        sys.stdout.flush()
        return 0

    if args.name is not None and args.key is None:
        parser.error("--name needs --key")
    result, code = lists.check_file(args.file, args.key, args.name)
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
