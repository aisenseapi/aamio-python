"""The commands under aamio addon domain.

    aamio addon domain file [--name NAME]    your public key as the list a website publishes
    aamio addon domain validate FILE         is this a valid list: reads one file, no domain and no home
    aamio addon domain allow DOMAIN          let this runtime read that website's list
    aamio addon domain forget DOMAIN
    aamio addon domain list
    aamio addon domain check DOMAIN --partner NAME [--name LABEL]

check exits 0 listed, 3 not_listed, 4 no_list, 5 unreachable and 2 invalid or
refused here before anything was read. listed says this site listed this key when
it was read, and permits nothing. The domain comes from your own records, never
from a message. A message can only be checked from inside aamio serve, through
aamio_addon_domain_check: what a process verified is not kept for the next one.
AAMIO_DOMAIN_DENY: comma separated networks a check never reads.
"""

import argparse
import json
import sys

from aamio.cli import out

from . import lists, policy

# One exit code per answer, so a script need not read the JSON to tell a key that
# is not listed from a list it could not read.
EXIT_CODES = {"listed": 0, "not_listed": 3, "no_list": 4, "unreachable": 5, "invalid": 2}


def add_commands(parser):
    parser.description = __doc__
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    sub = parser.add_subparsers(dest="domain_command", required=True)
    one = sub.add_parser("file", help="your public key as a list to publish at https://DOMAIN/.well-known/aamio-keys.json")
    one.add_argument("--name", help="a label for the key on the list, as support. It authorises nothing")
    one = sub.add_parser("validate", help="check a local file against the format. Reads no domain and no home")
    one.add_argument("file")
    one = sub.add_parser("allow", help="put a website on the list of those this runtime may read")
    one.add_argument("domain")
    one = sub.add_parser("forget", help="take a website off that list")
    one.add_argument("domain")
    sub.add_parser("list", help="the websites this runtime may read")
    one = sub.add_parser("check", help="read a website's list once and say whether it lists a partner's key")
    one.add_argument("domain")
    one.add_argument("--partner", required=True, help="a name in your address book")
    one.add_argument("--name", help="the label the key should be listed under; leave it out for any")


def early(args):
    """validate, before any runtime: creating one takes the home's lock and tidies the home, and this reads one file.

    It works beside a running server and on a machine with no home at all, and
    it cannot make a key by accident.
    """
    if args.domain_command == "validate":
        result, code = lists.check_file(args.file)
        out(result)
        return code
    return None


def command(args, runtime):
    """The commands that need the runtime. Adding a website is the user's word, here or in a form over MCP."""
    try:
        if args.domain_command == "file":
            raw = lists.make([{"key": runtime.keys.public, "name": args.name}])
            # The bytes as they are, so this is the file every generator writes:
            # print would turn the line break into CRLF on Windows.
            sys.stdout.flush()
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            print("aamio: this holds your public key and nothing secret. Publish it at https://YOUR-DOMAIN%s, with no login and no redirect, on a domain you already control." % lists.PATH, file=sys.stderr)
        elif args.domain_command == "allow":
            out(dict(policy.allow(runtime, args.domain), note="This runtime may now read this website's key list when a check asks for it. Nothing was read now, and a key it lists permits nothing."))
        elif args.domain_command == "forget":
            out(policy.forget(runtime, args.domain))
        elif args.domain_command == "list":
            out({"domains": policy.allowed_domains(runtime)})
        else:
            found = policy.check(runtime, args.domain, partner=args.partner, name=args.name)
            out(found)
            return EXIT_CODES[found["status"]]
    except lists.InvalidDocument as error:
        # To stderr: standard output here is the file, and `aamio addon domain file > aamio-keys.json`
        # would publish the complaint.
        print(json.dumps({"error": error.reason, "fix": "--name is a label of 1 to 64 characters of a-z, 0-9, dot, underscore and dash."}), file=sys.stderr)
        return 2
    except policy.Refused as refused:
        out(policy.refusal(refused))
        return 2
    return 0
