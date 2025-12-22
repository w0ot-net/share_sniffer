#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile


COMMON_SMBCLIENT_PATHS = [
    "/usr/share/doc/python3-impacket/examples/smbclient.py",
    "/usr/lib/python3/dist-packages/impacket/examples/smbclient.py",
    "/usr/local/bin/smbclient.py",
    "/usr/bin/smbclient.py",
]


def print_wrapper_help():
    print("wrapper options:")
    print("  --targets <host|ip|file>       can be repeated; file has one target per line")
    print("  --username <name>              optional username to apply to all targets")
    print("  --domain <name>                optional domain to apply to all targets")
    print("  --password <value>             optional password to apply to all targets")
    print("  --debug                        print smbclient output on failures")
    print("  -o, --output <dir>             output directory (default: ./results)")


def build_smbclient_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="SMB client implementation.",
    )
    parser.add_argument("-file", type=argparse.FileType("r"), help="input file with commands to execute in the mini shell")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")
    group.add_argument(
        "-k",
        action="store_true",
        help=(
            "Use Kerberos authentication. Grabs credentials from ccache file "
            "(KRB5CCNAME) based on target parameters. If valid credentials "
            "cannot be found, it will use the ones specified in the command line"
        ),
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )

    group = parser.add_argument_group("connection")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain part "
            "(FQDN) specified in the target parameter"
        ),
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the target machine. If omitted it will use whatever was specified as target. "
            "This is useful when target is the NetBIOS name and you cannot resolve it"
        ),
    )
    group.add_argument(
        "-port",
        choices=["139", "445"],
        nargs="?",
        default="445",
        metavar="destination port",
        help="Destination port to connect to SMB Server",
    )
    return parser


def split_args(argv):
    targets = []
    passthrough = []
    wrapper = {
        "username": None,
        "domain": None,
        "password": None,
        "debug": False,
        "output": "./results",
    }
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--targets":
            if idx + 1 >= len(argv):
                return None, None, None, "error: --targets requires a value"
            targets.append(argv[idx + 1])
            idx += 2
            continue
        if arg.startswith("--targets="):
            targets.append(arg.split("=", 1)[1])
            idx += 1
            continue
        if arg in ("--username", "--user"):
            if idx + 1 >= len(argv):
                return None, None, None, f"error: {arg} requires a value"
            wrapper["username"] = argv[idx + 1]
            idx += 2
            continue
        if arg.startswith("--username="):
            wrapper["username"] = arg.split("=", 1)[1]
            idx += 1
            continue
        if arg.startswith("--user="):
            wrapper["username"] = arg.split("=", 1)[1]
            idx += 1
            continue
        if arg == "--domain":
            if idx + 1 >= len(argv):
                return None, None, None, "error: --domain requires a value"
            wrapper["domain"] = argv[idx + 1]
            idx += 2
            continue
        if arg.startswith("--domain="):
            wrapper["domain"] = arg.split("=", 1)[1]
            idx += 1
            continue
        if arg == "--password":
            if idx + 1 >= len(argv):
                return None, None, None, "error: --password requires a value"
            wrapper["password"] = argv[idx + 1]
            idx += 2
            continue
        if arg.startswith("--password="):
            wrapper["password"] = arg.split("=", 1)[1]
            idx += 1
            continue
        if arg == "--debug":
            wrapper["debug"] = True
            idx += 1
            continue
        if arg in ("-o", "--output"):
            if idx + 1 >= len(argv):
                return None, None, None, f"error: {arg} requires a value"
            wrapper["output"] = argv[idx + 1]
            idx += 2
            continue
        if arg.startswith("--output="):
            wrapper["output"] = arg.split("=", 1)[1]
            idx += 1
            continue
        passthrough.append(arg)
        idx += 1
    return targets, wrapper, passthrough, None


def expand_targets(raw_targets):
    targets = []
    for raw in raw_targets:
        if os.path.isfile(raw):
            with open(raw, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    targets.append(line)
            continue
        targets.append(raw)

    seen = set()
    deduped = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            deduped.append(target)
    return deduped


def ensure_smbclient_on_path():
    path = shutil.which("smbclient.py")
    if path:
        return path

    candidates = [p for p in COMMON_SMBCLIENT_PATHS if os.path.isfile(p)]
    if not candidates:
        print("error: smbclient.py not found on PATH or in common locations.", file=sys.stderr)
        print("checked:", *COMMON_SMBCLIENT_PATHS, sep="\n  ", file=sys.stderr)
        sys.exit(1)

    candidate = candidates[0]
    if not sys.stdin.isatty():
        print(
            f"error: smbclient.py not on PATH. Found {candidate} but cannot prompt to add PATH.",
            file=sys.stderr,
        )
        sys.exit(1)

    reply = input(
        f"smbclient.py not on PATH. Found at {candidate}. "
        "Add its directory to PATH for this run? [y/N]: "
    ).strip().lower()
    if reply != "y":
        print("error: smbclient.py not on PATH; refusing to operate.", file=sys.stderr)
        sys.exit(1)

    os.environ["PATH"] = f"{os.path.dirname(candidate)}{os.pathsep}{os.environ.get('PATH', '')}"
    path = shutil.which("smbclient.py")
    if not path:
        print("error: failed to add smbclient.py to PATH.", file=sys.stderr)
        sys.exit(1)
    return path


def sanitize_target(target):
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def build_target(target, username, domain, password):
    if "@" in target:
        return target

    if domain or password:
        if not username:
            raise ValueError("error: --domain/--password require --username")

    if not username:
        return target

    userpart = username
    if domain:
        userpart = f"{domain}/{username}"
    if password is not None:
        userpart = f"{userpart}:{password}"
    return f"{userpart}@{target}"


def run_smbclient(smbclient_path, smbclient_args, target, command, debug):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(command)
            handle.write("\n")
            temp_path = handle.name
        cmd = [smbclient_path] + smbclient_args + ["-file", temp_path, target]
        result = subprocess.run(cmd, capture_output=True, text=True)
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    output = result.stdout or ""
    if result.stderr:
        if output and not output.endswith("\n"):
            output += "\n"
        output += result.stderr
    if debug:
        print(f"[debug] smbclient cmd: {' '.join(cmd)}")
    return result.returncode, output


def parse_shares(output):
    shares = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("sharename") or line.startswith("----"):
            continue
        if line.startswith("SMB") or line.startswith("Authentication"):
            continue
        parts = re.split(r"\s{2,}", line)
        if parts and parts[0]:
            shares.append(parts[0])
    return shares


def main(argv):
    targets_raw, wrapper, smbclient_args, err = split_args(argv)
    if err:
        print(err, file=sys.stderr)
        print_wrapper_help()
        return 1

    parser = build_smbclient_parser()
    try:
        parsed, unknown = parser.parse_known_args(smbclient_args)
    except SystemExit as exc:
        if exc.code == 0:
            print()
            print_wrapper_help()
            return 0
        print()
        print_wrapper_help()
        return 1

    if parsed.file is not None:
        parsed.file.close()
        print("error: do not pass -file; the wrapper manages commands", file=sys.stderr)
        return 1

    if unknown:
        print(f"error: unexpected arguments: {' '.join(unknown)}", file=sys.stderr)
        print("hint: provide targets via --targets", file=sys.stderr)
        print()
        print_wrapper_help()
        return 1

    smbclient_path = ensure_smbclient_on_path()
    targets = expand_targets(targets_raw)
    if not targets:
        print("error: no targets provided", file=sys.stderr)
        return 1

    if wrapper["username"] or wrapper["domain"] or wrapper["password"] is not None:
        for target in targets:
            if "@" in target:
                print(
                    "error: do not mix --username/--domain/--password with targets that already include credentials",
                    file=sys.stderr,
                )
                return 1
        try:
            targets = [
                build_target(target, wrapper["username"], wrapper["domain"], wrapper["password"])
                for target in targets
            ]
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    output_root = wrapper["output"]
    os.makedirs(output_root, exist_ok=True)

    for target in targets:
        target_dir = os.path.join(output_root, sanitize_target(target))
        os.makedirs(target_dir, exist_ok=True)
        print(f"[*] {target}: enumerating shares")

        code, output = run_smbclient(smbclient_path, smbclient_args, target, "shares", wrapper["debug"])
        if code != 0:
            print(f"[!] {target}: failed to enumerate shares", file=sys.stderr)
            if wrapper["debug"] and output:
                print(output, file=sys.stderr)
            continue

        shares = parse_shares(output)
        if not shares:
            print(f"[!] {target}: no shares found or output unparseable", file=sys.stderr)
            continue

        for share in shares:
            share_dir = os.path.join(target_dir, share)
            os.makedirs(share_dir, exist_ok=True)
            out_path = os.path.join(share_dir, "files.txt")
            print(f"[+] {target}: {share} -> {out_path}")

            command = f'use "{share}"\nrecurse\nls'
            _, listing = run_smbclient(
                smbclient_path,
                smbclient_args,
                target,
                command,
                wrapper["debug"],
            )
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write(listing)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
