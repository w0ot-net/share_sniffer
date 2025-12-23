#!/usr/bin/env python3
import argparse
import datetime
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
    print("  --paths <unc|file>             can be repeated; file has one UNC path per line")
    print("  --username <name>              optional username to apply to all targets")
    print("  --domain <name>                optional domain to apply to all targets")
    print("  --password <value>             optional password to apply to all targets")
    print("  --verbose                      print smbclient output and wrapper commands")
    print("  -o, --output <dir>             output directory (default: ./downloads_<timestamp>)")
    print()
    print("note: smbclient.py has its own -debug flag for protocol logging.")


def build_smbclient_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="SMB client implementation.",
    )
    parser.add_argument(
        "-file",
        action="store",
        metavar="FILE",
        help="input file with commands to execute in the mini shell (legacy)",
    )
    parser.add_argument(
        "-inputfile",
        action="store",
        metavar="INPUTFILE",
        help="input file with commands to execute in the mini shell",
    )
    parser.add_argument(
        "-outputfile",
        action="store",
        metavar="OUTPUTFILE",
        help="output file to write the command results",
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")

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
    paths = []
    passthrough = []
    default_output = f"./downloads_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    wrapper = {
        "username": None,
        "domain": None,
        "password": None,
        "verbose": False,
        "output": default_output,
    }
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--paths":
            if idx + 1 >= len(argv):
                return None, None, None, "error: --paths requires a value"
            paths.append(argv[idx + 1])
            idx += 2
            continue
        if arg.startswith("--paths="):
            paths.append(arg.split("=", 1)[1])
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
        if arg == "--verbose":
            wrapper["verbose"] = True
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
    return paths, wrapper, passthrough, None


def expand_paths(raw_paths):
    paths = []
    for raw in raw_paths:
        if os.path.isfile(raw):
            with open(raw, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    paths.append(line)
            continue
        paths.append(raw)

    seen = set()
    deduped = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
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


def detect_input_flag(smbclient_path):
    result = subprocess.run([smbclient_path, "-h"], capture_output=True, text=True)
    combined = (result.stdout or "") + (result.stderr or "")
    if "-inputfile" in combined:
        return "-inputfile"
    if "-file" in combined:
        return "-file"
    return "-inputfile"


def build_target(host, username, domain, password):
    if domain or password:
        if not username:
            raise ValueError("error: --domain/--password require --username")

    if not username:
        return host

    userpart = username
    if domain:
        userpart = f"{domain}/{username}"
    if password is not None:
        userpart = f"{userpart}:{password}"
    return f"{userpart}@{host}"


def parse_unc(unc):
    unc = unc.strip()
    if unc.startswith("\\\\"):
        unc = unc.replace("\\", "/")
    if not unc.startswith("//"):
        raise ValueError(f"invalid UNC path (expected //host/share/path): {unc}")
    parts = unc[2:].split("/")
    if len(parts) < 3:
        raise ValueError(f"invalid UNC path (missing share or path): {unc}")
    host = parts[0]
    share = parts[1]
    remote = "/".join(parts[2:])
    if not remote:
        raise ValueError(f"invalid UNC path (missing file path): {unc}")
    return host, share, remote


def run_smbclient(smbclient_path, smbclient_args, target, commands, verbose, input_flag):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(commands)
            handle.write("\n")
            temp_path = handle.name
        cmd = [smbclient_path] + smbclient_args + [input_flag, temp_path, target]
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
    if verbose:
        print(f"[debug] smbclient cmd: {' '.join(cmd)}")
    return result.returncode, output


def main(argv):
    paths_raw, wrapper, smbclient_args, err = split_args(argv)
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
        print("error: do not pass -file; the wrapper manages commands", file=sys.stderr)
        return 1
    if parsed.inputfile is not None:
        print("error: do not pass -inputfile; the wrapper manages commands", file=sys.stderr)
        return 1
    if parsed.outputfile is not None:
        print("error: do not pass -outputfile; the wrapper manages output", file=sys.stderr)
        return 1

    if unknown:
        print(f"error: unexpected arguments: {' '.join(unknown)}", file=sys.stderr)
        print("hint: provide UNC paths via --paths", file=sys.stderr)
        print()
        print_wrapper_help()
        return 1

    smbclient_path = ensure_smbclient_on_path()
    input_flag = detect_input_flag(smbclient_path)

    paths = expand_paths(paths_raw)
    if not paths:
        print("error: no UNC paths provided", file=sys.stderr)
        return 1

    output_root = wrapper["output"]
    os.makedirs(output_root, exist_ok=True)

    entries = []
    for raw in paths:
        try:
            host, share, remote = parse_unc(raw)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        entries.append((host, share, remote))

    if wrapper["username"] or wrapper["domain"] or wrapper["password"] is not None:
        for host, _, _ in entries:
            if "@" in host:
                print(
                    "error: do not mix --username/--domain/--password with UNC paths that include credentials",
                    file=sys.stderr,
                )
                return 1

    grouped = {}
    for host, share, remote in entries:
        grouped.setdefault((host, share), []).append(remote)

    for (host, share), remotes in grouped.items():
        try:
            target = build_target(host, wrapper["username"], wrapper["domain"], wrapper["password"])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        commands = [f"use {share}"]
        for remote in sorted(set(remotes)):
            local_path = os.path.join(output_root, host, share, remote)
            local_dir = os.path.dirname(local_path)
            os.makedirs(local_dir, exist_ok=True)
            abs_local = os.path.abspath(local_path)
            commands.append(f'get "{remote}" "{abs_local}"')

        command_text = "\n".join(commands)
        code, output = run_smbclient(
            smbclient_path,
            smbclient_args,
            target,
            command_text,
            wrapper["verbose"],
            input_flag,
        )
        if code != 0:
            print(f"[!] {host}/{share}: download failed", file=sys.stderr)
            if wrapper["verbose"] and output:
                print(output, file=sys.stderr)
            continue
        if wrapper["verbose"] and output:
            print(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
