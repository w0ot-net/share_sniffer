#!/usr/bin/env python3
import argparse
import os
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


def ensure_smbclient_on_path():
    path = shutil.which("smbclient.py")
    if path:
        return [path]

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
    if path:
        return [path]
    if not os.access(candidate, os.R_OK):
        print("error: failed to add smbclient.py to PATH.", file=sys.stderr)
        sys.exit(1)
    return [sys.executable, candidate]


def detect_input_flag(smbclient_cmd):
    result = subprocess.run(smbclient_cmd + ["-h"], capture_output=True, text=True)
    combined = (result.stdout or "") + (result.stderr or "")
    if "-inputfile" in combined:
        return "-inputfile"
    if "-file" in combined:
        return "-file"
    return "-inputfile"


def run_smbclient(smbclient_cmd, smbclient_args, target, commands, verbose, input_flag):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(commands)
            handle.write("\n")
            temp_path = handle.name
        cmd = smbclient_cmd + smbclient_args + [input_flag, temp_path, target]
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
