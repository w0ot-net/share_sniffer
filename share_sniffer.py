#!/usr/bin/env python3
import datetime
import os
import re
import sys

from smbclient_utils import build_smbclient_parser, detect_input_flag, ensure_smbclient_on_path, run_smbclient


def print_wrapper_help():
    print("wrapper options:")
    print("  --targets <host|ip|file>       can be repeated; file has one target per line")
    print("  --username <name>              optional username to apply to all targets")
    print("  --domain <name>                optional domain to apply to all targets")
    print("  --password <value>             optional password to apply to all targets")
    print("  --verbose                      print smbclient output and wrapper commands")
    print("  -o, --output <dir>             output directory (default: ./results_<timestamp>)")
    print()
    print("note: smbclient.py has its own -debug flag for protocol logging.")


def split_args(argv):
    targets = []
    passthrough = []
    default_output = f"./results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
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


def sanitize_target(target):
    return re.sub(r"[^A-Za-z0-9._@-]", "_", target)


def target_for_folder(target):
    if "@" not in target:
        return target
    userpart, host = target.split("@", 1)
    if "/" in userpart:
        userpart = userpart.split("/", 1)[1]
    if ":" in userpart:
        userpart = userpart.split(":", 1)[0]
    if not userpart:
        return host
    return f"{userpart}@{host}"


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


def is_share_readable(output, returncode):
    if returncode != 0:
        return False
    lowered = output.lower()
    blocked_markers = [
        "status_access_denied",
        "access is denied",
        "status_bad_network_name",
        "no share selected",
        "not logged in",
        "status_logon_failure",
        "smb sessionerror",
    ]
    return not any(marker in lowered for marker in blocked_markers)


def parse_shares(output):
    shares = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("sharename") or line.startswith("----"):
            continue
        if line.startswith("SMB") or line.startswith("Authentication"):
            continue
        if line.startswith("Impacket v"):
            continue
        if line.startswith("[*]") or line.startswith("[-]"):
            continue
        if lower.startswith("usage:") or lower.startswith("smbclient.py:"):
            continue
        if "executing commands from" in lower:
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
        print("hint: provide targets via --targets", file=sys.stderr)
        print()
        print_wrapper_help()
        return 1

    smbclient_cmd = ensure_smbclient_on_path()
    input_flag = detect_input_flag(smbclient_cmd)
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
        folder_target = target_for_folder(target)
        target_dir = os.path.join(output_root, sanitize_target(folder_target))
        os.makedirs(target_dir, exist_ok=True)
        print(f"[*] {target}: enumerating shares")

        code, output = run_smbclient(
            smbclient_cmd,
            smbclient_args,
            target,
            "shares",
            wrapper["verbose"],
            input_flag,
        )
        if code != 0:
            print(f"[!] {target}: failed to enumerate shares", file=sys.stderr)
            if wrapper["verbose"] and output:
                print(output, file=sys.stderr)
            continue

        shares = parse_shares(output)
        if not shares:
            print(f"[!] {target}: no shares found or output unparseable", file=sys.stderr)
            continue

        for share in shares:
            command = f"use {share}\ntree"
            code, listing = run_smbclient(
                smbclient_cmd,
                smbclient_args,
                target,
                command,
                wrapper["verbose"],
                input_flag,
            )
            if not is_share_readable(listing, code):
                if wrapper["verbose"]:
                    print(f"[!] {target}: {share} not readable, skipping", file=sys.stderr)
                    if listing:
                        print(listing, file=sys.stderr)
                continue

            share_dir = os.path.join(target_dir, share)
            os.makedirs(share_dir, exist_ok=True)
            out_path = os.path.join(share_dir, "files.txt")
            print(f"[+] {target}: {share} -> {out_path}")
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write(listing)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
