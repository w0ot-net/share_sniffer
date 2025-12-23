#!/usr/bin/env python3
import argparse
import datetime
import os
import re
import sys

from smbclient_utils import build_smbclient_parser, detect_input_flag, ensure_smbclient_on_path, run_smbclient


def print_wrapper_help():
    print("wrapper options:")
    print("  --paths <unc|file>             can be repeated; file has one UNC path per line")
    print("  --username <name>              optional username to apply to all targets")
    print("  --domain <name>                optional domain to apply to all targets")
    print("  --password <value>             optional password to apply to all targets")
    print("  --verbose                      print smbclient output and wrapper commands")
    print("  -o, --output <dir>             output directory (default: ./files)")
    print()
    print("note: smbclient.py has its own -debug flag for protocol logging.")


def split_args(argv):
    paths = []
    passthrough = []
    default_output = "./files"
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


def sanitize_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


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

    smbclient_cmd = ensure_smbclient_on_path()
    input_flag = detect_input_flag(smbclient_cmd)

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

        downloads_dir = os.path.abspath(output_root)
        def shell_quote(value):
            return "'" + value.replace("'", "'\"'\"'") + "'"

        for remote in sorted(set(remotes)):
            remote = remote.lstrip("/")
            remote_dir = os.path.dirname(remote).replace("\\", "/")
            filename = os.path.basename(remote)
            encoded_remote = remote.replace("\\", "/").replace("/", "_")
            encoded = sanitize_filename(f"{host}_{share}_{encoded_remote}").lstrip("_")
            local_path = os.path.join(output_root, encoded)
            abs_local = os.path.abspath(local_path)

            commands = [f"lcd {downloads_dir}", f"use {share}"]
            if remote_dir:
                commands.append(f"cd /{remote_dir}")
            else:
                commands.append("cd /")
            commands.append(f"get {filename}")
            commands.append(
                f"shell mv -f {shell_quote(filename)} {shell_quote(abs_local)}"
            )

            command_text = "\n".join(commands)
            print(f"downloading: //{host}/{share}/{remote}")
            code, output = run_smbclient(
                smbclient_cmd,
                smbclient_args,
                target,
                command_text,
                wrapper["verbose"],
                input_flag,
            )
            output_lower = output.lower()
            if os.path.isfile(abs_local):
                status = "ok"
            elif "error" in output_lower or "sessionerror" in output_lower:
                status = "failed"
            else:
                status = "unknown"
            print(f"{status}: //{host}/{share}/{remote} -> {abs_local}")
            if wrapper["verbose"] and output:
                print(output, file=sys.stderr if code != 0 else sys.stdout)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
