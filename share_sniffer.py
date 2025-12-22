#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
import sys


COMMON_SMBCLIENT_PATHS = [
    "/usr/share/doc/python3-impacket/examples/smbclient.py",
    "/usr/lib/python3/dist-packages/impacket/examples/smbclient.py",
    "/usr/local/bin/smbclient.py",
    "/usr/bin/smbclient.py",
]


def print_wrapper_help():
    print("wrapper options:")
    print("  --targets <host|ip|file|csv>   can be repeated; file has one target per line")


def split_args(argv):
    targets = []
    passthrough = []
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--targets":
            if idx + 1 >= len(argv):
                return None, None, "error: --targets requires a value"
            targets.append(argv[idx + 1])
            idx += 2
            continue
        if arg.startswith("--targets="):
            targets.append(arg.split("=", 1)[1])
            idx += 1
            continue
        passthrough.append(arg)
        idx += 1
    return targets, passthrough, None


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
        if "," in raw:
            for part in raw.split(","):
                part = part.strip()
                if part:
                    targets.append(part)
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


def run_smbclient(smbclient_path, smbclient_args, target, command):
    cmd = [smbclient_path] + smbclient_args + ["-c", command, target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout or ""
    if result.stderr:
        if output and not output.endswith("\n"):
            output += "\n"
        output += result.stderr
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
    targets_raw, smbclient_args, err = split_args(argv)
    if err:
        print(err, file=sys.stderr)
        print_wrapper_help()
        return 1

    if any(opt in ("-c", "--command") for opt in smbclient_args):
        print("error: do not pass -c/--command; the wrapper controls commands", file=sys.stderr)
        return 1

    if any(opt in ("-h", "--help") for opt in smbclient_args):
        smbclient_path = ensure_smbclient_on_path()
        subprocess.run([smbclient_path, "-h"], check=False)
        print()
        print_wrapper_help()
        return 0

    smbclient_path = ensure_smbclient_on_path()
    targets = expand_targets(targets_raw)
    if not targets:
        print("error: no targets provided", file=sys.stderr)
        return 1

    for target in targets:
        target_dir = sanitize_target(target)
        os.makedirs(target_dir, exist_ok=True)
        print(f"[*] {target}: enumerating shares")

        code, output = run_smbclient(smbclient_path, smbclient_args, target, "shares")
        if code != 0:
            print(f"[!] {target}: failed to enumerate shares", file=sys.stderr)
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

            command = f'use "{share}"; recurse; ls'
            _, listing = run_smbclient(smbclient_path, smbclient_args, target, command)
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write(listing)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
