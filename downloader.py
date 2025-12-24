#!/usr/bin/env python3
import argparse
import getpass
import os
import re
import sys

from impacket.smbconnection import SMBConnection, SessionError

from wrapper_utils import expand_list_items


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Download files over SMB using impacket.",
    )
    parser.add_argument(
        "--paths",
        action="append",
        help="UNC path (//host/share/path) or file with one UNC path per line (can be repeated).",
    )
    parser.add_argument(
        "--username",
        help="Username to authenticate with.",
    )
    parser.add_argument(
        "--domain",
        help="Domain to authenticate with.",
    )
    parser.add_argument(
        "--password",
        help="Password to authenticate with.",
    )
    parser.add_argument(
        "--hashes",
        help="NTLM hashes in LMHASH:NTHASH format.",
    )
    parser.add_argument(
        "--no-pass",
        action="store_true",
        help="Do not prompt for password (use empty password).",
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos authentication.",
    )
    parser.add_argument(
        "--aes-key",
        help="AES key for Kerberos authentication.",
    )
    parser.add_argument(
        "--dc-ip",
        help="Domain controller IP (used with Kerberos).",
    )
    parser.add_argument(
        "--target-ip",
        help="Override target IP (single host only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=445,
        help="SMB port (default: 445).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="SMB connection timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="./files",
        help="Output directory (default: ./files).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logging.",
    )
    return parser.parse_args(argv)


def parse_hashes(hashes):
    if not hashes:
        return None, None
    if ":" not in hashes:
        raise ValueError("error: --hashes must be LMHASH:NTHASH")
    lmhash, nthash = hashes.split(":", 1)
    return lmhash, nthash


def parse_target(value):
    if "@" not in value:
        return value, None, None, None
    userpart, host = value.split("@", 1)
    domain = None
    if "/" in userpart:
        domain, userpart = userpart.split("/", 1)
    password = None
    if ":" in userpart:
        username, password = userpart.split(":", 1)
    else:
        username = userpart
    username = username or None
    return host, username, password, domain


def parse_unc(unc):
    unc = unc.strip()
    if unc.startswith("\\\\"):
        unc = unc.replace("\\", "/")
    if not unc.startswith("//"):
        raise ValueError(f"invalid UNC path (expected //host/share/path): {unc}")
    parts = unc[2:].split("/")
    if len(parts) < 3:
        raise ValueError(f"invalid UNC path (missing share or path): {unc}")
    host_part = parts[0]
    share = parts[1]
    remote = "/".join(parts[2:])
    if not remote:
        raise ValueError(f"invalid UNC path (missing file path): {unc}")
    host, username, password, domain = parse_target(host_part)
    return host, share, remote, username, password, domain


def sanitize_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def resolve_password(username, provided_password, use_no_pass, hashes_present):
    if provided_password is not None:
        return provided_password
    if not username:
        return ""
    if use_no_pass or hashes_present:
        return ""
    if sys.stdin.isatty():
        return getpass.getpass("Password: ")
    raise ValueError("error: --password required (or use --no-pass)")


def connect_smb(host, username, password, domain, lmhash, nthash, args, target_ip):
    remote_host = target_ip or host
    conn = SMBConnection(host, remote_host, sess_port=args.port, timeout=args.timeout)
    if args.kerberos:
        conn.kerberosLogin(
            username,
            password,
            domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=args.aes_key,
            kdcHost=args.dc_ip,
        )
    else:
        conn.login(username, password, domain, lmhash=lmhash, nthash=nthash)
    return conn


def main(argv):
    args = parse_args(argv)
    if not args.paths:
        print("error: no UNC paths provided", file=sys.stderr)
        return 1

    raw_paths = expand_list_items(args.paths)
    if not raw_paths:
        print("error: no UNC paths provided", file=sys.stderr)
        return 1

    entries = []
    inline_creds = False
    for raw in raw_paths:
        try:
            host, share, remote, username, password, domain = parse_unc(raw)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if username or password or domain:
            inline_creds = True
        entries.append((host, share, remote, username, password, domain))

    global_creds = any(
        [
            args.username,
            args.domain,
            args.password is not None,
            args.hashes,
            args.no_pass,
            args.kerberos,
            args.aes_key,
        ]
    )
    if inline_creds and global_creds:
        print(
            "error: do not mix inline credentials in UNC paths with authentication flags",
            file=sys.stderr,
        )
        return 1

    if args.target_ip and len({host for host, _, _, _, _, _ in entries}) > 1:
        print("error: --target-ip only supports a single host", file=sys.stderr)
        return 1

    try:
        lmhash, nthash = parse_hashes(args.hashes)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.kerberos and not (args.username or inline_creds):
        print("error: --kerberos requires --username or inline credentials", file=sys.stderr)
        return 1

    os.makedirs(args.output, exist_ok=True)

    grouped = {}
    for host, share, remote, username, password, domain in entries:
        key = (host, username, password, domain)
        grouped.setdefault(key, []).append((share, remote))

    for (host, inline_user, inline_pass, inline_domain), items in grouped.items():
        username = inline_user or args.username or ""
        domain = inline_domain or args.domain or ""
        try:
            password = resolve_password(
                username,
                inline_pass if inline_user else args.password,
                args.no_pass,
                bool(args.hashes),
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        if args.hashes and not username:
            print("error: --hashes requires a username", file=sys.stderr)
            return 1

        try:
            conn = connect_smb(host, username, password, domain, lmhash, nthash, args, args.target_ip)
        except SessionError as exc:
            print(f"[!] {host}: authentication failed: {exc}", file=sys.stderr)
            continue
        except Exception as exc:
            print(f"[!] {host}: connection failed: {exc}", file=sys.stderr)
            continue

        for share, remote in items:
            remote = remote.lstrip("/")
            encoded_remote = remote.replace("\\", "/").replace("/", "_")
            encoded = sanitize_filename(f"{host}_{share}_{encoded_remote}").lstrip("_")
            local_path = os.path.join(args.output, encoded)
            abs_local = os.path.abspath(local_path)
            tmp_path = abs_local + ".part"

            remote_win = "\\" + remote.replace("/", "\\").lstrip("\\")
            print(f"downloading: //{host}/{share}/{remote}")

            try:
                with open(tmp_path, "wb") as handle:
                    conn.getFile(share, remote_win, handle.write)
                os.replace(tmp_path, abs_local)
                status = "ok"
            except SessionError as exc:
                status = "failed"
                if args.verbose:
                    print(f"[!] {host}: {exc}", file=sys.stderr)
                try:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                except OSError:
                    pass
            except Exception as exc:
                status = "failed"
                if args.verbose:
                    print(f"[!] {host}: {exc}", file=sys.stderr)
                try:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                except OSError:
                    pass

            print(f"{status}: //{host}/{share}/{remote} -> {abs_local}")

        conn.logoff()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
