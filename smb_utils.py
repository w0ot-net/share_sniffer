#!/usr/bin/env python3
import argparse
import getpass
import os
import sys

from impacket.smbconnection import SMBConnection


def add_auth_args(parser):
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
        help="Override target IP (single target only).",
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
        "--verbose",
        action="store_true",
        help="Verbose logging.",
    )


def expand_list_items(raw_items):
    items = []
    for raw in raw_items:
        if os.path.isfile(raw):
            with open(raw, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    items.append(line)
            continue
        items.append(raw)

    seen = set()
    deduped = []
    for item in items:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


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
