#!/usr/bin/env python3
import argparse
import datetime
import getpass
import os
import re
import sys

from impacket.smbconnection import SMBConnection, SessionError

from wrapper_utils import expand_list_items


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Scan SMB shares using impacket.",
    )
    parser.add_argument(
        "--targets",
        action="append",
        help="Target host/ip or file with one target per line (can be repeated).",
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
        "-o",
        "--output",
        help="Output directory (default: ./results_<timestamp>).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose logging.",
    )
    parser.add_argument(
        "-t",
        "--target-threds",
        "--threads",
        dest="threads",
        type=int,
        default=1,
        help="Max simultaneous targets (default: 1).",
    )
    parser.add_argument(
        "--share-threads",
        type=int,
        default=1,
        help="Max simultaneous shares per target (default: 1).",
    )
    parser.add_argument(
        "--dir-threads",
        type=int,
        default=1,
        help="Max simultaneous directory listings per share (default: 1).",
    )
    return parser.parse_args(argv)


def sanitize_target(target):
    return re.sub(r"[^A-Za-z0-9._@-]", "_", target)


def target_folder(host, username):
    if not username:
        return host
    return f"{username}@{host}"


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


def normalize_share_name(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    return raw.rstrip("\x00")


def write_tree(conn, share, handle, verbose, initial_entries=None, dir_threads=1, connect_func=None):
    """Enumerate files in a share and write paths to handle.

    If dir_threads > 1 and connect_func is provided, uses parallel directory
    enumeration with multiple connections.
    """
    if dir_threads == 1 or connect_func is None:
        # Single-threaded recursive approach
        def walk(win_path, display_path, entries=None):
            if entries is None:
                try:
                    entries = conn.listPath(share, f"{win_path}*")
                except SessionError as exc:
                    if verbose:
                        print(f"[!] {share}: {exc}", file=sys.stderr)
                    return
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                display = f"{display_path}/{name}" if display_path else f"/{name}"
                if entry.is_directory():
                    handle.write(display + "/\n")
                    walk(f"{win_path}{name}\\", display)
                else:
                    handle.write(display + "\n")

        walk("\\", "", initial_entries)
    else:
        # Parallel directory enumeration using work queue
        import queue
        import threading
        from concurrent.futures import ThreadPoolExecutor

        work_queue = queue.Queue()
        results_lock = threading.Lock()
        results = []  # List of (display_path, is_dir) tuples

        def process_entries(entries, win_path, display_path):
            """Process entries and queue subdirectories for enumeration."""
            subdirs = []
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                display = f"{display_path}/{name}" if display_path else f"/{name}"
                if entry.is_directory():
                    with results_lock:
                        results.append((display + "/", True))
                    subdirs.append((f"{win_path}{name}\\", display))
                else:
                    with results_lock:
                        results.append((display, False))
            return subdirs

        def worker():
            """Worker thread that processes directories from the queue."""
            local_conn = None
            try:
                local_conn = connect_func()
                while True:
                    try:
                        item = work_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if item is None:
                        break
                    win_path, display_path = item
                    try:
                        entries = local_conn.listPath(share, f"{win_path}*")
                        subdirs = process_entries(entries, win_path, display_path)
                        for subdir in subdirs:
                            work_queue.put(subdir)
                    except SessionError as exc:
                        if verbose:
                            print(f"[!] {share}: {exc}", file=sys.stderr)
                    finally:
                        work_queue.task_done()
            finally:
                if local_conn:
                    try:
                        local_conn.logoff()
                    except Exception:
                        pass

        # Process initial entries (root level)
        if initial_entries:
            subdirs = process_entries(initial_entries, "\\", "")
            for subdir in subdirs:
                work_queue.put(subdir)
        else:
            work_queue.put(("\\", ""))

        # Start worker threads
        workers = []
        for _ in range(dir_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        # Wait for all work to complete
        work_queue.join()

        # Signal workers to stop
        for _ in workers:
            work_queue.put(None)
        for t in workers:
            t.join(timeout=1.0)

        # Write results to file (sorted for consistent output)
        for path, _ in sorted(results):
            handle.write(path + "\n")


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
    if not args.targets:
        print("error: no targets provided", file=sys.stderr)
        return 1

    targets = expand_list_items(args.targets)
    if not targets:
        print("error: no targets provided", file=sys.stderr)
        return 1

    parsed_targets = []
    inline_creds = False
    for target in targets:
        host, username, password, domain = parse_target(target)
        if username or password or domain:
            inline_creds = True
        parsed_targets.append((host, username, password, domain))

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
            "error: do not mix inline credentials in targets with authentication flags",
            file=sys.stderr,
        )
        return 1

    if args.threads < 1:
        print("error: --threads must be >= 1", file=sys.stderr)
        return 1
    if args.share_threads < 1:
        print("error: --share-threads must be >= 1", file=sys.stderr)
        return 1
    if args.dir_threads < 1:
        print("error: --dir-threads must be >= 1", file=sys.stderr)
        return 1

    if args.target_ip and len(parsed_targets) > 1:
        print("error: --target-ip only supports a single target", file=sys.stderr)
        return 1

    try:
        lmhash, nthash = parse_hashes(args.hashes)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.kerberos and not (args.username or inline_creds):
        print("error: --kerberos requires --username or inline credentials", file=sys.stderr)
        return 1

    output_root = args.output or f"./results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_root, exist_ok=True)

    resolved_targets = []
    for host, inline_user, inline_pass, inline_domain in parsed_targets:
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

        resolved_targets.append((host, username, password, domain))

    def process_target(entry):
        host, username, password, domain = entry
        target_label = target_folder(host, username)
        target_dir = os.path.join(output_root, sanitize_target(target_label))
        os.makedirs(target_dir, exist_ok=True)
        print(f"[*] {host}: enumerating shares")

        def make_connection():
            return connect_smb(host, username, password, domain, lmhash, nthash, args, args.target_ip)

        try:
            conn = make_connection()
        except SessionError as exc:
            print(f"[!] {host}: authentication failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:
            print(f"[!] {host}: connection failed: {exc}", file=sys.stderr)
            return

        try:
            shares = []
            for share in conn.listShares():
                name = normalize_share_name(share["shi1_netname"])
                if name:
                    shares.append(name)
        except SessionError as exc:
            print(f"[!] {host}: failed to list shares: {exc}", file=sys.stderr)
            conn.logoff()
            return

        if not shares:
            print(f"[!] {host}: no shares found", file=sys.stderr)
            conn.logoff()
            return

        def process_share(share_name, share_conn=None):
            owns_connection = share_conn is None
            closed_connection = False
            if owns_connection:
                try:
                    share_conn = make_connection()
                except SessionError as exc:
                    print(f"[!] {host}: authentication failed: {exc}", file=sys.stderr)
                    return
                except Exception as exc:
                    print(f"[!] {host}: connection failed: {exc}", file=sys.stderr)
                    return

            try:
                try:
                    initial_entries = share_conn.listPath(share_name, "\\*")
                except SessionError as exc:
                    if args.verbose:
                        print(f"[!] {host}: {share_name} not readable: {exc}", file=sys.stderr)
                    return
                if args.dir_threads > 1 and owns_connection:
                    share_conn.logoff()
                    closed_connection = True

                share_dir = os.path.join(target_dir, share_name)
                os.makedirs(share_dir, exist_ok=True)
                out_path = os.path.join(share_dir, "files.txt")
                print(f"[+] {host}: {share_name} -> {out_path}")
                with open(out_path, "w", encoding="utf-8") as handle:
                    # Pass dir_threads and connect_func for parallel enumeration
                    connect_func = make_connection if args.dir_threads > 1 else None
                    write_tree(
                        share_conn, share_name, handle, args.verbose, initial_entries,
                        dir_threads=args.dir_threads, connect_func=connect_func
                    )
            finally:
                if owns_connection and not closed_connection:
                    share_conn.logoff()

        if args.share_threads == 1:
            # Single-threaded: reuse the main connection for all shares
            for share in shares:
                process_share(share, share_conn=conn)
            conn.logoff()
        else:
            # Multi-threaded: each thread gets its own connection
            conn.logoff()  # Close the initial connection, threads will create their own
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=args.share_threads) as executor:
                futures = [executor.submit(process_share, share) for share in shares]
                for future in futures:
                    future.result()

    if args.threads == 1:
        for entry in resolved_targets:
            process_target(entry)
    else:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(process_target, entry) for entry in resolved_targets]
            for future in futures:
                future.result()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
