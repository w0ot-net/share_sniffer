#!/usr/bin/env python3
import argparse
import os
import re
import sys


INTERESTING_EXTS = {
    ".html",
    ".php",
    ".vbs",
    ".ps1",
    ".ashx",
    ".asmx",
    ".pl",
    ".py",
    ".conf",
    ".config",
    ".ini",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    ".bak",
    ".old",
    ".swp",
    ".sql",
    ".db",
    ".sqlite",
    ".pfx",
    ".p12",
    ".key",
    ".pem",
    ".crt",
    ".cer",
    ".kdbx",
    ".rdp",
}
INTERESTING_NAME_KEYWORDS = {
    "admin",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "creds",
    "credential",
    "key",
    "private",
    "backup",
    "vault",
    "keystore",
    "id_rsa",
}
INTERESTING_XML_FILENAMES = {
    "web.config",
    "app.config",
    "machine.config",
    "applicationhost.config",
    "webservices.config",
}
INTERESTING_PATH_KEYWORDS = {
    "/config/",
    "/secrets/",
    "/backup/",
    "/old/",
    "/tmp/",
    "/home/",
    "/users/",
}
RESULTS_PATTERN = re.compile(r"^results_\\d{8}_\\d{6}$")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Scan share_sniffer results for interesting file extensions.",
    )
    parser.add_argument(
        "-d",
        "--dir",
        dest="results_dir",
        help="Results directory to scan (defaults to most recent results_<timestamp>)",
    )
    return parser.parse_args(argv)


def find_latest_results_dir():
    candidates = []
    for entry in os.listdir("."):
        if RESULTS_PATTERN.match(entry) and os.path.isdir(entry):
            candidates.append(entry)
    if not candidates:
        return None
    return sorted(candidates)[-1]


def extract_host(target_folder):
    if "@" in target_folder:
        return target_folder.split("@", 1)[1]
    return target_folder


def find_filename_matches(filename):
    matches = []
    lowered = filename.lower()
    for keyword in INTERESTING_NAME_KEYWORDS:
        if keyword in lowered:
            matches.append(keyword)
    _, ext = os.path.splitext(lowered)
    if ext in INTERESTING_EXTS:
        matches.append(ext)
    return matches


def highlight_filename(filename, matches):
    if not matches:
        return filename
    pattern = "|".join(re.escape(m) for m in sorted(set(matches), key=len, reverse=True))
    regex = re.compile(pattern, re.IGNORECASE)
    return regex.sub(lambda m: f"\x1b[31m{m.group(0)}\x1b[0m", filename)


def is_interesting(path):
    path = path.strip().rstrip("/")
    if not path:
        return False
    if os.path.basename(path).lower() == "thumbs.db":
        return False
    lowered = path.lower()
    base = os.path.basename(lowered)
    if base in INTERESTING_XML_FILENAMES:
        return True
    _, ext = os.path.splitext(lowered)
    if ext in INTERESTING_EXTS:
        return True
    for keyword in INTERESTING_NAME_KEYWORDS:
        if keyword in base:
            return True
    for keyword in INTERESTING_PATH_KEYWORDS:
        if keyword in lowered:
            return True
    return False


def parse_tree_output(lines):
    for line in lines:
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if line.startswith("#") or line.startswith("["):
            continue
        if line.startswith("Impacket v"):
            continue
        if lower.startswith("usage:") or lower.startswith("smbclient.py:"):
            continue
        if "executing commands from" in lower:
            continue
        if lower.startswith("finished -"):
            continue
        yield line


def main(argv):
    args = parse_args(argv)
    results_dir = args.results_dir or find_latest_results_dir()
    if not results_dir:
        print("error: no results_<timestamp> directories found", file=sys.stderr)
        return 1
    if not os.path.isdir(results_dir):
        print(f"error: results directory not found: {results_dir}", file=sys.stderr)
        return 1

    for root, _, files in os.walk(results_dir):
        if "files.txt" not in files:
            continue
        files_path = os.path.join(root, "files.txt")
        rel = os.path.relpath(root, results_dir)
        parts = rel.split(os.sep)
        if len(parts) < 2:
            continue
        target_folder, share = parts[0], parts[1]
        host = extract_host(target_folder)
        with open(files_path, "r", encoding="utf-8", errors="replace") as handle:
            for path in parse_tree_output(handle):
                if not is_interesting(path):
                    continue
                if not path.startswith("/"):
                    path = "/" + path.lstrip("/")
                filename = os.path.basename(path)
                matches = find_filename_matches(filename)
                highlighted = highlight_filename(filename, matches)
                if highlighted != filename:
                    path = path[: -len(filename)] + highlighted
                unc = f"//{host}/{share}{path}"
                print(unc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
