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
    "private",
    "backup",
    "vault",
    "keystore",
    "id_rsa",
}
INTERESTING_KEYWORD_PATTERNS = {
    "key": re.compile(r"\\bkey\\b", re.IGNORECASE),
}
INTERESTING_XML_FILENAMES = {
    "web.config",
    "app.config",
    "machine.config",
    "applicationhost.config",
    "webservices.config",
}
INTERESTING_INI_FILENAMES = {
    "config.ini",
    "settings.ini",
    "secrets.ini",
    "credentials.ini",
    "creds.ini",
    "passwords.ini",
    "db.ini",
}
INTERESTING_FILENAMES = {
    ".env",
    ".env.local",
    ".env.dev",
    ".env.development",
    ".env.stage",
    ".env.staging",
    ".env.prod",
    ".env.production",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".git-credentials",
    "credentials",
    "credential",
    "creds",
    "secrets",
    "secret",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa.ppk",
    "id_dsa.ppk",
    "id_ecdsa.ppk",
    "id_ed25519.ppk",
    "known_hosts",
    "rdp.rdp",
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
    base = os.path.basename(lowered)
    if base in INTERESTING_FILENAMES or base.startswith(".env."):
        matches.append(base)
    for keyword in INTERESTING_NAME_KEYWORDS:
        if keyword in lowered:
            matches.append(keyword)
    for keyword, pattern in INTERESTING_KEYWORD_PATTERNS.items():
        if pattern.search(base):
            matches.append(keyword)
    _, ext = os.path.splitext(lowered)
    if ext in INTERESTING_EXTS:
        matches.append(ext)
    if ext == ".ini":
        if base in INTERESTING_INI_FILENAMES:
            matches.append(base)
    return matches


def find_path_matches(path):
    lowered = path.lower()
    return [keyword for keyword in INTERESTING_PATH_KEYWORDS if keyword in lowered]


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
    if base in INTERESTING_FILENAMES or base.startswith(".env."):
        return True
    if base in INTERESTING_XML_FILENAMES:
        return True
    _, ext = os.path.splitext(lowered)
    if ext == ".ini":
        if base in INTERESTING_INI_FILENAMES:
            return True
        for keyword in INTERESTING_NAME_KEYWORDS:
            if keyword in base:
                return True
        for pattern in INTERESTING_KEYWORD_PATTERNS.values():
            if pattern.search(base):
                return True
        return False
    if ext in INTERESTING_EXTS:
        return True
    for keyword in INTERESTING_NAME_KEYWORDS:
        if keyword in base:
            return True
    for pattern in INTERESTING_KEYWORD_PATTERNS.values():
        if pattern.search(base):
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

    results = []
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
                filename_matches = find_filename_matches(filename)
                path_matches = find_path_matches(path)
                all_matches = filename_matches + path_matches
                highlighted = highlight_filename(filename, filename_matches)
                if highlighted != filename:
                    path = path[: -len(filename)] + highlighted
                unc = f"//{host}/{share}{path}"
                if all_matches:
                    primary = sorted(set(all_matches))[0]
                else:
                    primary = "other"
                results.append((primary, unc))
    for _, unc in sorted(results, key=lambda item: (item[0], item[1].lower())):
        print(unc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
