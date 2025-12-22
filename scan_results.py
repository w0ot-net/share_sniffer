#!/usr/bin/env python3
import argparse
import os
import re
import sys


INTERESTING_EXTS = {
    ".html",
    ".htm",
    ".php",
    ".phtml",
    ".vbs",
    ".ps1",
    ".ashx",
    ".asmx",
    ".aspx",
    ".asax",
    ".jsp",
    ".jspx",
    ".do",
    ".action",
    ".cgi",
    ".shtml",
    ".cshtml",
    ".vbhtml",
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
    "nude",
}
WORD_BOUNDARY_KEYWORDS = {"key"}
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
    parser.add_argument(
        "-v",
        "--ignore",
        action="append",
        default=[],
        help="Keyword to ignore (can be repeated).",
    )
    parser.add_argument(
        "-i",
        "--case-insensitive",
        action="store_true",
        help="Match keywords case-insensitively.",
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


def build_keyword_patterns(case_insensitive):
    patterns = {}
    flags = re.IGNORECASE if case_insensitive else 0
    for keyword in WORD_BOUNDARY_KEYWORDS:
        patterns[keyword] = re.compile(rf"\b{re.escape(keyword)}\b", flags)
    return patterns


def find_filename_matches(filename, case_insensitive, ignore_set, keyword_patterns):
    matches = []
    compare_name = filename.lower() if case_insensitive else filename
    base = os.path.basename(compare_name)
    if (base in INTERESTING_FILENAMES or base.startswith(".env.")) and base not in ignore_set:
        matches.append(base)
    for keyword in INTERESTING_NAME_KEYWORDS:
        if keyword in ignore_set:
            continue
        if keyword in compare_name:
            matches.append(keyword)
    for keyword, pattern in keyword_patterns.items():
        if keyword in ignore_set:
            continue
        if pattern.search(base):
            matches.append(keyword)
    _, ext = os.path.splitext(compare_name)
    if ext in INTERESTING_EXTS:
        matches.append(ext)
    if ext == ".ini":
        if base in INTERESTING_INI_FILENAMES:
            matches.append(base)
    return matches


def find_path_matches(path, case_insensitive, ignore_set):
    compare_path = path.lower() if case_insensitive else path
    matches = []
    for keyword in INTERESTING_PATH_KEYWORDS:
        if keyword in ignore_set:
            continue
        if keyword in compare_path:
            matches.append(keyword)
    return matches


def is_exact_filename_match(base, ignore_set):
    return (
        (base in INTERESTING_FILENAMES and base not in ignore_set)
        or (base.startswith(".env.") and base not in ignore_set)
        or (base in INTERESTING_XML_FILENAMES and base not in ignore_set)
        or (base in INTERESTING_INI_FILENAMES and base not in ignore_set)
    )


def highlight_filename(filename, matches, case_insensitive):
    if not matches:
        return filename
    pattern = "|".join(re.escape(m) for m in sorted(set(matches), key=len, reverse=True))
    flags = re.IGNORECASE if case_insensitive else 0
    regex = re.compile(pattern, flags)
    return regex.sub(lambda m: f"\x1b[31m{m.group(0)}\x1b[0m", filename)


def is_interesting(path, case_insensitive, ignore_set, keyword_patterns):
    path = path.strip().rstrip("/")
    if not path:
        return False
    if os.path.basename(path).lower() == "thumbs.db":
        return False
    if path.lower().endswith(".adml"):
        return False
    compare_path = path.lower() if case_insensitive else path
    base = os.path.basename(compare_path)
    if (base in INTERESTING_FILENAMES and base not in ignore_set) or (
        base.startswith(".env.") and base not in ignore_set
    ):
        return True
    if base in INTERESTING_XML_FILENAMES and base not in ignore_set:
        return True
    _, ext = os.path.splitext(compare_path)
    if ext == ".ini":
        if base in INTERESTING_INI_FILENAMES and base not in ignore_set:
            return True
        for keyword in INTERESTING_NAME_KEYWORDS:
            if keyword in ignore_set:
                continue
            if keyword in base:
                return True
        for keyword, pattern in keyword_patterns.items():
            if keyword in ignore_set:
                continue
            if pattern.search(base):
                return True
        return False
    if ext in INTERESTING_EXTS:
        return True
    for keyword in INTERESTING_NAME_KEYWORDS:
        if keyword in ignore_set:
            continue
        if keyword in base:
            return True
    for keyword, pattern in keyword_patterns.items():
        if keyword in ignore_set:
            continue
        if pattern.search(base):
            return True
    for keyword in INTERESTING_PATH_KEYWORDS:
        if keyword in ignore_set:
            continue
        if keyword in compare_path:
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

    ignore_set = set(args.ignore)
    if args.case_insensitive:
        ignore_set = {item.lower() for item in ignore_set}
    keyword_patterns = build_keyword_patterns(args.case_insensitive)

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
                if not is_interesting(path, args.case_insensitive, ignore_set, keyword_patterns):
                    continue
                if not path.startswith("/"):
                    path = "/" + path.lstrip("/")
                filename = os.path.basename(path)
                filename_matches = find_filename_matches(
                    filename,
                    args.case_insensitive,
                    ignore_set,
                    keyword_patterns,
                )
                path_matches = find_path_matches(path, args.case_insensitive, ignore_set)
                all_matches = filename_matches + path_matches
                highlighted = highlight_filename(filename, filename_matches, args.case_insensitive)
                if highlighted != filename:
                    path = path[: -len(filename)] + highlighted
                unc = f"//{host}/{share}{path}"
                base = os.path.basename(path)
                base_compare = base.lower() if args.case_insensitive else base
                exact_match = is_exact_filename_match(base_compare, ignore_set)
                if "nude" in all_matches:
                    primary = "nude"
                elif "password" in all_matches:
                    primary = "password"
                elif all_matches:
                    primary = sorted(set(all_matches))[0]
                else:
                    primary = "other"
                priority = 0 if exact_match or "nude" in all_matches or "password" in all_matches else 1
                results.append((priority, primary, unc))
    def sort_key(item):
        priority, primary, unc = item
        return (priority, primary, unc.lower())

    for _, _, unc in sorted(results, key=sort_key):
        print(unc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
