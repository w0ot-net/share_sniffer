#!/usr/bin/env python3
import os
import sys


def split_args(argv, list_flag, default_output):
    items = []
    passthrough = []
    wrapper = {
        "username": None,
        "domain": None,
        "password": None,
        "verbose": False,
        "output": default_output,
    }
    idx = 0
    list_opt = f"--{list_flag}"
    while idx < len(argv):
        arg = argv[idx]
        if arg == list_opt:
            if idx + 1 >= len(argv):
                return None, None, None, f"error: {list_opt} requires a value"
            items.append(argv[idx + 1])
            idx += 2
            continue
        if arg.startswith(f"{list_opt}="):
            items.append(arg.split("=", 1)[1])
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
    return items, wrapper, passthrough, None


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


def build_target(host, username, domain, password):
    if "@" in host:
        return host

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


def require_no_inline_creds(items, err_msg):
    for item in items:
        if "@" in item:
            print(err_msg, file=sys.stderr)
            return False
    return True
