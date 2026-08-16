# share_sniffer

Scan SMB shares, analyze recursive listings, and download selected files using
`impacket`.

Install the `impacket` Python package first, for example with `python3-impacket` from
your operating system or `pip install impacket`.

## Scan shares

```bash
./share_sniffer.py 10.0.0.1
./share_sniffer.py targets.txt
./share_sniffer.py targets.txt -o ./results
./share_sniffer.py 10.0.0.1 --username USER --domain DOMAIN
./share_sniffer.py targets.txt --target-threads 5 --share-threads 3 --dir-threads 3
./share_sniffer.py targets.txt --exclude-shares 'ADMIN$,C$'
```

Targets are positional arguments; each may be a host/IP or a file containing one target
per line. `--target-threads`, `--share-threads`, and `--dir-threads` control concurrency
at their respective levels. `--exclude-shares` accepts a case-insensitive,
comma-separated list.

The scanner writes one recursive listing per readable share:

```text
./results_<timestamp>/<target>/<share>/files.txt
```

The scanner exits `0` when at least one requested target has a successfully enumerated
share, and `1` when all requested targets fail or input is invalid. Individual
inaccessible shares and directories remain best-effort skips.

## Authentication

Authentication flags are shared by `share_sniffer.py` and `downloader.py`:

```text
--username USER --domain DOMAIN --password PASS
--username USER --hashes LMHASH:NTHASH
--no-pass
-k/--kerberos --aes-key HEX --dc-ip IP
--target-ip IP --port 445 --timeout 10
```

When `--username` is provided without `--password`, an interactive terminal prompts for
the password. Prefer the prompt when possible: a command-line password may be visible
in shell history or process listings.

## Analyze results

```bash
./analyze.py
./analyze.py -d ./results_20240101_120000
```

Matching filenames are highlighted only when stdout is an interactive terminal.
Redirected analyzer result paths contain raw UNC text without ANSI color bytes.

## Download files

```bash
./downloader.py --paths //host/share/path/file.txt
./downloader.py --paths unc_list.txt
./downloader.py --paths unc_list.txt -o ./files
```

Downloads use a flat local filename containing a readable sanitized prefix and a
SHA-256 suffix derived from the canonical UNC path. This prevents distinct remote paths
from silently overwriting each other after sanitization.

The downloader attempts all requested files and exits `0` only when every transfer
succeeds; any connection or transfer failure produces exit status `1`.

## Tests

```bash
python3 -m unittest discover -v
```
