# share_sniffer
scan smb shares using impacket

requires the `impacket` Python package (for example `python3-impacket` or `pip install impacket`).

## usage
```
./share_sniffer.py --targets targets.txt
./share_sniffer.py --targets 10.0.0.1
./share_sniffer.py --targets targets.txt --username USER --domain DOMAIN --password PASS
./share_sniffer.py --targets targets.txt -o ./results
./share_sniffer.py --targets targets.txt --threads 5
```

outputs a directory per target, then per share, with a `files.txt` recursive listing:
```
./results_<timestamp>/<target>/<share>/files.txt
```

## scan results
```
./scan_results.py
./scan_results.py -d ./results_20240101_120000
```

## download files
```
./downloader.py --paths //host/share/path/file.txt
./downloader.py --paths unc_list.txt
./downloader.py --paths unc_list.txt -o ./files
```
