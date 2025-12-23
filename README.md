# share_sniffer
scan smb shares using impacket's smbclient

## usage
```
./share_sniffer.py --targets targets.txt <smbclient.py args>
./share_sniffer.py --targets 10.0.0.1 <smbclient.py args>
./share_sniffer.py --targets targets.txt --username USER --domain DOMAIN --password PASS <smbclient.py args>
./share_sniffer.py --targets targets.txt -o ./results <smbclient.py args>
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
./downloader.py --paths //host/share/path/file.txt <smbclient.py args>
./downloader.py --paths unc_list.txt <smbclient.py args>
./downloader.py --paths unc_list.txt -o ./files <smbclient.py args>
```
