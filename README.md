# share_sniffer
scan smb shares using impacket's smbclient

## usage
```
./share_sniffer.py --targets targets.txt <smbclient.py args>
./share_sniffer.py --targets 10.0.0.1,10.0.0.2 <smbclient.py args>
```

outputs a directory per target, then per share, with a `files.txt` recursive listing:
```
<target>/<share>/files.txt
```
