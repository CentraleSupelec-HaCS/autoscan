# autoscan
A simple automated script for scanning web-apps

## Dependencies

- `python3-nmap`
- `python-Wappalyzer`
- `dnspython`
- `argparse`
- `gobuster`

The script is to be run as root:

```txt
usage: autoscan [-h] [-s] target

scanner

positional arguments:
  target      Target IP address

options:
  -h, --help  show this help message and exit
  -s, --save  Save results to file
```
It will download [SecLists](https://github.com/danielmiessler/SecLists) to your `~/.local/share/scanner/SecLists/`


