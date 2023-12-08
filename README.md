# autoscanner
A simple automated script for scanning web-apps

## Dependencies

- `python3-nmap`
- `python-Wappalyzer`
- `dnspython`
- `argparse`
- `gobuster`

The script is to be run as root:

```txt
usage: autoscanner [-h] [-s] [-O] [-A] [-P] [-f] target

autoscanner - Automated recon tool

positional arguments:
  target         Target IP address

options:
  -h, --help     show this help message and exit
  -s, --save     Save results to file
  -O, --no-os    Save results to file
  -A, --no-app   Save results to file
  -P, --no-port  Save results to file
  -f, --fuzz     Save results to file
```
It will download [SecLists](https://github.com/danielmiessler/SecLists) to your `~/.local/share/autoscan/SecLists/`


