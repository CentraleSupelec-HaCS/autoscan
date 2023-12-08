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
  -O, --no-os    Doesn't perform OS Scan
  -A, --no-app   Doesn't perform App/Stack Scan
  -P, --no-port  Doesn't perform Port Scan
  -f, --fuzz     Lauch gobuster fuzzing and generate fuzz file
```
It will download [SecLists](https://github.com/danielmiessler/SecLists) to your `~/.local/share/autoscan/SecLists/`


