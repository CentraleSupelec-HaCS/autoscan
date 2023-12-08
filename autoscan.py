#!/usr/bin/env python3
import nmap3
import argparse
import os

seclist_dir = "/usr/local/share/autoscan/SecLists"
nmap = nmap3.Nmap()

technology_specific_lists = {
    "Node.js": [f"{seclist_dir}/Discovery/Web-Content/nodejs.txt"],
    "PHP": [f"{seclist_dir}/Discovery/Web-Content/Common-PHP-Filenames.txt", 
        f"{seclist_dir}/Discovery/Web-Content/Common-Backdoors-PHP.txt",
        f"{seclist_dir}/Discovery/Web-Content/PHP.fuzz.txt",],
    "Perl": [f"{seclist_dir}/Discovery/Web-Content/Common-Backdoors-PL.fuzz"],
    "ASP": [f"{seclist_dir}/Discovery/Web-Content/Common-Backdoors-ASP.fuzz"],
    "JSP": [f"{seclist_dir}/Discovery/Web-Content/Common-Backdoors-JSP.fuzz"],
    "ColdFusion": [f"{seclist_dir}/Discovery/Web-Content/coldfusion.txt"],
    "SharePoint": [f"{seclist_dir}/Discovery/Web-Content/sharepoint-enumeration.txt"],
    "Nginx": [f"{seclist_dir}/Discovery/Web-Content/nginx.txt"],
    "Apache": [f"{seclist_dir}/Discovery/Web-Content/Apache.fuzz.txt", 
        f"{seclist_dir}/Discovery/Web-Content/ApacheTomcat.fuzz.txt"],
    "CGI": [f"{seclist_dir}/Discovery/Web-Content/CGIS.txt", 
        f"{seclist_dir}/Discovery/Web-Content/CGI-HTTP-POST-Windows.fuzz.txt", 
        f"{seclist_dir}/Discovery/Web-Content/CGI-HTTP-POST.fuzz.txt", 
        f"{seclist_dir}/Discovery/Web-Content/CGI-Microsoft.fuzz.txt",
        f"{seclist_dir}/Discovery/Web-Content/CGI-XPlatform.fuzz.txt"],
    "Tomcat": [f"{seclist_dir}/Discovery/Web-Content/tomcat.txt", 
        f"{seclist_dir}/Discovery/Web-Content/ApacheTomcat.fuzz.txt"],
    "Oracle": [f"{seclist_dir}/Discovery/Web-Content/oracle.txt",
        f"{seclist_dir}/Discovery/Web-Content/Oracle-EBS-wordlist.txt",
        f"{seclist_dir}/Discovery/Web-Content/Oracle9i.fuzz.txt",
        f"{seclist_dir}/Discovery/Web-Content/OracleAppServer.fuzz.txt"],
    "general": [f"{seclist_dir}/Discovery/Web-Content/raft-large-directories.txt",
        f"{seclist_dir}/Discovery/Web-Content/raft-large-files.txt",
        f"{seclist_dir}/Discovery/Web-Content/raft-large-extensions.txt",
        f"{seclist_dir}/Discovery/Web-Content/common.txt",
        f"{seclist_dir}/Discovery/Web-Content/big.txt",
        f"{seclist_dir}/Discovery/Web-Content/quickhits.txt",
        f"{seclist_dir}/Discovery/Web-Content/Randomfiles.fuzz.txt"]

}

def get_ports(target, ip, save=False):
    print("Starting port scan...")
    results = nmap.scan_top_ports(target)
    for port in results[ip]['ports']:
        print(f"Port: {port['portid']}\tState: {port['state']}\tService: {port['service']['name']}")
    if save:
        save_results(results, target, 'port')
    return results

def is_ip(target):
    if target.count(".") == 3 or target.count(":") == 7:
        return True
    return False

def get_ip(target):
    print("Resolving IP address...")
    import dns
    import dns.resolver, dns.rdataclass, dns.rdatatype
    try:
        answers = dns.resolver.resolve(target, 'A')
        for rdata in answers:
            print(f"IP: {rdata.address}")
            return rdata.address
    except:
        print("Unable to resolve IP address")
        return None

def get_os(target, ip, save=False):
    print("Starting os scan...")
    if os.geteuid() != 0:
        print("OS scan requires root privileges")
        exit(1)
    results = nmap.nmap_os_detection(target)
    for match in results[ip]['osmatch']:
        print(f"OS: {match['name']}, Accuracy: {match['accuracy']}")
    if save:
        save_results(results, target, 'os')
    return results

def save_results(results, target, source):
    import json
    with open(f"{target}/{target}_{source}_results.json", "w") as f:
        json.dump(results, f)
        f.close()

def get_wordlists():
    global seclist_dir_prefix
    global seclist_dir
    if not os.path.exists(seclist_dir):
        print("Downloading SecLists...")
        os.system(f"git clone https://github.com/danielmiessler/SecLists {seclist_dir}")

def get_wappalyzer(target, save=False):
    print("Starting wappalyzer scan...")
    from Wappalyzer import Wappalyzer, WebPage
    wappalyzer = Wappalyzer.latest()
    page = WebPage.new_from_url(f"http://{target}")
    results = list(wappalyzer.analyze(page))
    print(f"{target} is running:")
    for app in results:
        print(f"App: {app}")
    if save:
        save_results(results, target, 'wappalyzer')
    return results

def parse_args():
    parser = argparse.ArgumentParser(description="autoscanner - Automated recon tool")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-s", "--save", help="Save results to file", action="store_true")
    parser.add_argument("-O", "--no-os", help="Doesn't perform OS Scan", action="store_false")
    parser.add_argument("-A", "--no-app", help="Doesn't perform App/Stack Scan", action="store_false")
    parser.add_argument("-P", "--no-port", help="Doesn't perform Port Scan", action="store_false")
    parser.add_argument("-f", "--fuzz", help="Lauch gobuster fuzzing and generate fuzz file", action="store_true")
    args = parser.parse_args()
    return args

def generate_fuzz_file(target, apps):
    print("Generating fuzz file...")
    global technology_specific_lists
    global seclist_dir
    global seclist_dir_prefix
    fuzz_file = f"{target}/fuzz.txt"
    sources = technology_specific_lists["general"]
    with open(fuzz_file, "w") as f:
        for app in apps:
            if app in technology_specific_lists:
                sources += technology_specific_lists[app]
        for source in sources:
            with open(source, "r") as f2:
                f.writelines(f2.readlines())
                f2.close()
        f.close()
    print("Using the following wordlists:")
    for source in sources:
        print(source)
    return sources

def check_program_exists(program):
    return os.system(f"which {program} > /dev/null") == 0

def main():
    args = parse_args()
    if args.save:
        try:
            os.mkdir(args.target)
        except:
            print("Failed to create directory: Folder already exists")
            exit(1)
    ip = get_ip(args.target)

    if not args.no_port:
        _ = get_ports(args.target, ip, args.save)
    if not args.no_os:
        _ = get_os(args.target, ip, args.save)

    if not args.no_app:
        apps = get_wappalyzer(args.target, args.save)
    else:
        apps = []
    
    if args.fuzz:
        get_wordlists()
        sources = generate_fuzz_file(args.target, apps)

        if check_program_exists("gobuster"):
            print("Running gobuster...")
            print("\n" + f"gobuster dir -u http://{args.target} -w {args.target}/fuzz.txt -t 100 -r -o {args.target}/gobuster_results.txt\n")
            os.system(f"gobuster dir -u http://{args.target} -w {args.target}/fuzz.txt -t 100 -r -o {args.target}/gobuster_results.txt")


if __name__ == "__main__":
    main()
