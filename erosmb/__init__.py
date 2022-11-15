import argparse
import logging
import ipaddress
import threading

from erosmb.SMBScanner import SMBScanner
from colorama import init, Fore, Style

__version__ = "0.1.4"

parser = argparse.ArgumentParser(description='Enumerate Windows machines in network.')

parser.add_argument("target", help="target IPs. May be range 192.168.0.0/24 or single ip")
parser.add_argument("-v", "--verbose", default=False, action="store_true", help="print warnings")
parser.add_argument("-vv", "-d", "--debug", default=False, action="store_true", help="print debug information")
parser.add_argument("-t", "--timeout", default=0.1, type=float, help="timeout before deciding to mark a port as closed")
parser.add_argument("-o", "--output", default=False, type=str, help="file to output list of machines")
parser.add_argument("-s", "--sort", default=False, action="store_true", help="sort by kernel version")
parser.add_argument('-V', '--version', action='version', version=__version__)
parser.add_argument("--username", default="anonymous")
parser.add_argument("--password", default="anonymous", help="password for username")
parser.add_argument("--domain", default="LANPARTY", help="domain for username")
parser.add_argument("--nologo", default=False, action="store_true", help="do not display logo")
parser.add_argument("--nothreads", default=False, action="store_true", help="do not use multithreading")

args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)
if args.verbose:
    logging.basicConfig(level=logging.WARNING)
else:
    logging.basicConfig(level=logging.ERROR)


def banner():
    logo = """\
eeeeee            ssssssss
ee                ss                b
eeeeee rrrr  ooo  ssssssss  mm  mm  bbbb
ee     rr   o   o       ss  m mm m  b  bb
eeeeee r     ooo  ssssssss  m    m  bbbb
________________________________________
"""
    logo += "\n\nSmb scanner\n"
    print(Fore.MAGENTA)
    print(logo)
    print(Style.RESET_ALL)


machines = []


def common_scan(ip):
    smb_scanner = SMBScanner(ip)
    smb_info = smb_scanner.scan(args.username, args.password, args.domain)

    if 'host' in smb_info:
        # output immediately, if we don't need sorting
        if not args.sort:
            print_info(smb_info)

        machines.append(smb_info)


def print_info(smb_info):
    answer = f"{Fore.GREEN}[{smb_info['host']:^15}]{Fore.RESET} " \
             f"{smb_info['os']} {Fore.YELLOW}{smb_info['arch']}{Fore.RESET} " \
             f"[{Fore.CYAN}{smb_info['domain']}\\\\{smb_info['name']}{Fore.RESET}]"

    if smb_info["logged_in"]:
        answer += f" {Fore.RED}Logged in as {args.username}{Fore.RESET}"

    if args.verbose:
        print(answer,
              Fore.GREEN, "DNS:", smb_info['dns_hostname'], "IsLoginReq:", smb_info['is_login_required'],
              Fore.RESET)
    else:
        print(answer)


def main():
    init()

    if not args.nologo:
        banner()

    threads = []
    for ip in ipaddress.IPv4Network(args.target):
        if args.nothreads:
            common_scan(ip.compressed)
        else:
            thread = threading.Thread(target=common_scan, args=(ip.compressed,))

            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()

    if args.verbose:
        print(f"Current online: {Fore.GREEN}{len(machines)}{Fore.RESET}")

    if args.sort:
        m = list(machines)
        m.sort(key=lambda e: e['os'], reverse=True)
        for smb_info in m:
            print_info(smb_info)

    if args.output:
        try:
            f = open(args.output, "w", encoding='utf8')
            for machine in machines:
                f.write(machine['host'] + "\n")
            print("Written to file", f.name)
            f.close()
        except FileNotFoundError:
            logging.error("Error writing to file: bad filename")


if __name__ == "__main__":
    main()
