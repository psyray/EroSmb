import argparse
import logging
import ipaddress
import threading
import psutil
from datetime import datetime

from erosmb.Machine import Machine
from erosmb.SMBScanner import SMBScanner
from colorama import init, Fore, Style

__version__ = "0.1.5"

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
parser.add_argument("--threads", default=255, help="set a number of threads (default: 255)")
parser.add_argument("--nothreads", default=False, action="store_true", help="do not use multithreading")

args = parser.parse_args()

if args.debug:
    logging.root.setLevel(logging.INFO)
elif args.verbose:
    logging.root.setLevel(logging.WARNING)
else:
    logging.root.setLevel(logging.CRITICAL)

log = logging.getLogger(__name__)
formatter = logging.Formatter('%(levelname)s | %(name)s | %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)


def banner():
    print(f"{Fore.MAGENTA}EroSmb {__version__} | enumerate Windows machines in your network{Style.RESET_ALL}\n")


machines = []


def common_scan(ip):
    smb_scanner = SMBScanner(ip)
    machine = smb_scanner.scan(args.username, args.password, args.domain)

    if machine is not None:
        # output immediately, if we don't need sorting
        if not args.sort:
            print_info(machine)

        machines.append(machine)

def print_info(machine: Machine):
    try:
        answer = f"{Fore.GREEN}[{machine.ip:^15}]{Fore.RESET} " \
                f"{machine.os:<45} {Fore.YELLOW}{machine.arch}{Fore.RESET} " \
                f"[{Fore.CYAN}{machine.domain}\\\\{machine.name}{Fore.RESET}]"

        if machine.logged_in:
            answer += f" {Fore.RED}Logged in as {args.username}{Fore.RESET}"

        if args.verbose or args.debug:
            print(answer,
                Fore.GREEN, "DNS:", machine.dns_name, "IsLoginReq:", machine.is_login_req,
                "SMBVer:", hex(machine.smb_dialect),
                Fore.RESET)
        else:
            print(answer)
    except AttributeError:
        answer = f"{Fore.RED}[{machine.ip:^15}]{Fore.RED} Error"
        print(answer)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def update_progress_bar(progress, total, target):
    percentage = (progress / total) * 100
    bar_length = 30
    filled_length = int(bar_length * progress // total)
    bar = '#' * filled_length + '-' * (bar_length - filled_length)
    print(f"\rScanning {target}: |{Fore.GREEN}{bar}{Fore.RESET}| {percentage:.1f}% Complete", end="\r")

def process_target(target, semaphore, total_ips, progress_dict):
    for ip in ipaddress.IPv4Network(target, strict=False):
        ip_str = ip.compressed
        semaphore.acquire()  # Acquire a semaphore slot
        if args.nothreads:
            try:
                common_scan(ip_str)
            finally:
                with progress_dict['lock']:
                    progress_dict['progress'] += 1
                    update_progress_bar(progress_dict['progress'], total_ips, target)
                semaphore.release()
        else:
            thread = threading.Thread(target=lambda: common_scan_thread(ip_str, semaphore, target, progress_dict, total_ips))
            thread.start()

def common_scan_thread(ip, semaphore, target, progress_dict, total_ips):
    try:
        common_scan(ip)
    finally:
        with progress_dict['lock']:
            progress_dict['progress'] += 1
            update_progress_bar(progress_dict['progress'], total_ips, target)
        semaphore.release()

def main():
    init()

    if not args.nologo:
        banner()

    max_threads = int(args.threads)
    semaphore = threading.Semaphore(max_threads)

    target = args.target

    print(f"Scanning: {Fore.GREEN}{target}{Fore.RESET} with {Fore.YELLOW}{max_threads}{Fore.RESET} threads")
    start_time = datetime.now()
    print(f"Start scanning {target} at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if target is an IP or IP range, otherwise read from file
    if is_valid_ip(target) or is_valid_ip_range(target):
        total_ips = len(list(ipaddress.IPv4Network(target, strict=False)))
        progress_dict = {'progress': 0, 'lock': threading.Lock()}
        process_target(target, semaphore, total_ips, progress_dict)
    else:
        # Read targets from file
        try:
            with open(target, 'r') as file:
                for line in file:
                    line = line.strip()
                    if is_valid_ip(line) or is_valid_ip_range(line):
                        total_ips = len(list(ipaddress.IPv4Network(line, strict=False)))
                        progress_dict = {'progress': 0, 'lock': threading.Lock()}
                        process_target(line, semaphore, total_ips, progress_dict)
        except FileNotFoundError:
            print(f"Error: File {target} not found.")
            return
        except IOError as e:
            print(f"IOError: {e}")
            return

    # Wait for all threads to finish
    main_thread = threading.current_thread()
    for t in threading.enumerate():
        if t is not main_thread:
            t.join()

    print()
    
    if args.verbose:
        print(f"Current online: {Fore.GREEN}{len(machines)}{Fore.RESET}")

    if args.sort:
        sorted_machines = list(machines)
        sorted_machines.sort(key=lambda machine: machine.os, reverse=True)
        for machine in sorted_machines:
            print_info(machine)

    if args.output:
        try:
            f = open(args.output, "w", encoding='utf8')
            for machine in machines:
                f.write(machine.ip + "\n")
            print("Written to file", f.name)
            f.close()
        except FileNotFoundError:
            log.error("Error writing to file: bad filename")
        except PermissionError:
            log.error("Error writing to file: not enough permissions.")
        except Exception as e:
            log.error(e)

    end_time = datetime.now()
    print(f"Finished scanning {target} at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Calculate duration
    duration_seconds = (end_time - start_time).total_seconds()
    duration_minutes = int(duration_seconds // 60)
    duration_seconds = int(duration_seconds % 60)
    print(f"Duration for {target}: {Fore.YELLOW}{duration_minutes} minutes {duration_seconds} seconds{Fore.RESET}")


if __name__ == "__main__":
    main()
