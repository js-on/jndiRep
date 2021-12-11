#!/usr/bin/env python
from shutil import get_terminal_size
from time import time, ctime
import threading
import requests
import argparse
import base64
import sys
import re
import os

paths = []
findings = []
WIDTH = get_terminal_size().columns
RED = "\x1b[31m"
GREEN = "\x1b[32m"
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
IP_RE = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
url = 'https://api.abuseipdb.com/api/v2/report'


class JNDI:
    def __init__(self, path: str, lines: list):
        self.path = path
        self.lines = lines


def error(msg: str):
    msg = msg.replace("\n", "\n    ")
    print(f"{RED}[!]{RESET} {msg}")
    sys.exit(1)


def info(msg: str):
    msg = msg.replace("\n", "\n    ")
    print(f"{GREEN}[!]{RESET} {msg}")


def progress(size: int):
    prog = round(50/size*(size-len(paths)))
    msg = f"Progress: [{prog*'#'}{(50-prog)*' '}] {size-len(paths)}/{size}"
    msg += (WIDTH-len(msg)) * ' '
    print(msg, end='\r')


def decode_payload(log: str) -> bytes:
    payload = b""
    if b"Base64" in log:
        payload = base64.decodebytes(log.split(b"Base64/")[1].split(b"}")[0])
    elif b"${lower" in log or b"${upper" in log:
        log = b'$' + b'$'.join(log.split(b"$")[1:])[:-1]
        payload = re.sub(r'\$\{\w+:(\w+)\}', r"\1", log.decode()).encode()
    return payload

def run(size: int, grep: str):
    while len(paths) != 0:
        path = paths.pop()
        progress(size)
        try:
            scan_file(path, grep)
        except Exception as e:
            error(
                str(e) + "\nPlease file an issue at https://github.com/js-on/jndiRep/issues")


def scan_directory(directory: str, jobs: int, grep: str):
    for root, _, files in os.walk(directory):
        for name in files:
            fname = os.path.join(root, name)
            paths.append(fname)

    procs = []
    size = len(paths)
    if size < jobs:
        jobs = size

    info(f"Spawning {jobs} threads\nStart at {ctime(time())}")
    for i in range(jobs):
        procs.append(threading.Thread(target=run, args=(size, grep)))
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()

    print()
    info(f"Stop at {ctime(time())}")


def scan_file(path: str, grep: str):
    log = []
    with open(path, "rb") as f:
        grep = grep.encode()
        for line in f:
            if grep in line:
                t = line.strip()
                payload = decode_payload(t)
                if payload != b"":
                    t += b"\nPayload: " + payload
                log.append(t)

    if len(log) != 0:
        findings.append(JNDI(path=path, lines=log))


def write_findings(output: str):
    with open(output, "w") as f:
        for finding in findings:
            f.write(f"{finding.path}\n")
            for log in finding.lines:
                f.write(f"{log.decode()}\n")
            f.write("\n")

    info(f"Findings written to {output}")


def print_findings():
    for finding in findings:
        print(f"\n{BOLD}=== {finding.path} ==={RESET}")
        for log in finding.lines:
            try:
                log = log.decode()
                ips = IP_RE.findall(log)
                for ip in ips:
                    log = log.replace(ip, f"{GREEN}{ip}{RESET}")
                log = log.replace("Payload", f"{RED}Payload{RESET}")
                print(log, end="\n\n")
            except:
                print(log, end="\nn")


def report(api_key: str, include_logs: bool, comment: str, dedup: bool):
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    ips = []
    for finding in findings:
        for line in finding.lines:
            line = line.decode()
            msg = comment
            ip = line.split(" ")[0]

            # Deduplication of reports
            if dedup:
                if ip in ips:
                    continue
                else:
                    ips.append(ip)
            if include_logs:
                log = line[line.index("["):].split("\nPayload: ")[0]
                msg += " - " + log
            data = {
                "ip": ip,
                "categories": "21",
                "comment": msg
            }
            res = requests.request(method='POST', url=url, headers=headers, params=data)
            if res.status_code // 100 == 4:
                error(res.text)
            else:
                info(res.text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--api-key",
                    type=str, help="AbuseIPDB Api Key")
    ap.add_argument("-d", "--directory", type=str, help="Directory to scan")
    ap.add_argument("-f", "--file", type=str, help="File to scan")
    ap.add_argument("-g", "--grep", type=str,
                    help="Custom word to grep for", default="jndi")
    ap.add_argument("-o", "--output", type=str,
                    help="File to store results. stdout if not set", default=None)
    ap.add_argument("-t", "--threads", type=int,
                    help="Number of threads to start. Default is 4", default=4)
    ap.add_argument("-r", "--report", action="store_true",
                    help="Report IPs to AbuseIPDB with category 21 (malicious web request)", default=False)
    ap.add_argument("-c", "--comment", type=str, help="Comment sent with your report",
                    default="Request related to CVE-2021-44228")
    ap.add_argument("--include-logs", action="store_true", default=False,
                    help="Include logs in your report. PII will NOT be stripped of!!!")
    ap.add_argument("--no-dedup", action="store_true", default=False, help="If set, report ever occurrence of IP. Default: Report only once.")
    args = ap.parse_args(sys.argv[1:])

    if args.report:
        if not args.api_key:
            error("Api Key is required. (-a, --api-key)")

    if args.directory:
        scan_directory(os.path.join(os.getcwd(), args.directory),
                       args.threads, args.grep)
    elif args.file:
        scan_file(os.path.join(args.file), args.grep)
    else:
        error("Either (-f) or (-d) is required.")

    if args.output:
        write_findings(os.path.join(os.getcwd(), args.output))
    else:
        print_findings()

    if args.report:
        report(args.api_key, args.include_logs, args.comment, not args.no_dedup)


if __name__ == "__main__":
    main()
