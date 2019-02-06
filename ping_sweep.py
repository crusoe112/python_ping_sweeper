#!/usr/bin/python3

import multiprocessing
import argparse, sys, ctypes
from os import getuid
try:
    is_admin = getuid() == 0
except AttributeError:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

if not is_admin:
    print('This program requires root/administrator privileges.')
    sys.exit()
import platform as plat
from scapy.all import *
MAX_PROCESSES = 20
if plat.system() != 'Windows':
    conf.L3socket = L3RawSocket
    MAX_PROCESSES = 200
from socket import inet_aton

if not is_admin:
    print('This program requires root/administrator privileges.')
    sys.exit()

def ping(jobs, results, is_sorted=False, attempts=1, timeout=1):
    while True:
        ip = jobs.get()
        if ip is None: 
            break

        for attempt in range(attempts):
            packet = IP(dst=ip, ttl=20)/ICMP()
            try:
                reply = sr1(packet, timeout=timeout, verbose=False)
            except Exception as e:
                print('Error sending ping to address: {}'.format(ip))
                return
            if reply is not None:
                if not is_sorted:
                    print(ip)
                results.put(ip)

def clamp(proc_num):
    if proc_num <= 0:
        return 1
    if proc_num > MAX_PROCESSES:
        return MAX_PROCESSES
    return proc_num

def parse_args(args):
    parser = argparse.ArgumentParser(description='Ping Sweeper')
    parser.add_argument('domain', action='store', 
                        help='The first 3 octets (e.g. 192.168.0)')
    parser.add_argument('start', type=int, action='store', 
                        help='The lowest value to try for the 4th octet')
    parser.add_argument('end', type=int, action='store',
                        help='The highest value to try for the 4th octet')
    parser.add_argument('--attempts', '-a', type=int, default=1, action='store',
                        help='The number of times to try to ping before failure')
    parser.add_argument('--timeout', '-t', type=int, default=1, action='store',
                        help='The time to wait before timing out in seconds')
    parser.add_argument('--sorted', '-s', default=False, action='store_true',
                        help='If not set, print IPs as soon as a response is received.')
    return parser.parse_args(args)

def main(args):
    parsed = parse_args(args)
    domain = parsed.domain
    start = parsed.start
    end = parsed.end
    attempts = parsed.attempts
    timeout = parsed.timeout
    is_sorted = parsed.sorted
    pool_size = clamp(end + 1 - start)
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=ping, args=(jobs, results,
                                                       is_sorted, attempts,
                                                       timeout))
            for i in range(pool_size)]

    #print('Adding jobs to the queue...')
    for i in range(start, end+1):
        jobs.put('{}.{}'.format(domain, i))

    #print('Starting processes...')
    for proc in pool:
        proc.start()

    #print('Waiting for processes to finish...')
    for proc in pool:
        jobs.put(None)

    #print('Joining processes...')
    for proc in pool:
        proc.join()

    ip_list = []

    #print('Getting results...')
    while not results.empty():
        ip_list.append(results.get())

    if is_sorted:
        ip_list = sorted(ip_list, key=lambda ip: inet_aton(ip))
        for ip in ip_list:
            print(ip)

if __name__ == '__main__':
    args = sys.argv[1:]
    main(args)
