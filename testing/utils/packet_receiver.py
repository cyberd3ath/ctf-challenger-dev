#!/usr/bin/env python3
import argparse
import socket
import sys
from scapy.all import sniff, IP, ICMP

def recv_tcp(listen_ip, listen_port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listen_ip, listen_port))
    s.listen(1)
    s.settimeout(timeout)
    try:
        conn, addr = s.accept()
        data = conn.recv(1024)
        print(f"TCP packet received from {addr}: {data}")
        sys.exit(0)
    except socket.timeout:
        print("TCP receive timeout", file=sys.stderr)
        sys.exit(1)
    finally:
        s.close()

def recv_udp(listen_ip, listen_port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((listen_ip, listen_port))
    s.settimeout(timeout)
    try:
        data, addr = s.recvfrom(4096)
        print(f"UDP packet received from {addr}: {data}")
        sys.exit(0)
    except socket.timeout:
        print("UDP receive timeout", file=sys.stderr)
        sys.exit(1)
    finally:
        s.close()

def recv_icmp(listen_ip, timeout):
    packets = sniff(filter=f"icmp and dst host {listen_ip}", timeout=timeout)
    if packets:
        print(f"ICMP packet received: {packets[0].summary()}")
        sys.exit(0)
    else:
        print("ICMP receive timeout", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp"], required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()

    if args.proto == "tcp":
        recv_tcp(args.listen, args.port, args.timeout)
    elif args.proto == "udp":
        recv_udp(args.listen, args.port, args.timeout)
    elif args.proto == "icmp":
        recv_icmp(args.listen, args.timeout)
