#!/usr/bin/env python3
import argparse
import socket
import sys
from scapy.all import IP, ICMP, send

def send_tcp(src_ip, dst_ip, dst_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((src_ip, 0))
    try:
        s.connect((dst_ip, dst_port))
        s.sendall(b"Test")
    except Exception as e:
        print(f"TCP send error: {e}", file=sys.stderr)
    finally:
        s.close()

def send_udp(src_ip, dst_ip, dst_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src_ip, 0))
    try:
        s.sendto(b"Test", (dst_ip, dst_port))
    except Exception as e:
        print(f"UDP send error: {e}", file=sys.stderr)
    finally:
        s.close()

def send_icmp(src_ip, dst_ip):
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP()
    send(pkt, verbose=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp"], required=True)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    if args.proto == "tcp":
        send_tcp(args.src, args.dst, args.port)
    elif args.proto == "udp":
        send_udp(args.src, args.dst, args.port)
    elif args.proto == "icmp":
        send_icmp(args.src, args.dst)
