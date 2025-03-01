#!/bin/bash

set -e

# Help function
display_help() {
    echo -e "\nUsage: [sudo] $0\n"
    echo -e "This script disables IP forwarding and removes a NAT rule from iptables."
    echo -e "- IP forwarding is turned off by setting /proc/sys/net/ipv4/ip_forward to 0."
    echo -e "- The iptables NAT rule for 10.8.0.0/24 is removed from the POSTROUTING chain."
    echo -e "\nRequirements: Run this script as root.\n"
    exit 0
}

# Check for help flag
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    display_help
fi

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "\nError: This script must be run as root. Use sudo or switch to root.\n"
    exit 1
fi

# Disable IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward || { echo -e "\nError: Failed to disable IP forwarding.\n"; exit 1; }

# Remove NAT rule from iptables
if iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE || { echo -e "\nError: Failed to remove NAT rule from iptables.\n"; exit 1; }
else
    echo -e "\nWarning: NAT rule not found, skipping removal.\n"
fi

echo -e "\nIP forwarding disabled and NAT rule removed successfully.\n"
