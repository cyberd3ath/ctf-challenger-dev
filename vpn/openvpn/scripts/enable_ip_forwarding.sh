#!/bin/bash

set -e

# Help function
display_help() {
    echo -e "\nUsage: [sudo] $0\n"
    echo -e "This script enables IP forwarding and adds a NAT rule to iptables."
    echo -e "- IP forwarding is enabled by setting /proc/sys/net/ipv4/ip_forward to 1."
    echo -e "- The iptables NAT rule for 10.8.0.0/24 is added to the POSTROUTING chain."
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

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward || { echo -e "\nError: Failed to enable IP forwarding.\n"; exit 1; }

# Add NAT rule to iptables
if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE || { echo -e "\nError: Failed to add NAT rule to iptables.\n"; exit 1; }
else
    echo -e "\nWarning: NAT rule already exists, skipping addition.\n"
fi

echo -e "\nIP forwarding enabled and NAT rule added successfully.\n"
