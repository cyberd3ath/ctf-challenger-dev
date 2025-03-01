#!/bin/bash

# Function to convert decimal to hex with fixed width
dec_to_hex() {
    printf "%0${2}X" "$1"
}

# Function to display help message
show_help() {
    echo "Usage: $0 <add|remove> <user_id> <challenge_id> <subnet_id> [subnet (for add)]"
    echo -e "\nOptions:"
    echo "  add      Add a new network device with the given user ID, challenge ID, and subnet ID. Requires a subnet."
    echo "  remove   Remove an existing network device based on user ID, challenge ID, and subnet ID."
    echo "  -h, --help  Show this help message and exit."
    exit 0
}

# Ensure script is run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Validate input
if [[ $# -lt 1 ]]; then
    echo "Error: Missing arguments. Use -h or --help for usage information."
    exit 1
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
fi

if [[ $# -lt 4 ]]; then
    echo "Error: Insufficient arguments. Use -h or --help for usage information."
    exit 1
fi

action=$1
user_id=$2
challenge_id=$3
subnet_id=$4

# Convert IDs to hexadecimal with fixed width
user_hex=$(dec_to_hex "$user_id" 5)
challenge_hex=$(dec_to_hex "$challenge_id" 5)
subnet_hex=$(dec_to_hex "$subnet_id" 2)

device_name="u${user_hex}c${challenge_hex}n${subnet_hex}"

if [[ ${#device_name} -gt 15 ]]; then
    echo "Error: Generated device name '$device_name' exceeds 15 characters."
    exit 1
fi

if [[ "$action" == "add" ]]; then
    if [[ -z "$5" ]]; then
        echo "Error: Subnet is required for adding a device."
        exit 1
    fi
    subnet=$5
    
    echo "Adding network device: $device_name with subnet: $subnet"
    ip link add "$device_name" type bridge
    ip addr add "$subnet" dev "$device_name"
    ip link set "$device_name" up
elif [[ "$action" == "remove" ]]; then
    echo "Removing network device: $device_name"
    ip link set "$device_name" down
    ip link delete "$device_name"
else
    echo "Error: Invalid action '$action'. Use 'add' or 'remove'."
    exit 1
fi
