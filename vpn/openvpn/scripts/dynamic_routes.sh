#!/bin/bash

set -e

# Help function
display_help() {
    echo -e "\nUsage: [sudo] $0 <output_file>\n"
    echo -e "This script assigns routes to OpenVPN clients based on a predefined route file."
    echo -e "- Reads routes from /etc/openvpn/routes.txt"
    echo -e "- Pushes routes to clients dynamically"
    echo -e "- Configures iptables for NAT and forwarding\n"
    echo -e "Arguments:"
    echo -e "  <output_file>  The file to which route push directives will be appended. (stdout by default when run with openvpn)"
    echo -e "\nRequirements: Run this script as root and ensure OpenVPN provides the CLIENT_IP variable.\n"
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

# Validate argument
if [[ -z "$1" ]]; then
    echo -e "\nError: Missing output file argument.\n"
    display_help
fi

OUTPUT_FILE="$1"
ROUTES_FILE="/etc/openvpn/routes.txt"
LOG_FILE="/var/log/openvpn-routes.log"

# Ensure routes file exists
if [[ ! -f "$ROUTES_FILE" ]]; then
    echo -e "\nError: Routes file $ROUTES_FILE not found.\n"
    exit 1
fi

# Environment variable from OpenVPN
CLIENT_IP=$ifconfig_pool_remote_ip
if [[ -z "$CLIENT_IP" ]]; then
    echo -e "\nError: CLIENT_IP variable not set by OpenVPN.\n"
    exit 1
fi

echo "Client with IP $CLIENT_IP connected" >> "$LOG_FILE"

# Function to convert CIDR to subnet mask
cidr_to_netmask() {
    case "$1" in
        8) echo "255.0.0.0" ;;
        16) echo "255.255.0.0" ;;
        24) echo "255.255.255.0" ;;
        32) echo "255.255.255.255" ;;
        *) echo -e "\nError: Unknown subnet mask for CIDR $1\n"; exit 1 ;;
    esac
}

# Process routes
while read -r CLIENT ROUTE INTERFACE; do
    if [[ "$CLIENT" == "$CLIENT_IP" ]]; then
        MASK_CIDR="${ROUTE#*/}"
        NETMASK=$(cidr_to_netmask "$MASK_CIDR")
        NETWORK="${ROUTE%/*}"
        
        echo "Assigning route $NETWORK/$MASK_CIDR via interface $INTERFACE to client $CLIENT_IP" >> "$LOG_FILE"
        echo "push \"route $NETWORK $NETMASK\"" >> "$OUTPUT_FILE"

        # Add route to system
        ip route add "$NETWORK/$MASK_CIDR" via "$CLIENT_IP" dev tun0 || { echo -e "\nError: Failed to add route $NETWORK/$MASK_CIDR via $CLIENT_IP.\n"; exit 1; }

        # Configure iptables for forwarding
        iptables -t nat -A POSTROUTING -o "$INTERFACE" -s "$CLIENT_IP" -j MASQUERADE
        iptables -A FORWARD -i tun0 -o "$INTERFACE" -s "$CLIENT_IP" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -i "$INTERFACE" -o tun0 -d "$CLIENT_IP" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
done < "$ROUTES_FILE"

echo "Finished processing routes for client $CLIENT_IP" >> "$LOG_FILE"
exit 0
