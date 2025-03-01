#!/bin/bash

set -e

# Help function
display_help() {
    echo -e "\nUsage: [sudo] $0 <client_name> <static_ip>\n"
    echo -e "This script generates OpenVPN client keys, certificates, and configuration files."
    echo -e "\nArguments:"
    echo -e "  <client_name>   The name of the OpenVPN client."
    echo -e "  <static_ip>     The static IP to assign to the client."
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

CLIENT_NAME=$1
STATIC_IP=$2

# Validate arguments
if [[ -z "$CLIENT_NAME" || -z "$STATIC_IP" ]]; then
    echo -e "\nError: Missing arguments.\n"
    display_help
fi

EASY_RSA_DIR="/etc/openvpn/easy-rsa"
CCD_DIR="/etc/openvpn/ccd"
CLIENT_CONFIG_DIR="/etc/openvpn/client_configs"
VPN_SERVER_IP="10.0.2.4"

# Ensure necessary directories exist
mkdir -p "$CCD_DIR" "$CLIENT_CONFIG_DIR"

# Generate keys and certificates
echo -e "\nGenerating keys and certificates for $CLIENT_NAME...\n"
cd "$EASY_RSA_DIR" || { echo -e "\nError: Failed to access Easy-RSA directory.\n"; exit 1; }
./easyrsa --batch build-client-full "$CLIENT_NAME" nopass || { echo -e "\nError: Failed to generate client certificate.\n"; exit 1; }

# Assign static IP in CCD
echo -e "\nAssigning static IP $STATIC_IP to $CLIENT_NAME...\n"
echo "ifconfig-push $STATIC_IP 255.255.255.0" > "$CCD_DIR/$CLIENT_NAME"

# Generate client configuration file
CLIENT_CONFIG="$CLIENT_CONFIG_DIR/$CLIENT_NAME.ovpn"
echo -e "\nGenerating client config at $CLIENT_CONFIG...\n"

cat > "$CLIENT_CONFIG" <<EOF
client
dev tun
proto udp
remote $VPN_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
compress lzo
verb 3

key-direction 1

<ca>
$(cat "$EASY_RSA_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$EASY_RSA_DIR/pki/issued/$CLIENT_NAME.crt")
</cert>
<key>
$(cat "$EASY_RSA_DIR/pki/private/$CLIENT_NAME.key")
</key>
<tls-auth>
$(cat "$EASY_RSA_DIR/ta.key")
</tls-auth>
EOF

if [[ -f "$CLIENT_CONFIG" ]]; then
    echo -e "\nClient configuration file created at: $CLIENT_CONFIG\n"
else
    echo -e "\nError: Failed to create client configuration file.\n"
    exit 1
fi
