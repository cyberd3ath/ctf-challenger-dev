#!/bin/bash

# Help screen function
display_help() {
    echo -e "Usage: $0 <client_name>"
    echo -e "\nDescription:"
    echo -e "This script removes an OpenVPN client from the server."
    echo -e "It deletes the client's configuration, certificate, key, and static IP mapping."
    echo -e "\nArguments:"
    echo -e "  <client_name>  The name of the OpenVPN client to remove."
    exit 1
}

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[31mError: This script must be run as root. Please use sudo or log in as root.\e[0m"
    exit 1
fi

# Check if client name is provided
CLIENT_NAME=$1
if [ -z "$CLIENT_NAME" ]; then
    echo -e "\e[31mError: No client name provided.\e[0m"
    display_help
fi

EASY_RSA_DIR="/etc/openvpn/easy-rsa"
CCD_DIR="/etc/openvpn/ccd"
CLIENT_CONFIG_DIR="/etc/openvpn/client_configs"

echo -e "Removing files for client \e[33m$CLIENT_NAME\e[0m..."

# Function to remove files safely
remove_file() {
    local file=$1
    local description=$2
    if [ -f "$file" ]; then
        rm -f "$file" && echo -e "Removed $description: \e[32m$file\e[0m" || {
            echo -e "\e[31mError removing $description: $file\e[0m"
            exit 1
        }
    else
        echo -e "$description not found: \e[33m$file\e[0m"
    fi
}

# Remove the client configuration file
remove_file "$CLIENT_CONFIG_DIR/$CLIENT_NAME.ovpn" "client configuration"

# Remove the client certificate, key, and request files
remove_file "$EASY_RSA_DIR/pki/issued/$CLIENT_NAME.crt" "client certificate"
remove_file "$EASY_RSA_DIR/pki/private/$CLIENT_NAME.key" "client key"
remove_file "$EASY_RSA_DIR/pki/reqs/$CLIENT_NAME.req" "client request file"

# Remove the static IP entry from CCD
remove_file "$CCD_DIR/$CLIENT_NAME" "static IP entry in CCD"

# Revoke the client certificate if needed (uncomment to use)
./easyrsa --batch revoke $CLIENT_NAME
./easyrsa gen-crl
cp $EASY_RSA_DIR/pki/crl.pem /etc/openvpn/

echo -e "\e[32mClient $CLIENT_NAME removed successfully.\e[0m"
