#!/bin/bash

set -e

# Help function
display_help() {
    echo -e "\nUsage: sudo $0\n"
    echo -e "This script installs and configures an OpenVPN server using Easy-RSA."
    echo -e "It sets up a Certificate Authority (CA), generates server keys, and configures OpenVPN."
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

# Get the absolute path of the script
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)"

# Create a working directory
WORKDIR="$SCRIPT_PATH/workdir"
mkdir -p "$WORKDIR" || { echo -e "\nError: Failed to create working directory at $WORKDIR.\n"; exit 1; }

# Install OpenVPN and Easy-RSA
apt update && apt install -y openvpn easy-rsa || { echo -e "\nError: Failed to install required packages.\n"; exit 1; }

# Set up the CA directory
EASYRSA_DIR="$WORKDIR/easy-rsa"
mkdir -p "$EASYRSA_DIR" || { echo -e "\nError: Failed to create EasyRSA directory.\n"; exit 1; }
ln -s /usr/share/easy-rsa/* "$EASYRSA_DIR/" 2>/dev/null || { echo -e "\nWarning: Failed to create symlink for EasyRSA files (may already exist).\n"; }
chown -R root:root "$EASYRSA_DIR"
cd "$EASYRSA_DIR" || { echo -e "\nError: Failed to enter EasyRSA directory.\n"; exit 1; }

# Initialize EasyRSA
echo 'set_var EASYRSA_BATCH 1' > vars
./easyrsa init-pki || { echo -e "\nError: Failed to initialize PKI.\n"; exit 1; }

# Build the CA
./easyrsa build-ca nopass || { echo -e "\nError: Failed to build Certificate Authority.\n"; exit 1; }

# Generate server certificate and key
./easyrsa gen-req server nopass || { echo -e "\nError: Failed to generate server request.\n"; exit 1; }
./easyrsa sign-req server server || { echo -e "\nError: Failed to sign server request.\n"; exit 1; }

# Generate Diffie-Hellman parameters
./easyrsa gen-dh || { echo -e "\nError: Failed to generate Diffie-Hellman parameters.\n"; exit 1; }

# Generate TLS authentication key
openvpn --genkey secret "$EASYRSA_DIR/ta.key" || { echo -e "\nError: Failed to generate TLS key.\n"; exit 1; }

# Copy files to OpenVPN directory
if [[ -d "$SCRIPT_PATH/openvpn" ]]; then
    cp -r "$SCRIPT_PATH/openvpn"/* /etc/openvpn/ || { echo -e "\nError: Failed to copy OpenVPN configuration files.\n"; exit 1; }
else
    echo -e "\nWarning: No OpenVPN configuration directory found at $SCRIPT_PATH/openvpn.\n"
fi
cp -r "$EASYRSA_DIR" /etc/openvpn/ || { echo -e "\nError: Failed to copy EasyRSA directory to /etc/openvpn/.\n"; exit 1; }

# Create directory for client configurations
mkdir -p /etc/openvpn/ccd || { echo -e "\nError: Failed to create client configuration directory.\n"; exit 1; }

# Start and enable OpenVPN service
systemctl start openvpn@server || { echo -e "\nError: Failed to start OpenVPN service.\n"; exit 1; }
systemctl enable openvpn@server || { echo -e "\nError: Failed to enable OpenVPN service.\n"; exit 1; }

echo -e "\nOpenVPN server setup complete.\n"
