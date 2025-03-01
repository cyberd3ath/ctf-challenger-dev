#!/bin/bash

set -e

# Help function
display_help() {
    echo -e "\nUsage: [sudo] $0 <ova-file> <vmid>\n"
    echo -e "This script extracts a given OVA file, retrieves the OVF descriptor, and imports it into Proxmox using qm importovf."
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

# Validate arguments
if [ "$#" -ne 2 ]; then
    echo -e "\nError: Invalid arguments.\n"
    display_help
fi

OVA_FILE="$1"
VMID="$2"
WORKDIR="/var/lib/proxmox-ova-import"

# Ensure the workdir exists
mkdir -p "$WORKDIR"

# Extract the OVA file
TEMP_DIR=$(mktemp -d -p "$WORKDIR") || { echo -e "\nError: Failed to create temporary directory.\n"; exit 1; }
cp "$OVA_FILE" "$TEMP_DIR" || { echo -e "\nError: Failed to copy OVA file.\n"; exit 1; }
cd "$TEMP_DIR" || { echo -e "\nError: Failed to change directory to temporary folder.\n"; exit 1; }
tar -xvf "$OVA_FILE" || { echo -e "\nError: Failed to extract OVA file.\n"; exit 1; }

# Find the OVF descriptor
OVF_DESCRIPTOR=$(find "$TEMP_DIR" -name "*.ovf" | head -n 1)
if [ -z "$OVF_DESCRIPTOR" ]; then
    echo -e "\nError: No OVF descriptor found. Exiting.\n"
    exit 1
fi

# Import the OVF into Proxmox
qm importovf "$VMID" "$OVF_DESCRIPTOR" local-lvm || { echo -e "\nError: Failed to import OVF file into Proxmox.\n"; exit 1; }

# Cleanup
echo "Cleaning up..."
rm -rf "$TEMP_DIR"

echo -e "\nVM import complete. VM ID: $VMID\n"
