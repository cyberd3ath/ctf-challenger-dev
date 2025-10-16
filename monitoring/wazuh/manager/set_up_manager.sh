#!/bin/bash

# ===========================
# Default Credentials
# ===========================
API_USER="wazuh-wui"
API_PASS="MyS3cr37P450r.*-"
DASH_USER="kibanaserver"
DASH_PASS="kibanaserver"
INDEXER_USER="admin"
INDEXER_PASS="SecretPassword"

# ===========================
# Parse CLI arguments
# ===========================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-user)
      API_USER="$2"
      shift 2
      ;;
    --api-pass)
      API_PASS="$2"
      shift 2
      ;;
    --dashboard-user)
      DASH_USER="$2"
      shift 2
      ;;
    --dashboard-pass)
      DASH_PASS="$2"
      shift 2
      ;;
    --indexer-user)
      INDEXER_USER="$2"
      shift 2
      ;;
    --indexer-pass)
      INDEXER_PASS="$2"
      shift 2
      ;;
    *)
      echo "Unknown parameter: $1"
      exit 1
      ;;
  esac
done

# ===========================
# Functions
# ===========================
function print_info() {
    echo -e "\e[34m[Info]:\e[0m $1"
}

function print_warning() {
    echo -e "\e[33m[Warn]:\e[0m $1"
}

function print_error() {
    echo -e "\e[31m[Error]:\e[0m $1"
}

# ===========================
# Prechecks
# ===========================
if [ $(id -u) -ne 0 ]; then
    echo "Please run this script as root or using sudo!"
    exit 1
fi

SYSCTL_CONF="/etc/sysctl.conf"
IP_ADDRESS=$(hostname -I | awk '{print $1}')
RAM_MIN=8388608
RAM=$(awk '/MemTotal/ {print $2}' /proc/meminfo)

if [ $RAM -le $RAM_MIN ]; then
    print_warning "Not Enough Memory! MINIMUM: $RAM_MIN, Current: $RAM"
    echo "Ignore warning? [y/yes]"
    read SET_UP_APPROVED
    if [ "$SET_UP_APPROVED" != "y" ] && [ "$SET_UP_APPROVED" != "yes" ]; then
        print_info "Setup Aborted"
        exit 1
    fi
fi

# ===========================
# Clone Repo
# ===========================
print_info "Cloning Wazuh Docker repository..."
git clone "https://github.com/wazuh/wazuh-docker.git" || print_warning "Repository already exists, skipping clone."

cd wazuh-docker
git checkout v4.11.1

# ===========================
# System Config
# ===========================
print_info "Setting vm.max_map_count..."
sysctl -w vm.max_map_count=262144
if grep -q "vm.max_map_count" "$SYSCTL_CONF"; then
    sed -i 's/^vm.max_map_count.*/vm.max_map_count=262144/' "$SYSCTL_CONF"
else
    echo "vm.max_map_count=262144" >> "$SYSCTL_CONF"
fi

# ===========================
# Generate Certificates
# ===========================
print_info "Generating certificates..."
cd single-node
sudo -u $SUDO_USER docker-compose -f generate-indexer-certs.yml run --rm generator

# ===========================
# Update docker-compose.yml with CLI credentials
# ===========================
COMPOSE_FILE="docker-compose.yml"
print_info "Updating docker-compose.yml with provided credentials..."

# API credentials
sed -i "s#API_USERNAME=.*#API_USERNAME=${API_USER}#" "$COMPOSE_FILE"
sed -i "s#API_PASSWORD=.*#API_PASSWORD=${API_PASS}#" "$COMPOSE_FILE"

# Dashboard credentials
sed -i "s#DASHBOARD_USERNAME=.*#DASHBOARD_USERNAME=${DASH_USER}#" "$COMPOSE_FILE"
sed -i "s#DASHBOARD_PASSWORD=.*#DASHBOARD_PASSWORD=${DASH_PASS}#" "$COMPOSE_FILE"

# Indexer credentials
sed -i "s#INDEXER_USERNAME=.*#INDEXER_USERNAME=${INDEXER_USER}#" "$COMPOSE_FILE"
sed -i "s#INDEXER_PASSWORD=.*#INDEXER_PASSWORD=${INDEXER_PASS}#" "$COMPOSE_FILE"

# ===========================
# Start Docker Compose
# ===========================
print_info "Starting Docker Compose..."
sudo -u $SUDO_USER docker-compose up -d

# ===========================
# Add Custom Rules
# ===========================
print_info "Adding custom rules..."
cd ..
docker cp /var/lib/wazuh/manager/config/local_rules.xml $(docker ps -aqf "name=single-node-wazuh.manager-1"):/var/ossec/etc/rules/local_rules.xml
docker cp /var/lib/wazuh/manager/config/local_decoder.xml $(docker ps -aqf "name=single-node-wazuh.manager-1"):/var/ossec/etc/decoders/local_decoder.xml

# ===========================
# Restart Manager
# ===========================
print_info "Restarting Wazuh manager..."
docker restart $(docker ps -aqf "name=single-node-wazuh.manager-1")

# ===========================
# Finish
# ===========================
echo
print_info "Wazuh Docker Installation Finished!"
echo "Dashboard: https://$IP_ADDRESS"
echo "User: $DASH_USER"
echo "Password: $DASH_PASS"
echo "Indexer User: $INDEXER_USER"
echo "Indexer Password: $INDEXER_PASS"
