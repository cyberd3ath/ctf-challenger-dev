#!/bin/bash
get_ipv6_by_mac_prefix() {
  local mac_prefix="${1,,}"
  local iface mac ipv6

  while IFS= read -r line; do
    iface=$(awk -F': ' '{print $2}' <<< "$line")
    mac=$(ip link show dev "$iface" 2>/dev/null | awk '/link\/ether/ {print $2}')
    if [[ -n "$mac" && "${mac,,}" == ${mac_prefix}* ]]; then
      ipv6=$(ip -6 addr show dev "$iface" 2>/dev/null \
             | awk '/inet6/ && $2 !~ /^fe80/ {print $2; exit}' \
             | cut -d'/' -f1 || true)
      if [[ -n "$ipv6" ]]; then
        printf '%s' "$ipv6"
        return 0
      fi
    fi
  done < <(ip -o link show)

  return 1
}

LOCAL_IP_ADDRESS=$(get_ipv6_by_mac_prefix "0a:01") || {
    echo "[Error] Could not detect a suitable IPv6 address for LOCAL_IP_ADDRESS"; exit 1
}
MANAGER_IP_ADDRESS=$(hostname -I | awk '{print $1}')
AGENT_NAME="Agent_$LOCAL_IP_ADDRESS"
SYSTEM_HEALTH="true"
BASH_LOG="true"
UFW="true"
MODE="full"

OS_RPM_AMD="Linux RPM amd64"
OS_RPM_AARCH="Linux RPM aarch64"
OS_DEB_AMD="Linux DEB amd64"
OS_DEB_AARCH="Linux DEB aarch64"
OS_WIN="Windows MSI 32/64 bits"
OS_INTEL="macOS intel"
OS_SILICON="macOS Apple silicon"
OS_SUSE_AMD="SUSE Linux RPM amd64"
OS_SUSE_AARCH="SUSE Linux RPM aarch64"
OS_ARCH="Arch Linux"

CMD_RUN_LINUX=" systemctl daemon-reload &&  systemctl enable wazuh-agent &&  systemctl start wazuh-agent"
CMD_RUN_WIN="NET START WazuhSvc"
CMD_RUN_MAC=" /Library/Ossec/bin/wazuh-control start"
CMD_RUN_ARCH="$CMD_RUN_LINUX"

# Install commands WITH env vars
CMD_INSTALL_RPM_AMD='curl -o wazuh-agent-4.11.1-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.1-1.x86_64.rpm &&  WAZUH_MANAGER="${MANAGER_IP_ADDRESS}" WAZUH_AGENT_NAME="${AGENT_NAME}" rpm -ihv wazuh-agent-4.11.1-1.x86_64.rpm'
CMD_INSTALL_RPM_AARCH='curl -o wazuh-agent-4.11.1-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.1-1.aarch64.rpm &&  WAZUH_MANAGER="${MANAGER_IP_ADDRESS}" WAZUH_AGENT_NAME="${AGENT_NAME}" rpm -ihv wazuh-agent-4.11.1-1.aarch64.rpm'
CMD_INSTALL_DEB_AMD='wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.1-1_amd64.deb &&  WAZUH_MANAGER="${MANAGER_IP_ADDRESS}" WAZUH_AGENT_NAME="${AGENT_NAME}" dpkg -i ./wazuh-agent_4.11.1-1_amd64.deb'
CMD_INSTALL_DEB_AARCH='wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.1-1_arm64.deb &&  WAZUH_MANAGER="${MANAGER_IP_ADDRESS}" WAZUH_AGENT_NAME="${AGENT_NAME}" dpkg -i ./wazuh-agent_4.11.1-1_arm64.deb'
CMD_INSTALL_WIN='Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.1-1.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER="${MANAGER_IP_ADDRESS}" WAZUH_AGENT_NAME="${AGENT_NAME}"'
CMD_INSTALL_MAC_INTEL='curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.11.1-1.intel64.pkg && echo "WAZUH_MANAGER=\"${MANAGER_IP_ADDRESS}\" WAZUH_AGENT_NAME=\"${AGENT_NAME}\"" > /tmp/wazuh_envs &&  installer -pkg ./wazuh-agent.pkg -target /'
CMD_INSTALL_MAC_SILICON='curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.11.1-1.arm64.pkg && echo "WAZUH_MANAGER=\"${MANAGER_IP_ADDRESS}\" WAZUH_AGENT_NAME=\"${AGENT_NAME}\"" > /tmp/wazuh_envs &&  installer -pkg ./wazuh-agent.pkg -target /'

CMD_INSTALL_SUSE_AMD="$CMD_INSTALL_RPM_AMD"
CMD_INSTALL_SUSE_AARCH="$CMD_INSTALL_RPM_AARCH"

CMD_INSTALL_ARCH='
if command -v yay >/dev/null 2>&1; then
  yay -S --noconfirm wazuh-agent
elif command -v paru >/dev/null 2>&1; then
  paru -S --noconfirm wazuh-agent
else
   pacman -Syu --noconfirm wazuh-agent || { echo "[Error] wazuh-agent not in pacman repos. Install manually or use an AUR helper."; exit 1; }
fi
'

# Install commands WITHOUT env vars
CMD_INSTALL_RPM_AMD_PLAIN='curl -o wazuh-agent-4.11.1-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.1-1.x86_64.rpm && rpm -ihv wazuh-agent-4.11.1-1.x86_64.rpm'
CMD_INSTALL_RPM_AARCH_PLAIN='curl -o wazuh-agent-4.11.1-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.11.1-1.aarch64.rpm && rpm -ihv wazuh-agent-4.11.1-1.aarch64.rpm'
CMD_INSTALL_DEB_AMD_PLAIN='wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.1-1_amd64.deb && dpkg -i ./wazuh-agent_4.11.1-1_amd64.deb'
CMD_INSTALL_DEB_AARCH_PLAIN='wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.1-1_arm64.deb && dpkg -i ./wazuh-agent_4.11.1-1_arm64.deb'
CMD_INSTALL_WIN_PLAIN='Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.1-1.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q'
CMD_INSTALL_MAC_INTEL_PLAIN='curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.11.1-1.intel64.pkg && installer -pkg ./wazuh-agent.pkg -target /'
CMD_INSTALL_MAC_SILICON_PLAIN='curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.11.1-1.arm64.pkg && installer -pkg ./wazuh-agent.pkg -target /'

CMD_INSTALL_SUSE_AMD_PLAIN="$CMD_INSTALL_RPM_AMD_PLAIN"
CMD_INSTALL_SUSE_AARCH_PLAIN="$CMD_INSTALL_RPM_AARCH_PLAIN"

CMD_INSTALL="$CMD_INSTALL_DEB_AMD"

# Detect OS
detect_os() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_SUFFIX="amd" ;;
        aarch64|arm64) ARCH_SUFFIX="aarch" ;;
        *) ARCH_SUFFIX="unknown" ;;
    esac

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            arch|manjaro) echo "arch" ;;
            opensuse*|sles|suse) echo "suse_${ARCH_SUFFIX}" ;;
            ubuntu|debian) echo "deb_${ARCH_SUFFIX}" ;;
            centos|rhel|fedora) echo "rpm_${ARCH_SUFFIX}" ;;
            *)
                if [ -f /etc/redhat-release ]; then
                    echo "rpm_${ARCH_SUFFIX}"
                elif [ -f /etc/debian_version ]; then
                    echo "deb_${ARCH_SUFFIX}"
                else
                    echo "unknown"
                fi
                ;;
        esac
    else
        echo "unknown"
    fi
}

function print_info() { echo -e "\e[34m[Info]:\e[0m $1"; }
function print_warning() { echo -e "\e[33m[Warning]:\e[0m $1"; }
function print_error() { echo -e "\e[31m[Error]:\e[0m $1"; }

update_ossec_config() {
    local config_file="/var/ossec/etc/ossec.conf"
    local new_manager="$1"
    local new_agent_name="$2"

    if [ ! -f "$config_file" ]; then
        print_error "Config file $config_file not found!"
        return 1
    fi

    print_info "Updating Wazuh configuration..."

    # Update manager address
    if [ -n "$new_manager" ]; then
        sed -i "s|<address>.*</address>|<address>$new_manager</address>|g" "$config_file"
        print_info "Updated manager address to: $new_manager"
    fi

    # Update agent name
    if [ -n "$new_agent_name" ]; then
        # Try to find and replace agent_name in client block
        if grep -q "<agent_name>" "$config_file"; then
            sed -i "s|<agent_name>.*</agent_name>|<agent_name>$new_agent_name</agent_name>|g" "$config_file"
        else
            # Add agent_name if it doesn't exist (after <client> tag)
            sed -i "/<client>/a\    <agent_name>$new_agent_name</agent_name>" "$config_file"
        fi
        print_info "Updated agent name to: $new_agent_name"
    fi
}

OS_TYPE=$(detect_os)

# CLI arguments
SKIP_CONFIRMATION="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager=*) MANAGER_IP_ADDRESS="${1#*=}" ;;
    --name=*) AGENT_NAME="${1#*=}" ;;
    --use_system_health=*) SYSTEM_HEALTH="${1#*=}" ;;
    --use_bash_log=*) BASH_LOG="${1#*=}" ;;
    --use_ufw=*) UFW="${1#*=}" ;;
    --os=*) OS_TYPE="${1#*=}" ;;
    --install) MODE="install" ;;
    --run) MODE="run" ;;
    -y|--yes) SKIP_CONFIRMATION="true" ;;
    -h|--help)
        cat <<'EOF'
Usage: set_up_agent.sh [OPTIONS]

Options:
    --manager=<ip>              Manager IP address
    --name=<name>               Agent name
    --use_system_health=<bool>  Enable system health logging (default: true)
    --use_bash_log=<bool>       Enable bash logging (default: true)
    --use_ufw=<bool>            Enable UFW logging (default: true)
    --os=<type>                 OS type (auto-detected by default)
    --install                   Only install the agent (don't configure/run)
    --run                       Only configure and run the agent (don't install)
    -y, --yes                   Skip confirmation prompts
    -h, --help                  Show this help

OS Types:
    rpm_amd, rpm_aarch, deb_amd, deb_aarch, suse_amd, suse_aarch,
    arch, win, mac_intel, mac_silicon

Modes:
    Default (no mode flag):  Full installation + configuration + start
    --install:               Install agent only (no manager/name required)
    --run:                   Configure + start (requires --manager and --name)

Examples:
    # Full installation with manager config
    ./set_up_agent.sh --manager=192.168.1.100 --name=MyAgent

    # Install only (no configuration)
    ./set_up_agent.sh --install -y

    # Configure and start existing installation
    ./set_up_agent.sh --run --manager=192.168.1.200 --name=NewAgentName -y
EOF
        exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

# Validation for --run mode
if [ "$MODE" == "run" ]; then
    if [ -z "$MANAGER_IP_ADDRESS" ]; then
        print_error "--run mode requires --manager=<ip>"
        exit 1
    fi
    if [ -z "$AGENT_NAME" ]; then
        print_error "--run mode requires --name=<name>"
        exit 1
    fi
fi

# Map OS_TYPE to commands based on MODE
if [ "$MODE" == "install" ]; then
    # Plain installation without env vars
    case "$OS_TYPE" in
        rpm_amd) CMD_INSTALL="$CMD_INSTALL_RPM_AMD_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_RPM_AMD" ;;
        rpm_aarch) CMD_INSTALL="$CMD_INSTALL_RPM_AARCH_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_RPM_AARCH" ;;
        deb_amd) CMD_INSTALL="$CMD_INSTALL_DEB_AMD_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_DEB_AMD" ;;
        deb_aarch) CMD_INSTALL="$CMD_INSTALL_DEB_AARCH_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_DEB_AARCH" ;;
        suse_amd) CMD_INSTALL="$CMD_INSTALL_SUSE_AMD_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_SUSE_AMD" ;;
        suse_aarch) CMD_INSTALL="$CMD_INSTALL_SUSE_AARCH_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_SUSE_AARCH" ;;
        arch) CMD_INSTALL="$CMD_INSTALL_ARCH"; CMD_RUN="$CMD_RUN_ARCH"; OS="$OS_ARCH" ;;
        win) CMD_INSTALL="$CMD_INSTALL_WIN_PLAIN"; CMD_RUN="$CMD_RUN_WIN"; OS="$OS_WIN" ;;
        mac_intel) CMD_INSTALL="$CMD_INSTALL_MAC_INTEL_PLAIN"; CMD_RUN="$CMD_RUN_MAC"; OS="$OS_INTEL" ;;
        mac_silicon) CMD_INSTALL="$CMD_INSTALL_MAC_SILICON_PLAIN"; CMD_RUN="$CMD_RUN_MAC"; OS="$OS_SILICON" ;;
        *) CMD_INSTALL="$CMD_INSTALL_DEB_AMD_PLAIN"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_DEB_AMD" ;;
    esac
else
    # Full installation with env vars
    case "$OS_TYPE" in
        rpm_amd) CMD_INSTALL="$CMD_INSTALL_RPM_AMD"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_RPM_AMD" ;;
        rpm_aarch) CMD_INSTALL="$CMD_INSTALL_RPM_AARCH"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_RPM_AARCH" ;;
        deb_amd) CMD_INSTALL="$CMD_INSTALL_DEB_AMD"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_DEB_AMD" ;;
        deb_aarch) CMD_INSTALL="$CMD_INSTALL_DEB_AARCH"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_DEB_AARCH" ;;
        suse_amd) CMD_INSTALL="$CMD_INSTALL_SUSE_AMD"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_SUSE_AMD" ;;
        suse_aarch) CMD_INSTALL="$CMD_INSTALL_SUSE_AARCH"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_SUSE_AARCH" ;;
        arch) CMD_INSTALL="$CMD_INSTALL_ARCH"; CMD_RUN="$CMD_RUN_ARCH"; OS="$OS_ARCH" ;;
        win) CMD_INSTALL="$CMD_INSTALL_WIN"; CMD_RUN="$CMD_RUN_WIN"; OS="$OS_WIN" ;;
        mac_intel) CMD_INSTALL="$CMD_INSTALL_MAC_INTEL"; CMD_RUN="$CMD_RUN_MAC"; OS="$OS_INTEL" ;;
        mac_silicon) CMD_INSTALL="$CMD_INSTALL_MAC_SILICON"; CMD_RUN="$CMD_RUN_MAC"; OS="$OS_SILICON" ;;
        *) CMD_INSTALL="$CMD_INSTALL_DEB_AMD"; CMD_RUN="$CMD_RUN_LINUX"; OS="$OS_DEB_AMD" ;;
    esac
fi

echo "[Info] Mode: $MODE"
echo "[Info] Setting up Agent:"
echo "OS: $OS"

if [ "$MODE" != "install" ]; then
    echo "Agent Name: $AGENT_NAME"
    echo "Agent IP: $LOCAL_IP_ADDRESS"
    echo "Manager IP: $MANAGER_IP_ADDRESS"

    if [ "$MANAGER_IP_ADDRESS" == "$LOCAL_IP_ADDRESS" ]; then
      print_warning "Wazuh manager has same address as wazuh agent. Provide --manager if that's unintended."
    fi
fi

if [ "$MODE" == "full" ] || [ "$MODE" == "install" ]; then
    echo "Logging System Health: $SYSTEM_HEALTH"
    echo "Logging Bash: $BASH_LOG"
    echo "Logging UFW: $UFW"
fi

if [ "$SKIP_CONFIRMATION" != "true" ]; then
    echo "Proceed with setup? [y/yes]"
    read -r CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "yes" ]]; then
        echo "Setup aborted"; exit 0
    fi
fi

# INSTALL MODE
if [ "$MODE" == "full" ] || [ "$MODE" == "install" ]; then
    print_info "Downloading and Installing Agent..."
    eval "$CMD_INSTALL"

    if [ "$MODE" == "install" ]; then
        print_info "Agent installed. Use --run to configure and start it."
        exit 0
    fi

    print_info "Adding Localfiles..."
    if [ -f /var/monitoring/wazuh-agent/config/localfile_ossec_config ]; then
       tee -a /var/ossec/etc/ossec.conf < /var/monitoring/wazuh-agent/config/localfile_ossec_config >/dev/null
    else
      print_warning "/var/monitoring/wazuh-agent/config/localfile_ossec_config not found — skipping append."
    fi

    if [ "$SYSTEM_HEALTH" == "true" ]; then
      if [ -f /var/monitoring/wazuh-agent/config/localfile_ossec_config_system_health ]; then
         tee -a /var/ossec/etc/ossec.conf < /var/monitoring/wazuh-agent/config/localfile_ossec_config_system_health >/dev/null
      else
        print_warning "/var/monitoring/wazuh-agent/config/localfile_ossec_config_system_health not found"
      fi
    fi

    if [ "$BASH_LOG" == "true" ]; then
      if [ -x /var/monitoring/wazuh-agent/config/bash_loggin_set_up.sh ]; then
        mkdir -p /etc/monitoring
        mv /var/monitoring/wazuh-agent/config/bash_loggin_set_up.sh /etc/monitoring
        chmod +x /etc/monitoring/bash_loggin_set_up.sh
        mv /var/monitoring/wazuh-agent/config/bash_loggin_systemd.service /etc/systemd/system/
        mv /var/monitoring/wazuh-agent/config/bash_loggin_timer.timer /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable bash_loggin_systemd.service
        systemctl enable bash_loggin_timer.timer
        systemctl start bash_loggin_systemd.service
        systemctl start bash_loggin_timer.timer
      else
        print_warning "/var/monitoring/wazuh-agent/config/bash_loggin_set_up.sh missing or not executable"
      fi
    fi

    if [ "$UFW" == "true" ]; then
        if [ -f /var/monitoring/wazuh-agent/config/localfile_ossec_config_ufw_status ]; then
           tee -a /var/ossec/etc/ossec.conf < /var/monitoring/wazuh-agent/config/localfile_ossec_config_ufw_status >/dev/null
        fi
    fi

    if [ "$BASH_LOG" == "false" ] && [ "$UFW" == "false" ] && [ "$SYSTEM_HEALTH" == "false" ]; then
        print_info "Nothing additional to set up."
    fi

    # Fix commands.log
    if [ -f /var/log/commands.log ]; then
        print_info "Setting up /var/log/commands.log..."
        chown syslog:syslog /var/log/commands.log
        chmod 644 /var/log/commands.log
        systemctl restart rsyslog || true
        print_info "/var/log/commands.log permissions updated and rsyslog restarted."
    fi
fi

# RUN MODE
if [ "$MODE" == "run" ]; then
    # Update config with new parameters
    update_ossec_config "$MANAGER_IP_ADDRESS" "$AGENT_NAME"
fi

# Start agent
if [ "$MODE" == "full" ] || [ "$MODE" == "run" ]; then
    print_info "Starting Wazuh Agent..."
    eval "$CMD_RUN"
    print_info "Wazuh Agent is now running!"
fi

echo "[Info] Wazuh Agent setup finished! (Mode: $MODE)"