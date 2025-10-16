"""
Service Configuration Script
Deploys and configures Suricata, Zeek, Vector, and banner services
"""

import os
import sys
import argparse
import textwrap
from pathlib import Path
from dotenv import load_dotenv
sys.stdout.reconfigure(line_buffering=True)

# Load environment variables
load_dotenv()
MONITORING_FILES_DIR = os.getenv("MONITORING_FILES_DIR","/root/ctf-challenger/monitoring")
UTILS_DIR = f"{MONITORING_FILES_DIR}/utils"

# Import the script_helper module
sys.path.append(UTILS_DIR)
from script_helper import (
    log_info, log_debug, log_error, log_warning, log_success, log_section,
    execute_remote_command, execute_remote_command_with_key, run_cmd, Timer, time_function, DEBUG_MODE
)

# ===== CONFIGURATION CONSTANTS =====
SYSTEMD_DIR = "/etc/systemd/system"

# Network interfaces
VPN_MONITORING_DEVICE = os.getenv("MONITORING_VPN_INTERFACE", "ctf_monitoring")
DMZ_MONITORING_DEVICE = os.getenv("MONITORING_DMZ_INTERFACE", "dmz_monitoring")
BACKEND_NETWORK_DEVICE = os.getenv("BACKEND_NETWORK_DEVICE", "backend")

# Directory paths
SURICATA_DIR = Path(os.getenv("SURICATA_FILES_DIR", "/etc/suricata"))
VECTOR_DIR = Path(os.getenv("VECTOR_DIR", "/etc/vector"))

# Configuration files
SURICATA_VPN_YAML = SURICATA_DIR / "suricata-ctf.yaml"
SURICATA_DMZ_YAML = SURICATA_DIR / "suricata-dmz.yaml"
SURICATA_BACKEND_YAML = SURICATA_DIR / "suricata-backend.yaml"

VECTOR_VPN_TOML = VECTOR_DIR /"config" / "vector-vpn.toml"
VECTOR_DMZ_TOML = VECTOR_DIR / "config" / "vector-dmz.toml"
VECTOR_BACKEND_TOML = VECTOR_DIR / "config" / "vector-backend.toml"
VECTOR_ZEEK_TOML = VECTOR_DIR / "config" / "vector-zeek.toml"

# Remote server configuration
MONITORING_IP = os.getenv("MONITORING_HOST", "10.0.0.103")
SSH_USER = os.getenv("MONITORING_VM_USER", "ubuntu")
SSH_PASSWORD = os.getenv("MONITORING_VM_PASSWORD", "meow1234")
BANNER_REMOTE_PATH = "/var/lib/wazuh/banner/banner_server.py"
BANNER_SERVICE_NAME = "banner-server.service"
BANNER_SERVER_PORT = os.getenv("BANNER_SERVER_PORT", "80")
PROXMOX_SSH_KEYFILE = os.getenv("PROXMOX_SSH_KEYFILE", "/root/.ssh/id_rsa.pub")

# ===== SERVICE DEFINITIONS =====

SURICATA_VPN_SERVICE = f"""[Unit]
Description=Suricata IDS ({VPN_MONITORING_DEVICE})
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/suricata -c {SURICATA_VPN_YAML} -i {VPN_MONITORING_DEVICE}
Restart=always

[Install]
WantedBy=multi-user.target
"""

SURICATA_DMZ_SERVICE = f"""[Unit]
Description=Suricata IDS ({DMZ_MONITORING_DEVICE})
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/suricata -c {SURICATA_DMZ_YAML} -i {DMZ_MONITORING_DEVICE}
Restart=always

[Install]
WantedBy=multi-user.target
"""

SURICATA_BACKEND_SERVICE = f"""[Unit]
Description=Suricata IDS ({BACKEND_NETWORK_DEVICE} NFQUEUE Mode)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/suricata -c {SURICATA_BACKEND_YAML} -q 0 --runmode=workers
Restart=always

[Install]
WantedBy=multi-user.target
"""

ZEEK_SERVICE = """[Unit]
Description=Zeek IDS
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl restart
RemainAfterExit=yes
WorkingDirectory=/opt/zeek
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

VECTOR_VPN_SERVICE = f"""[Unit]
Description=Vector Log Shipper (Suricata VPN)
After=network-online.target suricata-vpn.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/vector --config {VECTOR_VPN_TOML}
Restart=always

[Install]
WantedBy=multi-user.target
"""

VECTOR_DMZ_SERVICE = f"""[Unit]
Description=Vector Log Shipper (Suricata DMZ)
After=network-online.target suricata-dmz.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/vector --config {VECTOR_DMZ_TOML}
Restart=always

[Install]
WantedBy=multi-user.target
"""

VECTOR_BACKEND_SERVICE = f"""[Unit]
Description=Vector Log Shipper (Suricata Backend)
After=network-online.target suricata-backend.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/vector --config {VECTOR_BACKEND_TOML}
Restart=always

[Install]
WantedBy=multi-user.target
"""

VECTOR_ZEEK_SERVICE = f"""[Unit]
Description=Vector Log Shipper (Zeek)
After=network-online.target zeek.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/vector --config {VECTOR_ZEEK_TOML}
Restart=always

[Install]
WantedBy=multi-user.target
"""

# Service definitions mapping
SERVICES = {
    "suricata-vpn.service": SURICATA_VPN_SERVICE,
    "suricata-dmz.service": SURICATA_DMZ_SERVICE,
    "suricata-backend.service": SURICATA_BACKEND_SERVICE,
    "zeek.service": ZEEK_SERVICE,
    "vector-vpn.service": VECTOR_VPN_SERVICE,
    "vector-dmz.service": VECTOR_DMZ_SERVICE,
    "vector-backend.service": VECTOR_BACKEND_SERVICE,
    "vector-zeek.service": VECTOR_ZEEK_SERVICE,
}


def check_root_privileges():
    """
    Verify script is running with root privileges
    """
    if os.geteuid() != 0:
        log_error("This script must be run as root")
        return False
    return True


@time_function
def create_local_services():
    """
    Create and enable all local systemd services
    """
    log_section("Creating Local Systemd Services")

    # Create all service files
    for name, content in SERVICES.items():
        path = os.path.join(SYSTEMD_DIR, name)
        log_info(f"Creating service: {name}")

        try:
            with open(path, "w") as f:
                f.write(content)
            log_debug(f"Successfully wrote service file: {path}")
        except Exception as e:
            log_error(f"Failed to create service file {path}: {e}")
            raise

    # Reload systemd and enable services
    try:
        log_info("Reloading systemd daemon")
        result = run_cmd(["systemctl", "daemon-reload"], check=True)

        for name in SERVICES.keys():
            log_info(f"Enabling service: {name}")
            result = run_cmd(["systemctl", "enable", name], check=True)
            result = run_cmd(["systemctl", "start", name], check=True)

        log_success(f"Created, enabled and started {len(SERVICES)} local services")

    except Exception as e:
        log_error(f"Failed to manage services via systemctl: {e}")
        raise


@time_function
def setup_remote_banner_service():
    """
    Deploy and configure the banner server service on remote monitoring host
    """
    log_section("Setting up Remote Banner Service")

    banner_unit = f"""[Unit]
Description=CTF Banner Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 {BANNER_REMOTE_PATH} --port {BANNER_SERVER_PORT}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
"""

    tmp_file = "/tmp/banner-server.service"

    # Dedent to remove leading spaces
    banner_unit = textwrap.dedent(banner_unit)

    try:
        # Safe heredoc with EOF flush to left
        command_write_unit = f"""cat <<'EOF' > {tmp_file}
{banner_unit}
EOF
sudo mv {tmp_file} /etc/systemd/system/{BANNER_SERVICE_NAME}"""

        execute_remote_command_with_key(
            MONITORING_IP,
            command_write_unit,
            SSH_USER,
            ssh_key_path=PROXMOX_SSH_KEYFILE,
            shell=True
        )

        # Reload systemd and enable service
        execute_remote_command_with_key(MONITORING_IP, "sudo systemctl daemon-reload", SSH_USER, ssh_key_path=PROXMOX_SSH_KEYFILE)
        execute_remote_command_with_key(MONITORING_IP, f"sudo systemctl enable {BANNER_SERVICE_NAME}", SSH_USER, ssh_key_path=PROXMOX_SSH_KEYFILE)
        execute_remote_command_with_key(MONITORING_IP, f"sudo systemctl start {BANNER_SERVICE_NAME}", SSH_USER, ssh_key_path=PROXMOX_SSH_KEYFILE)
        execute_remote_command_with_key(MONITORING_IP, f"sudo ufw enable {BANNER_SERVER_PORT}/tcp", SSH_USER, ssh_key_path=PROXMOX_SSH_KEYFILE)

        log_success(f"Banner server service deployed and started on {MONITORING_IP}")

    except Exception as e:
        log_error(f"Failed to setup remote banner service: {e}")
        raise


def create_vector_checkpoints_dir():
    run_cmd(["mkdir", "-p", "/var/lib/vector/suricata_dmz"])
    run_cmd(["mkdir", "-p", "/var/lib/vector/suricata_vpn"])
    run_cmd(["mkdir", "-p", "/var/lib/vector/suricata_backend"])


@time_function
def main():
    """
    Main execution function
    """
    global DEBUG_MODE

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Service Configuration Script")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    DEBUG_MODE = args.debug

    try:
        with Timer():
            log_section("Starting Service Configuration")

            # Verify root privileges
            if not check_root_privileges():
                sys.exit(1)

            create_vector_checkpoints_dir()

            # Create and enable local services
            create_local_services()

            # Setup remote banner service
            setup_remote_banner_service()



            log_success("Service configuration completed successfully")

    except Exception as e:
        log_error(f"Service configuration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()