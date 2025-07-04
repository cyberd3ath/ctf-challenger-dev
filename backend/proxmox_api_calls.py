import os
from dotenv import load_dotenv
import requests

load_dotenv()
node = os.getenv("PROXMOX_HOSTNAME", "pve")


def make_api_call(method, endpoint, data=None):
    """
    Make an API call to Proxmox.
    """
    proxmox_url = os.getenv("PROXMOX_URL")
    proxmox_api_token = os.getenv("PROXMOX_API_TOKEN")

    headers = {}
    if data is not None:
        headers = {"Content-Type": "application/json"}

    if proxmox_api_token:
        headers["Authorization"] = f"PVEAPIToken={proxmox_api_token}"

    url = f"{proxmox_url}/{endpoint}"
    response = requests.request(method, url, headers=headers, json=data, verify="/etc/pve/pve-root-ca.pem")

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to make API call: {endpoint} - {response.status_code} - {response.text}")


def clone_vm_api_call(machine_template, machine):
    """
    Clone a virtual machine in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine_template.id}/clone"
    data = {
        "newid": machine.id,
        "full": False
    }
    return make_api_call("POST", endpoint, data)


def create_network_api_call(network):
    """
    Create a network in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/network"
    data = {
        "iface": network.host_device,
        "type": "bridge",
        "cidr": network.router_ip + "/" + network.subnet_mask,
        "autostart": True,
    }
    return make_api_call("POST", endpoint, data)


def reload_network_api_call():
    """
    Reload a network in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/network"
    data = {}

    return make_api_call("PUT", endpoint, data)


def delete_vm_api_call(machine):
    """
    Delete a virtual machine in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine.id}"
    return make_api_call("DELETE", endpoint)


def delete_network_api_call(network):
    """
    Delete a network in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/network/{network.host_device}"
    return make_api_call("DELETE", endpoint)


def attach_networks_to_vm_api_call(machine):
    """
    Attach networks to a virtual machine in Proxmox.
    """
    responses = []

    for local_connection_id, connection in enumerate(machine.connections.values()):
        endpoint = f"api2/json/nodes/{node}/qemu/{machine.id}/config"
        data = {
            f"net{local_connection_id}": f"model=e1000,"
                                         f"bridge={connection.network.host_device},"
                                         f"macaddr={connection.client_mac}"
        }

        responses.append(make_api_call("PUT", endpoint, data))

    return responses


def launch_vm_api_call(machine):
    """
    Launch a virtual machine in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine.id}/status/start"
    return make_api_call("POST", endpoint)


def stop_vm_api_call(machine):
    """
    Stop a virtual machine in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine.id}/status/stop"
    return make_api_call("POST", endpoint)


def vm_is_stopped_api_call(machine):
    """
    Check if a virtual machine is stopped in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine.id}/status/current"
    response = make_api_call("GET", endpoint)

    return response["data"]["status"] == "stopped"


def initial_configuration_api_call(machine_template):
    """
    Initial configuration of a virtual machine in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine_template.id}/config"
    data = {
        "memory": machine_template.ram,
        "cores": machine_template.cores,
        "sockets": 1,
        "cpu": "host",
    }
    return make_api_call("PUT", endpoint, data)


def convert_vm_to_template_api_call(machine_template_id):
    """
    Convert a virtual machine to a template in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine_template_id}/template"
    return make_api_call("POST", endpoint)


def vm_exists_api_call(machine):
    """
    Check if a virtual machine exists in Proxmox.
    """
    endpoint = f"api2/json/nodes/{node}/qemu/{machine.id}/status/current"
    try:
        make_api_call("GET", endpoint)
        return True
    except Exception:
        return False
