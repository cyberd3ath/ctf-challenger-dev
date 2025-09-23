import subprocess
from proxmox_api_calls import *
from DatabaseClasses import MachineTemplate, ChallengeTemplate
from hashlib import sha256
import time
import random


def import_machine_templates(challenge_template_id, db_conn):
    """
    Import a machine template from a disk image file and associate it with a challenge.
    """
    try:
        challenge_template = fetch_challenge_template(challenge_template_id, db_conn)

        fetch_machine_templates(challenge_template, db_conn)
    except Exception as e:
        raise RuntimeError(f"Failed to fetch challenge template: {e}")

    try:
        import_disk_images_to_vm_templates(challenge_template)

        configure_vms(challenge_template)

        convert_machine_template_vms_to_templates(challenge_template)
    except Exception as e:
        undo_import_machine_templates(challenge_template)
        raise RuntimeError(f"Failed to import disk images: {e}")


def fetch_challenge_template(challenge_id, db_conn):
    """
    Fetch the challenge details from the database.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM challenge_templates WHERE id = %s", (challenge_id,))
        result = cursor.fetchone()

    if result is None:
        raise ValueError(f"Challenge with ID {challenge_id} not found.")

    challenge_template = ChallengeTemplate(challenge_template_id=result[0])

    return challenge_template


def fetch_machine_templates(challenge_template, db_conn):
    """
    Fetch the machine templates associated with the challenge from the database.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id, disk_file_path, cores, ram_gb "
                       "FROM machine_templates "
                       "WHERE challenge_template_id = %s", (challenge_template.id,))

        for machine_template_id, disk_file_path, cores, ram_gb in cursor.fetchall():
            # Check if the disk file path is valid
            if not os.path.exists(disk_file_path):
                raise ValueError(f"Disk file path {disk_file_path} does not exist.")
            if not os.path.isfile(disk_file_path):
                raise ValueError(f"Disk file path {disk_file_path} is not a file.")
            if not disk_file_path.endswith(('.ova', '.iso')):
                raise ValueError(f"Disk file path {disk_file_path} is not a valid OVA or ISO file.")

            machine_template = MachineTemplate(
                machine_template_id=machine_template_id,
                challenge_template=challenge_template
            )
            machine_template.set_cores(cores)
            machine_template.set_ram(ram_gb * 1024)  # Convert GB to MB
            machine_template.set_disk_file_path(disk_file_path)
            challenge_template.add_machine_template(machine_template)


def check_user_input(user_input):
    """
    Sanitize user input to prevent command injection attacks.
    """
    import re

    blacklist_pattern = r"""[;&|><`$\\'"*?{}\[\]~!#()=]+"""
    if re.search(blacklist_pattern, user_input):
        raise ValueError("Input contains potentially dangerous characters.")


def import_disk_images_to_vm_templates(challenge_template):
    """
    Import the disk images to VM templates.
    """
    for machine_template in challenge_template.machine_templates.values():
        disk_file_path = machine_template.disk_file_path
        check_user_input(disk_file_path)

        disk_file_extension = os.path.splitext(disk_file_path)[1].lower()

        if disk_file_extension == ".ova":
            convert_ova_to_machine_template(disk_file_path, machine_template.id)

        elif disk_file_extension == ".iso":
            convert_iso_to_machine_template(disk_file_path, machine_template.id)


def convert_ova_to_machine_template(disk_file_path, machine_template_id):
    """
    Convert an OVA disk image file to a machine template.
    """

    tmp_dir_name = f"proxmox_import_{sha256(str(time.time()).encode() + b' ' + str(random.randint(0, 2**20)).encode()).hexdigest()}"

    tmp_dir = os.path.join("/tmp", tmp_dir_name)
    os.makedirs(tmp_dir, exist_ok=True)

    # Extract the OVA file
    try:
        subprocess.run(["tar", "-xvf", disk_file_path, "-C", tmp_dir], check=True, capture_output=True)
    except Exception as e:
        raise RuntimeError(f"Failed to extract OVA file: {e}")

    # Find the OVF file
    ovf_file_count = 0
    ovf_file = None
    for file in os.listdir(tmp_dir):
        if file.endswith(".ovf"):
            ovf_file = os.path.join(tmp_dir, file)
            ovf_file_count += 1

    if not ovf_file:
        raise ValueError("No OVF file found in the OVA archive.")

    if ovf_file_count > 1:
        raise ValueError("Multiple OVF files found in the OVA archive. Please provide a single OVF file.")

    # Convert the OVF file to a Proxmox template
    try:
        importovf_command = f"qm importovf {machine_template_id} '{ovf_file}' local-lvm"
        if "|" in importovf_command or ";" in importovf_command or "&" in importovf_command:
            raise ValueError("Invalid characters in import command.")
        subprocess.run(importovf_command, shell=True, check=True, capture_output=True)
    except Exception as e1:
        try:
            subprocess.run(["qm", "unlock", str(machine_template_id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template_id)], check=True, capture_output=True)
        except Exception:
            pass

        raise RuntimeError(f"Failed to import OVA file: {e1}")

    # Clean up the temporary directory
    try:
        subprocess.run(["rm", "-rf", tmp_dir], check=True, capture_output=True)
    except Exception as e:
        raise RuntimeError(f"Failed to clean up temporary directory: {e}")


def convert_iso_to_machine_template(disk_file_path, machine_template_id):
    """
    Convert an ISO disk image file to a machine template.
    """

    # Convert the ISO file to a Proxmox template
    try:
        if "|" in disk_file_path or ";" in disk_file_path or "&" in disk_file_path:
            raise ValueError("Invalid characters in disk file path.")

        importdisk_command = f"qm importdisk {machine_template_id} \"{disk_file_path}\" local-lvm"
        subprocess.run(importdisk_command, shell=True, check=True, capture_output=True)
    except Exception as e1:
        try:
            subprocess.run(["qm", "unlock", str(machine_template_id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template_id)], check=True, capture_output=True)
        except Exception as e2:
            pass

        raise RuntimeError(f"Failed to import ISO file: {e1}")


def configure_vms(challenge_template):
    """
    Configure the VM settings for the machine template.
    """

    for machine_template in challenge_template.machine_templates.values():
        try:
            initial_configuration_api_call(machine_template)
        except Exception as e:
            raise RuntimeError(f"Failed to configure VM: {e}")


def convert_machine_template_vms_to_templates(challenge_template):
    """
    Convert the VM to a template in Proxmox.
    """

    for machine_template in challenge_template.machine_templates.values():
        try:
            convert_vm_to_template_api_call(machine_template.id)
        except Exception as e:
            raise RuntimeError(f"Failed to convert VM to template: {e}")


def undo_import_machine_templates(challenge_template):
    """
    Undo the import of machine templates.
    """

    for machine_template in challenge_template.machine_templates.values():
        try:
            delete_vm_api_call(machine_template)
        except Exception:
            try:
                subprocess.run(["qm", "unlock", str(machine_template.id)], check=True, capture_output=True)
            except Exception:
                pass
            try:
                subprocess.run(["qm", "destroy", str(machine_template.id)], check=True, capture_output=True)
            except Exception:
                pass
