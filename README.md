
# CTF-Challenger

## Setup

To set up the service, follow these steps:
1. Set up a fresh Proxmox installation using pve/pve.local as a hostname
2. Disable the Proxmox VE repositories to prevent error output from apt update
3. Clone this repository into `/root/`
4. `cd /root/ctf-challenger/setup/`
5. Edit the `/root/ctf-challenger/setup/.env` variables to suit the environment of the Proxmox installation and the desired values
6. Install pre-requisites by running `bash /root/ctf-challenger/setup/install_requirements.sh`
7. Run the setup by executing `python3 /root/ctf-challenger/setup/setup.py`
8. Wait for the setup to complete, which may take a while (~10 minutes)
9. After the setup is complete, you can access the service at `http://localhost/` or `http://<external-proxmox-ip>/`

## TODO:

### Mandatory for production:
- Enable and enforce HTTPS/SSL
- anonymize ips in logs
- upload rate limiting
- 

### Optional improvements:
- unify html modal code in html or js
- add real lightmode styling
- (optional return list entries instead of isAdmin from header.php)
- (optional change extend limiter to timebased restricting)
- (optional cleaner styling / code on signup)
- (optional loading bar for direct upload)
- (optional extension warning popup einbauen)

