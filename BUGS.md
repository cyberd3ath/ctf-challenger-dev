# VULNERABILITIES

## External, No Privileges
- :check: !! HIGH, TODO !! No Brute-Force protection on login (CAPTCHA)
- :check: (HIGH, FIXED) Rework CSRF protection to use http-only cookies to prevent furter rework XSS attacks from stealing CSRF tokens
- :check: (MODERATE, FIXED) Webserver directory structure and filenames were leaked through 403 errors and 301 redirects when scanning without trailing slash.
- :check: (LOW, FIXED) Leaking Apache and PHP version numbers through HTTP headers. (fixed)
- :check: !! HIGH, TODO !! No rate limiting on signup (CAPTCHA)
- .check: (MODERATE, FIXED) Remove detailed error messages to the user to prevent information leakage
- :check: (MODERATE, FIXED) Missing locks in VPN config generation during signup leads to easy-rsa error which causes dangling database entries without created VPN config
- :check: (MODERATE, FIXED) Too many concurrent launches or stops of challenges lead to `ifreload` before finished network device setup, resulting in missing network devices
- :check: (LOW, FIXED) `SERIAL` IDs in `challenges` table and its use during MAC-Address generation could lead to duplicate MAC-Addresses due to overflow


## Website, admin privileges
- :check: !! MODERATE, TODO !! User account deletion of author or user could lead to dangling network devices or orphaned challenges if a challenge is running. Could also lead to double usage of network device names


## Webserver, Low Privilege (www-data)
- :check: (CRITICAL, FIXED) DB and PROXMOX credentials are stored in plaintext in the .env file on the webserver which is world-readable. Change to a templated DB query approach on the DB side and a API token approach with limited permissions for the Proxmox side
- :check: (CRITICAL, FIXED) A compromised www-data user on the webserver can modify webserver configs and files to serve malware to users, steal credentials, or deface the website. Mitigate by removing write permissions except for uploads, logs, and vpn configs
- :check: !! CRITICAL, TODO !! Modify VPN configs to be passed through to users directly from the backend to the users browser instead of being stored on the webserver to prevent attackers from changing them and rerouting user traffic through their own VPN server
- :check: (HIGH, FIXED) Introduce templated db queries on the database server side to prevent arbitrary SQL queries through a compromised webserver
- :check: !! HIGH, TODO !! Remove CSRF tokens and SESSION IDs from logs to prevent information leakage to a compromised www-data user


## Webserver, High Privilege (root, sudo)

## Database, Low Privilege (postgres)
## Database, High Privilege (root, sudo)

## Proxmox
- (MODERATE, FIXED) Only 1 core and 2GB RAM assigned to webserver and database VMs, which may be insufficient under load.
- (LOW, FIXED, updated to 8.4.14, upgrade to 9.x if possible) Used Proxmox Version 8.4.0 which misses some recent security patches relating to containers being created as privileged by default through the API and CLI and used 154 upgradable packages.
- (HIGH, FIXED) A firewall rule was missing to restrict access to the Proxmox host through the VPN network, allowing access to the same ports as through the secure internal network
## Challenge VM Breakout
- (HIGH, FIXED) CPU: host passthrough in Challenge VM import might expose host CPU vulnerabilities to the VM. Also using kvm64 future-proofs for possible cluster migration.


# BUGS
- (LOW, FIXED) Missing ordering by `ID` in paged SQL queries could lead to inconsistent results due to non-deterministic ordering of results


# IMPROVEMENTS
- !! LOW, TODO !! Clarify log messages (origin, timestamp, severity) for the backend and











