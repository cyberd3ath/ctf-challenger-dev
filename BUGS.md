# VULNERABILITIES

## DOS
- !! HIGH, TODO !! No rate limiting on signup (CAPTCHA)
- (MEDIUM, FIXED) Missing locks in VPN config generation during signup leads to easy-rsa error which causes dangling database entries without created VPN config
- (MEDIUM, FIXED) Too many concurrent launches or stops of challenges lead to `ifreload` before finished network device setup, resulting in missing network devices
- (MEDIUM, FIXED) Only 1 core and 2GB RAM assigned to webserver and database VMs, which may be insufficient under load.
- (LOW, FIXED) `SERIAL` IDs in `challenges` table and its use during MAC-Address generation could lead to duplicate MAC-Addresses due to overflow



## External, No Privileges
- !! HIGH, TODO !! No Brute-Force protection on login (CAPTCHA)
- !! HIGH, TODO !! Rework CSRF protection to use http-only cookies to prevent furter rework XSS attacks from stealing CSRF tokens
- !! MEDIUM, TODO !! User account deletion of author or user could lead to dangling network devices or orphaned challenges if a challenge is running. Could also lead to double usage of network device names
- (MEDIUM, FIXED) Webserver directory structure and filenames were leaked through 403 errors and 301 redirects when scanning without trailing slash.
- (LOW, FIXED) Leaking Apache and PHP version numbers through HTTP headers. (fixed)


## Webserver, Low Privilege (www-data)
- !! CRITICAL, TODO !! DB and PROXMOX credentials are stored in plaintext in the .env file on the webserver which is world-readable. Change to a templated DB query approach on the DB side and a API token approach with limited permissions for the Proxmox side
- !! CRITICAL, TODO !! A compromised www-data user on the webserver can modify webserver configs and files to serve malware to users, steal credentials, or deface the website. Mitigate by removing write permissions except for uploads, logs, and vpn configs
- !! CRITICAL, TODO !! Modify VPN configs to be passed through to users directly from the backend to the users browser instead of being stored on the webserver to prevent attackers from changing them and rerouting user traffic through their own VPN server
- !! HIGH, TODO !! Introduce templated db queries on the database server side to prevent arbitrary SQL queries through a compromised webserver
- !! HIGH, TODO !! Remove CSRF tokens and SESSION IDs from logs to prevent information leakage to a compromised www-data user
- !! MEDIUM, TODO !! Remove detailed error messages to the user to prevent information leakage
- !! LOW, TODO (low because mostly mitigated already) !! A compromised www-data user on the webserver could read them memory of the apache process and extract user data through ptrace. (Less likely because only parent process can ptrace, but should use `echo "kernel.yama.ptrace_scope = 2" | sudo tee /etc/sysctl.d/10-ptrace.conf; sudo sysctl --system` to restrict further)

## Webserver, High Privilege (root, sudo)

## Database, Low Privilege (postgres)
## Database, High Privilege (root, sudo)

## Proxmox
- (LOW, FIXED, updated to 8.4.14, upgrade to 9.x if possible) Used Proxmox Version 8.4.0 which misses some recent security patches relating to containers being created as privileged by default through the API and CLI and used 154 upgradable packages.

## Challenge VM Breakout
- (HIGH, FIXED) CPU: host passthrough in Challenge VM import might expose host CPU vulnerabilities to the VM. Also using kvm64 future-proofs for possible cluster migration.


# BUGS
- (LOW, FIXED) Missing ordering by `ID` in paged SQL queries could lead to inconsistent results due to non-deterministic ordering of results


# IMPROVEMENTS
- !! LOW, TODO !! Clarify log messages (origin, timestamp, severity) for the backend and











