# BUGS / VULNERABILITIES
- (FIXED) `SERIAL` IDs in `challenges` table and its use during MAC-Address GENERATION could lead to duplicate MAC-Addresses due to overflow
- !! TODO, CRITICAL !! User account deletion of author or user could lead to dangling network devices or orphaned challenges if a challenge is running. Could also lead to double usage of network device names
- (FIXED) Missing ordering by `ID` in paged SQL queries could lead to inconsistent results due to non-deterministic ordering of results
- (FIXED) Missing locks in VPN config generation during signup leads to easy-rsa error which causes dangling database entries without created VPN config
- (FIXED) Too many concurrent launches or stops of challenges lead to ifreload before finished network device setup, resulting in missing network devices
- (FIXED) Webserver directory structure was leaked through 403 errors and 301 redirects when scanning without trailing slash.
- (FIXED) Leaking Apache and PHP version numbers through HTTP headers. (fixed)
- (FIXED) Only 1 core and 2GB RAM assigned to webserver and database VMs, which may be insufficient under load. (fixed)
- (FIXED) CPU: host passthrough in Challenge VM import might expose host CPU vulnerabilities to the VM. Also using kvm64 future-proofs for possible cluster migration.
- (FIXED, updated to 8.4.14, upgrade to 9.x if possible) Used Proxmox Version 8.4.0 which misses some recent security patches relating to containers being created as privileged by default through the API and CLI and used 154 upgradable packages.
- !! TODO !! Introduce templated db queries on the database server side to prevent arbitrary SQL queries through a compromised webserver
- !! TODO, CRITICAL !! DB and !PROXMOX! credentials are stored in plaintext in the .env file on the webserver which is world-readable. Change to a templated DB query approach on the DB side and a API token approach with limited permissions for the Proxmox side
- !! TODO tests directory is copied to the webserver and is world-readable, might contain sensitive information
- !! TODO !! A compromised www-data user on the webserver could read them memory of the apache process and extract user data through ptrace. (Less likely because only parent process can ptrace, but should use `echo "kernel.yama.ptrace_scope = 2" | sudo tee /etc/sysctl.d/10-ptrace.conf; sudo sysctl --system` to restrict further)









