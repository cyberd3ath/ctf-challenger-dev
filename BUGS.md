# BUGS / VULNERABILITIES
- `SERIAL` IDs in `challenges` table and its use during MAC-Address GENERATION could lead to duplicate MAC-Addresses du to overflow
- User account deletion of author or user could lead to dangling network devices or orphaned challenges if a challenge is running. Could also lead to double usage of network device names
- Missing ordering by `ID` in paged SQL queries could lead to inconsistent results due to non-deterministic ordering of results
- Missing locks in VPN config generation during signup leads to easy-rsa error which causes dangling database entries without created VPN config
- Too many concurrent launches or stops of challenges lead to ifreload before finished network device setup, resulting in missing network devices
- 
- 