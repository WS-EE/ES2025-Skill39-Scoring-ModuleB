# Document where we prepare potential checks for modications from 30% changes and fixes

# 30% change proposals -- how will we check?
# --------------------------------------------
# Active Directory: Synchronize time from INET to PDC
# WAN: Configure BGP routing; split subnets between RTR-CPH<>INET and INET<>RTR-AAL
# Web Servers: Set up IIS High Availability behind NLB with DFS webroot replication
# SRV2: Enable NIC Teaming with Load Balancing + Failover
# Remote Desktop Services: Deploy RD Gateway and Publish RemoteApp (e.g Calculator)
# SRV1 & SRV2: Configure custom Acccess-Denied messages for network shares
# REMOTE-CLIENT: New machine connected to INET. Configure remote access VPN with connection to CPH
# DC: Write a disaster recovery plan for the backups.
# Helpdesk: Create a Helpdesk group with delegated rights to reset regular user passwords.
# SRV2: Install Print Server role and configure a local printer on port LPT1 with Microsoft PCL6 Class Driver, shares as \\srv2\office. Deploy it automatically to all users.
# DNS: Implement DNSSEC for skillsnet.dk
# Backups: Include DNS zone backups for skillsnet.dk, skillsdev.dk and skillspublic.dk
# GPO: Configure AppLocker to block access to WordPad on all systems
# GPO: Competitors are allowed to use also DFS path as a Folder Redirection destination. Additional complexity and points for GPO Task 6.
# DC - CDP and AIA certificate endpoints need to be hosted on DC. OCSP responder is also hosted on DC
# SRV1 - ADFS needs to be deployed on SRV1
# RODC -Deploy DFS and replicate share Public from SRV2 every day at 12:00 AM
# RTR-AAL - All clients must receive DHCP address from SRV1 & SRV2 cluster, Block all outbound connections to WinRM
# SRV1&SRV2 - There must be a DFS share called Public that contains a text document named after competitor with his country of origin inside (interchangeable, just needs to have some data written)


# Fixes needed from marking perspective
# --------------------------------------------
# DHCPv6 failover limitation
# B1.M1 & B2.M1 checks
# BitLocker TPM limitation