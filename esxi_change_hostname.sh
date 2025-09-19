# -----------------------------------------------------------------------------
# #1
# change_hostname_esxi7a.sh
# Commands to change ESXi hostname to esxi7a.lan
# -----------------------------------------------------------------------------

#!/bin/bash

# Set the hostname using esxcli
esxcli system hostname set --host=esxi7a --domain=lan --fqdn=esxi7a.lan

# Verify the hostname change
echo "Current hostname configuration:"
esxcli system hostname get

# Alternative method using vim-cmd (if needed)
# vim-cmd hostsvc/set_hostid hostname=esxi7a.lan

# Restart management agents to apply changes (optional but recommended)
echo "Restarting management agents..."
/etc/init.d/hostd restart
# /etc/init.d/vpxa restart


echo "Hostname change completed. Please verify with: esxcli system hostname get"
