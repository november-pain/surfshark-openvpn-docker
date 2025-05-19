#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "Starting OpenVPN client on Alpine Linux..."

# --- Configuration ---
# Use environment variables or default values
CREDENTIALS_FILE="${CREDENTIALS_FILE:-/etc/openvpn/auth/credentials.txt}"
CONFIG_DIR="/etc/openvpn/surfshark"
OPENVPN_PID_FILE="/var/run/openvpn.pid"
KUBERNETES_SERVICE_CIDR="${KUBERNETES_SERVICE_CIDR:-10.96.0.0/12}"
KUBERNETES_POD_CIDR="${KUBERNETES_POD_CIDR:-10.244.0.0/16}"

# Check if VPN_REGION_IDENTIFIER is set
if [ -z "$VPN_REGION_IDENTIFIER" ]; then
  echo "Error: VPN_REGION_IDENTIFIER environment variable is not set."
  exit 1
fi
echo "Target VPN Region Identifier: ${VPN_REGION_IDENTIFIER}"

# Check if credentials file exists
if [ ! -f "$CREDENTIALS_FILE" ]; then
  echo "Error: Credentials file not found at $CREDENTIALS_FILE"
  exit 1
fi

echo "Using pre-downloaded configurations from ${CONFIG_DIR}"

# Set VPN protocol preference (default to UDP with TCP fallback)
VPN_PROTOCOL="${VPN_PROTOCOL:-udp}"
echo "Preferred VPN protocol: ${VPN_PROTOCOL}"

# Find the appropriate configuration file
echo "Searching for OVPN file matching '${VPN_REGION_IDENTIFIER}' with protocol '${VPN_PROTOCOL}' in ${CONFIG_DIR}..."

# First try the preferred protocol
TARGET_OVPN_CONFIG=$(find "${CONFIG_DIR}" -type f -name "*${VPN_REGION_IDENTIFIER}*${VPN_PROTOCOL}*.ovpn" -print -quit)

# If not found and preferred is UDP, try TCP as fallback
if [ -z "$TARGET_OVPN_CONFIG" ] && [ "${VPN_PROTOCOL}" = "udp" ]; then
  echo "UDP configuration not found, trying TCP as fallback..."
  TARGET_OVPN_CONFIG=$(find "${CONFIG_DIR}" -type f -name "*${VPN_REGION_IDENTIFIER}*tcp*.ovpn" -print -quit)
fi

# If still not found, try without protocol specification
if [ -z "$TARGET_OVPN_CONFIG" ]; then
  echo "Protocol-specific configuration not found, trying any protocol..."
  TARGET_OVPN_CONFIG=$(find "${CONFIG_DIR}" -type f -name "*${VPN_REGION_IDENTIFIER}*.ovpn" -print -quit)
fi

if [ -z "$TARGET_OVPN_CONFIG" ]; then
  echo "Error: Could not find an OVPN file matching '${VPN_REGION_IDENTIFIER}' in the pre-downloaded configurations."
  echo "Available configurations:"
  ls -la "${CONFIG_DIR}"
  
  # Fallback: download configurations if not found
  echo "Attempting to download latest configurations..."
  TEMP_DIR="/tmp/vpnsetup-$$"
  CONFIGS_DIR="${TEMP_DIR}/extracted_configs"
  ZIP_FILE="${TEMP_DIR}/configurations.zip"
  
  mkdir -p "${TEMP_DIR}" "${CONFIGS_DIR}"
  
  # Clean up function for the temporary directory
  trap 'rm -rf ${TEMP_DIR}' EXIT
  
  if wget -q --no-check-certificate -O "${ZIP_FILE}" "https://surfshark.com/api/v1/server/configurations" && \
     unzip -q -o "${ZIP_FILE}" -d "${CONFIGS_DIR}"; then
    
    # Try with preferred protocol first in downloaded configs
    TARGET_OVPN_CONFIG=$(find "${CONFIGS_DIR}" -type f -name "*${VPN_REGION_IDENTIFIER}*${VPN_PROTOCOL}*.ovpn" -print -quit)
    
    # Try fallback protocol if preferred is UDP and not found
    if [ -z "$TARGET_OVPN_CONFIG" ] && [ "${VPN_PROTOCOL}" = "udp" ]; then
      echo "UDP configuration not found in downloads, trying TCP as fallback..."
      TARGET_OVPN_CONFIG=$(find "${CONFIGS_DIR}" -type f -name "*${VPN_REGION_IDENTIFIER}*tcp*.ovpn" -print -quit)
    fi
    
    # Last resort: any protocol
    if [ -z "$TARGET_OVPN_CONFIG" ]; then
      TARGET_OVPN_CONFIG=$(find "${CONFIGS_DIR}" -type f -name "*${VPN_REGION_IDENTIFIER}*.ovpn" -print -quit)
    fi
    
    if [ -z "$TARGET_OVPN_CONFIG" ]; then
      echo "Error: Still could not find configuration for ${VPN_REGION_IDENTIFIER} after download."
      echo "Available configurations after download:"
      ls -la "${CONFIGS_DIR}"
      exit 1
    fi
    
    echo "Found configuration after download: ${TARGET_OVPN_CONFIG}"
  else
    echo "Error: Failed to download or extract configurations."
    exit 1
  fi
fi

# Extract the actual protocol being used from the filename
if [[ "$TARGET_OVPN_CONFIG" == *"udp"* ]]; then
  ACTUAL_PROTOCOL="UDP"
elif [[ "$TARGET_OVPN_CONFIG" == *"tcp"* ]]; then
  ACTUAL_PROTOCOL="TCP"
else
  ACTUAL_PROTOCOL="unknown"
fi

echo "Found OVPN configuration file: ${TARGET_OVPN_CONFIG} (Protocol: ${ACTUAL_PROTOCOL})"

# --- Start OpenVPN ---
echo "Starting OpenVPN with configuration: $TARGET_OVPN_CONFIG"
mkdir -p "$(dirname "$OPENVPN_PID_FILE")"

# Setup auth-nocache with proper auth
openvpn \
  --config "$TARGET_OVPN_CONFIG" \
  --auth-user-pass "$CREDENTIALS_FILE" \
  --auth-nocache \
  --daemon \
  --log /dev/stdout \
  --writepid "$OPENVPN_PID_FILE" \
  --script-security 2 \
  --up-delay \
  --ping 10 \
  --ping-restart 60 \
  --persist-tun --persist-key

sleep 2 # Give time for PID file creation

if [ ! -f "$OPENVPN_PID_FILE" ] || ! OPENVPN_PID=$(cat "$OPENVPN_PID_FILE"); then
  echo "Error: OpenVPN PID file not found or failed to start."
  exit 1
fi
echo "OpenVPN daemon started with PID $OPENVPN_PID"

# --- Wait for tun0 Interface ---
echo "Waiting for tun0 interface..."
TIMEOUT=30; COUNT=0
until ip link show tun0 > /dev/null 2>&1; do
  if [ $COUNT -ge $TIMEOUT ]; then
    echo "Error: Timeout waiting for tun0 interface."
    kill "$OPENVPN_PID" 2>/dev/null || true
    exit 1
  fi
  echo "tun0 not found yet, waiting... (${COUNT}s / ${TIMEOUT}s)"
  sleep 1; ((COUNT++))
done
echo "tun0 interface is up."

# --- Configure Routing ---
echo "Configuring routing..."
EXCLUDED_CIDRS=( "127.0.0.1/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "${KUBERNETES_SERVICE_CIDR}" "${KUBERNETES_POD_CIDR}" )
VPN_TABLE=100

# Create routing table if it doesn't exist
mkdir -p /etc/iproute2/
touch /etc/iproute2/rt_tables
grep -q "$VPN_TABLE" /etc/iproute2/rt_tables || echo "$VPN_TABLE vpntable" >> /etc/iproute2/rt_tables

# Set up routing
ip route flush table $VPN_TABLE 2>/dev/null || true
ip route add default dev tun0 table $VPN_TABLE

# Ensure DNS resolution works properly
echo "Configuring DNS resolution..."
if grep -q "dhcp-option DNS" /proc/net/openvpn/status 2>/dev/null; then
  # Extract DNS servers pushed by VPN
  VPN_DNS=$(grep "dhcp-option DNS" /proc/net/openvpn/status | awk '{print $3}')
  echo "Using DNS servers from VPN: $VPN_DNS"
  
  # Use the VPN DNS servers
  echo "nameserver $VPN_DNS" > /etc/resolv.conf
  echo "nameserver 8.8.8.8" >> /etc/resolv.conf  # Google DNS as backup
  echo "nameserver 1.1.1.1" >> /etc/resolv.conf  # Cloudflare DNS as backup
else
  # Fallback to public DNS servers
  echo "No VPN DNS servers detected, using public DNS servers"
  echo "nameserver 8.8.8.8" > /etc/resolv.conf  # Google DNS
  echo "nameserver 1.1.1.1" >> /etc/resolv.conf  # Cloudflare DNS
fi

# More straightforward IP policy routing setup
echo "Configuring IP policy routing..."
ip rule flush 2>/dev/null || true

# Setup policy routing with correct priorities (lower = higher priority)
# 1. Handle loopback traffic
ip rule add prio 10 from all to 127.0.0.0/8 lookup local

# 2. Add bidirectional rules for Kubernetes with higher priority
for cidr in "${EXCLUDED_CIDRS[@]}"; do
  echo "Setting bidirectional rules for $cidr"
  ip rule add from "$cidr" prio 50 lookup main
  ip rule add to "$cidr" prio 50 lookup main
done

# 3. Add local pod address rule
SIDECAR_IP=$(hostname -i 2>/dev/null || echo "")
if [ -n "$SIDECAR_IP" ]; then
  echo "Setting rules for sidecar IP: $SIDECAR_IP"
  ip rule add from "$SIDECAR_IP" prio 60 lookup main
fi

# 4. Add main route table lookup with medium priority
ip rule add prio 100 from all lookup main

# 5. Add default and VPN routes with lowest priority
ip rule add prio 200 from all lookup default
ip rule add prio 200 lookup $VPN_TABLE

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Set up NAT for the VPN interface
echo "Setting up NAT..."
iptables -t nat -F POSTROUTING 2>/dev/null || true
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT
echo "Routing setup complete."

echo "Adding specific routes for Kubernetes networks..."
DEFAULT_GW=$(ip route | grep -m 1 "^default.*eth0" | awk '{print $3}')
if [ -n "$DEFAULT_GW" ]; then
  for cidr in "${EXCLUDED_CIDRS[@]}"; do
    # Skip the loopback network
    if [ "$cidr" != "127.0.0.1/8" ]; then
      echo "Adding route for $cidr via $DEFAULT_GW"
      ip route add "$cidr" via "$DEFAULT_GW" dev eth0
    else
      echo "Skipping loopback network $cidr - already handled by local routing"
    fi
  done
  # Flush routing cache to apply changes immediately
  ip route flush cache
  echo "Kubernetes-specific routes added successfully"
else
  echo "Warning: Could not determine default gateway for eth0"
fi

# Print network status for debugging
echo "Network interfaces:"
ip addr
echo "Routing tables:"
ip route
echo "Routing rules:"
ip rule show
echo "DNS configuration:"
cat /etc/resolv.conf

# Print the current IP address for verification
echo "Current external IP address:"
# Try multiple IP detection services with better error handling
IP_FOUND=false
for service in "http://ipinfo.io/ip" "http://checkip.amazonaws.com" "http://icanhazip.com" "http://api.ipify.org"; do
  echo "Checking IP using $service..."
  if IP=$(wget -q -T 5 -t 2 -O - "$service" 2>/dev/null) && [ -n "$IP" ]; then
    echo "$IP"
    IP_FOUND=true
    break
  else
    echo "Failed to get IP from $service, trying next service..."
  fi
done

if ! $IP_FOUND; then
  echo "Warning: Could not determine external IP. Testing DNS resolution:"
  nslookup google.com || echo "DNS resolution failed"
  ping -c 1 8.8.8.8 || echo "Cannot ping Google DNS (8.8.8.8)"
fi

# --- Monitor OpenVPN Process ---
echo "Monitoring OpenVPN process (PID: $OPENVPN_PID)..."
while kill -0 "$OPENVPN_PID" 2>/dev/null && grep -q openvpn /proc/"$OPENVPN_PID"/cmdline; do
  sleep 10
  # Periodically check if the tunnel is still up
  if ! ip link show tun0 > /dev/null 2>&1; then
    echo "Error: tun0 interface disappeared. Trying to restart OpenVPN..."
    if kill -0 "$OPENVPN_PID" 2>/dev/null; then
      kill "$OPENVPN_PID"
      sleep 2
    fi
    exec "$0" # Restart the script
  fi
done
echo "OpenVPN process (PID: $OPENVPN_PID) has exited or is no longer OpenVPN."
exit 1 # Exit with error