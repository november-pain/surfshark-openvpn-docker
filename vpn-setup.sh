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
  --log /var/log/openvpn.log \
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

ip route flush table $VPN_TABLE || true
ip route add default dev tun0 table $VPN_TABLE
ip rule flush || true
ip rule add prio 100 lookup main
for cidr in "${EXCLUDED_CIDRS[@]}"; do ip rule add to "$cidr" prio 150 lookup main; done
SIDECAR_IP=$(hostname -i)
if [ -n "$SIDECAR_IP" ]; then ip rule add from "$SIDECAR_IP" prio 140 lookup main; fi
ip rule add prio 200 lookup $VPN_TABLE
sysctl -w net.ipv4.ip_forward=1 > /dev/null
iptables -t nat -F POSTROUTING || true
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
echo "Routing setup complete."

# Print the current IP address for verification
echo "Current external IP address:"
wget -q -O - https://ifconfig.me/ip || echo "Could not determine external IP"

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