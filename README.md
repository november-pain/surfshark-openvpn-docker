# OpenVPN Sidecar Container

This is a custom OpenVPN client container designed specifically for use as a Kubernetes sidecar
with pre-downloaded Surfshark VPN configurations. Can also be used as a standalone VPN container on any server.

## Features

- Pre-downloaded Surfshark VPN configurations (baked into image)
- Fallback to fresh download if the configuration isn't found
- Configurable via environment variables
- Automatic routing setup for Kubernetes
- Self-healing with connection monitoring
- Alpine-based for small image size

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VPN_REGION_IDENTIFIER` | Surfshark region code (e.g., "uk-lon") | (required) |
| `VPN_PROTOCOL` | VPN protocol to use (udp or tcp) | udp |
| `KUBERNETES_SERVICE_CIDR` | Kubernetes service CIDR | 10.96.0.0/12 |
| `KUBERNETES_POD_CIDR` | Kubernetes pod CIDR | 10.244.0.0/16 |
| `CREDENTIALS_FILE` | Path to credentials file | /etc/openvpn/auth/credentials.txt |

## Volume Mounts

- `/etc/openvpn/auth/credentials.txt` - Surfshark credentials file (required)

## Building the Image

```bash
docker build -t your-registry/openvpn-sidecar:latest .
```

## Usage in Kubernetes

```yaml
containers:
- name: app
  image: myapp:latest
  # ...other container config...
- name: vpn
  image: your-registry/openvpn-sidecar:latest
  env:
  - name: VPN_REGION_IDENTIFIER
    value: "uk-lon"
  securityContext:
    capabilities:
      add: ["NET_ADMIN"]
    privileged: true
  volumeMounts:
  - name: surfshark-credentials
    mountPath: /etc/openvpn/auth/credentials.txt
    subPath: credentials.txt
    readOnly: true
volumes:
- name: surfshark-credentials
  secret:
    secretName: surfshark-credentials
```

## Standalone Usage on a Server

You can run this container directly on any host with Docker:

```bash
# Create a credentials file
echo "your_surfshark_username
your_surfshark_password" > credentials.txt

# Run the container
docker run -d --name vpn \
  --cap-add=NET_ADMIN --privileged \
  -v $(pwd)/credentials.txt:/etc/openvpn/auth/credentials.txt:ro \
  -e VPN_REGION_IDENTIFIER="uk-lon" \
  --network host \
  your-registry/openvpn-sidecar:latest
```

### Network Modes

For standalone usage, there are two main ways to use the VPN container:

1. **Host network mode** (shown above): The VPN tunnel will be available to the host machine and all its processes.

2. **As a gateway for other containers**:

```bash
# Create a custom Docker network
docker network create vpn-network

# Run the VPN container
docker run -d --name vpn-gateway \
  --cap-add=NET_ADMIN --privileged \
  -v $(pwd)/credentials.txt:/etc/openvpn/auth/credentials.txt:ro \
  -e VPN_REGION_IDENTIFIER="uk-lon" \
  --network vpn-network \
  your-registry/openvpn-sidecar:latest

# Run other containers using the VPN
docker run -d --name app \
  --network vpn-network \
  --link vpn-gateway:vpn \
  your-application-image
```

### Route Specific Traffic

If you want only specific applications to use the VPN, but not the entire host, you can:

```bash
# Start the VPN container
docker run -d --name vpn \
  --cap-add=NET_ADMIN --privileged \
  -v $(pwd)/credentials.txt:/etc/openvpn/auth/credentials.txt:ro \
  -e VPN_REGION_IDENTIFIER="uk-lon" \
  your-registry/openvpn-sidecar:latest

# Get the container's IP
VPN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vpn)

# Now run any app container with routing through the VPN
docker run -d --name app \
  --net=container:vpn \
  your-application-image
```

## Credentials Format

The credentials file should contain:
