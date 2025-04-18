FROM alpine:3.18

# Install required packages in one layer to reduce image size
RUN apk add --no-cache \
    wget \
    unzip \
    openvpn \
    iptables \
    iproute2 \
    procps \
    bash \
    ca-certificates

# Create necessary directories
RUN mkdir -p /etc/openvpn/auth /etc/openvpn/config /etc/openvpn/surfshark

# Download and extract Surfshark configurations during build
WORKDIR /etc/openvpn/surfshark
RUN wget -q --no-check-certificate -O surfshark-configs.zip "https://surfshark.com/api/v1/server/configurations" \
    && unzip -q surfshark-configs.zip \
    && rm surfshark-configs.zip \
    && echo "$(date '+%Y-%m-%d %H:%M:%S') - Configurations downloaded and extracted during build" > /etc/openvpn/surfshark/download_info.txt

# Copy the startup script
COPY vpn-setup.sh /usr/local/bin/vpn-setup.sh
RUN chmod +x /usr/local/bin/vpn-setup.sh

# Default environment variables (can be overridden at runtime)
ENV VPN_REGION_IDENTIFIER="" \
    KUBERNETES_SERVICE_CIDR="10.96.0.0/12" \
    KUBERNETES_POD_CIDR="10.244.0.0/16" \
    CREDENTIALS_FILE="/etc/openvpn/auth/credentials.txt"

# Command to run
ENTRYPOINT ["/bin/bash", "/usr/local/bin/vpn-setup.sh"]
