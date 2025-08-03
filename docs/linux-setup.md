# Linux Setup Guide

This document provides step-by-step instructions for setting up dfirewall on a Linux system as a network router with firewall capabilities.

## Prerequisites

Start with a minimal Debian install. The example instructions assume that the machine:
- has two network interfaces
- WAN has a DHCP server willing to give you an IPv4 address
- LAN is using 192.168.21.0/24 subnet
- 1.1.1.1:53 is accessible
- WAN interface name is "enp2s0f0.3"
- LAN interface name is "ens9.31"

**Note**: You will need to account at least for the interface names in your environment.

## Step 1: Configure Network Interfaces

Use `/etc/network/interfaces` to configure your NICs. Here is an example:

```bash
auto lo
iface lo inet loopback

auto enp2s0f0.3
iface enp2s0f0.3 inet dhcp

auto ens9.31
iface ens9.31 inet static
  address 192.168.21.1/24
  netmask 255.255.255.0
```

Restart networking to apply changes:
```bash
/etc/init.d/networking restart
# Output: Restarting networking (via systemctl): networking.service.
```

## Step 2: Enable IP Forwarding

Enable IP forwarding and optionally disable IPv6 (IPv6 is now supported via AAAA records):

```bash
# Enable IP forwarding (required)
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/router.conf

# Optionally disable IPv6 if not needed (dfirewall supports IPv6 addresses and AAAA records)  
# echo "net.ipv6.conf.all.disable_ipv6=1"     >  /etc/sysctl.d/ipv6_disable.conf
# echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/ipv6_disable.conf

# Apply changes
sysctl --system
```

Verify interface configuration:
```bash
# Check WAN interface
ip ad sh enp2s0f0.3
# Expected output:
# 4: enp2s0f0.3@enp2s0f0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
#     link/ether c8:2a:14:0f:7c:9f brd ff:ff:ff:ff:ff:ff
#     inet 192.168.3.137/24 brd 192.168.3.255 scope global dynamic enp2s0f0.3
#        valid_lft 446sec preferred_lft 446sec

# Check LAN interface
ip ad sh ens9.31
# Expected output:
# 5: ens9.31@ens9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
#     link/ether 38:c9:86:13:f2:23 brd ff:ff:ff:ff:ff:ff
#     inet 192.168.21.1/24 brd 192.168.21.255 scope global ens9.31
#        valid_lft forever preferred_lft forever
```

## Step 3: Install Required Packages

Install packages needed for firewall functionality:
```bash
DEBIAN_FRONTEND=noninteractive apt -y install iptables ipset dnsmasq iptables-persistent git
```

## Step 4: Enable NAT (Network Address Translation)

Create iptables-persistent rules and restore them (**replace the WAN interface name with your interface**):

```bash
cat > /etc/iptables/rules.v4 <<EOF
*nat
-A POSTROUTING -o enp2s0f0.3 -j MASQUERADE
COMMIT

*filter
-A INPUT -i lo -j ACCEPT
# allow established connections
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# drop on WAN otherwise
-A INPUT -i enp2s0f0.3 -j DROP
COMMIT
EOF

# Apply the rules
iptables-restore < /etc/iptables/rules.v4
```

Verify the ruleset after loading:
```bash
iptables -L
# Expected output:
# Chain INPUT (policy ACCEPT)
# target     prot opt source               destination         
# ACCEPT     all  --  anywhere             anywhere            
# ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
# DROP       all  --  anywhere             anywhere            
# 
# Chain FORWARD (policy ACCEPT)
# target     prot opt source               destination         
# 
# Chain OUTPUT (policy ACCEPT)
# target     prot opt source               destination         

iptables -L -t nat
# Expected output:
# Chain PREROUTING (policy ACCEPT)
# target     prot opt source               destination         
# 
# Chain INPUT (policy ACCEPT)
# target     prot opt source               destination         
# 
# Chain OUTPUT (policy ACCEPT)
# target     prot opt source               destination         
# 
# Chain POSTROUTING (policy ACCEPT)
# target     prot opt source               destination         
# MASQUERADE  all  --  anywhere             anywhere           
```

## Step 5: Start DHCP Server

Setup dnsmasq as a DHCP server for the LAN (**replace LAN interface name with your interface**):

```bash
cat > /etc/dnsmasq.conf <<EOF
interface=ens9.31 # edit this to match your LAN interface
listen-address=127.0.0.1
port=0
domain=lan
dhcp-range=192.168.21.100,192.168.21.200,1h
dhcp-option=option:dns-server,192.168.21.1
EOF
```

Enable and start the service:
```bash
systemctl enable dnsmasq.service && systemctl restart dnsmasq.service
```

At this point, your Debian machine should be functioning as a router.

## Step 6: Install Docker and dfirewall

### Install Docker
```bash
# Configure Docker to not interfere with iptables
mkdir /etc/docker
echo '{ "iptables": false }' > /etc/docker/daemon.json

# Install Docker and Docker Compose
apt -y install docker.io docker-compose --no-install-recommends

# Enable and start Docker
systemctl enable docker && systemctl start docker
```

### Clone and Run dfirewall
```bash
# Clone the repository
git clone https://github.com/ddagunts/dfirewall 
cd dfirewall

# Start dfirewall with Docker Compose
docker-compose up -d
```

## Step 7: Testing the Setup

Connect a **new** client to the LAN (or ensure clean DNS cache on the client), then open some app to generate network traffic. You should see logs from the dfirewall container:

```bash
docker-compose logs -f dfirewall
# Expected output:
# dfirewall    | 2025/08/01 14:29:48 listening on port 53, set PORT env var to change
# dfirewall    | 2025/08/01 14:29:48 INVOKE_SCRIPT is set to /scripts/invoke_linux_ipset.sh
# dfirewall    | 2025/08/01 14:29:48 INVOKE_ALWAYS is set, executing INVOKE script for every matching request
# dfirewall    | 2025/08/01 14:29:48 EXPIRE_SCRIPT is set to /scripts/expire_generic.sh
# dfirewall    | 2025/08/01 14:29:48 WEB_UI_PORT is set to 8080
# dfirewall    | 2025/08/01 14:29:48 Connected to Redis at 127.0.0.1:6379
# dfirewall    | 2025/08/01 14:29:48 dfirewall started
```

### Verify Redis Storage
Check that clients, IPs, and domains are being stored in Redis:
```bash
docker exec -it redis redis-cli keys '*'
# Expected output:
# 1) "rules:192.168.21.142|185.199.109.133|raw.githubusercontent.com."
# 2) "rules:192.168.21.141|96.7.128.186|example.org."
```

### Verify ipsets
Check that ipsets are being populated on the host:
```bash
ipset list
# Expected output:
# Name: 192.168.21.180
# Type: hash:net 
# Revision: 7  
# Header: family inet hashsize 1024 maxelem 65536 timeout 60 bucketsize 12 initval 0x928f08a1
# Size in memory: 5640
# References: 1
# Number of entries: 1
# Members:
# 76.223.92.165 timeout 144
```

### Verify iptables Rules
Check that firewall rules are created for each client:
```bash
iptables -L
# Expected output should include rules like:
# Chain FORWARD (policy ACCEPT)
# target     prot opt source               destination
# ACCEPT     all  --  192.168.21.180       anywhere             match-set 192.168.21.180 dst
# REJECT     all  --  192.168.21.180       anywhere             reject-with icmp-port-unreachable
# ACCEPT     all  --  192.168.21.158       anywhere             match-set 192.168.21.158 dst
# REJECT     all  --  192.168.21.158       anywhere             reject-with icmp-port-unreachable
```

### Test Web Interface
Access the web interface at http://192.168.21.1:8080 to view and manage firewall rules.

### Test Firewall Functionality
From a client on the LAN, test the firewall behavior:

```bash
# Try to ping an IP directly (should fail)
ping -c1 1.1.1.1
# Expected: Destination Port Unreachable

# Ping by hostname (should work and create firewall rule)
ping -c1 one.one.one.one
# Expected: Success

# Now ping the IP directly again (should work until TTL expires)
ping -c1 1.1.1.1
# Expected: Success
```

## Step 8: Domain Blacklisting Testing

The example configuration includes domain blacklisting via Redis. Test it:

```bash
# Access the blacklist management script
docker exec -it dfirewall /scripts/manage_blacklists.sh

# List current blacklisted domains
docker exec -it dfirewall /scripts/manage_blacklists.sh list-domains

# Test DNS resolution for a blacklisted domain
dig www.google.com @192.168.21.1
# Expected: NXDOMAIN response if blacklisted
```

## Advanced Configuration

### Default Deny Policy
For better security, configure default deny instead of per-client REJECT rules. Modify `/etc/iptables/rules.v4`:

```bash
cat > /etc/iptables/rules.v4 <<EOF
*nat
-A POSTROUTING -o enp2s0f0.3 -j MASQUERADE
COMMIT

*filter                      
-A INPUT -i lo -j ACCEPT     
# allow established connections
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# drop on WAN otherwise      
-A INPUT -i enp2s0f0.3 -j DROP 
# Default deny for LAN forwarding
-A FORWARD -s 192.168.21.0/24 -j REJECT
COMMIT
EOF
```

This approach rejects forwarded traffic by default, and dfirewall creates ACCEPT rules for allowed IPs.

### Install Optional Tools
Install additional networking tools useful for router management:
```bash
apt -y install net-tools dnsutils netcat-openbsd tcpdump lsof htop iftop ldnsutils netdiscover --no-install-recommends
```

## Troubleshooting

### Common Issues

#### Network Interface Issues
- Verify interface names with `ip link show`
- Check interface configuration with `ip addr show`
- Ensure interfaces are up with `ip link set <interface> up`

#### iptables Issues
- Check current rules: `iptables -L -v -n`
- Verify NAT rules: `iptables -t nat -L -v -n`
- Monitor rule hits: `watch iptables -L -v -n`

#### Docker Issues
- Check container status: `docker-compose ps`
- View container logs: `docker-compose logs dfirewall`
- Verify network mode: `docker inspect dfirewall | grep NetworkMode`

#### DNS Resolution Issues
- Test upstream DNS: `dig @1.1.1.1 google.com`
- Check dfirewall DNS: `dig @127.0.0.1 google.com`
- Verify port binding: `netstat -tulpn | grep :53`

### Debug Commands
```bash
# Monitor DNS traffic
tcpdump -i any port 53

# Watch iptables rule creation
watch iptables -L -v -n

# Monitor ipset changes
watch ipset list

# Check dfirewall logs
docker-compose logs -f dfirewall

# Monitor Redis activity
docker exec -it redis redis-cli monitor
```

## Security Considerations

1. **Firewall Rules**: The example creates per-client REJECT rules. Consider default deny policy for better security.
2. **Network Isolation**: Ensure proper network segmentation between WAN and LAN.
3. **Service Security**: Secure Redis, Docker, and other services according to best practices.
4. **Updates**: Keep the system and Docker images updated.
5. **Monitoring**: Implement logging and monitoring for security events.
6. **Backup**: Backup configuration files and iptables rules.

## Performance Optimization

1. **Redis Tuning**: Configure Redis for optimal performance based on your traffic.
2. **ipset Optimization**: Use appropriate timeout values for ipset entries.
3. **iptables Optimization**: Order rules by frequency of matches.
4. **Hardware**: Ensure adequate CPU and memory for your traffic volume.
5. **Network Buffers**: Tune network buffer sizes for high throughput.

This completes the Linux setup for dfirewall as a network firewall router.
