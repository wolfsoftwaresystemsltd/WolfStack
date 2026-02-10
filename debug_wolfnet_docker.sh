#!/bin/bash
# WolfNet Docker Networking Diagnostic Script
# Run this ON THE SERVER where Docker containers are running

echo "============================================"
echo "  WolfNet Docker Networking Diagnostics"
echo "============================================"
echo ""

# 1. Find running Docker containers with WolfNet IPs
echo "=== Running Docker containers ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
echo ""

# 2. Find containers with wolfnet labels
echo "=== Containers with WolfNet IPs ==="
for c in $(docker ps -q 2>/dev/null); do
    name=$(docker inspect --format '{{.Name}}' "$c" | sed 's/^\//')
    wip=$(docker inspect --format '{{index .Config.Labels "wolfnet.ip"}}' "$c" 2>/dev/null)
    bridge_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")
    mac=$(docker inspect --format '{{.NetworkSettings.MacAddress}}' "$c")
    if [ -n "$wip" ]; then
        echo "  Container: $name"
        echo "    WolfNet IP: $wip"
        echo "    Bridge IP:  $bridge_ip"
        echo "    MAC:        $mac"
        echo ""
    fi
done

# 3. Check routes
echo "=== Host routes for 10.10.10.x ==="
ip route show | grep 10.10.10
echo ""

# 4. Check ARP/neighbor table for docker0
echo "=== Neighbor table for docker0 ==="
ip neigh show dev docker0
echo ""

# 5. Check iptables FORWARD
echo "=== iptables FORWARD chain ==="
iptables -L FORWARD -n -v --line-numbers 2>/dev/null | head -30
echo ""

# 6. Check Docker isolation rules
echo "=== Docker ISOLATION rules ==="
iptables -L DOCKER-ISOLATION-STAGE-1 -n -v 2>/dev/null
iptables -L DOCKER-ISOLATION-STAGE-2 -n -v 2>/dev/null
echo ""

# 7. Check sysctl
echo "=== Sysctl settings ==="
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.docker0.proxy_arp 2>/dev/null
echo ""

# 8. Check if container has the IP inside
echo "=== Container internal networking ==="
for c in $(docker ps -q 2>/dev/null); do
    name=$(docker inspect --format '{{.Name}}' "$c" | sed 's/^\//')
    wip=$(docker inspect --format '{{index .Config.Labels "wolfnet.ip"}}' "$c" 2>/dev/null)
    if [ -n "$wip" ]; then
        echo "  Container: $name (WolfNet: $wip)"
        echo "  --- ip addr show eth0 ---"
        docker exec "$name" ip addr show eth0 2>/dev/null
        echo "  --- ip route ---"
        docker exec "$name" ip route 2>/dev/null
        echo ""
    fi
done

# 9. Try to ping bridge IP
echo "=== Test: ping container bridge IP ==="
for c in $(docker ps -q 2>/dev/null); do
    name=$(docker inspect --format '{{.Name}}' "$c" | sed 's/^\//')
    bridge_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")
    wip=$(docker inspect --format '{{index .Config.Labels "wolfnet.ip"}}' "$c" 2>/dev/null)
    if [ -n "$wip" ] && [ -n "$bridge_ip" ]; then
        echo "  Pinging $name at bridge IP $bridge_ip..."
        ping -c 1 -W 2 "$bridge_ip" 2>&1 | tail -2
        echo ""
    fi
done

# 10. Try manual fix
echo "============================================"
echo "  Attempting manual fix..."
echo "============================================"
for c in $(docker ps -q 2>/dev/null); do
    name=$(docker inspect --format '{{.Name}}' "$c" | sed 's/^\//')
    wip=$(docker inspect --format '{{index .Config.Labels "wolfnet.ip"}}' "$c" 2>/dev/null)
    bridge_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")
    mac=$(docker inspect --format '{{.NetworkSettings.MacAddress}}' "$c")
    
    if [ -n "$wip" ] && [ -n "$bridge_ip" ] && [ -n "$mac" ]; then
        echo ""
        echo "Container: $name | WolfNet: $wip | Bridge: $bridge_ip | MAC: $mac"
        
        # Add IP inside container
        echo "  [1] Adding $wip/32 to container eth0..."
        docker exec "$name" ip addr add "$wip/32" dev eth0 2>&1 || echo "  (already exists)"
        
        # Add static neighbor entry
        echo "  [2] Adding static ARP: $wip -> $mac on docker0..."
        ip neigh replace "$wip" lladdr "$mac" dev docker0 nud permanent
        ip neigh show "$wip" dev docker0
        
        # Delete old route and add new one
        echo "  [3] Adding route: $wip/32 dev docker0..."
        ip route del "$wip/32" 2>/dev/null
        ip route add "$wip/32" dev docker0
        ip route show | grep "$wip"
        
        # Enable forwarding
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        sysctl -w net.ipv4.conf.docker0.proxy_arp=1 > /dev/null
        
        # Test ping
        echo "  [4] Testing ping to $wip..."
        ping -c 2 -W 2 "$wip" 2>&1
        echo ""
        
        # If that failed, try pinging bridge IP to confirm basic connectivity  
        echo "  [5] Testing ping to bridge IP $bridge_ip..."
        ping -c 1 -W 2 "$bridge_ip" 2>&1 | tail -2
        echo ""
    fi
done

echo "============================================"
echo "  WolfStack journal logs (last 20 WolfNet-related lines):"
echo "============================================"
journalctl -u wolfstack --no-pager -n 100 2>/dev/null | grep -i "wolfnet\|wolfd\|route\|mac\|bridge\|container.*routed" | tail -20
