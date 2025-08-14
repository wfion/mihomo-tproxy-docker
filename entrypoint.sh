#!/bin/bash
# 使用 iptables 版 TProxy 规则

MIHOMO_PORT=7893
MIHOMO_DNS_PORT=1053
TPROXY_MARK=1
ROUTE_TABLE=100

CN_IP_FILE="/mihomo/config/cn_cidr.txt"

RESERVED_IPS="0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"

# 校验环境变量
if [ "$BYPASS_CN" != "true" ] && [ "$BYPASS_CN" != "false" ]; then
    echo "Error: '\$BYPASS_CN' Must be 'true' or 'false'."
    exit 1
fi

if [ "$QUIC" != "true" ] && [ "$QUIC" != "false" ]; then
    echo "Error: '\$QUIC' Must be 'true' or 'false'."
    exit 1
fi

if [ "$CONTAINER_PROXY" != "true" ] && [ "$CONTAINER_PROXY" != "false" ]; then
    echo "Error: '\$CONTAINER_PROXY' Must be 'true' or 'false'."
    exit 1
fi

# 路由标记
ip rule add fwmark $TPROXY_MARK table $ROUTE_TABLE 2>/dev/null
ip route add local 0.0.0.0/0 dev lo table $ROUTE_TABLE 2>/dev/null

# 清理已有规则
iptables -t mangle -F
iptables -t mangle -X clash 2>/dev/null
iptables -t mangle -N clash

# 保留地址不代理
for ip in $RESERVED_IPS; do
    iptables -t mangle -A clash -d $ip -j RETURN
done

# 中国大陆 IP 分流
if [ "$BYPASS_CN" = "true" ] && [ -f "$CN_IP_FILE" ]; then
    while read -r ip; do
        [[ "$ip" =~ ^#.*$ || -z "$ip" ]] && continue
        iptables -t mangle -A clash -d "$ip" -j RETURN
    done < "$CN_IP_FILE"
fi

# 禁用 QUIC
if [ "$QUIC" = "false" ]; then
    iptables -t mangle -A clash -p udp --dport 443 -j DROP
fi

# TProxy 转发
iptables -t mangle -A clash -p udp -j TPROXY --on-port $MIHOMO_PORT --tproxy-mark $TPROXY_MARK
iptables -t mangle -A clash -p tcp -j TPROXY --on-port $MIHOMO_PORT --tproxy-mark $TPROXY_MARK

# DNS 劫持
#iptables -t mangle -A PREROUTING -p udp --dport 53 -j TPROXY --on-port $MIHOMO_DNS_PORT --tproxy-mark $TPROXY_MARK

# 应用 chain
iptables -t mangle -A PREROUTING -j clash

echo "*** Starting Mihomo ***"
exec "$@"
